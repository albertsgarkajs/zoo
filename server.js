import express from 'express';
import sqlite3 from 'sqlite3';
import crypto from 'crypto';
import session from 'express-session';
const { default: connectSQLite3 } = await import('connect-sqlite3');
const SQLiteStore = connectSQLite3(session);
const sessionStore = new SQLiteStore({
    db: 'session.sqlite',
    dir: '/data/sessions'  // ← THIS IS THE FIX
});
import path from 'path';
import fs from 'fs';
import nodemailer from 'nodemailer';
import cron from 'node-cron';
import http from 'http';
import { Server } from 'socket.io';
import multer from 'multer';
import { fileURLToPath } from 'url';
import { db } from './db.js';

import util from 'util';

const PORT = process.env.PORT || 8080;
const HOST = '0.0.0.0';
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==================== HTTP SERVER + SOCKET.IO ====================
const server = http.createServer(app); // <-- TAGAD SERVERIS
const io = new Server(server, { // <-- SOCKET.IO
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const sessionMiddleware = session({
    store: sessionStore,
    secret: 'change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
});

(async () => {
    try {
        console.log('[DB] Initializing database...');
        await initDb(); // ← THIS MUST FINISH FIRST
        console.log('[DB] Database ready');

        const PORT = process.env.PORT || 8080;
        const HOST = '0.0.0.0';

        server.listen(PORT, HOST, () => {
            console.log(`Server running on http://0.0.0.0:${PORT}`);
            console.log(`Socket.IO ready`);
        });

    } catch (err) {
        console.error('[ERROR] Failed to start server:', err);
        process.exit(1);
    }
})();

// === DB & SEED SETUP ===
(async () => {
    try {
        const db = new sqlite3.Database(process.env.SQLITE_PATH || 'db.sqlite');
        db.run = util.promisify(db.run);
        db.get = util.promisify(db.get);
        db.all = util.promisify(db.all);
        console.log('[DB] Promisify funkcijas pievienotas – dbRun/dbGet/dbAll gatavas!');

        // CREATE TABLES
        await db.run(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        icon TEXT,
        UNIQUE(title)
      )
    `);
        console.log('[DB] tasks table ready');

        // LOAD animals.json IF EMPTY
        const row = await db.get('SELECT COUNT(*) as count FROM tasks');
        if (row.count === 0) {
            const animalsPath = path.join(__dirname, 'animals.json');
            if (fs.existsSync(animalsPath)) {
                const data = JSON.parse(fs.readFileSync(animalsPath, 'utf8'));
                console.log(`[START] Ielādēti ${data.length} uzdevumi no animals.json`);
                for (const task of data) {
                    await db.run(
                        `INSERT OR IGNORE INTO tasks (title, description, icon) VALUES (?, ?, ?)`,
                        [task.title, task.description || '', task.icon || '']
                    );
                }
                console.log('[DB] Data loaded');
            }
        } else {
            console.log(`[DB] Already has ${row.count} tasks – skipping seed`);
        }

        // START SERVER
        const server = app.listen(3000, '0.0.0.0', () => {
            console.log(`Serveris uz http://192.168.1.231:3000`);
        });

        const io = new Server(server);
        // ... your socket.io setup

    } catch (err) {
        console.error('Startup failed:', err);
        process.exit(1);
    }
})();

// Globāli pieejams broadcast
global.io = io;
global.broadcastAnimalsUpdate = () => {
    if (global.io) {
        global.io.emit('animals-updated');
        console.log('[SOCKET] 📢 Broadcast: animals-updated (visi klienti reload)');
    }
};

// ==================== 5. STATIC FILES ====================
app.use(session({
    store: sessionStore,  // ← THIS WAS MISSING
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,        // Set true on HTTPS
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
}));

app.use(sessionMiddleware);
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

app.use(express.static('.'));           // serves login.html, admin.html
app.use('/public', express.static('public'));  // /public/task-icons/...

app.use(express.static(__dirname));
app.use('/style.css', (req, res) => {
    res.setHeader('Content-Type', 'text/css');
    res.sendFile(path.join(__dirname, 'style.css'));
});

// ==================== 1. DB + PRODUCTION SETUP ====================
const isProd = process.env.NODE_ENV === 'production';
const dbPath = isProd ? '/tmp/db.sqlite' : './db.sqlite';
const db = new sqlite3.Database(dbPath);

// === PROMISIFY SQLITE (lai async/await strādātu) ===
const dbRun = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve(this); // this.lastID pieejams
    });
});

const dbGet = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
    });
});

const dbAll = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
    });
});

console.log('[DB] Promisify funkcijas pievienotas – dbRun/dbGet/dbAll gatavas!');

// Vercel DB copy
if (isProd && fs.existsSync('./db.sqlite') && !fs.existsSync(dbPath)) {
    fs.copyFileSync('./db.sqlite', dbPath);
    console.log('Copied db.sqlite to /tmp');
}

// ==================== 2. BODY PARSERS ====================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ==================== 3. SESSION ====================
const sessionStorePath = isProd ? '/tmp/sessions.db' : './sessions.db';
app.use(session({
    store: new SQLiteStore({
        db: path.basename(sessionStorePath),
        dir: path.dirname(sessionStorePath)
    }),
    secret: process.env.SESSION_SECRET || 'super-secret-key-12345-change-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax'
    }
}));

// ==================== 4. CORS ====================
app.use((req, res, next) => {
    const origin = req.headers.origin || '*';
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// ==================== 6. MOBILE DETECTION ====================

// ==================== ANTI-CACHE FOR ALL HTML PAGES ====================
app.use((req, res, next) => {
    if (req.path.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    next();
});

const mobileUserAgents = [
    /Android/i, /webOS/i, /iPhone/i, /iPad/i, /iPod/i,
    /BlackBerry/i, /IEMobile/i, /Opera Mini/i, /Mobile/i, /Windows Phone/i,
    /Tablet/i, /Kindle/i, /Silk/i, /PlayBook/i  // papildu planšetēm
];

// PĀRVieto uz pašām beigām, lai tas būtu PIRMS visiem route'iem (izņemot static un session)
app.use((req, res, next) => {
    const ua = req.headers['user-agent'] || '';
    const isMobile = mobileUserAgents.some(regex => regex.test(ua));
    req.isMobile = isMobile;  // saglabājam req, lai login var izmantot
    console.log(`UA: ${ua} → isMobile: ${isMobile}`);

    // Tikai root un dashboard.html → mobile
    if (isMobile && (req.path === '/' || req.path === '/dashboard.html')) {
        console.log(`MOBILE REDIRECT: ${req.path} → /mobile-dashboard.html`);
        return res.redirect('/mobile-dashboard.html');
    }
    next();
});

app.use('/task-icons', express.static(path.join(__dirname, 'public', 'task-icons'), {
    setHeaders: (res) => {
        res.setHeader('Cache-Control', 'no-store');
    }
}));

app.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(__dirname, 'favicon.ico'), { maxAge: 86400000 });
});

app.get('*', (req, res) => {
    res.sendFile('login.html', { root: '.' });
});

app.get('/mobile-activity.html', (req, res) => {
    if (!req.session?.user) return res.redirect('/login.html');
    res.sendFile(path.join(__dirname, 'mobile-activity.html'));
});

// ==================== 7. CONSTS & HELPERS ====================
const ROLES = [
    'Vivāriju dzīvnieku kopējs I',
    'Vivāriju dzīvnieku kopējs II',
    'Vivāriju dzīvnieku kopējs III',
    'Zootehniķis',
    'Veterinārārsts',
    'Veterinārārsta asistents',
    'Entomologs'
];

function hashPassword(p) {
    return crypto.createHash('sha256').update(p).digest('hex');
}

// Load animals.json
let tasks = []; // globāls

// Startā ielādē tasks no animals.json
function loadTasksFromFile() {
    if (fs.existsSync('./animals.json')) {
        const animals = JSON.parse(fs.readFileSync('./animals.json', 'utf8'));
        tasks = animals.map(a => ({
            id: a.id,
            cage: a.cage,
            name: a.name
        }));
        console.log(`[START] Ielādēti ${tasks.length} uzdevumi no animals.json`);
    }
}
loadTasksFromFile();

let animals = [];
try {
    animals = JSON.parse(fs.readFileSync('./animals.json', 'utf8'));
} catch (err) {
    console.error('animals.json not found or invalid!');
}

// ==================== 8. DATABASE INITIALIZATION ====================
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        email TEXT,
        is_active INTEGER
    )`);

    db.run(`DROP INDEX IF EXISTS idx_cage_history_task`, (err) => {
        if (err) console.error('[DB] Kļūda dzēšot vecu indeksu:', err);
        else console.log('[DB] Vecais idx_cage_history_task izdzēsts (ja bija)');

        // 2. Izveido tabulu
        db.run(`
            CREATE TABLE IF NOT EXISTS cage_history (
                task_id INTEGER PRIMARY KEY,
                cages TEXT DEFAULT '',
                dates TEXT DEFAULT ''
            )
        `, (err) => {
            if (err) {
                console.error('[DB] Kļūda veidojot cage_history tabulu:', err);
            } else {
                console.log('[DB] cage_history tabula gatava vai jau eksistē ✅');

                // 3. TIKAI TAGAD – izveido indeksu (pēc tabulas!)
                db.run(`
                    CREATE INDEX IF NOT EXISTS idx_cage_history_task ON cage_history(task_id)
                `, (err) => {
                    if (err) {
                        console.error('[DB] Kļūda veidojot idx_cage_history_task:', err);
                    } else {
                        console.log('[DB] idx_cage_history_task indekss izveidots veiksmīgi ✅');
                    }
                });
            }
        });
    });
});

    const initialUsers = [
        ['admin', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', 'Admin', 'admin@example.com', 1],
        ['Zoologs', 'e5ab0b213d8af8e68a31ae1661a6abb65f85c5c2927bf29bdb4b700b58ffc678', 'Zoologs', 'albertsgarkajs@gmail.com', 1],
        ['BugTester', 'e5ab0b213d8af8e68a31ae1661a6abb65f85c5c2927bf29bdb4b700b58ffc678', 'Admin', 'kopejs1@example.com', 1],
        ['Aivars', '4432a2cad3e8840ecfaa4b9a937f5bde496e76bbbf4abee21177bf636f5a7e4c', 'Admin', 'tycoon4@inbox.lv', 1],
        ['Pertikis', 'e5ab0b213d8af8e68a31ae1661a6abb65f85c5c2927bf29bdb4b700b58ffc678', 'Admin', 'pertikis@example.com', 1]
    ];
    initialUsers.forEach(u => {
        db.get("SELECT * FROM users WHERE username = ?", [u[0]], (err, row) => {
            if (!row) db.run("INSERT INTO users (username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?)", u);
        });
    });

    db.run(`DROP TABLE IF EXISTS role_tasks`);
    db.run(`DROP TABLE IF EXISTS weekly_assignments`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, cage TEXT, name TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS weekly_schedule (role TEXT, weekday INTEGER, task_id INTEGER, PRIMARY KEY (role, weekday, task_id))`);
    db.run(`CREATE TABLE IF NOT EXISTS daily_substitutes (main_role TEXT, substitute_user TEXT, date TEXT, PRIMARY KEY (main_role, date))`);
    db.run(`CREATE TABLE IF NOT EXISTS password_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, token TEXT UNIQUE, expires INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))`);
    db.run(`CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, animal_id INTEGER, action TEXT, username TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS completed_tasks (animal_id INTEGER, completed_by TEXT, date TEXT, PRIMARY KEY (animal_id, date))`);
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        animal_id INTEGER,
        user TEXT,
        comment TEXT,
        timestamp TEXT,
        resolved INTEGER DEFAULT 0,
        parent_id INTEGER DEFAULT 0
    )`);

    const stmt = db.prepare(`INSERT OR IGNORE INTO tasks (id, cage, name) VALUES (?, ?, ?)`);
    animals.forEach(a => stmt.run(a.id, a.cage, a.name));
    stmt.finalize();

// ==================== 9. EMAIL ====================
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: { user: 'albertsgarkajs@gmail.com', pass: 'dmol kfli anuw bfvn' },
    tls: { rejectUnauthorized: false },
    debug: true,
    logger: true
});

// ==================== 10. ROUTES ====================
app.get('/', (req, res) => res.redirect('/login.html'));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/admin.html', (req, res) => {
    if (!req.session.user) return res.redirect('/login.html');
    if (!['Admin', 'Zoologs'].includes(req.session.user.role)) return res.redirect('/dashboard.html');
    res.sendFile(path.join(__dirname, 'admin.html'));
});
// MOBILE REDIRECT DROŠĪBA VISĀM LAPĀM
app.get(['/dashboard.html', '/admin.html'], (req, res, next) => {
    if (req.isMobile) {
        console.log(`[MOBILE DETECTED] ${req.path} → /mobile-dashboard.html`);
        return res.redirect('/mobile-dashboard.html');
    }
    next();
});
app.get('/mobile-dashboard.html', (req, res) => {
    if (!req.session?.user) {
        console.log('Mobile: No session → /login.html');
        return res.redirect('/login.html');
    }
    console.log(`Mobile: Dashboard served to ${req.session.user.username}`);
    res.sendFile(path.join(__dirname, 'mobile-dashboard.html'));
});

// LOGIN – WITH ANTI-CACHE + 307 FORCE REDIRECT
app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
        return res.send(`<script>alert('Enter username and password!'); history.back();</script>`);
    }
    const hash = hashPassword(password);
    db.get("SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1", [username, hash], (err, user) => {
        if (!user) {
            return res.send(`<script>alert('Wrong username or password!'); window.location='/login.html';</script>`);
        }
        req.session.user = { id: user.id, username: user.username, role: user.role };
        req.session.save((err) => {
            if (err) return res.status(500).send('Server error');

            const redirectTo = req.isMobile
                ? '/mobile-dashboard.html'
                : (user.role === 'Admin' || user.role === 'Zoologs') ? '/admin.html' : '/dashboard.html';

            console.log(`[LOGIN SUCCESS] ${username} → ${redirectTo} (mobile: ${req.isMobile})`);

            // === ANTI-CACHE + FORCE REDIRECT ===
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            res.status(307).redirect(redirectTo);  // 307 = DO NOT CACHE THIS REDIRECT
        });
    });
});

// LOGOUT
app.get('/logout', (req, res) => {
    const isMobile = mobileUserAgents.some(r => r.test(req.headers['user-agent'] || ''));
    req.session.destroy(() => {
        res.redirect(isMobile ? '/mobile-dashboard.html' : '/login.html');
    });
});

// REGISTER
app.post('/register', (req, res) => {
    const { username, password, email, role } = req.body;
    if (!username || !password || !email || !role) {
        return res.send(`<script>alert('Aizpildiet visus laukus!'); history.back();</script>`);
    }
    db.get(`SELECT 1 FROM users WHERE role = ? AND is_active = 1`, [role], (err, row) => {
        if (row) {
            return res.send(`<script>alert('Šī loma jau ir aizņemta!'); history.back();</script>`);
        }
        const password_hash = hashPassword(password);
        db.run(`INSERT INTO users (username, password_hash, email, role, is_active) VALUES (?, ?, ?, ?, 1)`,
            [username, password_hash, email, role], function (err) {
                if (err) {
                    return res.send(`<script>alert('Kļūda: ${err.message}'); history.back();</script>`);
                }
                res.send(`
                    <div style="font-family: sans-serif; text-align: center; margin-top: 100px;">
                        <h2>Reģistrācija veiksmīga!</h2>
                        <p>Lietotājs <strong>${username}</strong> ar lomu <strong>${role}</strong> izveidots.</p>
                        <p>Novirzām uz pieteikšanos...</p>
                    </div>
                    <script>setTimeout(() => location.href = '/login.html', 2000);</script>
                `);
            });
    });
});

// === /api/roles – REĢISTRĀCIJAI: TIKAI BRĪVĀS (unique) ===
app.get('/api/roles', (req, res) => {
    db.all(`SELECT role FROM users WHERE is_active = 1 AND role IN (${ROLES.map(() => '?').join(',')})`, ROLES, (err, rows) => {
        if (err) return res.status(500).json([]);
        const taken = new Set(rows.map(r => r.role));
        const free = ROLES.filter(r => !taken.has(r));
        res.json(free);
    });
});

// === /api/all-roles – ADMINAM: VISAS ROLES + 'Admin' (var piešķirt jebkuram) ===
app.get('/api/all-roles', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) {
        return res.status(403).json([]);
    }
    const all = [...ROLES, 'Admin'];
    res.json(all);
});

// === /api/task-roles – NEDĒĻAS GRAFIKAM/AIZVIETOŠANAI: TIKAI ROLES (bez Admin) ===
app.get('/api/task-roles', (req, res) => {
    res.json(ROLES);
});

// === TASK IKONAS DROPDOWNIEM === (pievieno pie citiem API)
app.get('/api/task-icons-map', (req, res) => {
    db.all(`SELECT id FROM tasks`, (err, tasks) => {
        if (err) return res.status(500).json({});
        const iconsDir = path.join(__dirname, 'public', 'task-icons');
        const files = fs.existsSync(iconsDir) ? fs.readdirSync(iconsDir) : [];
        const map = {};
        tasks.forEach(t => {
            const iconFile = files.find(f => f.startsWith(t.id + '.'));
            if (iconFile) map[t.id] = `/task-icons/${iconFile}`;
        });
        res.json(map); // { "12": "/task-icons/12.png", "15": "/task-icons/15.jpg", ... }
    });
});

app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-pasts obligāts' });
    db.get(`SELECT id, username FROM users WHERE email = ? AND is_active = 1`, [email], (err, user) => {
        if (err || !user) {
            return res.json({ success: true, message: 'Ja e-pasts reģistrēts, saite nosūtīta.' });
        }
        const token = crypto.randomBytes(32).toString('hex');
        const expires = Date.now() + 3600000;
        db.run(`INSERT INTO password_resets (user_id, token, expires) VALUES (?, ?, ?)`, [user.id, token, expires], err => {
            if (err) return res.status(500).json({ error: 'DB kļūda' });
            const resetLink = `http://192.168.1.231:3000/reset-password.html?token=${token}`;
            transporter.sendMail({
                from: '"Latgales Zoodārzs" <albertsgarkajs@gmail.com>',
                to: email,
                subject: 'Paroles atiestatīšana',
                html: `
                    <h2>Sveiks, ${user.username}!</h2>
                    <p>Klikšķini uz saites, lai atiestatītu paroli:</p>
                    <p style="margin:15px 0;"><a href="${resetLink}" style="background:#0066cc;color:white;padding:12px 20px;text-decoration:none;border-radius:5px;font-weight:bold;">Atiestatīt paroli</a></p>
                    <p><small>Saite derīga 1 stundu.</small></p>
                `
            }, (err, info) => {
                if (err) {
                    console.error('EMAIL ERROR:', err);
                    return res.status(500).json({ error: 'Neizdevās nosūtīt' });
                }
                res.json({ success: true, message: 'Saite nosūtīta!' });
            });
        });
    });
});

app.post('/api/reset-password', (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Trūkst datu' });
    db.get(`SELECT user_id, expires FROM password_resets WHERE token = ?`, [token], (err, row) => {
        if (err || !row || row.expires < Date.now()) {
            return res.status(400).json({ error: 'Nederīga vai beigusies saite' });
        }
        const hash = hashPassword(password);
        db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [hash, row.user_id], err => {
            if (err) return res.status(500).json({ error: 'DB kļūda' });
            db.run(`DELETE FROM password_resets WHERE token = ?`, [token]);
            res.json({ success: true });
        });
    });
});

app.get('/api/user', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    res.json({ username: req.session.user.username, role: req.session.user.role });
});

app.get('/api/daily-tasks', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

    const userRole = req.session.user.role;
    const today = new Date();
    const weekday = today.getDay() === 0 ? 7 : today.getDay();
    const todayStr = today.toISOString().split('T')[0];
    console.log(`[daily-tasks] User: ${userRole}, Weekday: ${weekday}, Date: ${todayStr}`);

    const result = {};
    ROLES.forEach(r => result[r] = { tasks: [], substitute: '' });

    db.all(`SELECT ws.role, t.id, t.cage, t.name FROM weekly_schedule ws JOIN tasks t ON ws.task_id = t.id WHERE ws.weekday = ? ORDER BY t.cage`, [weekday], (err, rows) => {
        if (err) {
            console.error('[daily-tasks] DB error weekly:', err);
            return res.status(500).json({ error: 'DB weekly' });
        }
        console.log(`[daily-tasks] Found ${rows.length} weekly tasks`);
        rows.forEach(row => {
            if (result[row.role]) result[row.role].tasks.push({ id: row.id, cage: row.cage, name: row.name });
        });

        db.all(`SELECT main_role, substitute_user FROM daily_substitutes WHERE date = ?`, [todayStr], (err, subs) => {
            if (err) {
                console.error('[daily-tasks] DB error subs:', err);
                return res.status(500).json({ error: 'DB subs' });
            }
            console.log(`[daily-tasks] Substitutes:`, subs);

            // Admin redz substitute string
            subs.forEach(s => {
                if (s.substitute_user && result[s.main_role]) {
                    result[s.main_role].substitute = s.substitute_user;
                }
            });

            try {
                if (!['Admin', 'Zoologs'].includes(userRole)) {
                    const finalTasks = new Set(); // lai nav dublēšanās
                    const substituteLabels = [];

                    // 1. Ko es aizvietoju? (es esmu substitute_user → main_role uzdevumi)
                    const iReplace = subs
                        .filter(sub => sub.substitute_user === userRole)
                        .map(sub => sub.main_role);
                    if (iReplace.length > 0) {
                        substituteLabels.push(`Aizvieto: ${iReplace.join(', ')}`);
                        iReplace.forEach(r => {
                            if (result[r]) result[r].tasks.forEach(t => finalTasks.add(t.id));
                        });
                    }

                    // 2. Kas mani aizvieto? (es esmu main_role → substitute_user uzdevumi)
                    const replacesMe = subs
                        .filter(sub => sub.main_role === userRole && sub.substitute_user)
                        .map(sub => sub.substitute_user);
                    if (replacesMe.length > 0) {
                        substituteLabels.push(`Aizvieto: ${replacesMe.join(', ')}`);
                        replacesMe.forEach(r => {
                            if (result[r]) result[r].tasks.forEach(t => finalTasks.add(t.id));
                        });
                    }

                    // 3. Paša uzdevumi (ja nav aizvietots)
                    if (result[userRole] && !replacesMe.includes(userRole)) {
                        result[userRole].tasks.forEach(t => finalTasks.add(t.id));
                    }

                    // Konvertē Set → Array + saglabā objektus
                    const taskObjects = [];
                    finalTasks.forEach(id => {
                        for (const role in result) {
                            const found = result[role].tasks.find(t => t.id === id);
                            if (found) {
                                taskObjects.push(found);
                                break;
                            }
                        }
                    });

                    const finalSubstitute = substituteLabels.join(' | ') || '';

                    console.log(`[daily-tasks] ${userRole} → ${taskObjects.length} uzdevumi, substitute: "${finalSubstitute}"`);
                    res.json({ tasks: taskObjects, substitute: finalSubstitute });
                } else {
                    res.json(result);
                }
            } catch (e) {
                console.error('[daily-tasks] CRASH:', e);
                res.status(500).json({ error: 'Logic error' });
            }
        });
    });
});

app.get('/api/comments/:animalId', (req, res) => {
    const animalId = req.params.animalId;
    db.all(`SELECT c.id, c.animal_id, c.user, c.comment, c.timestamp, c.resolved, c.parent_id, p.user AS parent_user 
            FROM comments c LEFT JOIN comments p ON c.parent_id = p.id WHERE c.animal_id = ? ORDER BY c.timestamp ASC`, [animalId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(rows || []);
    });
});

app.post('/api/add-comment', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id, comment, parent_id = 0 } = req.body;
    const user = req.session.user.username;
    const timestamp = new Date().toISOString();
    db.run(`INSERT INTO comments (animal_id, user, comment, timestamp, parent_id) VALUES (?, ?, ?, ?, ?)`,
        [animal_id, user, comment, timestamp, parent_id], function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true, id: this.lastID });
        });
});

app.post('/api/resolve-comment', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { comment_id } = req.body;
    db.run(`UPDATE comments SET resolved = 1 WHERE id = ?`, [comment_id], err => {
        res.json({ success: !err });
    });
});

app.get('/api/tasks', (req, res) => {
    db.all(`SELECT id, cage, name FROM tasks ORDER BY id`, (err, rows) => {
        if (err) {
            console.error('[API/TASKS] DB kļūda:', err);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`[API/TASKS] Nosūtīti ${rows.length} dzīvnieki`);
        res.json(rows || []);
    });
});

app.get('/api/weekly-schedule', (req, res) => {
    db.all(`SELECT role, weekday, task_id FROM weekly_schedule ORDER BY role, weekday`, (err, rows) => {
        if (err) {
            console.error('Kļūda ielādējot weekly_schedule:', err);
            return res.status(500).json({ error: 'DB kļūda' });
        }

        // DROŠA inicializācija – dinamiska pēc DB datiem!
        const schedule = {};

        rows.forEach(r => {
            const role = (r.role || '').trim() || 'Bez lomas';  // drošs fallback
            const day = parseInt(r.weekday);                    // pārliecināmies, ka ir skaitlis

            if (!role || day < 1 || day > 7) {
                console.warn('Ignorēts nekorekts ieraksts weekly_schedule:', r);
                return; // izlaiž sliktos ierakstus
            }

            // Auto-izveido lomu, ja neeksistē
            if (!schedule[role]) {
                schedule[role] = {
                    1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: []
                };
            }

            // Droši push (tagad diena vienmēr pastāv)
            schedule[role][day].push(r.task_id);
        });

        // Ja vajag pievienot tukšas lomas (piem. priekš frontend), vari pievienot:
        // const fixedRoles = ['Barošana', 'Tīrīšana', 'Vet', 'Cits']; // tavas fiksētās
        // fixedRoles.forEach(fr => {
        //     if (!schedule[fr]) {
        //         schedule[fr] = {1:[],2:[],3:[],4:[],5:[],6:[],7:[]};
        //     }
        // });

        console.log('✅ Weekly schedule API nosūtīts (lomas:', Object.keys(schedule).length + ')');
        res.json(schedule);
    });
});

app.post('/api/weekly-schedule', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) return res.status(403).json({ error: 'Forbidden' });
    const { role, weekday, taskIds } = req.body;
    if (!ROLES.includes(role) || weekday < 1 || weekday > 7) return res.status(400).json({ error: 'Invalid data' });
    db.run(`DELETE FROM weekly_schedule WHERE role = ? AND weekday = ?`, [role, weekday], () => {
        const stmt = db.prepare(`INSERT INTO weekly_schedule (role, weekday, task_id) VALUES (?, ?, ?)`);
        (taskIds || []).forEach(id => stmt.run(role, weekday, id));
        stmt.finalize(() => res.json({ success: true }));
    });
});

app.post('/api/replace', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { main_role, substitute_user } = req.body; // substitute_user = role string
    if (!ROLES.includes(main_role) || (substitute_user && !ROLES.includes(substitute_user))) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    const today = new Date().toISOString().split('T')[0];
    db.run(`DELETE FROM daily_substitutes WHERE main_role = ?`, [main_role], () => {
        if (substitute_user) {
            db.run(`INSERT INTO daily_substitutes (main_role, substitute_user, date) VALUES (?, ?, ?)`,
                [main_role, substitute_user, today], (err) => {
                    console.log(`[replace] ${main_role} → ${substitute_user} (${today})`);
                    res.json({ success: !err });
                });
        } else {
            res.json({ success: true });
        }
    });
});

app.post('/api/mark-actions', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id, actions } = req.body;
    const username = req.session.user.username;
    const today = new Date().toISOString().split('T')[0];
    const stmt = db.prepare(`INSERT INTO actions (animal_id, action, username, date) VALUES (?, ?, ?, ?)`);
    let count = 0;
    const total = actions.length;
    actions.forEach(a => {
        stmt.run(animal_id, a, username, today, () => {
            if (++count === total) {
                stmt.finalize(() => res.json({ success: true }));
            }
        });
    });
});

// === BŪRA MAIŅA AR VĒSTURI (cages + dates pēc komata) ===
app.post('/api/change-cage', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Veterinārārsta asistents') {
        return res.status(403).json({ error: 'Piekļuve liegta!' });
    }

    const { animalId, newCage, weekSchedule } = req.body;

    console.log('[CHANGE-CAGE] Saņemts:', req.body);

    if (!animalId || !newCage || !Array.isArray(weekSchedule) || weekSchedule.length !== 7) {
        return res.status(400).json({ error: 'Trūkst datu!' });
    }

    const changeDate = new Date().toISOString().split('T')[0]; // 2025-11-10

    try {
        // 1. Paņem esošo task + vēsturi
        const task = await dbGet('SELECT cage FROM tasks WHERE id = ?', [animalId]);
        if (!task) return res.status(404).json({ error: 'Dzīvnieks nav atrasts!' });

        const oldCage = task.cage;

        // 2. Atjauno cage tasks tabulā
        await dbRun('UPDATE tasks SET cage = ? WHERE id = ?', [newCage, animalId]);

        // 3. Atjauno weekly_schedule (dzēš veco + jauns)
        await dbRun('DELETE FROM weekly_schedule WHERE task_id = ?', [animalId]);
        for (let i = 0; i < 7; i++) {
            const dayNumber = i + 1;
            const role = weekSchedule[i]?.role || null;
            await dbRun('INSERT INTO weekly_schedule (task_id, weekday, role) VALUES (?, ?, ?)', [animalId, dayNumber, role]);
        }

        // 4. PIEVIENO / ATJAUNO VĒSTURI cage_history
        const history = await dbGet('SELECT cages, dates FROM cage_history WHERE task_id = ?', [animalId]);

        if (history) {
            // Pievieno pēc komata
            const newCages = history.cages ? `${history.cages}, ${newCage}` : newCage;
            const newDates = history.dates ? `${history.dates}, ${changeDate}` : changeDate;

            await dbRun(
                'UPDATE cage_history SET cages = ?, dates = ? WHERE task_id = ?',
                [newCages, newDates, animalId]
            );
        } else {
            // Pirmā vēsture
            await dbRun(
                'INSERT INTO cage_history (task_id, cages, dates) VALUES (?, ?, ?)',
                [animalId, newCage, changeDate]
            );
        }

        console.log(`[CHANGE-CAGE] SUCCESS → task_id=${animalId} | cage: ${oldCage} → ${newCage} | vēsture atjaunota`);

        res.json({
            success: true,
            message: 'Būris nomainīts + vēsture pievienota!',
            taskId: animalId,
            newCage,
            oldCage
        });

    } catch (err) {
        console.error('Kļūda /api/change-cage:', err);
        res.status(500).json({ error: 'Servera kļūda', details: err.message });
    }
});



// Izveido mapi, ja nav
// Use /data/public in Docker, ./public locally
const publicRoot = process.env.PUBLIC_PATH || path.join(__dirname, 'public');
const iconsDir = path.join(publicRoot, 'task-icons');

if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
    console.log(`[FS] Created icons directory: ${iconsDir}`);
}

if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
    console.log(`[FS] Created icons directory: ${iconsDir}`);
}

// Multer iestatījumi – tikai attēli, max 2MB
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, iconsDir),
    filename: (req, file, cb) => {
        const taskId = req.body.taskId;
        const ext = path.extname(file.originalname).toLowerCase();
        if (!['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
            return cb(new Error('Tikai attēli!'));
        }
        cb(null, `${taskId}${ext}`); // saglabā kā ID.jpg/png
    }
});

// === MULTER AR FORSĒTU TASKID FILENAME (IZLABOTS – BEZ SYNTAX ERROR) ===
const uploadIcon = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, iconsDir),
        filename: (req, file, cb) => {
            // 1. Prioritāte: req.body.taskId
            let taskId = req.body.taskId || req.body['taskId'];
            if (!taskId) {
                // 2. Fallback: no faila nosaukuma (piem. "116.jpg")
                const match = file.originalname.match(/^(\d+)/);
                taskId = match ? match[1] : 'unknown';
            }
            taskId = taskId.toString().trim().replace(/[^0-9]/g, '') || 'unknown';

            const ext = path.extname(file.originalname).toLowerCase() || '.png';
            const validExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
            if (!validExts.includes(ext)) {
                return cb(new Error('Tikai attēli (jpg/png/gif/webp)!'));
            }

            const filename = `${taskId}${ext}`;
            cb(null, filename);
        }
    }),
    limits: { fileSize: 2 * 1024 * 1024 }, // ← IZLABOTS: fileSize, NEVIS file-Identifier !!!
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
            return cb(new Error('Tikai attēli!'));
        }
        cb(null, true);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
            return cb(new Error('Tikai attēli (jpg/png/gif/webp)!'));
        }
        cb(null, true);
    }
});

// === GALĪGAIS IKONU UPLOAD – TASKID VIENMĒR NONĀK + PĀRSAUKĀ ===
app.post('/api/upload-task-icon',
    express.urlencoded({ extended: true }), // ← ŠIS IR ATSLĒGA! Parsē taskId no FormData
    uploadIcon.single('icon'),
    (req, res) => {
        if (!req.file) {
            return res.status(400).json({ error: 'Nav faila!' });
        }

        // Tagad req.body.taskId 100% ir
        const rawTaskId = req.body.taskId || 'unknown';
        const taskId = rawTaskId.toString().trim().replace(/[^0-9]/g, '') || 'unknown';

        const ext = path.extname(req.file.originalname).toLowerCase() || '.png';
        const validExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        if (!validExts.includes(ext)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Tikai attēli!' });
        }

        const filename = `${taskId}${ext}`;
        const newPath = path.join(iconsDir, filename);

        // Dzēš vecās ikonas ar to pašu ID
        try {
            const oldFiles = fs.readdirSync(iconsDir)
                .filter(f => f.startsWith(taskId + '.') && f !== filename);
            oldFiles.forEach(f => fs.unlinkSync(path.join(iconsDir, f)));
        } catch (e) { /* ignorē */ }

        fs.rename(req.file.path, newPath, (err) => {
            if (err) {
                console.error('Rename kļūda:', err);
                return res.status(500).json({ error: 'Saglabāšanas kļūda' });
            }

            console.log(`✅ Ikona augšupielādēta task ID ${taskId}: ${filename}`);
            res.json({
                success: true,
                filename,
                url: `/task-icons/${filename}`
            });
        });
    }
);

// API: Dzēš ikonu
app.delete('/api/delete-task-icon/:taskId', (req, res) => {
    const taskId = req.params.taskId;
    const files = fs.readdirSync(iconsDir).filter(f => f.startsWith(taskId + '.'));
    if (files.length === 0) return res.json({ success: true, message: 'Nav ikonas' });

    files.forEach(f => fs.unlinkSync(path.join(iconsDir, f)));
    console.log(`🗑️ Ikona dzēsta task ID ${taskId}`);
    res.json({ success: true });
});

// API: Dabū visus task ar ikonām (admin panelim)
app.get('/api/tasks-with-icons', (req, res) => {
    db.all(`SELECT id, name, cage FROM tasks ORDER BY name`, (err, tasks) => {
        if (err) return res.status(500).json({ error: 'DB kļūda' });

        const icons = fs.readdirSync(iconsDir);
        tasks.forEach(t => {
            const iconFile = icons.find(f => f.startsWith(t.id + '.'));
            t.icon = iconFile ? `/task-icons/${iconFile}` : null;
        });
        res.json(tasks);
    });
});

app.post('/api/complete-task', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id } = req.body;
    const username = req.session.user.username;
    const today = new Date().toISOString().split('T')[0];
    db.run(`INSERT OR REPLACE INTO completed_tasks (animal_id, completed_by, date) VALUES (?, ?, ?)`, [animal_id, username, today], err => {
        res.json({ success: !err });
    });
});

app.post('/api/cancel-task', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id } = req.body;
    const today = new Date().toISOString().split('T')[0];
    db.run(`DELETE FROM completed_tasks WHERE animal_id = ? AND date = ?`, [animal_id, today], err => {
        res.json({ success: !err });
    });
});

app.get('/api/today-actions', (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    db.all(`SELECT a.animal_id, t.cage, t.name, a.action, a.username FROM actions a JOIN tasks t ON a.animal_id = t.id WHERE a.date = ? ORDER BY a.id DESC`, [today], (err, actions) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        db.all(`SELECT animal_id, COUNT(*) as count FROM comments WHERE resolved = 0 GROUP BY animal_id`, [], (err, commentCounts) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            const commentMap = {};
            commentCounts.forEach(c => commentMap[c.animal_id] = c.count);
            const result = actions.map(a => ({
                animal_id: a.animal_id,
                cage: a.cage,
                name: a.name,
                action: a.action,
                username: a.username,
                comment_count: commentMap[a.animal_id] || 0
            }));
            res.json(result);
        });
    });
});

// VISAS UNIKĀLĀS ROLES (arī nepiešķirtās lietotājiem)
app.get('/api/roles', (req, res) => {
    // Ja gribi hardcodēt roles (drošāk, jo neviens nevar pievienot random role)
    const allRoles = ['Barotājs', 'Ūdens maiņa', 'Kopējs', 'Veterinārārsta asistents', 'Administrators'];
    res.json(allRoles);

    // VAI no DB (ja gribi dinamiski):
    // db.all(`SELECT DISTINCT role FROM users WHERE role IS NOT NULL ORDER BY role`, (err, rows) => {
    //     const roles = rows.map(r => r.role);
    //     res.json(roles.length ? roles : ['Barotājs', 'Ūdens maiņa', 'Kopējs']);
    // });
});

app.get('/api/cage-history/:id', async (req, res) => {
    const history = await dbGet('SELECT cages, dates FROM cage_history WHERE task_id = ?', [req.params.id]);
    res.json(history || { cages: '', dates: '' });
});

app.get('/api/users', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    db.all(`SELECT id, username, email, role, is_active FROM users ORDER BY username`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.get('/api/completed-today', (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    db.all(`SELECT ct.animal_id, t.cage, t.name, ct.completed_by FROM completed_tasks ct JOIN tasks t ON ct.animal_id = t.id WHERE ct.date = ?`, [today], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/update-role', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Tikai Admin/Zoologs!' });
    }

    const { user_id, new_role } = req.body;
    const uid = parseInt(user_id);

    db.get(`SELECT role FROM users WHERE id = ?`, [uid], (err, target) => {
        if (err || !target) return res.status(404).json({ error: 'Nav lietotāja' });

        const wasAdmin = target.role === 'Admin';
        const willBeAdmin = new_role === 'Admin';
        const removingAdmin = wasAdmin && !willBeAdmin;

        if (removingAdmin) {
            db.get(`SELECT COUNT(*) as c FROM users WHERE role = 'Admin' AND is_active = 1`, (err, row) => {
                if (row.c <= 1) {
                    return res.status(403).json({ error: 'NEVAR noņemt pēdējo Admin!' });
                }
                doUpdate();
            });
        } else {
            doUpdate();
        }

        function doUpdate() {
            const allowed = [...ROLES, 'Admin', null];
            if (new_role !== null && !allowed.includes(new_role)) {
                return res.status(400).json({ error: 'Nederīga loma!' });
            }

            db.run(`UPDATE users SET role = ? WHERE id = ?`, [new_role || null, uid], function(err) {
                if (err || this.changes === 0) return res.status(500).json({ error: 'DB kļūda' });
                console.log(`[ADMIN] Loma mainīta user ${uid} → ${new_role || 'bez'}`);
                res.json({ success: true });
                global.io.emit('users-updated');
                global.io.emit('tasks-updated');
            });
        }
    });
});

// === JAUNA API: /api/assignable-roles → TIKAI 7 ROLES PIEVIENOŠANAI / BŪRA MAIŅAI ===
app.get('/api/assignable-roles', (req, res) => {
    // Pārbauda vai ir sesija un vai ir Veterinārārsta asistents
    if (!req.session.user) {
        return res.status(401).json({ error: 'Nav autorizēts' });
    }
    if (req.session.user.role !== 'Veterinārārsta asistents') {
        return res.status(403).json({ error: 'Tikai Veterinārārsta asistents drīkst!' });
    }

    // Atgriež tikai mūsu 7 roles
    res.json(ROLES);
});

app.get('/api/animal-history/:id', (req, res) => {
    const animalId = req.params.id;
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const dateStr = sevenDaysAgo.toISOString().split('T')[0];
    db.all(`SELECT a.action, a.username, a.date FROM actions a WHERE a.animal_id = ? AND a.date >= ? ORDER BY a.date DESC, a.id DESC`, [animalId, dateStr], (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/mobile-tasks', (req, res) => {
    // TIEŠI TĀ PATI LOĢIKA KĀ /api/daily-tasks – MOBILAIS TAGAD 100% SINHRONIZĒTS!
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

    const userRole = req.session.user.role;
    const today = new Date();
    const weekday = today.getDay() === 0 ? 7 : today.getDay();
    const todayStr = today.toISOString().split('T')[0];
    console.log(`[mobile-tasks] User: ${userRole}, Weekday: ${weekday}, Date: ${todayStr}`);

    const result = {};
    ROLES.forEach(r => result[r] = { tasks: [], substitute: '' });

    db.all(`SELECT ws.role, t.id, t.cage, t.name FROM weekly_schedule ws JOIN tasks t ON ws.task_id = t.id WHERE ws.weekday = ? ORDER BY t.cage`, [weekday], (err, rows) => {
        if (err) {
            console.error('[mobile-tasks] DB error weekly:', err);
            return res.status(500).json({ error: 'DB weekly' });
        }
        rows.forEach(row => {
            if (result[row.role]) result[row.role].tasks.push({ id: row.id, cage: row.cage, name: row.name });
        });

        db.all(`SELECT main_role, substitute_user FROM daily_substitutes WHERE date = ?`, [todayStr], (err, subs) => {
            if (err) {
                console.error('[mobile-tasks] DB error subs:', err);
                return res.status(500).json({ error: 'DB subs' });
            }
            console.log(`[mobile-tasks] Substitutes:`, subs);

            subs.forEach(s => {
                if (s.substitute_user && result[s.main_role]) {
                    result[s.main_role].substitute = s.substitute_user;
                }
            });

            try {
                if (!['Admin', 'Zoologs'].includes(userRole)) {
                    const finalTasks = new Set();
                    const substituteLabels = [];

                    // 1. Ko es aizvietoju?
                    const iReplace = subs
                        .filter(sub => sub.substitute_user === userRole)
                        .map(sub => sub.main_role);
                    if (iReplace.length > 0) {
                        substituteLabels.push(`Aizvietots ar: ${iReplace.join(', ')}`);
                        iReplace.forEach(r => {
                            if (result[r]) result[r].tasks.forEach(t => finalTasks.add(t.id));
                        });
                    }

                    // 2. Kas mani aizvieto?
                    const replacesMe = subs
                        .filter(sub => sub.main_role === userRole && sub.substitute_user)
                        .map(sub => sub.substitute_user);
                    if (replacesMe.length > 0) {
                        substituteLabels.push(`Jūs aizvietojat: ${replacesMe.join(', ')}`);
                        replacesMe.forEach(r => {
                            if (result[r]) result[r].tasks.forEach(t => finalTasks.add(t.id));
                        });
                    }

                    // 3. Paša uzdevumi
                    if (result[userRole] && !replacesMe.includes(userRole)) {
                        result[userRole].tasks.forEach(t => finalTasks.add(t.id));
                    }

                    const taskObjects = [];
                    finalTasks.forEach(id => {
                        for (const role in result) {
                            const found = result[role].tasks.find(t => t.id === id);
                            if (found) {
                                taskObjects.push(found);
                                break;
                            }
                        }
                    });

                    const finalSubstitute = substituteLabels.join(' | ') || '';

                    console.log(`[mobile-tasks] Nosūta ${taskObjects.length} uzdevumus, substitute: "${finalSubstitute}"`);
                    res.json({ tasks: taskObjects, substitute: finalSubstitute });
                } else {
                    // Adminam mobilajā – visi uzdevumi (ja kāds adminš lieto mobilo)
                    const allTasks = [];
                    Object.values(result).forEach(roleData => allTasks.push(...roleData.tasks));
                    res.json({ tasks: allTasks, substitute: 'Admin' });
                }
            } catch (e) {
                console.error('[mobile-tasks] CRASH:', e);
                res.status(500).json({ error: 'Logic error' });
            }
        });
    });
});

app.post('/api/mobile-complete', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id } = req.body;
    const { username } = req.session.user;
    const today = new Date().toISOString().split('T')[0];
    db.run(`INSERT OR REPLACE INTO completed_tasks (animal_id, completed_by, date) VALUES (?, ?, ?)`, [animal_id, username, today], function(err) {
        if (err) {
            console.error('Mobile complete error:', err.message);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`Mobile: Task ${animal_id} completed by ${username}`);
        res.json({ success: true });
    });
});

app.post('/api/add-animal', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Veterinārārsta asistents') {
        return res.status(403).json({ error: 'Piekļuve liegta!' });
    }

    const { cage, name } = req.body;
    if (!cage || !name) {
        return res.status(400).json({ error: 'Būris un vārds obligāti!' });
    }

    const cageTrim = cage.trim();
    const nameTrim = name.trim();

    // BEZ PĀRBAUDĒM – TIEŠI INSERT (dublikāti atļauti VISIEM!)
    db.run(`INSERT INTO tasks (cage, name) VALUES (?, ?)`, [cageTrim, nameTrim], function(err) {
        if (err) {
            console.error('[ADD-ANIMAL] DB kļūda:', err);
            return res.status(500).json({ error: 'DB kļūda' });
        }

        const newId = this.lastID;
        const newAnimal = { id: newId, cage: cageTrim, name: nameTrim };

        console.log(`[ADD-ANIMAL] ✅ ${req.session.user.username} pievienoja: ${cageTrim} – ${nameTrim} (ID: ${newId}) [DUBLIKĀTI ATĻAUTI]`);

        // BROADCAST VISIEM
        global.broadcastAnimalsUpdate();

        res.json({ success: true, animal: newAnimal });
    });
});

app.post('/api/mobile-cancel', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id } = req.body;
    const today = new Date().toISOString().split('T')[0];
    db.run(`DELETE FROM completed_tasks WHERE animal_id = ? AND date = ?`, [animal_id, today], function(err) {
        if (err) {
            console.error('Mobile cancel error:', err.message);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`Mobile: Task ${animal_id} canceled`);
        res.json({ success: true });
    });
});

app.post('/api/mobile-actions', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id, actions } = req.body;
    const { username } = req.session.user;
    const today = new Date().toISOString().split('T')[0];
    if (!Array.isArray(actions) || actions.length === 0) return res.json({ success: true });
    const stmt = db.prepare(`INSERT INTO actions (animal_id, action, username, date) VALUES (?, ?, ?, ?)`);
    let count = 0;
    const total = actions.length;
    actions.forEach(action => {
        stmt.run(animal_id, action, username, today, () => {
            if (++count === total) {
                stmt.finalize(() => {
                    console.log(`Mobile: ${actions.length} actions marked on ${animal_id} by ${username}`);
                    res.json({ success: true });
                });
            }
        });
    });
});

app.post('/api/mobile-comment', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { animal_id, comment } = req.body;
    const { username } = req.session.user;
    const timestamp = new Date().toISOString();
    db.run(`INSERT INTO comments (animal_id, user, comment, timestamp, resolved, parent_id) VALUES (?, ?, ?, ?, 0, 0)`,
        [animal_id, username, comment, timestamp], function(err) {
            if (err) {
                console.error('Mobile comment error:', err.message);
                return res.status(500).json({ error: 'DB error' });
            }
            console.log(`Mobile comment added by ${username} on ${animal_id}`);
            res.json({ success: true, id: this.lastID });
        });
});

app.get('/api/mobile-user', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    res.json({ username: req.session.user.username, role: req.session.user.role });
});

app.get('/api/users', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) return res.status(403).json({ error: 'Forbidden' });
    db.all(`SELECT id, username, email, role, is_active FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/user-role', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { userId, role } = req.body;

    // ADMINAM DIEVA REŽĪMS – VAR PIEŠĶIRT JEBKURU LOMU, PAT JA AIZŅEMTA!
    const sql = role
        ? `UPDATE users SET role = ? WHERE id = ?`
        : `UPDATE users SET role = NULL WHERE id = ?`;

    const params = role ? [role, userId] : [userId];

    db.run(sql, params, function(err) {
        if (err) {
            console.error('DB ERROR /api/user-role:', err);
            return res.status(500).json({ error: 'Datubāzes kļūda' });
        }
        res.json({ success: true });
    });
});

app.post('/api/user-status', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) return res.status(403).json({ error: 'Forbidden' });
    const { userId, is_active } = req.body;
    db.run(`UPDATE users SET is_active = ? WHERE id = ?`, [is_active ? 1 : 0, userId], err => {
        res.json({ success: !err });
    });
});

app.post('/api/user-delete', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs'].includes(req.session.user.role)) return res.status(403).json({ error: 'Forbidden' });
    const { userId } = req.body;
    db.run(`DELETE FROM users WHERE id = ?`, [userId], err => {
        res.json({ success: !err });
    });
});

// MANUAL RELOAD ENDPOINTS (tikai Admin/Zoologs) – LABOTS req.session.user
// MANUAL RELOAD ENDPOINTS – LABOTS UZ JAUNO animals.json (tikai id, cage, name)
app.post('/api/reload-animals', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs', 'Veterinārārsta asistents'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Piekļuve liegta' });
    }
    try {
        animals = JSON.parse(fs.readFileSync('./animals.json', 'utf8'));
        console.log('[RELOAD] animals.json pārlādēts –', animals.length, 'dzīvnieki');
        res.json({ success: true, count: animals.length, message: 'animals.json pārlādēts!' });
    } catch (err) {
        console.error('[RELOAD] Kļūda pārlādējot animals.json:', err);
        res.status(500).json({ error: 'Nevar nolasīt animals.json – pārbaudi failu!' });
    }
});

app.post('/api/reload-tasks', (req, res) => {
    if (!req.session.user || !['Admin', 'Zoologs', 'Veterinārārsta asistents'].includes(req.session.user.role)) {
        return res.status(403).json({ error: 'Piekļuve liegta' });
    }
    try {
        animals = JSON.parse(fs.readFileSync('./animals.json', 'utf8'));
        tasks = animals.map((a, index) => ({
            id: index + 1,
            cage: a.cage,
            name: a.name,
            species: a.species || '',
            feed: a.feed || 'Standarta',
            water: a.water || 'Ik dienu',
            clean: a.clean || 'Reizi nedēļā'
        }));
        console.log('Tasks manuāli atjaunoti –', tasks.length, 'uzdevumi');
        res.json({ success: true, count: tasks.length });
    } catch (err) {
        console.error('Kļūda atjaunojot tasks:', err);
        res.status(500).json({ error: 'Kļūda' });
    }
});

// AUTO-RELOAD (ja fails mainās)
fs.watchFile('./animals.json', (curr, prev) => {
    if (curr.mtime !== prev.mtime) {
        console.log('animals.json mainījies – auto reload...');
        try {
            animals = JSON.parse(fs.readFileSync('./animals.json', 'utf8'));
            // Auto atjauno tasks
            tasks = animals.map((a, index) => ({
                id: index + 1,
                cage: a.cage,
                name: a.name,
                species: a.species || '',
                feed: a.feed || 'Standarta',
                water: a.water || 'Ik dienu',
                clean: a.clean || 'Reizi nedēļā'
            }));
            console.log('AUTO RELOAD: animals + tasks atjaunoti');
        } catch (err) {
            console.error('Auto reload kļūda:', err);
        }
    }
});

// ==================== 12. DAILY CRON REPORT (TIKAI NO weekly_schedule + DROŠS LEFT JOIN) ====================
cron.schedule('30 17 * * *', async () => {
    console.log('🔔 Generating daily report...');
    const today = new Date().toISOString().split('T')[0];
    const todayLv = new Date().toLocaleString('lv-LV');
    const weekday = (new Date().getDay() || 7); // 1=Pirmdiena ... 7=Svētdiena

    // 1. Šodienas uzdevumi – TIKAI no weekly_schedule, LEFT JOIN uz tasks (drošs!)
    db.all(`
        SELECT
            ws.role,
            ws.weekday,
            COALESCE(t.name, 'Nezināms dzīvnieks') AS name,
            COALESCE(t.cage, '??') AS cage,
            t.id AS task_id
        FROM weekly_schedule ws
                 LEFT JOIN tasks t ON ws.task_id = t.id
        WHERE ws.weekday = ?
        ORDER BY COALESCE(ws.role, 'Bez lomas'), name
    `, [weekday], (err, allTasks) => {
        if (err) return console.error('All today tasks query error:', err);

        if (allTasks.length === 0) {
            const html = `<h2>📋 Dienas ziņojums - ${today}</h2><p><strong>Laiks:</strong> ${todayLv}</p><p>Šodien grafikā nav uzdevumu! 🎉</p><hr><em>Latgales Zoodārzs</em>`;
            transporter.sendMail({ from: '"Latgales Zoodārzs" <albertsgarkajs@gmail.com>', to: 'albertsgarkajs@gmail.com', subject: `📋 Ziņojums - ${today} (nav uzdevumu)`, html }, (err, info) => {
                err ? console.error('Email failed:', err) : console.log('Sent (no tasks):', info.response);
            });
            return;
        }

        // 2. Izpildītie šodien – ar LEFT JOIN uz tasks
        db.all(`
            SELECT
                ct.animal_id,
                COALESCE(t.name, 'Nezināms') AS name,
                COALESCE(t.cage, '??') AS cage,
                COALESCE(ws.role, 'Bez lomas') AS role,
                ct.completed_by
            FROM completed_tasks ct
                     JOIN weekly_schedule ws ON ws.task_id = ct.animal_id AND ws.weekday = ?
                     LEFT JOIN tasks t ON ct.animal_id = t.id
            WHERE ct.date = ?
        `, [weekday, today], (err, completed) => {
            if (err) return console.error('Completed query error:', err);

            const completedIds = completed.map(c => c.animal_id);
            const pending = allTasks.filter(t => !completedIds.includes(t.task_id));

            // Droša grupēšana
            const groupByRole = (items) => {
                const groups = {};
                items.forEach(item => {
                    const role = (item.role || '').trim() || 'Bez lomas';
                    if (!groups[role]) groups[role] = [];
                    groups[role].push(item);
                });
                return groups;
            };

            const completedByRole = groupByRole(completed);
            const pendingByRole = groupByRole(pending);

            const total = allTasks.length;
            const done = completed.length;
            const rate = Math.round((done / total) * 100);

            const roleHtml = Object.keys({...completedByRole, ...pendingByRole}).sort().map(role => {
                const c = completedByRole[role] || [];
                const p = pendingByRole[role] || [];
                return `
                    <h4>🎭 ${role} (${c.length} ✅ | ${p.length} ⏳)</h4>
                    <table border="1" style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
                        <tr style="background:#f0f0f0;"><th>Dzīvnieks</th><th>Krātiņš</th><th>Statuss</th><th>Izpildīja</th></tr>
                        ${c.map(x => `<tr style="background:#e8f5e9;"><td>${x.name}</td><td>${x.cage}</td><td>✅</td><td>${x.completed_by}</td></tr>`).join('')}
                        ${p.map(x => `<tr style="background:#ffebee;"><td>${x.name}</td><td>${x.cage}</td><td>⏳</td><td>—</td></tr>`).join('')}
                    </table>`;
            }).join('');

            const html = `
                <h2>📋 Dienas ziņojums - ${today}</h2>
                <p><strong>Laiks:</strong> ${todayLv}</p>
                <p><strong>Kopā grafikā:</strong> ${total} | <strong>Izpildīti:</strong> ${done} | <strong>Neizpildīti:</strong> ${total-done} | <strong>${rate}%</strong></p>

                <h3>📊 Pa lomām</h3>
                ${roleHtml}

                <h3>✅ Vispārējais saraksts</h3>
                <h4>Izpildītie (${done})</h4>
                ${done > 0 ? `<table border="1" style="border-collapse: collapse; width: 100%;"><tr style="background:#f0f0f0;"><th>Dzīvnieks</th><th>Krātiņš</th><th>Izpildīja</th></tr>${completed.map(c => `<tr style="background:#e8f5e9;"><td>${c.name}</td><td>${c.cage}</td><td>${c.completed_by}</td></tr>`).join('')}</table>` : '<p>Nav.</p>'}

                <h4>⏳ Neizpildītie (${total-done})</h4>
                ${pending.length > 0 ? `<ul>${pending.map(p => `<li>${p.cage} – ${p.name}</li>`).join('')}</ul>` : '<p>Visi izpildīti! 🎉</p>'}

                <hr><p><em>Automātisks ziņojums no Latgales Zoodārza sistēmas</em></p>
            `;

            transporter.sendMail({
                from: '"Latgales Zoodārzs" <albertsgarkajs@gmail.com>',
                to: 'albertsgarkajs@gmail.com',
                subject: `📋 Dienas ziņojums - ${today} (${rate}%)`,
                html
            }, (err, info) => {
                err ? console.error('Email failed:', err) : console.log('Daily report sent:', info.response);
            });
        });
    });
}, { scheduled: true, timezone: "Europe/Riga" });

// ==================== 13. 404 & START ====================
app.use((req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({error: 'API not found'});
    res.status(404).send('Page not found');
})