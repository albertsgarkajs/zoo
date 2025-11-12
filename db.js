import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProd = process.env.NODE_ENV === 'production';
const dbPath = isProd ? '/tmp/db.sqlite' : path.join(__dirname, 'db.sqlite');

export const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
});

// Promisify
db.run = (sql, params) => db.run(sql, params);
db.get = (sql, params) => db.get(sql, params);
db.all = (sql, params) => db.all(sql, params);