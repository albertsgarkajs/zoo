const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./db.sqlite');
const schedule = JSON.parse(fs.readFileSync('./weekly-schedule.json', 'utf8'));

const ROLES = [
  'Vivāriju dzīvnieku kopējs I',
  'Vivāriju dzīvnieku kopējs II',
  'Vivāriju dzīvnieku kopējs III',
  'Zootehniķis',
  'Veterinārārsts',
  'Veterinārārsta asistents',
  'Entomologs'
];

db.serialize(() => {
  db.run(`DELETE FROM weekly_schedule`);

  const stmt = db.prepare(`
    INSERT INTO weekly_schedule (role, weekday, task_id)
    VALUES (?, ?, ?)
  `);

  let count = 0;
  for (const [weekday, roles] of Object.entries(schedule)) {
    for (const role of ROLES) {
      const tasks = roles[role] || [];
      for (const taskId of tasks) {
        stmt.run(role, parseInt(weekday), taskId);
        count++;
      }
    }
  }

  stmt.finalize(() => {
    console.log(`SUCCESS: ${count} tasks auto-assigned to roles`);
    db.close();
  });
});