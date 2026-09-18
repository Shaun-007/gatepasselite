// Database connection and setup.
//
// Two ways to run:
//  1. LOCAL  -> Node's built-in node:sqlite, a single file (data/gatepass.db).
//               Nothing extra to install or start.
//  2. CLOUD  -> Turso (/libSQL) when TURSO_DATABASE_URL is set, so the hosted
//               backend on Render shares one database.
//
// Both answer the same simple questions: db.get(), db.all(), db.run(), db.exec().
// The routes never care which one is being used.

const { DatabaseSync } = require('node:sqlite');
const { createClient } = require('@libsql/client');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Turn a plain password into a fixed hash. Plain passwords are never stored.
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function openDatabase() {
  const tursoUrl = process.env.TURSO_DATABASE_URL || process.env.DATABASE_URL;
  const isCloud = Boolean(tursoUrl || process.env.TURSO_AUTH_TOKEN);

  if (isCloud) {
    return openTurso(tursoUrl, process.env.TURSO_AUTH_TOKEN);
  }
  return openLocal();
}

// ----- Cloud (Turso / libSQL) -----------------------------------------------

async function openTurso(dbUrl, authToken) {
  console.log(`[Database] Connecting to Turso Cloud (${(dbUrl || '').split('@').pop() || 'libsql://...'})`);
  const client = createClient({ url: dbUrl, authToken });

  const db = {
    isCloud: true,

    async get(sql, args = []) {
      const rs = await client.execute({ sql, args });
      return rs.rows[0] ?? null;
    },

    async all(sql, args = []) {
      const rs = await client.execute({ sql, args });
      return rs.rows;
    },

    async run(sql, args = []) {
      const rs = await client.execute({ sql, args });
      return {
        lastInsertRowid: rs.lastInsertRowid == null ? null : Number(rs.lastInsertRowid),
        rowsAffected: rs.rowsAffected ?? 0,
      };
    },

    async exec(sql) {
      return client.executeMultiple(sql);
    },
  };

  await createTables(db);
  await seedDemoUsers(db);
  return db;
}

// ----- Local (Node's built-in sqlite) ---------------------------------------

function openLocal() {
  const dbPath = path.join(__dirname, '..', 'data', 'gatepass.db');
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  console.log(`[Database] Using local SQLite file: ${dbPath}`);

  const client = new DatabaseSync(dbPath);

  const db = {
    isCloud: false,

    get(sql, args = []) {
      return client.prepare(sql).get(...args) ?? null;
    },

    all(sql, args = []) {
      return client.prepare(sql).all(...args);
    },

    run(sql, args = []) {
      const result = client.prepare(sql).run(...args);
      return {
        lastInsertRowid: result.lastInsertRowid == null ? null : Number(result.lastInsertRowid),
        rowsAffected: result.changes == null ? 0 : Number(result.changes),
      };
    },

    exec(sql) {
      client.exec(sql);
    },
  };

  createTables(db);
  seedDemoUsers(db);
  return db;
}

// ----- Tables + demo users ---------------------------------------------------

function createTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      loginId TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      roomNumber TEXT
    );

    CREATE TABLE IF NOT EXISTS gate_passes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      studentId INTEGER NOT NULL,
      reason TEXT NOT NULL,
      fromDateTime TEXT NOT NULL,
      toDateTime TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      qrToken TEXT
    );

    CREATE TABLE IF NOT EXISTS gate_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      gatePassId INTEGER NOT NULL,
      studentId INTEGER NOT NULL,
      action TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      userId INTEGER NOT NULL,
      createdAt TEXT NOT NULL
    );
  `);
}

// Demo users are added once so the app works straight away.
function seedDemoUsers(db) {
  const demoUsers = [
    { loginId: 'STU001', name: 'Rahul', password: 'student123', role: 'STUDENT', roomNumber: 'B-204' },
    { loginId: 'STU002', name: 'Priya', password: 'student123', role: 'STUDENT', roomNumber: 'A-101' },
    { loginId: 'WARDEN01', name: 'Mr. Sharma', password: 'warden123', role: 'WARDEN', roomNumber: null },
    { loginId: 'SEC01', name: 'Gate Security', password: 'security123', role: 'SECURITY', roomNumber: null },
  ];

  for (const user of demoUsers) {
    const existing = db.get('SELECT id FROM users WHERE loginId = ?', [user.loginId]);
    if (!existing) {
      db.run('INSERT INTO users (loginId, name, password, role, roomNumber) VALUES (?, ?, ?, ?, ?)', [
        user.loginId,
        user.name,
        hashPassword(user.password),
        user.role,
        user.roomNumber,
      ]);
    }
  }
}

module.exports = { openDatabase, hashPassword };