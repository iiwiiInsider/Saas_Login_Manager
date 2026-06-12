const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'auth.db');
const SALT_ROUNDS = Number(process.env.SALT_ROUNDS || 12);

const app = express();
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'dev-session-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false
    }
  })
);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(DB_PATH);

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function initDb() {
  await run(
    db,
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_email TEXT,
      action TEXT NOT NULL,
      target_email TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );`
  );

  // Seed admin user if missing
  const adminEmail = 'admin@test.local';
  const adminPassword = 'Admin123';
  const existing = await get(db, 'SELECT id FROM users WHERE email = ? AND role = ?', [adminEmail, 'admin']);
  if (!existing) {
    const password_hash = await bcrypt.hash(adminPassword, SALT_ROUNDS);
    await run(
      db,
      'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
      [adminEmail, password_hash, 'admin']
    );
    console.log('Seeded admin credentials:', adminEmail);
  }
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  if (req.session?.user) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !password) return res.status(400).send('Email and password required');

  const user = await get(db, 'SELECT id, email, password_hash, role FROM users WHERE email = ?', [email]);
  if (!user) return res.status(401).send('Invalid credentials');

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).send('Invalid credentials');

  req.session.user = { id: user.id, email: user.email, role: user.role };
  if (user.role === 'admin') return res.redirect('/admin');
  return res.redirect('/dashboard');
});

app.get('/signup', (req, res) => {
  if (req.session?.user) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signup', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !password) return res.status(400).send('Email and password required');
  if (password.length < 8) return res.status(400).send('Password must be at least 8 characters');

  const existing = await get(db, 'SELECT id FROM users WHERE email = ?', [email]);
  if (existing) return res.status(409).send('Email already registered');

  const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
  await run(db, 'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [email, password_hash, 'user']);

  res.redirect('/login');
});

app.post('/logout', (req, res) => {
  if (req.session) req.session.destroy(() => res.redirect('/login'));
  else res.redirect('/login');
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/users', requireAdmin, async (req, res) => {
  const rows = await all(
    db,
    'SELECT email, role, created_at FROM users WHERE role != ? ORDER BY created_at DESC',
    ['admin']
  );
  res.json({ users: rows });
});

app.post('/admin/users/delete', requireAdmin, async (req, res) => {
  const targetEmail = String(req.body.email || '').trim().toLowerCase();
  if (!targetEmail) return res.status(400).json({ ok: false, error: 'Missing email' });

  const target = await get(db, 'SELECT id, email FROM users WHERE email = ? AND role != ?', [targetEmail, 'admin']);
  if (!target) return res.status(404).json({ ok: false, error: 'User not found' });

  await run(db, 'DELETE FROM users WHERE email = ? AND role != ?', [targetEmail, 'admin']);
  await run(
    db,
    'INSERT INTO audit (actor_email, action, target_email) VALUES (?, ?, ?)',
    [req.session.user.email, 'delete_user', targetEmail]
  );

  res.json({ ok: true });
});

app.post('/admin/users/change-password', requireAdmin, async (req, res) => {
  const targetEmail = String(req.body.email || '').trim().toLowerCase();
  const newPassword = String(req.body.newPassword || '');
  if (!targetEmail || !newPassword) return res.status(400).json({ ok: false, error: 'Missing fields' });
  if (newPassword.length < 8) return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters' });

  const target = await get(db, 'SELECT id FROM users WHERE email = ? AND role != ?', [targetEmail, 'admin']);
  if (!target) return res.status(404).json({ ok: false, error: 'User not found' });

  const password_hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  await run(db, 'UPDATE users SET password_hash = ? WHERE email = ? AND role != ?', [password_hash, targetEmail, 'admin']);
  await run(
    db,
    'INSERT INTO audit (actor_email, action, target_email) VALUES (?, ?, ?)',
    [req.session.user.email, 'change_password', targetEmail]
  );

  res.json({ ok: true });
});

app.post('/admin/users/change-email', requireAdmin, async (req, res) => {
  const targetEmail = String(req.body.email || '').trim().toLowerCase();
  const newEmail = String(req.body.newEmail || '').trim().toLowerCase();
  if (!targetEmail || !newEmail) return res.status(400).json({ ok: false, error: 'Missing fields' });
  if (targetEmail === newEmail) return res.status(400).json({ ok: false, error: 'Emails are the same' });

  const target = await get(db, 'SELECT id FROM users WHERE email = ? AND role != ?', [targetEmail, 'admin']);
  if (!target) return res.status(404).json({ ok: false, error: 'User not found' });

  const dupe = await get(db, 'SELECT id FROM users WHERE email = ?', [newEmail]);
  if (dupe) return res.status(409).json({ ok: false, error: 'New email already exists' });

  await run(db, 'UPDATE users SET email = ? WHERE email = ? AND role != ?', [newEmail, targetEmail, 'admin']);
  await run(
    db,
    'INSERT INTO audit (actor_email, action, target_email) VALUES (?, ?, ?)',
    [req.session.user.email, 'change_email', targetEmail]
  );

  res.json({ ok: true });
});

// Simple view for dashboard text
app.get('/_session', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('DB init failed:', err);
    process.exit(1);
  });

