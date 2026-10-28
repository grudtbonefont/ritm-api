'use strict';
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || 'https://grudtbonefont.github.io,http://localhost:8150,http://127.0.0.1:8150')
  .split(',').map(s => s.trim()).filter(Boolean);

if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error('JWT_SECRET missing or too short');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('DATABASE_URL missing');
  process.exit(1);
}

const useSsl = process.env.PGSSL === '1' || (process.env.PGSSL !== '0' && /frankfurt-postgres\.render\.com|\.render\.com:\d+/.test(DATABASE_URL));
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
  max: 5,
  idleTimeoutMillis: 20000,
  connectionTimeoutMillis: 20000
});

const ENTITIES = [
  'tasks','events','habits','goals','notes','tags','log','focus','timer','journal',
  'templates','countdowns','ach','stats','spaces','lessons','homework','exams',
  'health','money','budgets','settings','space','clean'
];

async function initDb() {
  const c = await pool.connect();
  try {
    await c.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    await c.query('CREATE SCHEMA IF NOT EXISTS ritm');
    await c.query(`CREATE TABLE IF NOT EXISTS ritm.users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS ritm.items (
      user_id UUID NOT NULL REFERENCES ritm.users(id) ON DELETE CASCADE,
      entity TEXT NOT NULL,
      item_id TEXT NOT NULL,
      data JSONB,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      deleted_at TIMESTAMPTZ,
      PRIMARY KEY (user_id, entity, item_id)
    )`);
    await c.query(`CREATE INDEX IF NOT EXISTS ritm_items_since ON ritm.items (user_id, updated_at)`);
  } finally {
    c.release();
  }
}

function sign(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return res.status(401).json({ error: 'Требуется вход' });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Сессия истекла' });
  }
}

function normEmail(e) {
  return String(e || '').trim().toLowerCase();
}

function validPass(p) {
  return typeof p === 'string' && p.length >= 8 && p.length <= 128;
}

const app = express();
app.set('trust proxy', 1);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.some(o => origin === o || origin.startsWith(o))) return cb(null, true);
    // allow local preview hosts
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: false
}));
app.use(express.json({ limit: '2mb' }));

app.get('/health', (_req, res) => res.json({ ok: true, service: 'ritm-api', v: 1 }));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Подождите немного.' }
});

app.post('/auth/register', authLimit, async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    const password = req.body?.password;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Некорректный email' });
    if (!validPass(password)) return res.status(400).json({ error: 'Пароль от 8 до 128 символов' });
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      `INSERT INTO ritm.users (email, password_hash) VALUES ($1,$2)
       RETURNING id, email, created_at`,
      [email, hash]
    );
    const user = r.rows[0];
    res.status(201).json({ token: sign(user), user: { id: user.id, email: user.email } });
  } catch (e) {
    if (e && e.code === '23505') return res.status(409).json({ error: 'Этот email уже зарегистрирован' });
    console.error('register', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/auth/login', authLimit, async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    const password = req.body?.password;
    if (!email || !password) return res.status(400).json({ error: 'Укажите email и пароль' });
    const r = await pool.query(`SELECT id, email, password_hash FROM ritm.users WHERE email=$1`, [email]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    res.json({ token: sign(user), user: { id: user.id, email: user.email } });
  } catch (e) {
    console.error('login', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/auth/me', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT id, email, created_at FROM ritm.users WHERE id=$1`, [req.user.sub]);
    if (!r.rows[0]) return res.status(401).json({ error: 'Пользователь не найден' });
    res.json({ user: r.rows[0] });
  } catch (e) {
    console.error('me', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

/**
 * Pull changes since timestamp (ISO). Returns items with updatedAt/deletedAt.
 * GET /sync?since=ISO
 */
app.get('/sync', auth, async (req, res) => {
  try {
    const since = req.query.since ? new Date(String(req.query.since)) : new Date(0);
    if (Number.isNaN(+since)) return res.status(400).json({ error: 'Некорректный since' });
    const r = await pool.query(
      `SELECT entity, item_id AS id, data, updated_at AS "updatedAt", deleted_at AS "deletedAt"
       FROM ritm.items WHERE user_id=$1 AND updated_at > $2
       ORDER BY updated_at ASC LIMIT 5000`,
      [req.user.sub, since.toISOString()]
    );
    res.json({
      serverTime: new Date().toISOString(),
      items: r.rows.map(row => ({
        entity: row.entity,
        id: row.id,
        data: row.deletedAt ? null : row.data,
        updatedAt: row.updatedAt,
        deletedAt: row.deletedAt
      }))
    });
  } catch (e) {
    console.error('sync get', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

/**
 * Push local changes. Body: { changes: [{entity,id,data,updatedAt,deletedAt?}] }
 * LWW: only apply if incoming updatedAt >= stored updatedAt
 */
app.post('/sync', auth, async (req, res) => {
  const changes = Array.isArray(req.body?.changes) ? req.body.changes : null;
  if (!changes) return res.status(400).json({ error: 'Нужен массив changes' });
  if (changes.length > 2000) return res.status(400).json({ error: 'Слишком много изменений' });
  const client = await pool.connect();
  let applied = 0, skipped = 0;
  try {
    await client.query('BEGIN');
    for (const ch of changes) {
      const entity = String(ch.entity || '');
      const id = String(ch.id || '');
      if (!ENTITIES.includes(entity) || !id || id.length > 80) { skipped++; continue; }
      const updatedAt = new Date(ch.updatedAt || 0);
      if (Number.isNaN(+updatedAt)) { skipped++; continue; }
      const deletedAt = ch.deletedAt ? new Date(ch.deletedAt) : null;
      const data = deletedAt ? null : (ch.data === undefined ? null : ch.data);
      const r = await client.query(
        `INSERT INTO ritm.items (user_id, entity, item_id, data, updated_at, deleted_at)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (user_id, entity, item_id) DO UPDATE SET
           data = EXCLUDED.data,
           updated_at = EXCLUDED.updated_at,
           deleted_at = EXCLUDED.deleted_at
         WHERE ritm.items.updated_at <= EXCLUDED.updated_at
         RETURNING item_id`,
        [req.user.sub, entity, id, data == null ? null : JSON.stringify(data), updatedAt.toISOString(), deletedAt ? deletedAt.toISOString() : null]
      );
      if (r.rowCount) applied++; else skipped++;
    }
    await client.query('COMMIT');
    res.json({ applied, skipped, serverTime: new Date().toISOString() });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('sync post', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  } finally {
    client.release();
  }
});

app.use((err, _req, res, _next) => {
  console.error('unhandled', err);
  res.status(500).json({ error: 'Ошибка сервера' });
});

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log('ritm-api on', PORT));
}).catch(e => {
  console.error('initDb failed', e);
  process.exit(1);
});
