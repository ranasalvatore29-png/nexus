// NEXUS accounts + community ratings, stored in Neon Postgres (added by Vercel as DATABASE_URL).
// Uses Neon's HTTP SQL endpoint with plain fetch, so no npm packages are needed.
const crypto = require('crypto');

const DB = process.env.DATABASE_URL || process.env.POSTGRES_URL;
const NAME = /^[؀-ۿA-Za-z0-9 _.\-]{2,30}$/;
const KEY = /^#[a-z]{1,3}\d{1,12}$/;

async function q(sql, params = []) {
  if (!DB) throw new Error('database missing');
  const host = new URL(DB.replace(/^postgres(ql)?:/, 'https:')).host;
  const r = await fetch('https://' + host + '/sql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Neon-Connection-String': DB },
    body: JSON.stringify({ query: sql, params })
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j.message || 'db error');
  return j.rows || [];
}

let ready = null;
function init() {
  if (!ready) {
    ready = (async () => {
      await q(`CREATE TABLE IF NOT EXISTS nx_users(
        name TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL,
        token TEXT, data JSONB NOT NULL DEFAULT '{}'::jsonb)`);
      await q(`CREATE TABLE IF NOT EXISTS nx_ratings(
        k TEXT NOT NULL, name TEXT NOT NULL, score INT NOT NULL, PRIMARY KEY(k,name))`);
    })().catch(e => { ready = null; throw e; });
  }
  return ready;
}

const hashPin = (pin, salt) => crypto.pbkdf2Sync(pin, salt, 100000, 32, 'sha256').toString('hex');

async function auth(req) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(req.headers.authorization || '');
  if (!m) return null;
  const rows = await q('SELECT name, data FROM nx_users WHERE token=$1', [m[1]]);
  return rows[0] || null;
}

module.exports = async (req, res) => {
  try {
    await init();
    const a = (req.query && req.query.a) || '';

    // Community average for a list of title keys, e.g. #m550
    if (req.method === 'GET' && a.startsWith('agg')) {
      const keys = String((req.query && req.query.keys) || '').split(',').filter(k => KEY.test(k)).slice(0, 60);
      const out = {};
      if (keys.length) {
        const ph = keys.map((_, i) => '$' + (i + 1)).join(',');
        const rows = await q(`SELECT k, ROUND(AVG(score)::numeric,1) AS avg, COUNT(*)::int AS n
                              FROM nx_ratings WHERE k IN (${ph}) GROUP BY k`, keys);
        rows.forEach(r => { out[r.k] = { avg: Number(r.avg), n: r.n }; });
      }
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json({ agg: out });
    }

    // Sign in, or create the account when the name is new
    if (req.method === 'POST' && a === 'enter') {
      const body = req.body || {};
      const name = String(body.name || '').trim();
      const pin = String(body.pin || '');
      if (!NAME.test(name) || !/^\d{4,6}$/.test(pin)) return res.status(400).json({ error: 'bad input' });
      const token = crypto.randomBytes(32).toString('hex');
      const rows = await q('SELECT name, salt, hash, data FROM nx_users WHERE name=$1', [name]);
      if (rows.length) {
        const u = rows[0];
        if (hashPin(pin, u.salt) !== u.hash) return res.status(401).json({ error: 'wrong pin' });
        await q('UPDATE nx_users SET token=$1 WHERE name=$2', [token, name]);
        return res.status(200).json({ token, data: u.data || {} });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      await q('INSERT INTO nx_users(name, salt, hash, token, data) VALUES($1,$2,$3,$4,$5::jsonb)',
              [name, salt, hashPin(pin, salt), token, '{}']);
      return res.status(200).json({ token, data: {} });
    }

    // Everything below needs a valid token
    const me = await auth(req);
    if (!me) return res.status(401).json({ error: 'login' });

    if (req.method === 'POST' && a === 'save') {
      const data = (req.body && req.body.data) || {};
      const str = JSON.stringify(data);
      if (str.length > 900000) return res.status(413).json({ error: 'too big' });
      const rate = data.rate && typeof data.rate === 'object' ? data.rate : {};
      const ents = Object.entries(rate)
        .filter(([k, v]) => KEY.test(k) && v && Number.isInteger(v.n) && v.n >= 1 && v.n <= 10)
        .slice(0, 2000);
      await q('UPDATE nx_users SET data=$1::jsonb WHERE name=$2', [str, me.name]);
      await q('DELETE FROM nx_ratings WHERE name=$1', [me.name]);
      if (ents.length) {
        const vals = [];
        const ph = ents.map(([k, v], i) => {
          vals.push(k, me.name, v.n);
          return `($${i * 3 + 1},$${i * 3 + 2},$${i * 3 + 3})`;
        }).join(',');
        await q(`INSERT INTO nx_ratings(k, name, score) VALUES ${ph}`, vals);
      }
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'method' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server' });
  }
};
