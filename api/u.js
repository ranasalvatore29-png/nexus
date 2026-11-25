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
      await q('ALTER TABLE nx_ratings ADD COLUMN IF NOT EXISTS meta JSONB');
      await q(`CREATE TABLE IF NOT EXISTS nx_comments(
        id SERIAL PRIMARY KEY, k TEXT NOT NULL, name TEXT NOT NULL, text TEXT NOT NULL,
        created TIMESTAMPTZ NOT NULL DEFAULT now(), reports INT NOT NULL DEFAULT 0,
        reporters TEXT[] NOT NULL DEFAULT '{}')`);
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

    // Top-rated titles by community (at least 3 ratings, average 8+)
    if (req.method === 'GET' && a === 'top') {
      const rows = await q(`SELECT k, ROUND(AVG(score)::numeric,1) AS avg, COUNT(*)::int AS n,
                              (ARRAY_AGG(meta))[1] AS meta
                            FROM nx_ratings GROUP BY k
                            HAVING COUNT(*) >= 3 AND AVG(score) >= 8
                            ORDER BY AVG(score) DESC, COUNT(*) DESC LIMIT 24`);
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json({ items: rows.filter(r => r.meta).map(r => ({ avg: Number(r.avg), n: r.n, meta: r.meta })) });
    }

    // Comments for one title (hidden once 3 people report them)
    if (req.method === 'GET' && a === 'comments') {
      const k = String((req.query && req.query.k) || '');
      if (!KEY.test(k)) return res.status(400).json({ error: 'bad key' });
      const rows = await q(`SELECT id, name, text, created FROM nx_comments
                            WHERE k=$1 AND reports < 3 ORDER BY created DESC LIMIT 100`, [k]);
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json({ comments: rows });
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

    function summary(name, d) {
      return { name, joined: d.joined || null,
               seen: Object.keys(d.seen || {}).length,
               rated: Object.keys(d.rate || {}).length,
               lists: Object.keys(d.lists || {}).length };
    }

    // Members list (all accounts, names are public)
    if (req.method === 'GET' && a === 'members') {
      const rows = await q(`SELECT name, data FROM nx_users ORDER BY name LIMIT 200`);
      return res.status(200).json({ members: rows.map(r => summary(r.name, r.data || {})) });
    }

    // One public profile
    if (req.method === 'GET' && a === 'member') {
      const name = String((req.query && req.query.name) || '');
      const rows = await q('SELECT name, data FROM nx_users WHERE name=$1', [name]);
      const d = rows[0] && rows[0].data;
      if (!d) return res.status(404).json({ error: 'not found' });
      return res.status(200).json({
        ...summary(rows[0].name, d),
        avatar: d.avatar || '',
        seenItems: Object.values(d.seen || {}).map(x => x && x.o).filter(Boolean).slice(0, 200),
        rateItems: Object.values(d.rate || {}).filter(x => x && x.o).map(x => ({ ...x.o, r: x.n })).slice(0, 200)
      });
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
          const o = v.o || {};
          const meta = { h: o.h || k, t: o.t || '', s: o.s || '', img: o.img || '' };
          vals.push(k, me.name, v.n, JSON.stringify(meta));
          return `($${i * 4 + 1},$${i * 4 + 2},$${i * 4 + 3},$${i * 4 + 4}::jsonb)`;
        }).join(',');
        await q(`INSERT INTO nx_ratings(k, name, score, meta) VALUES ${ph}`, vals);
      }
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'POST' && a === 'comment') {
      const body = req.body || {};
      const k = String(body.k || ''), text = String(body.text || '').trim();
      if (!KEY.test(k) || text.length < 1 || text.length > 500) return res.status(400).json({ error: 'bad input' });
      await q('INSERT INTO nx_comments(k, name, text) VALUES ($1,$2,$3)', [k, me.name, text]);
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'POST' && a === 'report') {
      const id = Number((req.body || {}).id);
      if (!Number.isInteger(id)) return res.status(400).json({ error: 'bad input' });
      await q(`UPDATE nx_comments SET reports = reports + 1, reporters = array_append(reporters, $1)
               WHERE id=$2 AND NOT ($1 = ANY(reporters))`, [me.name, id]);
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'method' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server' });
  }
};
