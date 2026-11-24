// NEXUS proxy: keeps the TMDB and RAWG keys on the server.
const SRC = {
  tmdb: { base: 'https://api.themoviedb.org/3', env: 'TMDB_KEY', param: 'api_key',
          allow: /^\/(movie|tv|search|person|company|discover|trending)(\/|$)/ },
  rawg: { base: 'https://api.rawg.io/api', env: 'RAWG_KEY', param: 'key',
          allow: /^\/(games|developers|publishers|genres)(\/|$)/ }
};

module.exports = async (req, res) => {
  const { s, path, ...rest } = req.query || {};
  const src = SRC[s];
  if (!src || typeof path !== 'string' || !src.allow.test(path) || path.includes('..') || path.includes('//')) {
    res.status(400).json({ error: 'bad request' });
    return;
  }
  const key = process.env[src.env];
  if (!key) {
    res.status(500).json({ error: 'server key missing' });
    return;
  }
  const u = new URL(src.base + path);
  for (const [k, v] of Object.entries(rest)) {
    if (typeof v === 'string' && k !== src.param) u.searchParams.set(k, v);
  }
  u.searchParams.set(src.param, key);
  try {
    const r = await fetch(u.toString());
    const body = await r.text();
    res.setHeader('Content-Type', 'application/json');
    if (r.ok) res.setHeader('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');
    res.status(r.status).send(body);
  } catch (e) {
    res.status(502).json({ error: 'upstream failed' });
  }
};
