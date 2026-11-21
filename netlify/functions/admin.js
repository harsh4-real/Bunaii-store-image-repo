/* Bunaii Store — admin backend (Netlify Function)
   Secrets live ONLY in Netlify → Environment variables, never in this file:
     ADMIN_USER, ADMIN_PASS, GITHUB_TOKEN, GITHUB_REPO  (e.g. username/repo-name)
     GITHUB_BRANCH (optional, default "main")
   Actions: login · load · blob (upload one optimised photo) · publish (one commit = one deploy) */
const crypto = require('crypto');

const BRANCH = process.env.GITHUB_BRANCH || 'main';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const json = (code, obj) => ({
  statusCode: code,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  body: JSON.stringify(obj)
});

/* ── auth ─────────────────────────────────────────────── */
const sha = (x) => crypto.createHash('sha256').update(String(x)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const key = () => sha('bunaii|' + process.env.ADMIN_USER + '|' + process.env.ADMIN_PASS + '|' + process.env.GITHUB_TOKEN);
const sign = (p) => crypto.createHmac('sha256', key()).update(p).digest('base64url');

function makeToken() {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600 * 1000 })).toString('base64url');
  return p + '.' + sign(p);
}
function checkToken(t) {
  const [p, s] = String(t || '').split('.');
  if (!p || !s || !safeEq(s, sign(p))) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch (e) { return false; }
}

const fails = new Map();                         /* ip → {n, t}  (slows down password guessing) */

/* ── GitHub ───────────────────────────────────────────── */
async function gh(path, method, body) {
  const r = await fetch('https://api.github.com/repos/' + process.env.GITHUB_REPO + path, {
    method: method || 'GET',
    headers: {
      Authorization: 'Bearer ' + process.env.GITHUB_TOKEN,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'bunaii-admin',
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await r.text();
  let d; try { d = JSON.parse(text); } catch (e) { d = { message: text }; }
  if (!r.ok) throw new Error('GitHub ' + r.status + ': ' + String(d.message || text).slice(0, 140));
  return d;
}

/* ── validation (never trust the browser) ─────────────── */
const line = (s, max) => String(s == null ? '' : s).replace(/[<>]/g, '').replace(/"/g, '”').replace(/\s+/g, ' ').trim().slice(0, max);
const para = (s, max) => String(s == null ? '' : s).replace(/[<>]/g, '').trim().slice(0, max);
const IMG_NEW = /^images\/[\w-]+\.(webp|jpg)$/i;
const IMG_ANY = /^(images\/[\w-]+|[\w .()-]+)\.(webp|jpe?g|png)$/i;

function clean(d) {
  if (!d || !Array.isArray(d.categories) || !Array.isArray(d.products)) throw new Error('Invalid data');
  if (d.categories.length > 60 || d.products.length > 500) throw new Error('Too many items');
  const keys = new Set();
  const categories = d.categories.map((c) => {
    const k = String(c.key || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 40);
    if (!k || keys.has(k)) throw new Error('Invalid category');
    keys.add(k);
    const o = { key: k, label: line(c.label, 40) || k, emoji: line(c.emoji, 8) || '🧶' };
    if (c.auto === 'under') { o.auto = 'under'; o.maxPrice = Math.max(1, Math.round(+c.maxPrice || 700)); }
    return o;
  });
  const auto = new Set(categories.filter((c) => c.auto).map((c) => c.key));
  const ids = new Set();
  const products = d.products.map((p) => {
    const id = Math.round(+p.id);
    if (!id || ids.has(id)) throw new Error('Invalid product id');
    ids.add(id);
    const name = line(p.name, 120);
    if (!name) throw new Error('A product has no name');
    if (!keys.has(p.category) || auto.has(p.category)) throw new Error('"' + name + '" needs a valid category');
    const img = String(p.img || '');
    if (img && (!IMG_ANY.test(img) || img.includes('..'))) throw new Error('"' + name + '" has an invalid image');
    return {
      id, name, category: p.category,
      price: Math.max(0, Math.round(+p.price || 0)),
      originalPrice: +p.originalPrice > 0 ? Math.round(+p.originalPrice) : null,
      badge: ['new', 'sale', 'bestseller'].includes(p.badge) ? p.badge : null,
      rating: Math.min(5, Math.max(1, Math.round(+p.rating || 5))),
      desc: para(p.desc, 4000),
      img,
      soldOut: !!p.soldOut
    };
  });
  return { categories, products };
}

/* ── handler ──────────────────────────────────────────── */
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'POST only' });
  const E = process.env;
  if (!E.ADMIN_USER || !E.ADMIN_PASS || !E.GITHUB_TOKEN || !E.GITHUB_REPO)
    return json(500, { error: 'Server not configured: add the 4 environment variables in Netlify.' });

  let b;
  try { b = JSON.parse(event.body || '{}'); } catch (e) { return json(400, { error: 'Bad request' }); }

  try {
    if (b.action === 'login') {
      const ip = String((event.headers || {})['x-nf-client-connection-ip'] || (event.headers || {})['x-forwarded-for'] || '?').split(',')[0].trim();
      const f = fails.get(ip);
      if (f && f.n >= 6 && Date.now() - f.t < 15 * 60 * 1000)
        return json(429, { error: 'Too many wrong attempts. Please wait 15 minutes.' });
      const okU = safeEq(b.username || '', E.ADMIN_USER);
      const okP = safeEq(b.password || '', E.ADMIN_PASS);
      if (okU && okP) { fails.delete(ip); return json(200, { token: makeToken() }); }
      fails.set(ip, { n: (f && Date.now() - f.t < 15 * 60 * 1000 ? f.n : 0) + 1, t: Date.now() });
      await sleep(900);
      return json(401, { error: 'Wrong username or password.' });
    }

    if (!checkToken(b.token)) return json(401, { error: 'Session expired. Please log in again.' });

    if (b.action === 'load') {
      const f = await gh('/contents/products.json?ref=' + encodeURIComponent(BRANCH));
      return json(200, { data: JSON.parse(Buffer.from(f.content, 'base64').toString('utf8')) });
    }

    if (b.action === 'blob') {                   /* store one photo in GitHub (does NOT change the site yet) */
      if (typeof b.content !== 'string' || b.content.length < 100 || b.content.length > 1500000)
        return json(400, { error: 'Photo is too large or empty.' });
      const r = await gh('/git/blobs', 'POST', { content: b.content, encoding: 'base64' });
      return json(200, { sha: r.sha });
    }

    if (b.action === 'publish') {
      const data = clean(b.data);
      const used = new Set(data.products.map((p) => p.img).filter(Boolean));
      const imgs = (Array.isArray(b.images) ? b.images : []).filter((i) =>
        i && IMG_NEW.test(i.path) && /^[0-9a-f]{40}$/.test(i.sha) && used.has(i.path));

      /* photos replaced/deleted since the last publish (only admin-uploaded images/ files are ever removed) */
      let old = { products: [] };
      try {
        const f = await gh('/contents/products.json?ref=' + encodeURIComponent(BRANCH));
        old = JSON.parse(Buffer.from(f.content, 'base64').toString('utf8'));
      } catch (e) { /* first publish */ }
      const drop = [...new Set((old.products || []).map((p) => p.img))].filter((p) => p && IMG_NEW.test(p) && !used.has(p));

      const ref = await gh('/git/ref/heads/' + encodeURIComponent(BRANCH));
      const base = await gh('/git/commits/' + ref.object.sha);
      const tree = [{ path: 'products.json', mode: '100644', type: 'blob', content: JSON.stringify(data, null, 2) + '\n' }];
      imgs.forEach((i) => tree.push({ path: i.path, mode: '100644', type: 'blob', sha: i.sha }));

      const commit = async (extra) => {
        const t = await gh('/git/trees', 'POST', { base_tree: base.tree.sha, tree: tree.concat(extra) });
        const c = await gh('/git/commits', 'POST', {
          message: 'Admin update: ' + data.products.length + ' products',
          tree: t.sha, parents: [ref.object.sha]
        });
        await gh('/git/refs/heads/' + encodeURIComponent(BRANCH), 'PATCH', { sha: c.sha });
      };
      const removals = drop.map((p) => ({ path: p, mode: '100644', type: 'blob', sha: null }));
      try { await commit(removals); } catch (e) { if (!removals.length) throw e; await commit([]); }
      return json(200, { ok: true, products: data.products.length, photos: imgs.length });
    }

    return json(400, { error: 'Unknown action' });
  } catch (e) {
    return json(500, { error: e.message || 'Server error' });
  }
};
