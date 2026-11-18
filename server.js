// server.js — Мурчат v6 (Node 18+, без зависимостей)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const INVITE = process.env.INVITE_CODE || '';
const MAX_USERS = Number(process.env.MAX_USERS) || 100;
const LATEST_VERSION = Number(process.env.LATEST_VERSION) || 6; // номер последней версии приложения
const UPDATE_URL = process.env.UPDATE_URL || '';                // куда вести кнопку «Обновить»
const BLOBS = path.join(DIR, 'blobs');
fs.mkdirSync(BLOBS, { recursive: true });

const DBF = path.join(DIR, 'db.json');
let db = { users: {}, msgs: {} };
try { db = JSON.parse(fs.readFileSync(DBF, 'utf8')); } catch (e) {}
db.users = db.users || {};
db.msgs = db.msgs || {};
let dirty = false;
setInterval(() => {
  if (!dirty) return;
  dirty = false;
  fs.writeFileSync(DBF + '.tmp', JSON.stringify(db));
  fs.renameSync(DBF + '.tmp', DBF);
}, 2000);

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const waiters = {};
const open = {};
const lastSeen = {};
const hidden = {};
let lastMsgId = 0;
const nextId = () => (lastMsgId = Math.max(lastMsgId + 1, Date.now() * 1000));

const hits = {};
setInterval(() => { for (const k in hits) delete hits[k]; }, 60000);
const limited = (ip, key, max) => { const k = ip + '|' + key; hits[k] = (hits[k] || 0) + 1; return hits[k] > max; };

const body = (req, limit) =>
  new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('big')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });

const reply = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(obj === undefined ? {} : obj));
};

const authed = (req) => {
  const n = req.headers['x-n'];
  const t = req.headers['x-t'];
  const u = n && db.users[n];
  if (!u || !t) return null;
  return crypto.timingSafeEqual(sha(t), Buffer.from(u.th, 'hex')) ? n : null;
};
const isOnline = (n) => !hidden[n] && ((open[n] || 0) > 0 || Date.now() - (lastSeen[n] || 0) < 35000);
const okEc = (s) => typeof s === 'string' && /^(#[0-9a-fA-F]{6})?$/.test(s);

const server = http.createServer(async (req, res) => {
  req.socket.setNoDelay(true);
  try {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (limited(ip, 'all', 1600)) return reply(res, 429, {});
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (req.method === 'GET' && (p === '/' || p === '/health')) return reply(res, 200, { ok: true });
    if (req.method === 'GET' && p === '/version') return reply(res, 200, { latest: LATEST_VERSION, url: UPDATE_URL });

    if (req.method === 'POST' && p === '/register') {
      if (limited(ip, 'reg', 20)) return reply(res, 429, {});
      const n = req.headers['x-n'];
      const t = req.headers['x-t'];
      if (!/^[a-z0-9_]{3,20}$/.test(n || '') || !t) return reply(res, 400, {});
      const { pub, av, dn, ec } = JSON.parse(await body(req, 60000));
      if (typeof pub !== 'string' || pub.length > 100) return reply(res, 400, {});
      const old = db.users[n];
      if (old) {
        if (!authed(req)) return reply(res, 409, {});
      } else {
        if (INVITE && req.headers['x-i'] !== INVITE) return reply(res, 403, {});
        if (Object.keys(db.users).length >= MAX_USERS) return reply(res, 403, {});
      }
      db.users[n] = {
        pub, th: sha(t).toString('hex'),
        av: typeof av === 'string' && av.length < 40000 ? av : old ? old.av : null,
        dn: typeof dn === 'string' && dn.trim() ? dn.trim().slice(0, 24) : old ? old.dn : n,
        ec: okEc(ec) && ec ? ec : old ? old.ec || '' : '',
        cf: old ? !!old.cf : false,
      };
      dirty = true;
      return reply(res, 200, {});
    }

    if (req.method === 'GET' && p.startsWith('/user/')) {
      const n = decodeURIComponent(p.slice(6));
      const u = db.users[n];
      if (!u) return reply(res, 404, {});
      return reply(res, 200, { pub: u.pub, av: u.av, dn: u.dn || n, ec: u.ec || '', cf: !!u.cf, online: isOnline(n), seen: hidden[n] ? 0 : lastSeen[n] || 0 });
    }

    if (req.method === 'GET' && p.startsWith('/blob/')) {
      const id = p.slice(6);
      if (!/^[a-f0-9]{32}$/.test(id)) return reply(res, 400, {});
      const f = path.join(BLOBS, id);
      if (!fs.existsSync(f)) return reply(res, 404, {});
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
      return fs.createReadStream(f).pipe(res);
    }

    const me = authed(req);
    if (!me) {
      if (limited(ip, 'bad', 40)) return reply(res, 429, {});
      return reply(res, 401, {});
    }

    if (req.method === 'POST' && p === '/profile') {
      const { av, dn, cf, ec } = JSON.parse(await body(req, 60000));
      const u = db.users[me];
      if (typeof av === 'string' && av.length < 40000) u.av = av;
      if (typeof dn === 'string' && dn.trim()) u.dn = dn.trim().slice(0, 24);
      if (typeof cf === 'boolean') u.cf = cf;
      if (okEc(ec)) u.ec = ec;
      dirty = true;
      return reply(res, 200, {});
    }

    if (req.method === 'GET' && p === '/presence') {
      const out = {};
      String(url.searchParams.get('ids') || '').split(',').slice(0, 40).forEach((n) => {
        if (db.users[n]) out[n] = { on: isOnline(n), seen: hidden[n] ? 0 : lastSeen[n] || 0 };
      });
      return reply(res, 200, out);
    }

    if (req.method === 'POST' && p === '/blob') {
      const data = await body(req, 16 * 1024 * 1024);
      const id = crypto.randomBytes(16).toString('hex');
      fs.writeFileSync(path.join(BLOBS, id), data);
      return reply(res, 200, { id });
    }

    if (p === '/backup') {
      const f = path.join(DIR, 'bk_' + me);
      if (req.method === 'POST') {
        fs.writeFileSync(f, await body(req, 4 * 1024 * 1024));
        return reply(res, 200, {});
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(fs.existsSync(f) ? fs.readFileSync(f) : '');
    }

    // Отправка. Элементы с e:1 («печатает…») недолговечны: не копятся и живут 20 секунд.
    if (req.method === 'POST' && p === '/send') {
      if (limited(ip, 'send', 600)) return reply(res, 429, {});
      const { items } = JSON.parse(await body(req, 400000));
      if (!Array.isArray(items) || items.length > 60) return reply(res, 400, {});
      for (const it of items) {
        if (!it || !db.users[it.to] || typeof it.c !== 'string' || it.c.length > 20000) continue;
        const q = (db.msgs[it.to] = db.msgs[it.to] || []);
        if (q.length > 3000) q.shift();
        const m = { id: nextId(), from: me, c: it.c, ts: Date.now() };
        if (it.e) m.x = Date.now() + 20000;
        q.push(m);
        (waiters[it.to] || []).splice(0).forEach((w) => w());
      }
      dirty = true;
      return reply(res, 200, {});
    }

    if (req.method === 'GET' && p === '/poll') {
      const after = Number(url.searchParams.get('after')) || 0;
      hidden[me] = req.headers['x-h'] === '1';
      lastSeen[me] = Date.now();
      const get = () => (db.msgs[me] || []).filter((m) => m.id > after && (!m.x || m.x > Date.now())).slice(0, 200);
      const now = get();
      if (now.length) return reply(res, 200, now);
      let done = false;
      open[me] = (open[me] || 0) + 1;
      const end = () => { if (!done) { done = true; clearTimeout(timer); open[me] = Math.max(0, (open[me] || 1) - 1); lastSeen[me] = Date.now(); } };
      const finish = () => { if (done) return; end(); reply(res, 200, get()); };
      const timer = setTimeout(finish, 25000);
      (waiters[me] = waiters[me] || []).push(finish);
      req.on('close', end);
      return;
    }

    reply(res, 404, {});
  } catch (e) {
    try { reply(res, 400, {}); } catch (_) {}
  }
});
server.keepAliveTimeout = 70000;
server.headersTimeout = 75000;

setInterval(() => {
  const now = Date.now();
  for (const n in db.msgs) db.msgs[n] = db.msgs[n].filter((m) => (m.x ? m.x > now : now - m.ts < 14 * 864e5));
  dirty = true;
}, 30000);
setInterval(() => {
  const now = Date.now();
  for (const f of fs.readdirSync(BLOBS)) {
    const fp = path.join(BLOBS, f);
    if (now - fs.statSync(fp).mtimeMs > 14 * 864e5) fs.unlinkSync(fp);
  }
}, 3600e3);

server.listen(PORT, () => console.log('Сервер запущен на порту ' + PORT));
