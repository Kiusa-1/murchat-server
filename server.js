// server.js — запуск: node server.js   (Node 18+, без зависимостей)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const BLOBS = path.join(DIR, 'blobs');
fs.mkdirSync(BLOBS, { recursive: true });

const DBF = path.join(DIR, 'db.json');
let db = { users: {}, msgs: {}, next: 1 };
try { db = JSON.parse(fs.readFileSync(DBF, 'utf8')); } catch (e) {}
let dirty = false;
setInterval(() => {
  if (!dirty) return;
  dirty = false;
  fs.writeFileSync(DBF + '.tmp', JSON.stringify(db));
  fs.renameSync(DBF + '.tmp', DBF);
}, 2000);

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const waiters = {};
// Номера сообщений растут всегда (даже после сброса базы), чтобы телефоны не «застревали»
let lastMsgId = 0;
const nextId = () => (lastMsgId = Math.max(lastMsgId + 1, Date.now() * 1000));

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
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj === undefined ? {} : obj));
};

const authed = (req) => {
  const n = req.headers['x-n'];
  const t = req.headers['x-t'];
  const u = n && db.users[n];
  if (!u || !t) return null;
  return crypto.timingSafeEqual(sha(t), Buffer.from(u.th, 'hex')) ? n : null;
};

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    // Проверка живости (для Render и «будильника»)
    if (req.method === 'GET' && (p === '/' || p === '/health')) return reply(res, 200, { ok: true });

    // Регистрация / вход. Ник привязан к ключу восстановления (из него считается токен).
    if (req.method === 'POST' && p === '/register') {
      const n = req.headers['x-n'];
      const t = req.headers['x-t'];
      if (!/^[a-z0-9_]{3,20}$/.test(n || '') || !t) return reply(res, 400, {});
      const { pub, av } = JSON.parse(await body(req, 60000));
      if (typeof pub !== 'string' || pub.length > 100) return reply(res, 400, {});
      const old = db.users[n];
      if (old && !authed(req)) return reply(res, 409, {});
      const newAv = typeof av === 'string' && av.length < 40000 ? av : old ? old.av : null;
      db.users[n] = { pub, th: sha(t).toString('hex'), av: newAv };
      dirty = true;
      return reply(res, 200, {});
    }

    if (req.method === 'GET' && p.startsWith('/user/')) {
      const u = db.users[decodeURIComponent(p.slice(6))];
      return u ? reply(res, 200, { pub: u.pub, av: u.av }) : reply(res, 404, {});
    }

    if (req.method === 'GET' && p.startsWith('/blob/')) {
      const id = p.slice(6);
      if (!/^[a-f0-9]{32}$/.test(id)) return reply(res, 400, {});
      const f = path.join(BLOBS, id);
      if (!fs.existsSync(f)) return reply(res, 404, {});
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return fs.createReadStream(f).pipe(res);
    }

    const me = authed(req);
    if (!me) return reply(res, 401, {});

    if (req.method === 'POST' && p === '/profile') {
      const { av } = JSON.parse(await body(req, 60000));
      if (typeof av === 'string' && av.length < 40000) { db.users[me].av = av; dirty = true; }
      return reply(res, 200, {});
    }

    if (req.method === 'POST' && p === '/blob') {
      const data = await body(req, 16 * 1024 * 1024);
      const id = crypto.randomBytes(16).toString('hex');
      fs.writeFileSync(path.join(BLOBS, id), data);
      return reply(res, 200, { id });
    }

    // Резервная копия истории (зашифрована ключом из ключа восстановления)
    if (p === '/backup') {
      const f = path.join(DIR, 'bk_' + me);
      if (req.method === 'POST') {
        fs.writeFileSync(f, await body(req, 4 * 1024 * 1024));
        return reply(res, 200, {});
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(fs.existsSync(f) ? fs.readFileSync(f) : '');
    }

    // Пакетная отправка: по копии каждому участнику и себе (для других устройств)
    if (req.method === 'POST' && p === '/send') {
      const { items } = JSON.parse(await body(req, 400000));
      if (!Array.isArray(items) || items.length > 60) return reply(res, 400, {});
      for (const it of items) {
        if (!it || !db.users[it.to] || typeof it.c !== 'string' || it.c.length > 20000) continue;
        const q = (db.msgs[it.to] = db.msgs[it.to] || []);
        if (q.length > 3000) q.shift();
        q.push({ id: nextId(), from: me, c: it.c, ts: Date.now() });
        (waiters[it.to] || []).splice(0).forEach((w) => w());
      }
      dirty = true;
      return reply(res, 200, {});
    }

    // Долгий опрос: ответ сразу при новом сообщении или через 25 с
    if (req.method === 'GET' && p === '/poll') {
      const after = Number(url.searchParams.get('after')) || 0;
      const get = () => (db.msgs[me] || []).filter((m) => m.id > after).slice(0, 200);
      const now = get();
      if (now.length) return reply(res, 200, now);
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reply(res, 200, get());
      };
      const timer = setTimeout(finish, 25000);
      (waiters[me] = waiters[me] || []).push(finish);
      req.on('close', () => { done = true; clearTimeout(timer); });
      return;
    }

    reply(res, 404, {});
  } catch (e) {
    try { reply(res, 400, {}); } catch (_) {}
  }
});

// Очистка: файлы и сообщения старше 14 дней
setInterval(() => {
  const now = Date.now();
  for (const f of fs.readdirSync(BLOBS)) {
    const fp = path.join(BLOBS, f);
    if (now - fs.statSync(fp).mtimeMs > 14 * 864e5) fs.unlinkSync(fp);
  }
  for (const n in db.msgs) db.msgs[n] = db.msgs[n].filter((m) => now - m.ts < 14 * 864e5);
  dirty = true;
}, 3600e3);

server.listen(PORT, () => console.log('Сервер запущен на порту ' + PORT));
