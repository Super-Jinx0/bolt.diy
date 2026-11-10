// Entrypoint for Deplexo. Public port (default 5183) -> login -> bolt.diy on 127.0.0.1:INTERNAL_PORT.
// Starts the watchdog (deplexo-watchdog.mjs) which keeps bolt.diy alive. Node built-ins only.
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Watchdog } from './deplexo-watchdog.mjs';

const PORT = Number(process.env.PORT || 5183);
const INTERNAL_PORT = Number(process.env.INTERNAL_PORT || 5173);
const USER = process.env.BOLT_AUTH_USERNAME || 'admin';
const PASS = process.env.BOLT_AUTH_PASSWORD || '';
const SPAWN_APP = process.env.BOLT_SPAWN_APP !== '0';
const SEED_DIR = process.env.BOLT_SEED_DIR || '/opt/seed';
const STATE_DIR = process.env.BOLT_STATE_DIR || '/tmp/state';
const SESSION_SECONDS = 7 * 24 * 3600;
const COOKIE = 'bolt_gw';
const MAX_FAILS = 8; // failed logins per IP before lockout
const LOCK_MS = 15 * 60_000;

function fatal(msg) { console.error(`FATAL: ${msg}`); process.exit(1); }
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) fatal(`invalid PORT "${process.env.PORT}"`);
if (PORT === INTERNAL_PORT) fatal('PORT and INTERNAL_PORT must differ');
if (!/^[A-Za-z0-9._-]{1,64}$/.test(USER)) fatal('BOLT_AUTH_USERNAME may only contain letters, digits, dot, underscore, hyphen');
if (PASS.length < 16) fatal('set BOLT_AUTH_PASSWORD (16+ characters) in the Deplexo environment settings. Refusing to publish bolt.diy without a login.');

// ---------- auth ----------
const sha = (s) => crypto.createHash('sha256').update(s).digest();
const USER_HASH = sha(USER);
const PASS_HASH = sha(PASS);
const SECRET = sha(`bolt-session:${USER}:${PASS}`);
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const credsOk = (u, p) => { const a = same(sha(u), USER_HASH); const b = same(sha(p), PASS_HASH); return a && b; };

function basicOk(header) {
  if (!header || !/^basic /i.test(header)) return false;
  const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  return i >= 0 && credsOk(decoded.slice(0, i), decoded.slice(i + 1));
}
const sign = (exp) => crypto.createHmac('sha256', SECRET).update(String(exp)).digest('hex');
function cookieOk(header) {
  if (!header) return false;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k !== COOKIE) continue;
    const [exp, mac] = rest.join('=').split('.');
    if (!exp || !mac || !/^\d+$/.test(exp) || Number(exp) < Date.now() / 1000) return false;
    return same(Buffer.from(mac), Buffer.from(sign(exp)));
  }
  return false;
}
const isHttps = (req) => (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
function sessionCookie(secure) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  return `${COOKIE}=${exp}.${sign(exp)}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}
const clearCookie = `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`;

// failed-login throttle, keyed by the client IP the platform proxy appended (rightmost X-Forwarded-For)
const attempts = new Map();
function clientIp(req) {
  const xff = (req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : req.socket.remoteAddress || 'unknown';
}
const locked = (ip) => { const a = attempts.get(ip); return !!a && a.until > Date.now(); };
function recordFailure(ip) {
  const a = attempts.get(ip) || { n: 0, until: 0, first: Date.now() };
  if (Date.now() - a.first > LOCK_MS) { a.n = 0; a.first = Date.now(); }
  a.n += 1;
  if (a.n >= MAX_FAILS) { a.until = Date.now() + LOCK_MS; a.n = 0; }
  attempts.set(ip, a);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of attempts) if (v.until < now && now - v.first > LOCK_MS) attempts.delete(k); }, 5 * 60_000).unref();

/** ok: may proceed. viaBasic: Authorization header is OUR login (strip it before proxying). */
function authenticate(req) {
  const hasCookie = cookieOk(req.headers.cookie);
  const viaBasic = basicOk(req.headers.authorization);
  if (!hasCookie && !viaBasic && /^basic /i.test(req.headers.authorization || '')) recordFailure(clientIp(req));
  return { ok: hasCookie || viaBasic, viaBasic, hasCookie };
}

// ---------- pages ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeNext = (n) => (typeof n === 'string' && /^\/(?![/\\])[^\r\n]*$/.test(n) && !n.startsWith('/__bolt/') ? n : '/');
const CSS = 'body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0d12;color:#e8eaf0;font:16px system-ui,sans-serif}form,.card{background:#151922;border:1px solid #262c3a;border-radius:14px;padding:28px;width:min(360px,88vw)}h1{font-size:20px;margin:0 0 18px}label{display:block;font-size:13px;margin:12px 0 6px;color:#9aa3b5}input{width:100%;box-sizing:border-box;padding:11px;border-radius:8px;border:1px solid #2d3445;background:#0e1118;color:#fff;font-size:15px}button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:8px;background:#5b6cff;color:#fff;font-size:15px;cursor:pointer}.err{background:#3a1820;border:1px solid #7a2c3a;padding:9px;border-radius:8px;margin-bottom:8px;font-size:14px}a{color:#8f9bff}';
function loginPage(next, error) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>bolt.diy login</title><style>${CSS}</style></head><body><form method="post" action="/__bolt/login"><h1>bolt.diy &middot; ورود</h1>${error ? `<div class="err">${esc(error)}</div>` : ''}<input type="hidden" name="next" value="${esc(next)}"><label>Username / نام کاربری</label><input name="username" autocomplete="username" autofocus required><label>Password / رمز عبور</label><input name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in / ورود</button></form></body></html>`;
}
function startingPage(state) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="5"><meta name="viewport" content="width=device-width,initial-scale=1"><title>bolt.diy starting</title><style>${CSS}</style></head><body><div class="card"><h1>bolt.diy is ${esc(state)}…</h1><p>Page refreshes every 5 seconds. / در حال بالا آمدن، صفحه خودکار تازه می‌شود.</p><p><a href="/__bolt/logs">logs</a> · <a href="/__bolt/status">status</a></p></div></body></html>`;
}
const wantsHtml = (req) => (req.method === 'GET' || req.method === 'HEAD') && /text\/html/.test(req.headers.accept || '');
function send(res, code, type, body, extra = {}) {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra });
  res.end(body);
}
function readBody(req, limit = 4096) {
  return new Promise((resolve) => {
    let b = ''; let over = false;
    req.on('data', (c) => { if (b.length + c.length > limit) over = true; else b += c; });
    req.on('end', () => resolve(over ? null : b));
    req.on('error', () => resolve(null));
  });
}

// ---------- proxy ----------
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
let rewriteHost = false;
const wd = new Watchdog(process.env);

function upstreamHeaders(req, viaBasic, upgrade) {
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) h[k] = v;
  if (upgrade) { h.connection = 'Upgrade'; h.upgrade = req.headers.upgrade; }
  if (viaBasic) delete h.authorization;
  h['x-forwarded-for'] = [req.headers['x-forwarded-for'], req.socket.remoteAddress].filter(Boolean).join(', ');
  h['x-forwarded-proto'] = req.headers['x-forwarded-proto'] || 'https';
  h['x-forwarded-host'] = req.headers['x-forwarded-host'] || req.headers.host || '';
  if (rewriteHost) h.host = `127.0.0.1:${INTERNAL_PORT}`;
  return h;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url || '/';
    const p = url.split('?')[0];
    const ip = clientIp(req);

    if (p === '/healthz') return send(res, 200, 'text/plain', 'ok');
    if (p === '/readyz') return send(res, wd.state === 'ready' ? 200 : 503, 'text/plain', wd.state === 'ready' ? 'ready' : wd.state);

    if (p === '/__bolt/login' && req.method === 'POST') {
      const raw = await readBody(req);
      if (raw === null) return send(res, 413, 'text/plain', 'Too large');
      const f = new URLSearchParams(raw);
      const next = safeNext(f.get('next'));
      if (locked(ip)) return send(res, 429, 'text/html; charset=utf-8', loginPage(next, 'Too many attempts. Try again in 15 minutes. / تلاش بیش از حد، ۱۵ دقیقه صبر کنید.'), { 'Retry-After': '900' });
      if (credsOk(f.get('username') || '', f.get('password') || '')) {
        attempts.delete(ip);
        return send(res, 303, 'text/plain', 'ok', { Location: next, 'Set-Cookie': sessionCookie(isHttps(req)) });
      }
      recordFailure(ip);
      return setTimeout(() => send(res, 401, 'text/html; charset=utf-8', loginPage(next, 'Wrong username or password. / نام کاربری یا رمز اشتباه است.')), 500);
    }
    if (p === '/__bolt/logout') return send(res, 303, 'text/plain', 'bye', { Location: '/', 'Set-Cookie': clearCookie });

    const auth = authenticate(req);
    if (!auth.ok && locked(ip)) return send(res, 429, 'text/plain', 'Too many failed attempts. Try again later.', { 'Retry-After': '900' });
    if (!auth.ok) {
      if (p === '/' || wantsHtml(req)) return send(res, 200, 'text/html; charset=utf-8', req.method === 'HEAD' ? '' : loginPage(safeNext(url)));
      return setTimeout(() => send(res, 401, 'text/plain; charset=utf-8', 'Authentication required', { 'WWW-Authenticate': 'Basic realm="bolt.diy", charset="UTF-8"' }), 400);
    }

    const setCookie = auth.viaBasic && !auth.hasCookie ? sessionCookie(isHttps(req)) : null;

    if (p === '/__bolt/status') return send(res, 200, 'application/json', JSON.stringify(wd.status(), null, 2), setCookie ? { 'Set-Cookie': setCookie } : {});
    if (p === '/__bolt/logs') return send(res, 200, 'text/plain; charset=utf-8', wd.tail(300) || '(no output yet)', setCookie ? { 'Set-Cookie': setCookie } : {});

    if (wd.state !== 'ready') {
      const extra = { 'Retry-After': '5', ...(setCookie ? { 'Set-Cookie': setCookie } : {}) };
      return send(res, 503, wantsHtml(req) ? 'text/html; charset=utf-8' : 'text/plain', wantsHtml(req) ? startingPage(wd.state) : `bolt.diy is ${wd.state}`, extra);
    }

    const upstream = http.request(
      { host: '127.0.0.1', port: INTERNAL_PORT, method: req.method, path: url, headers: upstreamHeaders(req, auth.viaBasic, false) },
      (ur) => {
        const out = {};
        for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k)) out[k] = v;
        if (setCookie) out['set-cookie'] = [...[].concat(out['set-cookie'] || []), setCookie];
        res.writeHead(ur.statusCode || 502, ur.statusMessage, out);
        ur.pipe(res);
        ur.on('error', () => res.destroy());
      },
    );
    upstream.on('error', (e) => {
      console.error('[gateway] upstream error:', e.message);
      if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Bad gateway');
    });
    res.on('close', () => upstream.destroy());
    req.pipe(upstream);
  } catch (e) {
    console.error('[gateway] handler error:', e);
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal error');
  }
});

server.on('upgrade', (req, socket, head) => {
  const auth = authenticate(req);
  if (!auth.ok || wd.state !== 'ready') {
    socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  const up = net.connect(INTERNAL_PORT, '127.0.0.1', () => {
    let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(upstreamHeaders(req, auth.viaBasic, true))) for (const item of [].concat(v)) raw += `${k}: ${item}\r\n`;
    up.write(`${raw}\r\n`);
    if (head && head.length) up.write(head);
    socket.pipe(up).pipe(socket);
  });
  up.on('error', () => socket.destroy());
  socket.on('error', () => up.destroy());
});
server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;

process.on('uncaughtException', (e) => { console.error('[gateway] uncaughtException:', e); process.exit(1); });
process.on('unhandledRejection', (e) => { console.error('[gateway] unhandledRejection:', e); process.exit(1); });

// ---------- runtime directories (root filesystem is read-only, /tmp is writable) ----------
for (const d of ['home', 'xdg-config', 'xdg-data', 'xdg-cache', 'node-cache', 'vite-cache', 'vite-temp', 'wrangler-logs']) fs.mkdirSync(path.join('/tmp', d), { recursive: true });
for (const rel of ['.wrangler/state', '.wrangler/tmp', '.react-router/types', '.cloudflare/state', '.cloudflare/tmp']) {
  const target = path.join(STATE_DIR, rel);
  const seed = path.join(SEED_DIR, rel);
  fs.mkdirSync(target, { recursive: true });
  if (fs.existsSync(seed)) fs.cpSync(seed, target, { recursive: true });
}

wd.on('ready', (info) => { rewriteHost = !!info.hostBlocked; wd.log(`host header mode: ${rewriteHost ? 'rewrite (vite blocks foreign hosts)' : 'preserve'}`); });

server.listen(PORT, '0.0.0.0', () => console.log(`[gateway] listening on 0.0.0.0:${PORT}, login user "${USER}"`));
if (SPAWN_APP) wd.run().catch((e) => { console.error('[watchdog] fatal:', e); process.exit(1); });
else { wd.state = 'ready'; wd.log('BOLT_SPAWN_APP=0: using an external app on the internal port'); }

let closing = false;
async function shutdown() {
  if (closing) return;
  closing = true;
  setTimeout(() => process.exit(0), 9000).unref();
  await wd.stop();
  server.close(() => process.exit(0));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
