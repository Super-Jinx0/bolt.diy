// Watchdog ("نگهبان") for bolt.diy on Deplexo.
// Starts bolt.diy, waits until it really answers HTTP, probes it periodically,
// restarts it when it hangs / crashes / runs out of memory, keeps the last log lines
// for the gateway's /__bolt/logs page, and optionally sends Telegram / webhook alerts.
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';

const num = (v, d) => (v !== undefined && v !== '' && Number.isFinite(Number(v)) ? Number(v) : d);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Watchdog extends EventEmitter {
  constructor(env = process.env) {
    super();
    this.env = env;
    this.port = num(env.INTERNAL_PORT, 5173);
    this.appDir = env.BOLT_APP_DIR || '/app';
    this.heapMb = num(env.BOLT_NODE_HEAP_MB, 384);
    this.probePath = env.WATCHDOG_PROBE_PATH || '/api/health';
    this.intervalMs = num(env.WATCHDOG_INTERVAL_MS, 30_000);
    this.probeTimeoutMs = num(env.WATCHDOG_PROBE_TIMEOUT_MS, 15_000);
    this.maxFails = num(env.WATCHDOG_MAX_FAILS, 3);
    this.startTimeoutMs = num(env.WATCHDOG_START_TIMEOUT_MS, 180_000);
    this.backoffBaseMs = num(env.WATCHDOG_BACKOFF_BASE_MS, 2_000);
    this.backoffMaxMs = num(env.WATCHDOG_BACKOFF_MAX_MS, 60_000);
    this.memWarn = num(env.WATCHDOG_MEM_WARN, 0.9);
    this.memRestart = num(env.WATCHDOG_MEM_RESTART, 0.96);
    this.tgToken = env.WATCHDOG_TELEGRAM_TOKEN || '';
    this.tgChat = env.WATCHDOG_TELEGRAM_CHAT_ID || '';
    this.webhook = env.WATCHDOG_WEBHOOK_URL || '';
    this.state = 'stopped'; // starting | ready | restarting | stopped
    this.reason = '';
    this.child = null;
    this.stopping = false;
    this.variantIdx = 0;
    this.restarts = 0;
    this.crashTimes = [];
    this.startedAt = 0;
    this.readyAt = 0;
    this.lastProbeAt = 0;
    this.lastProbeOk = null;
    this.fails = 0;
    this.memHigh = 0;
    this.lastMemRestart = 0;
    this.lines = [];
    this.notified = new Map();
    this.preflightReport = [];
    const p = String(this.port);
    this.variants = [
      ['preview', '--configLoader', 'runner', '--host', '127.0.0.1', '--port', p, '--strictPort'],
      ['preview', '--host', '127.0.0.1', '--port', p, '--strictPort'],
    ];
  }

  // ---------- logging ----------
  log(msg) {
    const line = `${new Date().toISOString()} [watchdog] ${msg}`;
    this.push(line);
    console.log(line);
  }
  push(line) {
    const safe = this.redact(String(line));
    this.lines.push(safe);
    if (this.lines.length > 400) this.lines.splice(0, this.lines.length - 400);
  }
  redact(s) {
    let out = s;
    for (const secret of [this.tgToken, this.env.BOLT_AUTH_PASSWORD]) if (secret) out = out.split(secret).join('***');
    return out;
  }
  tail(n = 200) {
    return this.lines.slice(-n).join('\n');
  }

  // ---------- preflight ----------
  preflight() {
    const r = [];
    const check = (ok, label, hint = '') => r.push({ ok, label, hint });
    const exists = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };
    check(exists(path.join(this.appDir, 'node_modules/.bin/vite')), 'vite binary present', 'node_modules was pruned or install failed');
    check(exists(path.join(this.appDir, 'build/client')), 'build/client present', 'pnpm run build did not produce client output');
    check(exists(path.join(this.appDir, 'build/server')), 'build/server present', 'pnpm run build did not produce server output');
    check(exists(path.join(this.appDir, 'wrangler.jsonc')), 'wrangler.jsonc present');
    try { const f = '/tmp/.wd-write-test'; fs.writeFileSync(f, 'x'); fs.unlinkSync(f); check(true, '/tmp writable'); } catch { check(false, '/tmp writable', 'platform gave no writable /tmp'); }
    for (const rel of ['.wrangler/state', '.wrangler/tmp', '.react-router/types', '.cloudflare/state', '.cloudflare/tmp']) {
      try { fs.accessSync(path.join(this.appDir, rel), fs.constants.W_OK); check(true, `${rel} writable`); } catch { check(false, `${rel} writable`, 'symlink to /tmp/state missing'); }
    }
    const mem = this.cgroupMemory();
    if (mem) {
      const mb = Math.round(mem.max / 1048576);
      check(mem.max >= 900 * 1048576, `memory limit ${mb} MB`, 'bolt.diy needs about 1 GB: use the Pro plan');
    }
    check(Number(process.versions.node.split('.')[0]) >= 22, `node ${process.versions.node}`);
    this.preflightReport = r;
    for (const x of r) this.log(`preflight ${x.ok ? 'OK  ' : 'WARN'} ${x.label}${x.ok || !x.hint ? '' : ` (${x.hint})`}`);
    return r;
  }

  // ---------- memory ----------
  cgroupMemory() {
    try {
      const rd = (p) => fs.readFileSync(p, 'utf8').trim();
      let max; let cur;
      if (fs.existsSync('/sys/fs/cgroup/memory.max')) { max = rd('/sys/fs/cgroup/memory.max'); cur = rd('/sys/fs/cgroup/memory.current'); }
      else if (fs.existsSync('/sys/fs/cgroup/memory/memory.limit_in_bytes')) { max = rd('/sys/fs/cgroup/memory/memory.limit_in_bytes'); cur = rd('/sys/fs/cgroup/memory/memory.usage_in_bytes'); }
      else return null;
      if (max === 'max' || Number(max) > 2 ** 50) return null; // unlimited
      return { max: Number(max), current: Number(cur) };
    } catch { return null; }
  }

  // ---------- notifications ----------
  async notify(key, text) {
    const now = Date.now();
    if (now - (this.notified.get(key) || 0) < 5 * 60_000) return;
    this.notified.set(key, now);
    const msg = `bolt.diy watchdog: ${text}`;
    const post = async (url, body) => {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      try { await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: ctl.signal }); }
      catch (e) { this.push(`${new Date().toISOString()} [watchdog] alert delivery failed: ${e.name}`); }
      finally { clearTimeout(t); }
    };
    if (this.tgToken && this.tgChat) await post(`https://api.telegram.org/bot${this.tgToken}/sendMessage`, { chat_id: this.tgChat, text: msg });
    if (this.webhook) await post(this.webhook, { content: msg, text: msg });
  }

  // ---------- probing ----------
  portOpen() {
    return new Promise((resolve) => {
      const s = net.connect(this.port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => { s.destroy(); resolve(false); });
    });
  }
  httpProbe(p = this.probePath, host = `127.0.0.1:${this.port}`) {
    return new Promise((resolve) => {
      const r = http.request({ host: '127.0.0.1', port: this.port, path: p, headers: { host }, timeout: this.probeTimeoutMs }, (resp) => {
        let body = '';
        resp.on('data', (c) => { if (body.length < 2000) body += c; });
        resp.on('end', () => resolve({ status: resp.statusCode || 0, body }));
        resp.on('error', () => resolve({ status: 0, body: '' }));
      });
      r.on('error', () => resolve({ status: 0, body: '' }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: '' }); });
      r.end();
    });
  }

  // ---------- child process ----------
  spawnChild() {
    const env = { ...this.env };
    delete env.BOLT_AUTH_PASSWORD;
    delete env.WATCHDOG_TELEGRAM_TOKEN;
    delete env.WATCHDOG_WEBHOOK_URL;
    env.NODE_OPTIONS = `--max-old-space-size=${this.heapMb}`;
    env.NO_COLOR = '1';
    env.WRANGLER_LOG_PATH = '/tmp/wrangler-logs';
    const hosts = ['.deplexo.com', this.env.BOLT_ALLOWED_HOSTS].filter(Boolean).join(',');
    env.__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS = [env.__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS, hosts].filter(Boolean).join(',');
    const args = this.variants[this.variantIdx];
    this.log(`starting bolt.diy (variant ${this.variantIdx + 1}/${this.variants.length}): vite ${args.join(' ')}`);
    const child = spawn(path.join(this.appDir, 'node_modules/.bin/vite'), args, { cwd: this.appDir, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    const feed = (buf) => { for (const l of String(buf).split(/\r?\n/)) if (l.trim()) { this.push(l); console.log(`[app] ${this.redact(l)}`); } };
    child.stdout.on('data', feed);
    child.stderr.on('data', feed);
    child.on('error', (e) => this.log(`spawn error: ${e.message}`));
    this.child = child;
    this.startedAt = Date.now();
    return child;
  }

  killChild(signal = 'SIGTERM') {
    const c = this.child;
    if (!c || !c.pid) return;
    try { process.kill(-c.pid, signal); } catch { if (c.exitCode === null && !c.signalCode) { try { c.kill(signal); } catch { /* gone */ } } }
  }

  async stopChild() {
    const c = this.child;
    if (!c) return;
    if (c.exitCode !== null || c.signalCode) { this.killChild('SIGTERM'); return; }
    const exited = new Promise((r) => c.once('exit', r));
    this.killChild('SIGTERM');
    await Promise.race([exited, sleep(5000)]);
    if (c.exitCode === null && !c.signalCode) { this.killChild('SIGKILL'); await Promise.race([exited, sleep(2000)]); }
  }

  // ---------- main loop ----------
  async run() {
    this.preflight();
    let attempt = 0;
    while (!this.stopping) {
      this.state = attempt === 0 ? 'starting' : 'restarting';
      const child = this.spawnChild();
      const exited = new Promise((r) => {
        child.once('exit', (code, sig) => r({ code, sig }));
        child.once('error', (err) => r({ code: null, sig: err.message }));
      });
      const startup = await Promise.race([this.waitReady(child), exited.then((e) => ({ ok: false, why: `exited during startup (code=${e.code}, signal=${e.sig})` }))]);
      let why;
      if (startup.ok) {
        this.state = 'ready';
        this.readyAt = Date.now();
        this.fails = 0;
        this.emit('ready', startup);
        this.log(`bolt.diy is READY after ${Math.round((Date.now() - this.startedAt) / 1000)}s`);
        this.notify('ready', `bolt.diy is up (restarts so far: ${this.restarts}).`);
        const result = await Promise.race([this.monitor(child), exited.then((e) => ({ why: `process exited (code=${e.code}, signal=${e.sig})` }))]);
        if (Date.now() - this.readyAt >= 60000) attempt = 0;
        why = result.why;
      } else {
        why = startup.why;
        this.variantIdx = (this.variantIdx + 1) % this.variants.length; // try the next start variant
      }
      this.state = 'restarting';
      this.emit('down', why);
      if (this.stopping) break;
      this.restarts += 1;
      this.reason = why;
      this.log(`DOWN: ${why}`);
      await this.stopChild();
      const now = Date.now();
      this.crashTimes = this.crashTimes.filter((t) => now - t < 10 * 60_000).concat(now);
      if (this.crashTimes.length >= 5) this.notify('loop', `crash loop: ${this.crashTimes.length} failures in 10 min. Last: ${why}`);
      else this.notify('restart', `restarting bolt.diy. Reason: ${why}`);
      attempt += 1;
      const delay = Math.min(this.backoffMaxMs, this.backoffBaseMs * 2 ** Math.min(attempt - 1, 10));
      this.state = 'restarting';
      this.log(`restart #${this.restarts} in ${Math.round(delay / 1000)}s`);
      await sleep(delay);
    }
    this.state = 'stopped';
  }

  async waitReady(child) {
    const deadline = Date.now() + this.startTimeoutMs;
    while (Date.now() < deadline) {
      if (this.stopping) return { ok: false, why: 'stopping' };
      if (child.exitCode !== null || child.signalCode) return { ok: false, why: 'exited during startup' };
      if (await this.portOpen()) {
        const blocked = await this.httpProbe('/__watchdog_probe', 'probe.deplexo.com');
        const r = await this.httpProbe(this.probePath);
        if (r.status >= 200 && r.status < 300) return { ok: true, hostBlocked: blocked.status === 403 && /blocked request|not allowed/i.test(blocked.body) };
      }
      await sleep(1000);
    }
    return { ok: false, why: `no HTTP answer within ${Math.round(this.startTimeoutMs / 1000)}s` };
  }

  async monitor(child) {
    for (;;) {
      await sleep(this.intervalMs);
      if (this.stopping) return { why: 'stopping' };
      if (child.exitCode !== null || child.signalCode) return { why: 'process exited' };
      const r = await this.httpProbe();
      this.lastProbeAt = Date.now();
      const ok = r.status >= 200 && r.status < 300;
      this.lastProbeOk = ok;
      this.fails = ok ? 0 : this.fails + 1;
      if (!ok) this.log(`probe failed (${this.fails}/${this.maxFails}) status=${r.status}`);
      if (this.fails >= this.maxFails) return { why: `health probe failed ${this.fails} times in a row` };
      const mem = this.cgroupMemory();
      if (mem) {
        const ratio = mem.current / mem.max;
        if (ratio >= this.memWarn) {
          this.memHigh += 1;
          this.log(`memory high: ${Math.round(ratio * 100)}% of ${Math.round(mem.max / 1048576)} MB`);
          this.notify('mem', `memory at ${Math.round(ratio * 100)}% of the container limit. Consider the Pro plan or a lower BOLT_NODE_HEAP_MB.`);
        } else this.memHigh = 0;
      }
    }
  }

  async stop() {
    this.stopping = true;
    await this.stopChild();
    this.state = 'stopped';
  }

  status() {
    const mem = this.cgroupMemory();
    return {
      state: this.state,
      lastReason: this.reason || null,
      restarts: this.restarts,
      variant: this.variantIdx + 1,
      uptimeSeconds: this.state === 'ready' ? Math.round((Date.now() - this.readyAt) / 1000) : 0,
      lastProbeOk: this.lastProbeOk,
      lastProbeAgoSeconds: this.lastProbeAt ? Math.round((Date.now() - this.lastProbeAt) / 1000) : null,
      memory: mem ? { usedMb: Math.round(mem.current / 1048576), limitMb: Math.round(mem.max / 1048576) } : null,
      alerts: { telegram: !!(this.tgToken && this.tgChat), webhook: !!this.webhook },
      preflight: this.preflightReport,
    };
  }
}
