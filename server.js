// server.js
import express from 'express';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

/* ---------------- Logging ---------------- */
const LOG_LEVEL = (process.env.LOG_LEVEL || 'INFO').toUpperCase();
function log(level, msg, extra) {
  const show = LOG_LEVEL === 'DEBUG' || level === 'INFO';
  if (!show) return;
  extra !== undefined ? console.log(`[${level}] ${msg}`, extra)
                      : console.log(`[${level}] ${msg}`);
}
function mask(value) {
  if (!value || typeof value !== 'string') return '';
  return value.length > 6 ? `${value.slice(0,3)}***${value.slice(-3)}` : `${value[0] || '*'}***`;
}
const sha256 = (s) => crypto.createHash('sha256').update(s || '').digest('hex');

/* ---------------- Config ---------------- */
const METHOD            = (process.env.METHOD || 'VAULT').toUpperCase(); // AXIOS | VAULT
const VAULT_ADDR        = process.env.VAULT_ADDR;
const VAULT_TOKEN       = process.env.VAULT_TOKEN;
const KV_MOUNT          = process.env.KV_MOUNT || 'kv';
const KV_PATH           = process.env.KV_PATH  || 'booklib/api';
const KV_FIELD          = process.env.KV_FIELD || 'password';
const TRANSIT_KEY       = process.env.TRANSIT_KEY || ''; // if set, decrypt ciphertext
const CIPHER_FIELD      = process.env.CIPHER_FIELD || 'ciphertext';
const AGENT_RENDERED    = process.env.AGENT_RENDERED || './rendered/booklib.env';
const POLL_MS           = Number(process.env.POLL_MS || 5000);
const AUTO_WRITE_RENDERED = String(process.env.AUTO_WRITE_RENDERED || 'false').toLowerCase() === 'true';
const WATCH_RENDERED      = String(process.env.WATCH_RENDERED || 'true').toLowerCase() === 'true';

if (!VAULT_ADDR) {
  console.error('Missing VAULT_ADDR in env');
  process.exit(1);
}

/* ---------------- Vault HTTP client (AXIOS | VAULT/native fetch) ---------------- */
let vaultFetch;
if (METHOD === 'AXIOS') {
  const axios = await import('axios').then(m => m.default);
  const vx = axios.create({
    baseURL: VAULT_ADDR.replace(/\/+$/, ''),
    headers: VAULT_TOKEN ? { 'X-Vault-Token': VAULT_TOKEN } : {}
  });
  vaultFetch = async (path, { method = 'GET', body, headers = {} } = {}) => {
    const res = await vx.request({
      url: path,
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
      data: body
    });
    return res.data;
  };
  log('INFO', 'Vault client using AXIOS');
} else {
  // VAULT => Node’s built-in fetch (Node 18+)
  vaultFetch = async (p, { method = 'GET', body, headers = {} } = {}) => {
    const url = `${VAULT_ADDR.replace(/\/+$/, '')}${p}`;
    const res = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(VAULT_TOKEN ? { 'X-Vault-Token': VAULT_TOKEN } : {}),
        ...headers
      },
      body: body ? JSON.stringify(body) : undefined
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Vault ${method} ${p} -> ${res.status}: ${text}`);
    }
    return res.json();
  };
  log('INFO', 'Vault client using VAULT fetch');
}

/* ---------------- Vault helpers ---------------- */
async function readKvRaw() {
  // KV v2 GET: /v1/<mount>/data/<path>
  const data = await vaultFetch(`/v1/${KV_MOUNT}/data/${KV_PATH}`);
  return data.data; // { data: {...}, metadata: {...} }
}
async function transitDecrypt(ciphertext) {
  const data = await vaultFetch(`/v1/transit/decrypt/${TRANSIT_KEY}`, {
    method: 'POST',
    body: { ciphertext }
  });
  const b64 = data.data.plaintext;
  return Buffer.from(b64, 'base64').toString('utf8');
}

/* ---------------- Routes ---------------- */
app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/secret', async (_req, res) => {
  try {
    const payload = await readKvRaw();      // { data, metadata }
    const d = payload.data || {};

    if (d[KV_FIELD]) {
      log('INFO', 'KV read (plaintext)', { field: KV_FIELD, value: mask(d[KV_FIELD]) });
      return res.json({
        mode: 'kv-plaintext',
        version: payload.metadata?.version,
        field: KV_FIELD,
        value_preview: mask(d[KV_FIELD])
      });
    }

    if (TRANSIT_KEY && d[CIPHER_FIELD]) {
      const plain = await transitDecrypt(d[CIPHER_FIELD]);
      log('INFO', 'KV read (transit)', { field: CIPHER_FIELD, value: mask(plain) });
      return res.json({
        mode: 'kv+transit',
        version: payload.metadata?.version,
        field: CIPHER_FIELD,
        value_preview: mask(plain)
      });
    }

    return res.status(404).json({ error: 'Neither plaintext nor ciphertext fields found in KV.' });
  } catch (e) {
    log('INFO', 'Vault error on /secret', e.message || e);
    return res.status(500).json({ error: 'Vault error', detail: e.message || String(e) });
  }
});

app.get('/agent-secret', (_req, res) => {
  try {
    const raw = fs.readFileSync(AGENT_RENDERED, 'utf8');
    const env = parseEnvFile(raw);
    const pw = env.PASSWORD;
    if (!pw) return res.status(404).json({ error: 'No PASSWORD found in agent rendered file' });
    log('INFO', 'Agent file read', { value: mask(pw) });
    return res.json({
      mode: 'agent-template',
      value_preview: mask(pw),
      meta: { version: env.VERSION, updated: env.UPDATED }
    });
  } catch (e) {
    log('INFO', 'Agent file read error', e.message);
    return res.status(500).json({ error: 'Read error', detail: e.message });
  }
});

/* ---------------- Live rotation visibility ---------------- */
// A) KV polling
let lastKvPreview = '';
let lastKvRaw = '';
async function pollKv() {
  try {
    const payload = await readKvRaw();
    const d = payload.data || {};
    let plain = '';
    let preview = 'none';

    if (d[KV_FIELD]) {
      plain = d[KV_FIELD];
      preview = `kv:${mask(plain)}`;
    } else if (TRANSIT_KEY && d[CIPHER_FIELD]) {
      plain = await transitDecrypt(d[CIPHER_FIELD]);
      preview = `transit:${mask(plain)}`;
    }

    if (preview && preview !== lastKvPreview) {
      log('DEBUG', `KV rotation detected (v${payload.metadata?.version})`, { preview });
      lastKvPreview = preview;
    }

    // Only write rendered file if explicitly enabled (no-Agent mode)
    if (AUTO_WRITE_RENDERED && plain && plain !== lastKvRaw) {
      writeRenderedEnv(plain, {
        version: payload.metadata?.version,
        updated: payload.metadata?.updated_time || payload.metadata?.created_time
      });
      lastKvRaw = plain;
    }
  } catch (e) {
    log('DEBUG', 'KV polling error', e.message || e);
  }
}
if (POLL_MS > 0) {
  log('INFO', `KV polling enabled: every ${POLL_MS}ms`);
  pollKv();
  setInterval(pollKv, POLL_MS);
}

// B) Agent watcher (debounced + PASSWORD-hash; auto-attach when file appears)
function parseEnvFile(raw) {
  return Object.fromEntries(
    raw.split('\n')
      .filter(Boolean)
      .filter(line => !line.trim().startsWith('#'))
      .map(line => {
        const idx = line.indexOf('=');
        if (idx === -1) return [line.trim(), ''];
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        return [k, v];
      })
  );
}
function attachAgentWatcher(filePath) {
  try {
    fs.accessSync(filePath);
    log('INFO', `Agent watch enabled: ${filePath}`);

    let lastPwHash = '';
    let timer = null;

    const readAndMaybeLog = () => {
      try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const env = parseEnvFile(raw);
        const pw = env.PASSWORD || '';
        const curHash = sha256(pw);
        if (curHash === lastPwHash) return; // no real secret change
        lastPwHash = curHash;
        if (pw) {
          log('DEBUG', 'Agent file rotated', {
            value: mask(pw),
            version: env.VERSION,
            updated: env.UPDATED
          });
        }
      } catch (e) {
        log('DEBUG', 'Agent watch read error', e.message);
      }
    };

    // Initial read (seed the hash and avoid double-log)
    readAndMaybeLog();

    // Debounce bursty FS events
    fs.watch(filePath, { persistent: true }, () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(readAndMaybeLog, 200);
    });
    return true;
  } catch {
    return false;
  }
}
(function initAgentWatch() {
  if (! WATCH_RENDERED) {
    log('INFO', 'Agent watch disabled by config (WATCH_RENDERED=false)');
    return;
  }
  const target = path.resolve(AGENT_RENDERED);
  const dir = path.dirname(target);
  if (attachAgentWatcher(target)) return;

  log('INFO', `Agent watch pending (file not present yet): ${target}`);
  try {
    fs.watch(dir, { persistent: true }, (_event, filename) => {
      if (!filename) return;
      const created = path.resolve(dir, filename.toString());
      if (created === target) {
        if (attachAgentWatcher(target)) {
          log('INFO', `Agent watcher attached on creation: ${target}`);
        }
      }
    });
  } catch {
    log('INFO', `Agent directory watch failed; will not auto-attach for ${target}`);
  }
})();

/* ---------------- Rendered file writer (no-Agent mode helper) ---------------- */
function writeRenderedEnv(plain, meta = {}) {
  const target = path.resolve(AGENT_RENDERED);
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const content =
    `PASSWORD=${plain}\n` +
    `VERSION=${meta.version ?? ''}\n` +
    `UPDATED=${meta.updated ?? new Date().toISOString()}\n`;
  fs.writeFileSync(target, content, 'utf8');
  log('DEBUG', 'Wrote rendered env', { path: target });
}

/* ---------------- Start ---------------- */
app.listen(port, () => {
  log('INFO', `server listening on :${port}`);
});
