// server.js
import express from 'express';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { apiKeyMiddleware, startApiKeyRefresher } from './apiKeyAuth.js';

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
  return value.length > 6
    ? `${value.slice(0,3)}***${value.slice(-3)}`
    : `${value[0] || '*'}***`;
}
function maskMiddle(s, keep = 3) {
  if (!s || typeof s !== 'string') return '';
  if (s.length <= keep * 2) return s.replace(/./g, '*');
  return s.slice(0, keep) + '***' + s.slice(-keep);
}
const sha256 = (s) => crypto.createHash('sha256').update(s || '').digest('hex');

/* ---------------- Config ---------------- */
const METHOD              = (process.env.METHOD || 'VAULT').toUpperCase(); // AXIOS | VAULT
const VAULT_ADDR          = process.env.VAULT_ADDR;
const VAULT_TOKEN         = process.env.VAULT_TOKEN;
// Demo KV path
const KV_MOUNT            = process.env.KV_MOUNT || 'kv';
const KV_PATH             = process.env.KV_PATH  || 'booklib/api';
const KV_FIELD            = process.env.KV_FIELD || 'password';
const TRANSIT_KEY         = process.env.TRANSIT_KEY || ''; // if set, decrypt ciphertext
const CIPHER_FIELD        = process.env.CIPHER_FIELD || 'ciphertext';
// Rendered-file settings (optional, no agent)
const AGENT_RENDERED      = process.env.AGENT_RENDERED || './rendered/booklib.env';
const POLL_MS             = Number(process.env.POLL_MS || 5000);
const AUTO_WRITE_RENDERED = String(process.env.AUTO_WRITE_RENDERED || 'false').toLowerCase() === 'true';
const WATCH_RENDERED      = String(process.env.WATCH_RENDERED || 'true').toLowerCase() === 'true';

// API key KV path (separate)
const APIKEY_KV_MOUNT       = process.env.APIKEY_KV_MOUNT || 'kv';
const APIKEY_KV_PATH        = process.env.APIKEY_KV_PATH  || 'booklib/api-auth';
const APIKEY_FIELD          = process.env.APIKEY_FIELD    || 'password';
const APIKEY_CIPHER_FIELD   = process.env.APIKEY_CIPHER_FIELD || 'ciphertext';

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
async function readApiKeyKvRaw() {
  const data = await vaultFetch(`/v1/${APIKEY_KV_MOUNT}/data/${APIKEY_KV_PATH}`);
  return data.data; // { data, metadata }
}

/* ---------------- Demo telemetry (for status page) ---------------- */
const demoState = {
  apiKey: { currentMasked: '', prevMasked: '' },
  kv: { version: 0, lastUpdate: null },
  transit: { previewMasked: '', lastUpdate: null },
  startedAt: new Date().toISOString(),
};

/* ---------------- Start API key refresher ---------------- */
startApiKeyRefresher({
  readApiKeyKvRaw,
  transitDecrypt,
  APIKEY_FIELD,
  APIKEY_CIPHER_FIELD,
  TRANSIT_KEY,
  log
});

// (Optional) helper to fetch current/prev keys from refresher
async function getKeys() {
  const { __debug_getKeys } = await import('./apiKeyAuth.js');
  return __debug_getKeys();
}

/* ---------------- Routes ---------------- */
app.get('/api/status', async (_req, res) => {
  try {
    const { currentKey, previousKey, lastVersion } = await getKeys();
    // update demoState.apiKey here as well (so UI reflects the refresher)
    demoState.apiKey.currentMasked = maskMiddle(currentKey || '');
    demoState.apiKey.prevMasked = maskMiddle(previousKey || '');

    return res.json({
      service: 'booklib',
      api_key: {
        version: lastVersion || null,
        current_preview: mask(currentKey),
        previous_preview: previousKey ? mask(previousKey) : ''
      },
      time: new Date().toISOString()
    });
  } catch (e) {
    return res.status(500).json({ error: 'status unavailable', detail: e.message || String(e) });
  }
});

// Read-only telemetry for the status page
app.get('/api/demo-state', async (_req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    // API key (from refresher state)
    const { currentKey, previousKey, lastVersion } = await getKeys();
    demoState.apiKey.currentMasked = maskMiddle(currentKey || '');
    demoState.apiKey.prevMasked = maskMiddle(previousKey || '');

    // KV (fresh read to reflect latest Vault)
    let kv = { version: null, created: null, updated: null, preview: '', lastUpdate: null };
    try {
      const payload = await readKvRaw();
      const d = payload.data || {};
      kv.version = payload.metadata?.version ?? null;
      kv.created = payload.metadata?.created_time ?? null;
      kv.updated = payload.metadata?.updated_time ?? null;
      kv.lastUpdate = demoState.kv.lastUpdate || kv.updated || kv.created || null;

      if (d[KV_FIELD]) {
        kv.preview = `kv:${mask(d[KV_FIELD])}`;
      } else if (TRANSIT_KEY && d[CIPHER_FIELD]) {
        const plain = await transitDecrypt(d[CIPHER_FIELD]);
        kv.preview = `transit:${mask(plain)}`;
      }
    } catch (err) {
      kv.error = err?.message || String(err);
    }

    return res.json({
      ok: true,
      now: new Date().toISOString(),
      apiKey: {
        version: lastVersion || null,
        currentMasked: demoState.apiKey.currentMasked,
        prevMasked: demoState.apiKey.prevMasked
      },
      kv,
      transit: {
        previewMasked: demoState.transit.previewMasked,
        lastUpdate: demoState.transit.lastUpdate
      }
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

// Example protected route (uses API key)
app.get('/protected', apiKeyMiddleware, (_req, res) => {
  res.json({ ok: true, msg: 'You passed API key auth.' });
});

// Health
// app.get('/health', (_req, res) => res.json({ ok: true }));
app.get(['/health', '/api/health'], (_req, res) => res.json({ ok: true }));

// Demo: read Vault KV (plaintext or transit)
app.get('/secret', async (_req, res) => {
  try {
    const payload = await readKvRaw();
    const d = payload.data || {};

    if (d[KV_FIELD]) {
      const plain = d[KV_FIELD];
      log('INFO', 'KV read (plaintext)', { field: KV_FIELD, value: mask(plain) });
      return res.json({
        mode: 'kv-plaintext',
        version: payload.metadata?.version,
        field: KV_FIELD,
        value_preview: mask(plain)
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

// Agent-rendered file reader (kept for completeness)
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

/* ---------------- KV polling (updates demoState) ---------------- */
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

    // ---- update demo telemetry (for UI) ----
    demoState.kv.version = Number(payload.metadata?.version || demoState.kv.version || 0);
    demoState.kv.lastUpdate = new Date().toISOString();
    demoState.transit.previewMasked = maskMiddle(plain || '');
    demoState.transit.lastUpdate = new Date().toISOString();

    // Optional: write a rendered env file (no-agent mode)
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

/* ---------------- Agent watcher helpers (kept; optional) ---------------- */
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
        if (curHash === lastPwHash) return;
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

    // initial read
    readAndMaybeLog();

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
  if (!WATCH_RENDERED) {
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