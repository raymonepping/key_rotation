// booklib/server.js — modernised for the Durin token-file pattern.
// No VAULT_TOKEN env var: getToken() reads the file on every request.
import express from 'express';
import fs from 'fs';
import https from 'https';
import crypto from 'crypto';
import { apiKeyMiddleware, startApiKeyRefresher } from './apiKeyAuth.js';

const app = express();
app.use(express.json());

const port = Number(process.env.PORT || 3001);

/* ─────────────────── Logging ─────────────────── */
const LOG_LEVEL = (process.env.LOG_LEVEL || 'INFO').toUpperCase();
function log(level, msg, extra) {
  const show = LOG_LEVEL === 'DEBUG' || level === 'INFO';
  if (!show) return;
  extra !== undefined
    ? console.log(`[${level}] ${msg}`, extra)
    : console.log(`[${level}] ${msg}`);
}
function mask(value) {
  if (!value || typeof value !== 'string') return '';
  return value.length > 6
    ? `${value.slice(0, 3)}***${value.slice(-3)}`
    : `${value[0] || '*'}***`;
}
function maskMiddle(s, keep = 3) {
  if (!s || typeof s !== 'string') return '';
  if (s.length <= keep * 2) return s.replace(/./g, '*');
  return s.slice(0, keep) + '***' + s.slice(-keep);
}
const sha256 = (s) => crypto.createHash('sha256').update(s || '').digest('hex');

/* ─────────────────── Config ─────────────────── */
const VAULT_ADDR      = process.env.VAULT_ADDR;
const VAULT_SEAL_ADDR = process.env.VAULT_SEAL_ADDR;
const KV_MOUNT        = process.env.KV_MOUNT        || 'kv';
const KV_PATH         = process.env.KV_PATH         || 'booklib/api';
const KV_FIELD        = process.env.KV_FIELD        || 'password';
const TRANSIT_KEY     = process.env.TRANSIT_KEY     || '';
const CIPHER_FIELD    = process.env.CIPHER_FIELD    || 'ciphertext';
const APIKEY_KV_MOUNT = process.env.APIKEY_KV_MOUNT || 'kv';
const APIKEY_KV_PATH  = process.env.APIKEY_KV_PATH  || 'booklib/api-auth';
const APIKEY_FIELD    = process.env.APIKEY_FIELD    || 'password';
const APIKEY_CIPHER   = process.env.APIKEY_CIPHER_FIELD || 'ciphertext';
const POLL_MS         = Number(process.env.POLL_MS  || 5000);

if (!VAULT_ADDR) {
  console.error('Missing VAULT_ADDR');
  process.exit(1);
}

/* ─────────────────── Token-file reader ─────────────────── */
function getToken() {
  const file = process.env.VAULT_TOKEN_FILE;
  if (!file) throw new Error('VAULT_TOKEN_FILE not set');
  return fs.readFileSync(file, 'utf8').trim();
}

/* ─────────────────── HTTPS agent (lab CA) ─────────────────── */
let _httpsAgent;
function httpsAgent() {
  if (_httpsAgent) return _httpsAgent;
  const caPath = process.env.VAULT_CACERT;
  if (caPath && fs.existsSync(caPath)) {
    _httpsAgent = new https.Agent({ ca: fs.readFileSync(caPath) });
  } else {
    _httpsAgent = new https.Agent({ rejectUnauthorized: true });
  }
  return _httpsAgent;
}

/* ─────────────────── Vault HTTP client ─────────────────── */
async function vaultFetch(path, { method = 'GET', body } = {}) {
  const token = getToken();
  const url = `${VAULT_ADDR.replace(/\/+$/, '')}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Token': token,
    },
    body: body ? JSON.stringify(body) : undefined,
    // NODE_EXTRA_CA_CERTS handles TLS for Node's built-in fetch
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Vault ${method} ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

/* ─────────────────── Vault helpers ─────────────────── */
async function readKvRaw() {
  const data = await vaultFetch(`/v1/${KV_MOUNT}/data/${KV_PATH}`);
  return data.data;
}
async function readApiKeyKvRaw() {
  const data = await vaultFetch(`/v1/${APIKEY_KV_MOUNT}/data/${APIKEY_KV_PATH}`);
  return data.data;
}
async function transitDecrypt(ciphertext) {
  const data = await vaultFetch(`/v1/transit/decrypt/${TRANSIT_KEY}`, {
    method: 'POST',
    body: { ciphertext },
  });
  return Buffer.from(data.data.plaintext, 'base64').toString('utf8');
}

/* ─────────────────── Vault probe (unauthenticated) ─────────────────── */
async function probeVault(addr) {
  if (!addr) return { reachable: false };
  try {
    const url = `${addr}/v1/sys/health?standbyok=true&sealedcode=503&uninitcode=503`;
    const res = await fetch(url);
    const d = await res.json().catch(() => ({}));
    return {
      reachable:   true,
      initialized: !!d.initialized,
      sealed:      !!d.sealed,
      standby:     !!d.standby,
      version:     d.version || null,
    };
  } catch {
    return { reachable: false };
  }
}

/* ─────────────────── Demo telemetry ─────────────────── */
const demoState = {
  apiKey:  { currentMasked: '', prevMasked: '' },
  kv:      { version: 0, lastUpdate: null },
  transit: { previewMasked: '', lastUpdate: null },
  startedAt: new Date().toISOString(),
};

/* ─────────────────── API key refresher ─────────────────── */
startApiKeyRefresher({
  readApiKeyKvRaw,
  transitDecrypt,
  APIKEY_FIELD,
  APIKEY_CIPHER_FIELD: APIKEY_CIPHER,
  TRANSIT_KEY,
  log,
});

async function getKeys() {
  const { __debug_getKeys } = await import('./apiKeyAuth.js');
  return __debug_getKeys();
}

/* ─────────────────── Routes ─────────────────── */

// 1. Health — vault-s + vault-1 status pills for the Shell topbar
app.get('/health', async (_req, res) => {
  const file = process.env.VAULT_TOKEN_FILE;
  let tokenPresent = false;
  try {
    tokenPresent = !!(file && fs.readFileSync(file, 'utf8').trim());
  } catch { /* not yet written */ }

  const [seal, vault] = await Promise.all([
    probeVault(VAULT_SEAL_ADDR),
    probeVault(VAULT_ADDR),
  ]);

  res.json({ ok: true, vault_token: tokenPresent ? 'present' : 'missing', seal, vault });
});

// 2. API status
app.get('/api/status', async (_req, res) => {
  try {
    const { currentKey, previousKey, lastVersion } = await getKeys();
    demoState.apiKey.currentMasked = maskMiddle(currentKey || '');
    demoState.apiKey.prevMasked    = maskMiddle(previousKey || '');
    return res.json({
      service: 'booklib',
      version: lastVersion || 0,
      api_key: {
        version:          lastVersion || null,
        current_preview:  mask(currentKey),
        previous_preview: previousKey ? mask(previousKey) : '',
      },
      time: new Date().toISOString(),
    });
  } catch (e) {
    return res.status(500).json({ error: 'status unavailable', detail: e.message || String(e) });
  }
});

// 3. Demo state (polled by UI every 5s)
app.get('/api/demo-state', async (_req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const { currentKey, previousKey, lastVersion } = await getKeys();
    demoState.apiKey.currentMasked = maskMiddle(currentKey || '');
    demoState.apiKey.prevMasked    = maskMiddle(previousKey || '');

    let kv = { version: null, created: null, updated: null, preview: '', lastUpdate: null };
    try {
      const payload = await readKvRaw();
      const d = payload.data || {};
      kv.version   = payload.metadata?.version ?? null;
      kv.created   = payload.metadata?.created_time ?? null;
      kv.updated   = payload.metadata?.updated_time ?? null;
      kv.lastUpdate = kv.updated || kv.created || null;

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
        version:       lastVersion || null,
        currentMasked: demoState.apiKey.currentMasked,
        prevMasked:    demoState.apiKey.prevMasked,
      },
      kv,
      transit: {
        previewMasked: demoState.transit.previewMasked,
        lastUpdate:    demoState.transit.lastUpdate,
      },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

// 4. Protected route (requires valid API key)
app.get('/protected', apiKeyMiddleware, (_req, res) => {
  res.json({ ok: true, msg: 'You passed API key auth.' });
});

// 5. Test-key — frontend button calls this; backend tries /protected with the live key
app.post('/api/test-key', async (_req, res) => {
  try {
    const { currentKey } = await getKeys();
    if (!currentKey) {
      return res.status(503).json({ ok: false, status: 503, detail: 'no api key loaded yet' });
    }
    // Self-call: check the current key against /protected
    const url = `http://127.0.0.1:${port}/protected`;
    const r = await fetch(url, { headers: { 'X-Api-Key': currentKey } });
    return res.json({ ok: r.ok, status: r.status });
  } catch (e) {
    return res.status(500).json({ ok: false, status: 500, detail: e.message || String(e) });
  }
});

// 6. Read KV (TransitDemo panel)
app.get('/api/secret', async (_req, res) => {
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
        value_preview: mask(plain),
      });
    }

    if (TRANSIT_KEY && d[CIPHER_FIELD]) {
      const plain = await transitDecrypt(d[CIPHER_FIELD]);
      log('INFO', 'KV read (transit)', { field: CIPHER_FIELD, value: mask(plain) });
      return res.json({
        mode: 'kv+transit',
        version: payload.metadata?.version,
        field: CIPHER_FIELD,
        value_preview: mask(plain),
      });
    }

    return res.status(404).json({ error: 'Neither plaintext nor ciphertext fields found in KV.' });
  } catch (e) {
    return res.status(500).json({ error: 'Vault error', detail: e.message || String(e) });
  }
});

// Alias for backwards-compat with old tests
app.get('/secret', async (req, res) => {
  req.url = '/api/secret';
  app.handle(req, res);
});

// Agent-rendered file reader (kept for backwards-compat)
app.get('/agent-secret', (_req, res) => {
  const file = process.env.AGENT_RENDERED || './rendered/booklib.env';
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const env = Object.fromEntries(
      raw.split('\n').filter(Boolean).filter(l => !l.trim().startsWith('#'))
        .map(l => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; })
    );
    const pw = env.PASSWORD;
    if (!pw) return res.status(404).json({ error: 'No PASSWORD in rendered file' });
    return res.json({ mode: 'agent-template', value_preview: mask(pw) });
  } catch (e) {
    return res.status(500).json({ error: 'Read error', detail: e.message });
  }
});

/* ─────────────────── KV polling ─────────────────── */
async function pollKv() {
  try {
    const payload = await readKvRaw();
    const d = payload.data || {};
    let plain = '';

    if (d[KV_FIELD]) {
      plain = d[KV_FIELD];
      demoState.transit.previewMasked = maskMiddle(plain);
    } else if (TRANSIT_KEY && d[CIPHER_FIELD]) {
      plain = await transitDecrypt(d[CIPHER_FIELD]);
      demoState.transit.previewMasked = maskMiddle(plain);
    }

    demoState.kv.version   = Number(payload.metadata?.version || demoState.kv.version || 0);
    demoState.kv.lastUpdate = new Date().toISOString();
    demoState.transit.lastUpdate = new Date().toISOString();
  } catch { /* polling is best-effort */ }
}

if (POLL_MS > 0) {
  log('INFO', `KV polling every ${POLL_MS}ms`);
  pollKv();
  setInterval(pollKv, POLL_MS);
}

/* ─────────────────── Start ─────────────────── */
app.listen(port, () => log('INFO', `booklib listening on :${port}`));
