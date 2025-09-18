// apiKeyAuth.js
import fs from 'fs';

let currentKey = '';
let previousKey = '';
let lastVersion = 0;

function mask(val) {
  if (!val || typeof val !== 'string') return '';
  return val.length > 6 ? `${val.slice(0,3)}***${val.slice(-3)}` : `${val[0] || '*'}***`;
}

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

/**
 * Loader for API key via Vault (direct): call with helpers from server.js context.
 * Expects KV with either plaintext in APIKEY_FIELD or ciphertext in APIKEY_CIPHER_FIELD (with Transit enabled).
 */
export async function loadApiKeyFromVault({
  readKvRaw, transitDecrypt, APIKEY_FIELD, TRANSIT_KEY, APIKEY_CIPHER_FIELD, log
}) {
  const payload = await readKvRaw(); // { data, metadata }
  const d = payload.data || {};
  const ver = Number(payload.metadata?.version || 0);
  if (!ver || ver === lastVersion) return;

  let plain = '';
  if (d[APIKEY_FIELD]) {
    plain = d[APIKEY_FIELD];
  } else if (TRANSIT_KEY && d[APIKEY_CIPHER_FIELD]) {
    plain = await transitDecrypt(d[APIKEY_CIPHER_FIELD]);
  } else {
    return; // nothing usable
  }

  previousKey = currentKey;
  currentKey = plain;
  lastVersion = ver;
  log?.('INFO', `api-key: updated (v${ver})`, { current: mask(currentKey), prev: previousKey ? mask(previousKey) : '' });
}

/**
 * Loader for API key via Agent-rendered file.
 */
export function loadApiKeyFromFile({ filePath, log }) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const kv = parseEnvFile(raw);
  const plain = kv.PASSWORD || '';
  const ver = Number(kv.VERSION || 0);
  if (!plain || !ver || ver === lastVersion) return;

  previousKey = currentKey;
  currentKey = plain;
  lastVersion = ver;
  log?.('INFO', `api-key: updated from file (v${ver})`, { current: mask(currentKey), prev: previousKey ? mask(previousKey) : '' });
}

export function startApiKeyRefresher(ctx) {
  const intervalMs = Number(process.env.APIKEY_REFRESH_MS || 5000);
  const useFile = Boolean(process.env.AGENT_RENDERED);

  const tick = async () => {
    try {
      if (useFile) {
        loadApiKeyFromFile({ filePath: process.env.AGENT_RENDERED, log: ctx.log });
      } else {
        await loadApiKeyFromVault({
          readKvRaw: ctx.readApiKeyKvRaw,       // NOTE: special reader for API key path (see server.js patch)
          transitDecrypt: ctx.transitDecrypt,
          APIKEY_FIELD: ctx.APIKEY_FIELD,
          TRANSIT_KEY: ctx.TRANSIT_KEY,
          APIKEY_CIPHER_FIELD: ctx.APIKEY_CIPHER_FIELD,
          log: ctx.log
        });
      }
    } catch (e) {
      ctx.log?.('INFO', 'api-key refresh failed', e.message || String(e));
    }
  };

  tick();
  setInterval(tick, intervalMs);
}

export function apiKeyMiddleware(req, res, next) {
  const supplied = req.get('X-Api-Key') || '';
  if (supplied && (supplied === currentKey || (previousKey && supplied === previousKey))) {
    return next();
  }
  return res.status(401).json({ error: 'invalid api key' });
}

// For tests/debug
export function __debug_getKeys() {
  return { currentKey, previousKey, lastVersion };
}
