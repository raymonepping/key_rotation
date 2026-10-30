import React, { useState } from 'react';

export default function TransitDemoPanel() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  async function readSecret() {
    setLoading(true); setErr(null); setResult(null);
    try {
      const res = await fetch('/api/secret');
      const d   = await res.json();
      if (!res.ok) throw new Error(d.error || `HTTP ${res.status}`);
      setResult(d);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel">
      <h2>Transit Demo</h2>
      <p>
        Read the current KV secret. If the KV stores a ciphertext, Vault Transit
        decrypts it server-side. <strong>The application never sees the key — only Vault does.</strong>
      </p>

      <button type="button" onClick={readSecret} disabled={loading}>
        {loading ? 'Reading…' : 'Read Secret from Vault'}
      </button>

      {err && <div className="error-msg" style={{ marginTop: 12 }}>{err}</div>}

      {result && (
        <div style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
            <span className={`pill ${result.mode === 'kv+transit' ? 'cipher' : 'ok'}`}>
              {result.mode}
            </span>
            {result.version != null && (
              <span className="pill authority">v{result.version}</span>
            )}
          </div>
          <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '0.88rem' }}>
            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Field</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-cipher)' }}>{result.field}</dd>
            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Value</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-cipher)' }}>{result.value_preview}</dd>
          </dl>
          {result.mode === 'kv+transit' && (
            <p className="meta" style={{ marginTop: 10 }}>
              The plaintext was decrypted by Vault's Transit engine using the
              <code> booklib-aes</code> key. The app received only the preview.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
