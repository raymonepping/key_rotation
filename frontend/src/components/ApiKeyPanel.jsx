import React, { useEffect, useState } from 'react';

export default function ApiKeyPanel() {
  const [status, setStatus] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [err, setErr] = useState(null);

  // Poll /api/status every 5s for key metadata
  useEffect(() => {
    let stop = false;
    async function poll() {
      try {
        const res = await fetch('/api/status');
        const d   = await res.json();
        if (!stop) setStatus(d);
      } catch { /* best-effort */ }
    }
    poll();
    const t = setInterval(poll, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  async function testKey() {
    setTesting(true); setTestResult(null); setErr(null);
    try {
      const res = await fetch('/api/test-key', { method: 'POST' });
      const d   = await res.json();
      setTestResult(d);
    } catch (e) {
      setErr(e.message);
    } finally {
      setTesting(false);
    }
  }

  return (
    <section className="panel">
      <h2>API Key</h2>

      <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '0.88rem', marginBottom: 16 }}>
        <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Current key</dt>
        <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-cipher)' }}>
          {status?.api_key?.current_preview || '—'}
        </dd>
        <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Previous key</dt>
        <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-ink-3)' }}>
          {status?.api_key?.previous_preview || '—'}
        </dd>
        <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Version</dt>
        <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-ink-2)' }}>
          {status?.api_key?.version ?? '—'}
        </dd>
      </dl>

      <button type="button" onClick={testKey} disabled={testing} className="quiet">
        {testing ? 'Testing…' : 'Test Protected Route'}
      </button>

      {err && <div className="error-msg" style={{ marginTop: 12 }}>{err}</div>}

      {testResult && (
        <div className={`output-well ${testResult.ok ? 'ok' : 'denied'}`} style={{ marginTop: 12 }}>
          {testResult.ok
            ? `✓ ${testResult.status} OK — API key accepted`
            : `✗ ${testResult.status} — API key rejected`}
        </div>
      )}

      <p className="meta" style={{ marginTop: 12 }}>
        "Test Protected Route" calls <code>POST /api/test-key</code>, which
        checks the live key against <code>/protected</code> internally.
        Run <code>make rotate-demo</code> to trigger a rotation.
      </p>
    </section>
  );
}
