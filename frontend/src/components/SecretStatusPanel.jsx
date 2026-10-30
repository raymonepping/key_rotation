import React, { useEffect, useState } from 'react';

export default function SecretStatusPanel() {
  const [data, setData] = useState(null);
  const [err, setErr]   = useState(null);

  useEffect(() => {
    let stop = false;
    async function poll() {
      try {
        const res = await fetch('/api/demo-state');
        const d   = await res.json();
        if (!stop) { setData(d); setErr(null); }
      } catch (e) {
        if (!stop) setErr(e.message);
      }
    }
    poll();
    const t = setInterval(poll, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  return (
    <section className="panel">
      <h2>Secret Status</h2>

      {err && <div className="error-msg">{err}</div>}
      {!data && !err && <p className="loading">Loading…</p>}

      {data && (
        <>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}>
            {data.kv?.version != null && (
              <span className="pill cipher">KV v{data.kv.version}</span>
            )}
            {data.kv?.error && (
              <span className="pill denied">vault error</span>
            )}
          </div>

          <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '0.88rem' }}>
            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>KV preview</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-cipher)' }}>
              {data.kv?.preview || '—'}
            </dd>

            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Last KV update</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--vr-ink-2)' }}>
              {data.kv?.updated ? new Date(data.kv.updated).toLocaleString() : '—'}
            </dd>

            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>API key (current)</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-cipher)' }}>
              {data.apiKey?.currentMasked || '—'}
            </dd>

            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>API key (previous)</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', color: 'var(--vr-ink-3)' }}>
              {data.apiKey?.prevMasked || '—'}
            </dd>

            <dt style={{ fontWeight: 600, color: 'var(--vr-ink-3)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>API key version</dt>
            <dd style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--vr-ink-2)' }}>
              {data.apiKey?.version ?? '—'}
            </dd>
          </dl>

          <p className="meta" style={{ marginTop: 12 }}>
            Polled every 5 s from <code>/api/demo-state</code>.
          </p>
        </>
      )}
    </section>
  );
}
