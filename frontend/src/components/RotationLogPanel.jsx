import React, { useEffect, useRef, useState } from 'react';

const MAX_ENTRIES = 20;

export default function RotationLogPanel() {
  const [log, setLog]   = useState([]);
  const prevRef         = useRef({ kvVersion: null, apiVersion: null });

  useEffect(() => {
    let stop = false;
    async function poll() {
      try {
        const res = await fetch('/api/demo-state');
        const d   = await res.json();
        if (stop) return;

        const now = new Date().toLocaleTimeString();
        const entries = [];
        const prev = prevRef.current;

        // KV version change?
        const kvV = d.kv?.version ?? null;
        if (kvV != null && prev.kvVersion != null && kvV !== prev.kvVersion) {
          entries.push({
            ts: now,
            event: 'KV rotated',
            detail: `v${prev.kvVersion} → v${kvV}`,
            tone: 'ok',
          });
        }
        if (kvV != null) prev.kvVersion = kvV;

        // API key version change?
        const apiV = d.apiKey?.version ?? null;
        if (apiV != null && prev.apiVersion != null && apiV !== prev.apiVersion) {
          entries.push({
            ts: now,
            event: 'API key rotated',
            detail: `v${prev.apiVersion} → v${apiV}`,
            tone: 'warn',
          });
        }
        if (apiV != null) prev.apiVersion = apiV;

        if (entries.length) {
          setLog(prev => [...entries, ...prev].slice(0, MAX_ENTRIES));
        }
      } catch { /* best-effort */ }
    }
    poll();
    const t = setInterval(poll, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  return (
    <section className="panel">
      <h2>Rotation Log</h2>
      <p className="meta">
        Client-side — detects version changes from <code>/api/demo-state</code> polls.
        Run <code>make rotate-demo</code> to see entries appear.
      </p>

      {log.length === 0 ? (
        <p style={{ color: 'var(--vr-ink-3)', fontStyle: 'italic' }}>
          No rotations detected yet. Run <code>make rotate-demo</code> in your terminal.
        </p>
      ) : (
        <ul className="audit-list">
          {log.map((entry, i) => (
            <li key={i} className="audit-item">
              <span className="audit-time">{entry.ts}</span>
              <span className="audit-action">
                <span className={`pill ${entry.tone}`} style={{ marginRight: 8 }}>
                  {entry.event}
                </span>
                {entry.detail}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
