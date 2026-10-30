import React, { useEffect, useState } from 'react';

/* ── SVG icon paths (24×24 stroke) ─────────────────────────────────────── */
const ICONS = {
  status:  'M9 12l2 2 4-4M5 7h14M5 12h14M5 17h10',
  transit: 'M12 3v1m0 16v1M5.636 5.636l.707.707M17.657 17.657l.707.707M3 12h1m16 0h1M5.636 18.364l.707-.707M17.657 6.343l.707-.707',
  apikey:  'M15 7a4 4 0 11-8 0 4 4 0 018 0zM11 15l-1 4m4-4l1 4M8 19h8',
  rotate:  'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  ext:     'M14 4h6v6M20 4l-9 9M19 14v6H4V5h6',
  menu:    'M4 7h16M4 12h16M4 17h16',
};

const VIEWS = [
  { id: 'status',  label: 'Secret Status',  group: 'Monitor' },
  { id: 'transit', label: 'Transit Demo',   group: 'Monitor' },
  { id: 'apikey',  label: 'API Key',        group: 'Monitor' },
  { id: 'log',     label: 'Rotation Log',   group: 'Monitor' },
];

const LEGEND = [
  ['ok',        'Allowed / verified'],
  ['denied',    'Blocked / failed'],
  ['warn',      'Rotating / pending'],
  ['authority', 'Navigation / active'],
  ['cipher',    'Key material / KV'],
];

function Icon({ name }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="rail-icon">
      <path d={ICONS[name]} />
    </svg>
  );
}

function BrandMark() {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" className="brand-mark">
      <path d="M16 2l12 7v14l-12 7-12-7V9z" fill="#0f1a2a" />
      <path d="M7 16.5h5l2-4.5 3 9 2-4.5h6" fill="none" stroke="#e9eef3"
        strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ── Vault node status context ───────────────────────────────────────────── */
function NodeCtx({ label, status, tone, hideNarrow }) {
  return (
    <div className={`ctx tone-${tone}${hideNarrow ? ' ctx-hide-narrow' : ''}`}>
      <span className="ctx-label">{label}</span>
      <span className="ctx-value">{status}</span>
    </div>
  );
}

/* ── Poll /health every 5 s ─────────────────────────────────────────────── */
function useHealth() {
  const [health, setHealth] = useState(null);
  useEffect(() => {
    let stop = false;
    async function poll() {
      try {
        const res  = await fetch('/health');
        const data = await res.json();
        if (!stop) setHealth(data);
      } catch {
        if (!stop) setHealth(null);
      }
    }
    poll();
    const t = setInterval(poll, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);
  return health;
}

function healthTone(node) {
  if (!node)           return ['checking', 'warn'];
  if (!node.reachable) return ['unreachable', 'denied'];
  if (node.sealed)     return ['sealed', 'denied'];
  if (node.standby)    return ['standby', 'warn'];
  return ['active', 'ok'];
}

/* ── Shell ──────────────────────────────────────────────────────────────── */
export default function Shell({ view, onView, children }) {
  const [open, setOpen] = useState(false);
  const health = useHealth();

  const [sealLabel, sealTone]   = healthTone(health?.seal);
  const [vaultLabel, vaultTone] = healthTone(health?.vault);

  const vaultUiPort = import.meta.env.VITE_VAULT_UI_PORT || '18701';
  const vaultUiUrl  = `https://${location.hostname}:${vaultUiPort}/ui/`;

  // Group views by group label for the rail
  const groups = [...new Set(VIEWS.map(v => v.group))];

  return (
    <div className={`shell${open ? ' open' : ''}`}>

      {/* ── Rail ──────────────────────────────────────────────────────── */}
      <nav className="rail" aria-label="Key Rotation navigation">
        <a className="brand" href="#top">
          <BrandMark />
          <span>
            <span className="brand-name">Key Rotation</span>
            <span className="brand-sub">Vault Lab</span>
          </span>
        </a>

        {groups.map(group => (
          <div className="rail-group" key={group}>
            <div className="rail-group-label">{group}</div>
            {VIEWS.filter(v => v.group === group).map(({ id, label }) => (
              <button
                key={id}
                type="button"
                className={`rail-link${view === id ? ' current' : ''}`}
                onClick={() => { onView(id); setOpen(false); }}
              >
                <Icon name={id === 'log' ? 'rotate' : id} />
                {label}
              </button>
            ))}
          </div>
        ))}

        <div className="rail-group">
          <div className="rail-group-label">Tools</div>
          <a className="rail-link ext" href={vaultUiUrl} target="_blank" rel="noopener noreferrer">
            <Icon name="ext" />
            Vault UI
          </a>
        </div>

        <div className="rail-foot">
          <div className="legend">
            {LEGEND.map(([tone, label]) => (
              <span key={tone} className={`tone-${tone}`}>
                <i aria-hidden="true" />
                {label}
              </span>
            ))}
          </div>
        </div>
      </nav>

      {/* scrim — closes rail on mobile */}
      <button
        type="button"
        className="scrim"
        aria-label="Close navigation"
        onClick={() => setOpen(false)}
      />

      {/* ── Top bar ───────────────────────────────────────────────────── */}
      <header className="bar" id="top">
        <button
          type="button"
          className="menu-btn"
          aria-label="Open navigation"
          onClick={() => setOpen(true)}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d={ICONS.menu} />
          </svg>
        </button>

        <div>
          <div className="bar-title">Key Rotation Lab</div>
          <div className="bar-sub">KV · Transit · Rotate · Verify</div>
        </div>

        <div className="bar-context">
          <NodeCtx label="vault-s" status={sealLabel} tone={sealTone} hideNarrow />
          <NodeCtx label="vault-1" status={vaultLabel} tone={vaultTone} />
        </div>
      </header>

      {/* ── Main ──────────────────────────────────────────────────────── */}
      <main className="main" id="main">
        {children}
      </main>

      {/* ── Footer ────────────────────────────────────────────────────── */}
      <footer className="footer">
        <div className="footer-inner">
          <span>
            © {new Date().getFullYear()}{' '}
            <span className="sig-name" data-name="Raymon Epping" tabIndex={0}>
              Raymon Epping
            </span>
          </span>
          <span className="footer-quote">
            <em>"A rotated secret is one that cannot be replayed."</em>
          </span>
          <span className="footer-words">
            <span>KV</span>
            <span>Transit</span>
            <span>Rotate</span>
            <span>Verify</span>
          </span>
        </div>
      </footer>

    </div>
  );
}
