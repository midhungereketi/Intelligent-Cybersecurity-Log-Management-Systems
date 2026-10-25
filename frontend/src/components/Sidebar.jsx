import { Activity, ArrowUpRight, Shield } from 'lucide-react';

// Height of a nav row plus the gap between rows; keeps the sliding indicator aligned.
const NAV_ROW = 52;

export default function Sidebar({ activeTab, onSelectTab, navItems }) {
  const activeIndex = Math.max(navItems.findIndex(({ id }) => id === activeTab), 0);

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-mark"><Shield size={22} strokeWidth={2.2} /></div>
        <div className="sidebar-brand-copy">
          <strong>CYBERSHIELD<span className="brand-period">.</span></strong>
          <small>SECURITY OPERATIONS</small>
        </div>
      </div>
      <div className="sidebar-section-label">WORKSPACE <span>{String(activeIndex + 1).padStart(2, '0')} / {String(navItems.length).padStart(2, '0')}</span></div>
      <nav className="sidebar-nav" aria-label="Primary navigation">
        <span className="nav-indicator" style={{ transform: `translateY(${activeIndex * NAV_ROW}px)` }} aria-hidden="true" />
        {navItems.map(({ id, label, icon: Icon }, index) => (
          <button key={id} type="button" className={`nav-link ${activeTab === id ? 'active' : ''}`}
            onClick={() => onSelectTab(id)} aria-current={activeTab === id ? 'page' : undefined}>
            <Icon size={18} strokeWidth={1.9} />
            <span>{label}</span>
            {activeTab === id
              ? <ArrowUpRight className="nav-active-arrow" size={15} />
              : <span className="nav-kbd" aria-hidden="true">0{index + 1}</span>}
          </button>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="sidebar-signal">
          <div className="signal-top"><Activity size={14} /> LIVE TELEMETRY <span className="signal-pulse" /></div>
          <div className="signal-bars" aria-hidden="true">
            {Array.from({ length: 14 }, (_, i) => <i key={i} style={{ animationDelay: `${(i * 0.13) % 1.2}s` }} />)}
          </div>
          <strong>All sensors streaming</strong>
          <span>MongoDB logs and PostgreSQL cases in sync.</span>
        </div>
        <div className="sidebar-footer">CYBERSHIELD SOC <span>v2.0 · © 2026</span></div>
      </div>
    </aside>
  );
}
