import { Activity, ArrowUpRight, FileText, LayoutGrid, Radar, Shield, ShieldAlert, SlidersHorizontal, Workflow } from 'lucide-react';

export default function Sidebar({ activeTab, onSelectTab, currentUser }) {
  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: LayoutGrid },
    { id: 'logs', label: 'Log explorer', icon: FileText },
    { id: 'alerts', label: 'Threats & alerts', icon: ShieldAlert },
    { id: 'incidents', label: 'Investigations', icon: Workflow },
    { id: 'detection', label: 'Detection rules', icon: Radar },
  ];

  if (currentUser?.role_name === 'ADMIN') navItems.push({ id: 'admin', label: 'Administration', icon: SlidersHorizontal });

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-mark"><Shield size={24} strokeWidth={2.2} /></div>
        <div className="sidebar-brand-copy">
          <strong>CYBERSHIELD<span className="brand-period">.</span></strong>
          <small>SECURITY OPERATIONS</small>
        </div>
      </div>
      <div className="sidebar-section-label">WORKSPACE <span>{String(navItems.findIndex(({ id }) => id === activeTab) + 1).padStart(2, '0')} / {String(navItems.length).padStart(2, '0')}</span></div>
      <nav className="sidebar-nav" aria-label="Primary navigation">
        {navItems.map(({ id, label, icon: Icon }) => (
          <button key={id} type="button" className={`nav-link ${activeTab === id ? 'active' : ''}`}
            onClick={() => onSelectTab(id)} aria-current={activeTab === id ? 'page' : undefined}>
            <Icon size={18} strokeWidth={1.9} />
            <span>{label}</span>
            {activeTab === id && <ArrowUpRight className="nav-active-arrow" size={15} />}
          </button>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="sidebar-signal">
          <div className="signal-top"><Activity size={15} /> LIVE ENVIRONMENT <span className="signal-pulse" /></div>
          <strong>System monitoring active</strong>
          <span>Logs, rules and investigations in one place.</span>
        </div>
        <div className="sidebar-footer">CYBERSHIELD SOC <span>© 2026</span></div>
      </div>
    </aside>
  );
}
