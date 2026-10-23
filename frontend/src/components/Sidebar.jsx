import React from 'react';
import { 
  LayoutDashboard, 
  FileText, 
  ShieldAlert, 
  LifeBuoy, 
  Zap, 
  Sliders, 
  UserCheck 
} from 'lucide-react';

export default function Sidebar({ activeTab, onSelectTab, currentUser }) {
  const isAdmin = currentUser?.role === 'ADMIN';

  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'logs', label: 'Log Explorer & Ingest', icon: FileText },
    { id: 'alerts', label: 'Threats & Alerts', icon: ShieldAlert },
    { id: 'incidents', label: 'Incidents & Actions', icon: LifeBuoy, highlight: true },
    { id: 'detection', label: 'Detection Engine', icon: Zap },
  ];

  if (isAdmin) {
    navItems.push({ id: 'admin', label: 'Admin Management', icon: Sliders });
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <span style={{ fontSize: '0.8rem', letterSpacing: '0.08em', color: 'var(--text-dim)', fontWeight: 700, textTransform: 'uppercase' }}>
          Navigation
        </span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`nav-link ${isActive ? 'active' : ''}`}
              onClick={() => onSelectTab(item.id)}
              style={item.highlight ? { borderLeft: isActive ? '3px solid var(--rose-danger)' : 'none' } : {}}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <p>Intelligent Cybersecurity System</p>
        <p style={{ marginTop: '4px', color: 'var(--cyan-glow)' }}>Security Operations Console</p>
      </div>
    </aside>
  );
}
