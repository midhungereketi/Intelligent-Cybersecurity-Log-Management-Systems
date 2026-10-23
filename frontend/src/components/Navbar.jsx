import { ChevronRight, CircleUserRound, LogOut } from 'lucide-react';

export default function Navbar({ currentUser, onLogout, activeTab }) {
  const titles = {
    dashboard: 'Overview', logs: 'Log explorer', alerts: 'Threats & alerts',
    incidents: 'Investigations', detection: 'Detection rules', admin: 'Administration',
  };
  return (
    <header className="top-navbar">
      <div className="nav-crumbs"><span>WORKSPACE</span><ChevronRight size={14} /><strong>{titles[activeTab] || 'Overview'}</strong></div>
      <div className="nav-right">
        <div className="system-status"><span className="status-dot" /> SECURE SESSION</div>
        <div className="top-nav-divider" />
        <div className="user-profile-badge">
          <div className="user-avatar"><CircleUserRound size={18} /></div>
          <div className="user-copy"><strong>{currentUser?.username}</strong><small>{currentUser?.role_name}</small></div>
        </div>
        <button className="btn btn-secondary btn-sm nav-signout" onClick={onLogout} title="Sign out" aria-label="Sign out"><LogOut size={16} /></button>
      </div>
    </header>
  );
}
