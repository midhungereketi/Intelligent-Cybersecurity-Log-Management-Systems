import { useEffect, useState } from 'react';
import { ChevronRight, LogOut, Search } from 'lucide-react';
import { api } from '../api';

function LiveClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <div className="live-clock" aria-label="Current UTC time">
      <strong>{now.toISOString().slice(11, 19)}</strong>
      <small>UTC · {now.toISOString().slice(0, 10)}</small>
    </div>
  );
}

/** Scrolling strip of live platform metrics, refreshed every 30 seconds. */
function MetricsTicker() {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => api.getDashboardSummary().then((s) => { if (!cancelled) setSummary(s); }).catch(() => {});
    load();
    const timer = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const n = (v) => (v ?? 0).toLocaleString();
  const items = [
    { cls: '', label: 'LOGS INDEXED', value: n(summary?.logs?.total) },
    { cls: 'danger', label: 'CRITICAL EVENTS', value: n(summary?.logs?.by_severity?.CRITICAL) },
    { cls: 'warn', label: 'HIGH EVENTS', value: n(summary?.logs?.by_severity?.HIGH) },
    { cls: 'danger', label: 'OPEN ALERTS', value: n(summary?.alerts?.open) },
    { cls: 'warn', label: 'ACTIVE INCIDENTS', value: n(summary?.incidents?.active) },
    { cls: '', label: 'CORRELATED THREATS', value: n(summary?.threats?.total) },
    { cls: 'ok', label: 'RESOLVED ALERTS', value: n(summary?.alerts?.resolved) },
    { cls: 'ok', label: 'DETECTION ENGINE', value: 'ONLINE' },
  ];

  return (
    <div className="ticker" aria-hidden="true">
      <div className="ticker-track">
        {[...items, ...items].map((item, i) => (
          <span key={i} className={`ticker-item ${item.cls}`}><i />{item.label} <b>{item.value}</b></span>
        ))}
      </div>
    </div>
  );
}

export default function Navbar({ currentUser, onLogout, activeTab, navItems, onOpenPalette }) {
  const title = navItems.find(({ id }) => id === activeTab)?.label || 'Overview';
  const initials = (currentUser?.username || '?').slice(0, 2).toUpperCase();

  return (
    <>
      <header className="top-navbar">
        <div className="nav-crumbs"><span>WORKSPACE</span><ChevronRight size={14} /><strong key={activeTab}>{title}</strong></div>
        <div className="nav-right">
          <button type="button" className="cmdk-trigger" onClick={onOpenPalette} aria-label="Open command palette">
            <Search size={15} /><span>Search or jump to…</span><kbd>Ctrl K</kbd>
          </button>
          <LiveClock />
          <div className="system-status"><span className="status-dot" /> SECURE</div>
          <div className="top-nav-divider" />
          <div className="user-profile-badge">
            <div className="user-avatar">{initials}</div>
            <div className="user-copy"><strong>{currentUser?.username}</strong><small>{currentUser?.role_name}</small></div>
          </div>
          <button className="btn btn-secondary btn-sm nav-signout" onClick={onLogout} title="Sign out" aria-label="Sign out"><LogOut size={16} /></button>
        </div>
      </header>
      <MetricsTicker />
    </>
  );
}
