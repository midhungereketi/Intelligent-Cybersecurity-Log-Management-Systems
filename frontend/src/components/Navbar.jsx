import React from 'react';
import { Shield, ShieldAlert, User, LogOut, Activity } from 'lucide-react';

export default function Navbar({ currentUser, onLogout }) {
  return (
    <header className="top-navbar">
      <div className="nav-brand">
        <div className="brand-icon">
          <Shield size={20} color="#04101c" />
        </div>
        <span>CyberShield <span style={{ color: 'var(--cyan-glow)', fontWeight: 400 }}>SOC</span></span>
      </div>

      <div className="nav-right">
        <div className="system-status">
          <span className="status-dot"></span>
          <span>SOC Operational</span>
        </div>

        {currentUser && (
          <div className="user-profile-badge">
            <User size={16} color="var(--cyan-glow)" />
            <div>
              <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{currentUser.username}</span>
              <span 
                className={`badge ${currentUser.role === 'ADMIN' ? 'badge-critical' : 'badge-open'}`}
                style={{ marginLeft: '8px', fontSize: '0.65rem', padding: '1px 6px' }}
              >
                {currentUser.role}
              </span>
            </div>
          </div>
        )}

        {currentUser && (
          <button 
            className="btn btn-secondary btn-sm" 
            onClick={onLogout}
            title="Log Out"
          >
            <LogOut size={15} />
            <span>Sign Out</span>
          </button>
        )}
      </div>
    </header>
  );
}
