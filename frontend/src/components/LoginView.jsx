import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle, ArrowRight, Info } from 'lucide-react';
import { api, setStoredToken, setStoredUser } from '../api';

export default function LoginView({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.login(username, password);
      setStoredToken(res.access_token);
      setStoredUser(res.user);
      onLoginSuccess(res.user);
    } catch (err) {
      setError(err.message || 'Authentication failed. Check credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      background: 'radial-gradient(ellipse at 50% 30%, #17223b 0%, #080c14 70%)',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '440px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-glow)',
        borderRadius: 'var(--radius-lg)',
        padding: '36px',
        boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6), 0 0 30px rgba(6, 182, 212, 0.15)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, var(--cyan-primary), var(--purple-accent))',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--shadow-glow)',
            marginBottom: '16px',
          }}>
            <Shield size={32} color="#04101c" />
          </div>
          <h1 style={{ fontSize: '1.5rem', color: '#fff', marginBottom: '6px' }}>
            CyberShield <span style={{ color: 'var(--cyan-glow)' }}>SOC</span>
          </h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Intelligent Log Management &amp; Incident Investigation
          </p>
        </div>

        {error && (
          <div className="alert-banner banner-danger">
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <div style={{ position: 'relative' }}>
              <input
                id="login-username"
                type="text"
                className="form-control"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                required
                autoComplete="username"
                style={{ paddingLeft: '38px' }}
              />
              <User size={16} color="var(--text-dim)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: '24px' }}>
            <label className="form-label">Password</label>
            <div style={{ position: 'relative' }}>
              <input
                id="login-password"
                type="password"
                className="form-control"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required
                autoComplete="current-password"
                style={{ paddingLeft: '38px' }}
              />
              <Lock size={16} color="var(--text-dim)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
            </div>
          </div>

          <button
            type="submit"
            id="login-submit"
            className="btn btn-primary"
            style={{ width: '100%', padding: '11px', fontSize: '0.95rem' }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In to Operations Console'}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        {/* Local setup guidance — no credentials are hardcoded here. */}
        <div style={{ marginTop: '24px', paddingTop: '18px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '8px',
            padding: '12px 14px',
            background: 'rgba(6, 182, 212, 0.06)',
            border: '1px solid rgba(6, 182, 212, 0.2)',
            borderRadius: 'var(--radius-sm)',
          }}>
            <Info size={15} color="var(--cyan-glow)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.55' }}>
              <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '4px' }}>
                Local development setup
              </strong>
              Copy <code style={{ color: 'var(--cyan-glow)' }}>.env.example</code> to{' '}
              <code style={{ color: 'var(--cyan-glow)' }}>.env</code> and set{' '}
              <code style={{ color: 'var(--cyan-glow)' }}>ADMIN_USERNAME</code>,{' '}
              <code style={{ color: 'var(--cyan-glow)' }}>ADMIN_PASSWORD</code>, and{' '}
              <code style={{ color: 'var(--cyan-glow)' }}>ADMIN_EMAIL</code>.
              The backend bootstraps the admin account automatically on first startup.
              Use the admin account to create analyst accounts via{' '}
              <code style={{ color: 'var(--cyan-glow)' }}>POST /api/users</code>.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
