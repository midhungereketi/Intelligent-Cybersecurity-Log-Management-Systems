import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle, CheckCircle2, ArrowRight } from 'lucide-react';
import { api, setStoredToken, setStoredUser } from '../api';

export default function LoginView({ onLoginSuccess }) {
  const [username, setUsername] = useState('superadmin');
  const [password, setPassword] = useState('AdminStrongPass123!');
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

  const handlePrefill = (u, p) => {
    setUsername(u);
    setPassword(p);
    setError(null);
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
            Intelligent Log Management & Incident Investigation
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
                type="text"
                className="form-control"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                required
                style={{ paddingLeft: '38px' }}
              />
              <User size={16} color="var(--text-dim)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: '24px' }}>
            <label className="form-label">Password</label>
            <div style={{ position: 'relative' }}>
              <input
                type="password"
                className="form-control"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required
                style={{ paddingLeft: '38px' }}
              />
              <Lock size={16} color="var(--text-dim)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', padding: '11px', fontSize: '0.95rem' }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In to Operations Console'}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        <div style={{ marginTop: '28px', paddingTop: '20px', borderTop: '1px solid var(--border-subtle)' }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textAlign: 'center', marginBottom: '10px' }}>
            Select role credentials for testing:
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handlePrefill('admin_user', 'AdminSecurePass123!')}
            >
              ADMIN Demo
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handlePrefill('analyst_user', 'AnalystSecurePass123!')}
            >
              ANALYST Demo
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
