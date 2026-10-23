import { useState } from 'react';
import { Activity, ArrowRight, Eye, EyeOff, Fingerprint, LockKeyhole, Shield, ShieldCheck } from 'lucide-react';
import { api, setStoredToken, setStoredUser } from '../api';

export default function LoginView({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await api.login(username, password);
      setStoredToken(result.access_token);
      setStoredUser(result.user);
      onLoginSuccess(result.user);
    } catch (err) {
      setError(err.message || 'Sign-in failed. Check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-shell">
      <section className="login-story" aria-label="CyberShield introduction">
        <div className="login-story-top"><div className="login-logo"><Shield size={26} /></div><strong>CYBERSHIELD<span>.</span></strong><small>SOC PLATFORM</small></div>
        <div className="login-story-content">
          <div className="login-eyebrow"><span className="signal-pulse" /> INTELLIGENT SECURITY OPERATIONS</div>
          <h1>See the signal.<br /><em>Stop the threat.</em></h1>
          <p>One clear view of every log, alert and investigation. Built for fast decisions when every second counts.</p>
          <div className="login-story-line" />
          <div className="login-capabilities">
            <div><Activity size={20} /><span>Live log intelligence</span></div>
            <div><ShieldCheck size={20} /><span>Automated threat detection</span></div>
            <div><Fingerprint size={20} /><span>Connected incident response</span></div>
          </div>
        </div>
        <div className="login-story-bottom"><span>MONITOR · DETECT · RESPOND</span><span>SECURE OPERATIONS / 2026</span></div>
        <div className="login-orbit orbit-one" /><div className="login-orbit orbit-two" /><div className="login-orbit orbit-three" />
      </section>

      <section className="login-form-side">
        <div className="login-form-wrap">
          <div className="login-mobile-brand"><Shield size={22} /> CYBERSHIELD<span>.</span></div>
          <div className="login-form-kicker">SECURE ACCESS / 01</div>
          <h2>Welcome back.</h2>
          <p className="login-form-subtitle">Sign in to your operations workspace.</p>
          {error && <div className="alert-banner banner-danger login-error" role="alert">{error}</div>}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label" htmlFor="login-username">Username</label>
              <input id="login-username" type="text" className="form-control" value={username}
                onChange={(event) => setUsername(event.target.value)} placeholder="Enter your username" required autoComplete="username" />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="login-password">Password</label>
              <div className="login-password-field">
                <input id="login-password" type={showPassword ? 'text' : 'password'} className="form-control" value={password}
                  onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" required autoComplete="current-password" />
                <button type="button" className="password-toggle" onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={18} /> : <Eye size={18} />}</button>
              </div>
            </div>
            <button id="login-submit" type="submit" className="btn btn-primary login-submit" disabled={loading}>
              <span>{loading ? 'Signing in…' : 'Enter workspace'}</span><ArrowRight size={18} />
            </button>
          </form>
          <div className="login-security-note"><LockKeyhole size={16} /><span>Protected access for authorized team members.</span></div>
        </div>
        <div className="login-form-footer"><span>CYBERSHIELD SOC</span><span>SECURITY OPERATIONS PLATFORM</span></div>
      </section>
    </div>
  );
}
