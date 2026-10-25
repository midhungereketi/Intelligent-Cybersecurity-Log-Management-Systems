import { useEffect, useState } from 'react';
import { Activity, ArrowRight, Eye, EyeOff, Fingerprint, LockKeyhole, Shield, ShieldCheck, Sparkles } from 'lucide-react';
import { api, setStoredToken, setStoredUser } from '../api';

const ROTATING_WORDS = ['the threat.', 'the breach.', 'the attacker.', 'the noise.'];

/** Types and deletes each phrase in turn. */
function useTypewriter(words, { typeMs = 85, holdMs = 1600, deleteMs = 45 } = {}) {
  const [text, setText] = useState('');
  const [wordIndex, setWordIndex] = useState(0);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const word = words[wordIndex];
    let delay = deleting ? deleteMs : typeMs;
    if (!deleting && text === word) delay = holdMs;
    const timer = setTimeout(() => {
      if (!deleting && text === word) setDeleting(true);
      else if (deleting && text === '') {
        setDeleting(false);
        setWordIndex((i) => (i + 1) % words.length);
      } else {
        setText(word.slice(0, text.length + (deleting ? -1 : 1)));
      }
    }, delay);
    return () => clearTimeout(timer);
  }, [text, deleting, wordIndex, words, typeMs, holdMs, deleteMs]);

  return text;
}

function Radar() {
  const blips = [[420, 210, 0], [205, 380, 1.4], [470, 430, 2.7], [270, 160, 4.1], [380, 520, 5]];
  return (
    <div className="login-radar" aria-hidden="true">
      <svg viewBox="0 0 640 640">
        <defs>
          <radialGradient id="radar-bg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(34,211,238,.12)" />
            <stop offset="100%" stopColor="rgba(34,211,238,0)" />
          </radialGradient>
          <linearGradient id="sweep-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="rgba(34,211,238,0)" />
            <stop offset="100%" stopColor="rgba(34,211,238,.45)" />
          </linearGradient>
        </defs>
        <circle cx="320" cy="320" r="310" fill="url(#radar-bg)" />
        {[300, 230, 160, 90].map((r) => (
          <circle key={r} cx="320" cy="320" r={r} fill="none" stroke="rgba(129,140,248,.18)" strokeDasharray={r === 300 ? '2 6' : undefined} />
        ))}
        <line x1="10" y1="320" x2="630" y2="320" stroke="rgba(129,140,248,.12)" />
        <line x1="320" y1="10" x2="320" y2="630" stroke="rgba(129,140,248,.12)" />
        <g className="radar-sweep">
          <path d="M320 320 L620 320 A300 300 0 0 0 579.8 170 Z" fill="url(#sweep-grad)" />
          <line x1="320" y1="320" x2="620" y2="320" stroke="rgba(103,232,249,.9)" strokeWidth="2" />
        </g>
        {blips.map(([x, y, delay]) => (
          <circle key={`${x}-${y}`} className="radar-blip" cx={x} cy={y} r="4"
            fill={delay > 2 ? '#fb7185' : '#67e8f9'} style={{ animationDelay: `${delay}s` }} />
        ))}
      </svg>
    </div>
  );
}

export default function LoginView({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const typed = useTypewriter(ROTATING_WORDS);

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
        <Radar />
        <div className="login-story-top"><div className="login-logo"><Shield size={24} /></div><strong>CYBERSHIELD<span>.</span></strong><small>SOC PLATFORM · v2.0</small></div>
        <div className="login-story-content">
          <div className="login-eyebrow"><span className="signal-pulse" /> INTELLIGENT SECURITY OPERATIONS</div>
          <h1 aria-label="See the signal. Stop the threat.">See the signal.<br /><em>Stop <span className="typed">{typed}</span></em></h1>
          <p>One command center for every log, alert and investigation — hybrid MongoDB and PostgreSQL intelligence built for decisions measured in seconds.</p>
          <div className="login-story-line" />
          <div className="login-capabilities">
            <div><Activity size={20} /><span>Live log intelligence</span></div>
            <div><ShieldCheck size={20} /><span>Automated threat detection</span></div>
            <div><Fingerprint size={20} /><span>Connected incident response</span></div>
          </div>
          <div className="login-stats">
            <div><strong className="gradient-text">1M+</strong><small>LOGS BENCHMARKED</small></div>
            <div><strong className="gradient-text">3</strong><small>DETECTION ENGINES</small></div>
            <div><strong className="gradient-text">24/7</strong><small>WATCH POSTURE</small></div>
          </div>
        </div>
        <div className="login-story-bottom"><span>MONITOR · DETECT · RESPOND</span><span>SECURE OPERATIONS / 2026</span></div>
      </section>

      <section className="login-form-side">
        <div className="login-card">
          <div className="login-form-wrap">
            <div className="login-mobile-brand"><Shield size={22} /> CYBERSHIELD<span>.</span></div>
            <div className="login-form-kicker"><Sparkles size={13} /> SECURE ACCESS / 01</div>
            <h2>Welcome back.</h2>
            <p className="login-form-subtitle">Sign in to your operations workspace.</p>
            {error && <div key={error} className="alert-banner banner-danger login-error" role="alert">{error}</div>}
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
            <div className="login-security-note"><LockKeyhole size={16} /><span>Argon2id-hashed credentials · signed JWT sessions.</span></div>
          </div>
        </div>
        <div className="login-form-footer"><span>CYBERSHIELD SOC</span><span>SECURITY OPERATIONS PLATFORM</span></div>
      </section>
    </div>
  );
}
