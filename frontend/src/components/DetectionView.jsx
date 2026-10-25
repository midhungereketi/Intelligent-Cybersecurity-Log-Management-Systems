import React, { useState, useEffect } from 'react';
import { Zap, Play, CheckCircle2, AlertTriangle, ShieldCheck, Clock, Settings, RefreshCw } from 'lucide-react';
import { api } from '../api';

export default function DetectionView() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [scanLimit, setScanLimit] = useState(2000);
  const [runResult, setRunResult] = useState(null);
  const [error, setError] = useState(null);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await api.listRules();
      setRules(res || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch detection rules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleRunDetection = async () => {
    setRunning(true);
    setRunResult(null);
    setError(null);
    try {
      // An empty or out-of-range field would otherwise send NaN/null and fail validation
      const limit = Math.min(Math.max(parseInt(scanLimit, 10) || 2000, 1), 10000);
      setScanLimit(limit);
      const res = await api.runDetection({ limit });
      setRunResult(res);
    } catch (err) {
      setError(err.message || 'Detection pass failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div>
      {/* Title */}
      <div className="view-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', color: 'var(--text-main)' }}>Detection rules</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '4px' }}>
            Scan incoming activity with your team's active security rules.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={fetchRules} disabled={loading}>
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Rules</span>
        </button>
      </div>

      {error && (
        <div className="alert-banner banner-danger">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Trigger Card */}
      <div className="card" style={{ marginBottom: '24px', border: '1px solid var(--border-glow)' }}>
        <div className="card-header">
          <h3 className="card-title">
            <Zap size={20} color="var(--cyan-glow)" />
            <span>Execute Detection Batch Pass</span>
          </h3>
          <span style={{ fontSize: '0.8rem', color: 'var(--emerald-success)' }}>Idempotent Replay Protected</span>
        </div>

        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '18px' }}>
          Scans unprocessed MongoDB logs through active detection algorithms. Correlates threats and generates or increments deduplicated alerts in PostgreSQL.
        </p>

        <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ width: '220px' }}>
            <label className="form-label">Batch Event Limit</label>
            <input
              type="number"
              className="form-control"
              value={scanLimit}
              min="10"
              max="10000"
              onChange={(e) => setScanLimit(e.target.value)}
            />
          </div>

          <button
            className="btn btn-primary"
            onClick={handleRunDetection}
            disabled={running}
            style={{ padding: '10px 20px' }}
          >
            <Play size={16} />
            <span>{running ? 'Running Detection Algorithms...' : 'Trigger Detection Scan'}</span>
          </button>
        </div>

        {runResult && (
          <div style={{
            marginTop: '20px',
            padding: '16px',
            background: 'rgba(6, 182, 212, 0.08)',
            border: '1px solid rgba(6, 182, 212, 0.3)',
            borderRadius: 'var(--radius-sm)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyan-glow)', fontWeight: 600, marginBottom: '8px' }}>
              <CheckCircle2 size={18} />
              <span>Execution Summary</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', fontSize: '0.85rem' }}>
              <div>Scanned Events: <strong>{runResult.logs_scanned}</strong></div>
              <div>Rules Evaluated: <strong>{runResult.rules_evaluated}</strong></div>
              <div>New Alerts Created: <strong style={{ color: 'var(--rose-danger)' }}>{runResult.alerts_created}</strong></div>
              <div>Alerts Incremented: <strong style={{ color: 'var(--amber-warning)' }}>{runResult.alerts_updated}</strong></div>
            </div>
          </div>
        )}
      </div>

      {/* Rules Catalog */}
      <h3 style={{ fontSize: '1.2rem', color: 'var(--text-main)', marginBottom: '16px' }}>Configured detection algorithms</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        {rules.map((rule) => (
          <div key={rule.rule_id} className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <span className={`badge badge-${rule.severity?.toLowerCase()}`} style={{ marginBottom: '6px' }}>
                  {rule.severity}
                </span>
                <h4 style={{ fontSize: '1.05rem', color: 'var(--text-main)' }}>{rule.rule_name}</h4>
              </div>
              <span className={`badge ${rule.is_enabled ? 'badge-low' : 'badge-closed'}`}>
                {rule.is_enabled ? 'Active' : 'Disabled'}
              </span>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '16px', minHeight: '40px' }}>
              {rule.description}
            </p>

            <div style={{
              background: 'rgba(255,255,255,0.02)',
              padding: '12px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8rem',
              color: 'var(--text-dim)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}>
              <div>Rule Type: <code style={{ color: 'var(--cyan-glow)' }}>{rule.rule_type}</code></div>
              <div>Threshold: <strong>{rule.threshold} occurrences</strong></div>
              <div>Time Window: <strong>{rule.time_window_seconds} seconds</strong></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
