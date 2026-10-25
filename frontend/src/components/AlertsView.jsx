import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Check, 
  CheckCircle, 
  LifeBuoy, 
  Eye, 
  AlertTriangle, 
  RefreshCw, 
  X, 
  Radio, 
  Clock, 
  Activity,
  Layers
} from 'lucide-react';
import { api } from '../api';

export default function AlertsView({ onPromoteToIncident }) {
  const [activeSubTab, setActiveSubTab] = useState('alerts'); // 'alerts' or 'threats'
  const [alerts, setAlerts] = useState([]);
  const [threats, setThreats] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  // Selected Alert for inspection
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      const res = await api.listAlerts(params);
      setAlerts(res.items || []);
      setTotalAlerts(res.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  };

  const fetchThreats = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listThreats();
      setThreats(res.items || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch threats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeSubTab === 'alerts') {
      fetchAlerts();
    } else {
      fetchThreats();
    }
  }, [activeSubTab, statusFilter, severityFilter]);

  const handleAcknowledge = async (alertId) => {
    setActionLoading(true);
    try {
      const updated = await api.acknowledgeAlert(alertId);
      setAlerts(prev => prev.map(a => a.alert_id === alertId ? updated : a));
      if (selectedAlert?.alert_id === alertId) {
        setSelectedAlert(updated);
      }
    } catch (err) {
      alert(`Acknowledge failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleResolve = async (alertId) => {
    setActionLoading(true);
    try {
      const updated = await api.resolveAlert(alertId);
      setAlerts(prev => prev.map(a => a.alert_id === alertId ? updated : a));
      if (selectedAlert?.alert_id === alertId) {
        setSelectedAlert(updated);
      }
    } catch (err) {
      alert(`Resolve failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handlePromote = (alert) => {
    setSelectedAlert(null);
    onPromoteToIncident(alert);
  };

  return (
    <div>
      {/* Title & Tabs */}
      <div className="view-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', color: 'var(--text-main)' }}>Threats & alerts</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '4px' }}>
            Review suspicious activity, trace its evidence and take action.
          </p>
        </div>
        <button 
          className="btn btn-secondary" 
          onClick={activeSubTab === 'alerts' ? fetchAlerts : fetchThreats}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="tabs">
        <button 
          className={`tab-btn ${activeSubTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('alerts')}
        >
          <ShieldAlert size={16} />
          <span>Alerts ({totalAlerts})</span>
        </button>
        <button 
          className={`tab-btn ${activeSubTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('threats')}
        >
          <Activity size={16} />
          <span>Correlated Threats</span>
        </button>
      </div>

      {error && (
        <div className="alert-banner banner-danger">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Alerts View */}
      {activeSubTab === 'alerts' && (
        <>
          {/* Filters Bar */}
          <div className="card" style={{ marginBottom: '20px', padding: '16px 20px' }}>
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label className="form-label" style={{ marginBottom: 0 }}>Status:</label>
                <select
                  className="form-control"
                  style={{ width: '160px' }}
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <option value="">All Statuses</option>
                  <option value="OPEN">OPEN</option>
                  <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label className="form-label" style={{ marginBottom: 0 }}>Severity:</label>
                <select
                  className="form-control"
                  style={{ width: '160px' }}
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="">All Severities</option>
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>
            </div>
          </div>

          {/* Alerts Table */}
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Title & Rule</th>
                  <th>Source IP</th>
                  <th>Hits</th>
                  <th>Last Detected</th>
                  <th>Quick Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="8" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      Loading alerts...
                    </td>
                  </tr>
                ) : alerts.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
                      No alerts matching the selected filters.
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => (
                    <tr key={alert.alert_id} style={{ cursor: 'pointer' }} onClick={() => setSelectedAlert(alert)}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                        #{alert.alert_id}
                      </td>
                      <td>
                        <span className={`badge badge-${alert.severity.toLowerCase()}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${alert.status.toLowerCase()}`}>
                          {alert.status}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{alert.title}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Rule: {alert.rule_name}</div>
                      </td>
                      <td>
                        <code style={{ color: 'var(--cyan-glow)' }}>{alert.source_ip || 'N/A'}</code>
                      </td>
                      <td>
                        <span style={{ fontWeight: 700, color: alert.occurrence_count > 1 ? 'var(--amber-warning)' : 'var(--text-main)' }}>
                          {alert.occurrence_count}x
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                        {alert.last_seen_at?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }} onClick={(e) => e.stopPropagation()}>
                          <button 
                            className="btn btn-secondary btn-sm" 
                            title="Inspect Details"
                            onClick={() => setSelectedAlert(alert)}
                          >
                            <Eye size={13} />
                          </button>
                          {alert.status === 'OPEN' && (
                            <button 
                              className="btn btn-secondary btn-sm" 
                              title="Acknowledge Alert"
                              onClick={() => handleAcknowledge(alert.alert_id)}
                            >
                              <Check size={13} />
                            </button>
                          )}
                          {alert.status !== 'RESOLVED' && (
                            <button 
                              className="btn btn-success btn-sm" 
                              title="Resolve Alert"
                              onClick={() => handleResolve(alert.alert_id)}
                            >
                              <CheckCircle size={13} />
                            </button>
                          )}
                          <button 
                            className="btn btn-primary btn-sm"
                            title="Promote to Incident"
                            onClick={() => handlePromote(alert)}
                          >
                            <LifeBuoy size={13} />
                            <span>Escalate</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Threats View */}
      {activeSubTab === 'threats' && (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Threat ID</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {threats.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
                    No correlated threat profiles recorded yet.
                  </td>
                </tr>
              ) : (
                threats.map((t) => (
                  <tr key={t.threat_id}>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>#{t.threat_id}</td>
                    <td style={{ fontWeight: 600 }}>{t.threat_type}</td>
                    <td><span className={`badge badge-${t.severity.toLowerCase()}`}>{t.severity}</span></td>
                    <td><code style={{ color: 'var(--cyan-glow)' }}>{t.source_ip}</code></td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>{t.first_seen_at?.slice(0, 19).replace('T', ' ')}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>{t.last_seen_at?.slice(0, 19).replace('T', ' ')}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{t.description || '-'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Detailed Alert Modal */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-content modal-lg" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldAlert size={22} color="var(--rose-danger)" />
                <h3 className="card-title">Alert #{selectedAlert.alert_id}: {selectedAlert.title}</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedAlert(null)}>
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: 'var(--radius-sm)' }}>
                <span className="form-label" style={{ fontSize: '0.7rem' }}>Severity</span>
                <span className={`badge badge-${selectedAlert.severity.toLowerCase()}`}>{selectedAlert.severity}</span>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: 'var(--radius-sm)' }}>
                <span className="form-label" style={{ fontSize: '0.7rem' }}>Status</span>
                <span className={`badge badge-${selectedAlert.status.toLowerCase()}`}>{selectedAlert.status}</span>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: 'var(--radius-sm)' }}>
                <span className="form-label" style={{ fontSize: '0.7rem' }}>Source IP</span>
                <code style={{ color: 'var(--cyan-glow)' }}>{selectedAlert.source_ip || 'N/A'}</code>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: 'var(--radius-sm)' }}>
                <span className="form-label" style={{ fontSize: '0.7rem' }}>Occurrence Count</span>
                <strong style={{ color: 'var(--text-main)', fontSize: '1.1rem' }}>{selectedAlert.occurrence_count}x</strong>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label className="form-label">Description & Rule Details</label>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                {selectedAlert.description || 'No description provided.'}
              </p>
              <div style={{ marginTop: '8px', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                Deduplication Key: <code>{selectedAlert.deduplication_key}</code>
              </div>
            </div>

            <div style={{ marginBottom: '24px' }}>
              <label className="form-label">Supporting Evidence (Normalized Log References)</label>
              {selectedAlert.evidence?.length === 0 ? (
                <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No log references captured in evidence.</div>
              ) : (
                <div style={{
                  maxHeight: '160px',
                  overflowY: 'auto',
                  background: 'var(--bg-code)',
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.8rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--cyan-glow)',
                }}>
                  {selectedAlert.evidence.map((ev, idx) => (
                    <div key={idx} style={{ padding: '3px 0' }}>
                      • {typeof ev === 'object' ? JSON.stringify(ev) : ev}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="modal-footer" style={{ justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', gap: '8px' }}>
                {selectedAlert.status === 'OPEN' && (
                  <button 
                    className="btn btn-secondary" 
                    onClick={() => handleAcknowledge(selectedAlert.alert_id)}
                    disabled={actionLoading}
                  >
                    <Check size={14} />
                    <span>Acknowledge</span>
                  </button>
                )}
                {selectedAlert.status !== 'RESOLVED' && (
                  <button 
                    className="btn btn-success" 
                    onClick={() => handleResolve(selectedAlert.alert_id)}
                    disabled={actionLoading}
                  >
                    <CheckCircle size={14} />
                    <span>Mark Resolved</span>
                  </button>
                )}
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="btn btn-secondary" onClick={() => setSelectedAlert(null)}>
                  Close
                </button>
                <button 
                  className="btn btn-primary"
                  onClick={() => handlePromote(selectedAlert)}
                >
                  <LifeBuoy size={15} />
                  <span>Promote to Incident</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
