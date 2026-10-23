import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  FileText, 
  AlertTriangle, 
  LifeBuoy, 
  Activity, 
  RefreshCw, 
  Zap, 
  ExternalLink,
  CheckCircle2,
  Clock
} from 'lucide-react';
import { api } from '../api';

export default function DashboardView({ onNavigate }) {
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [topSources, setTopSources] = useState([]);
  const [eventTypes, setEventTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [detecting, setDetecting] = useState(false);
  const [detectResult, setDetectResult] = useState(null);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sumRes, timeRes, sourcesRes, typesRes] = await Promise.all([
        api.getDashboardSummary(),
        api.getEventsTimeline(12),
        api.getTopSources(5),
        api.getEventTypes(),
      ]);
      setSummary(sumRes);
      setTimeline(timeRes);
      setTopSources(sourcesRes);
      setEventTypes(typesRes);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunDetection = async () => {
    setDetecting(true);
    setDetectResult(null);
    try {
      const res = await api.runDetection({ limit: 2000 });
      setDetectResult(res);
      await fetchData();
    } catch (err) {
      alert(`Detection failed: ${err.message}`);
    } finally {
      setDetecting(false);
    }
  };

  const maxTimelineTotal = Math.max(...timeline.map(t => t.total), 1);
  const maxSourceTotal = Math.max(...topSources.map(s => s.total), 1);

  return (
    <div>
      {/* Header with Title and Action Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', color: '#fff' }}>Security Operations Center Dashboard</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '4px' }}>
            Central intelligence, live ingestion monitoring, automated alert correlation, and incident tracking.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button 
            className="btn btn-secondary" 
            onClick={fetchData} 
            disabled={loading}
          >
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button 
            className="btn btn-primary" 
            onClick={handleRunDetection}
            disabled={detecting}
          >
            <Zap size={15} />
            <span>{detecting ? 'Scanning Logs...' : 'Trigger Detection Pass'}</span>
          </button>
        </div>
      </div>

      {detectResult && (
        <div className="alert-banner banner-success" style={{ marginBottom: '20px' }}>
          <CheckCircle2 size={18} />
          <span>
            Detection pass complete: <strong>{detectResult.logs_scanned}</strong> events scanned across 
            <strong> {detectResult.rules_evaluated}</strong> rules. 
            Generated <strong>{detectResult.alerts_created}</strong> new alert(s), 
            updated <strong>{detectResult.alerts_updated}</strong> active alert(s).
          </span>
        </div>
      )}

      {error && (
        <div className="alert-banner banner-danger">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Primary KPI Stat Cards */}
      <div className="stat-grid">
        <div className="stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="stat-label">Total Ingested Logs</div>
              <div className="stat-value">{summary?.logs?.total?.toLocaleString() ?? 0}</div>
            </div>
            <FileText size={24} color="var(--cyan-glow)" />
          </div>
          <div style={{ marginTop: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            High: {summary?.logs?.by_severity?.HIGH ?? 0} | Crit: {summary?.logs?.by_severity?.CRITICAL ?? 0}
          </div>
        </div>

        <div className="stat-card stat-danger">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="stat-label">Security Alerts</div>
              <div className="stat-value" style={{ color: '#fda4af' }}>{summary?.alerts?.total ?? 0}</div>
            </div>
            <ShieldAlert size={24} color="var(--rose-danger)" />
          </div>
          <div style={{ marginTop: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <span style={{ color: 'var(--rose-danger)', fontWeight: 600 }}>{summary?.alerts?.open ?? 0} Open</span> | {summary?.alerts?.resolved ?? 0} Resolved
          </div>
        </div>

        <div className="stat-card stat-warning">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="stat-label">Member 3 Incidents</div>
              <div className="stat-value" style={{ color: '#fcd34d' }}>{summary?.incidents?.total ?? 0}</div>
            </div>
            <LifeBuoy size={24} color="var(--amber-warning)" />
          </div>
          <div style={{ marginTop: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <span style={{ color: 'var(--amber-warning)', fontWeight: 600 }}>{summary?.incidents?.open ?? 0} Active</span> | {summary?.incidents?.resolved ?? 0} Resolved
          </div>
        </div>

        <div className="stat-card stat-success">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="stat-label">Correlated Threats</div>
              <div className="stat-value" style={{ color: '#6ee7b7' }}>{summary?.threats?.total ?? 0}</div>
            </div>
            <Activity size={24} color="var(--emerald-success)" />
          </div>
          <div style={{ marginTop: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Persistent attacker host profiles
          </div>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid-2" style={{ marginBottom: '28px' }}>
        {/* Timeline Event Distribution Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <Activity size={18} color="var(--cyan-glow)" />
              <span>Event Volume Timeline (Hourly Buckets)</span>
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Recent Timeframe</span>
          </div>

          {timeline.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No time-series data available yet. Ingest logs to generate charts.
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', height: '180px', paddingTop: '20px' }}>
              {timeline.map((item, idx) => {
                const heightPct = Math.max((item.total / maxTimelineTotal) * 100, 6);
                return (
                  <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%' }}>
                    <div style={{ flex: 1, display: 'flex', alignItems: 'flex-end', width: '100%' }}>
                      <div 
                        title={`${item.time}: ${item.total} events (Crit: ${item.critical}, High: ${item.high})`}
                        style={{
                          width: '100%',
                          height: `${heightPct}%`,
                          borderRadius: '4px 4px 0 0',
                          background: item.critical > 0 
                            ? 'linear-gradient(180deg, var(--rose-danger), rgba(244, 63, 94, 0.4))'
                            : item.high > 0
                            ? 'linear-gradient(180deg, var(--amber-warning), rgba(245, 158, 11, 0.4))'
                            : 'linear-gradient(180deg, var(--cyan-primary), rgba(6, 182, 212, 0.3))',
                          transition: 'height 0.3s ease',
                          cursor: 'pointer',
                        }}
                      />
                    </div>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', marginTop: '8px', transform: 'rotate(-45deg)', whiteSpace: 'nowrap' }}>
                      {item.time.slice(11, 16)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Top Threat / Attack Source IPs */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <ShieldAlert size={18} color="var(--rose-danger)" />
              <span>Top Source IP Addresses (Event Ingestion)</span>
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Highest Activity</span>
          </div>

          {topSources.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No source IP logs recorded yet.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '8px' }}>
              {topSources.map((src, idx) => {
                const widthPct = Math.max((src.total / maxSourceTotal) * 100, 5);
                return (
                  <div key={idx}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '4px' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{src.source_ip}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{src.total.toLocaleString()} events</span>
                    </div>
                    <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${widthPct}%`,
                        height: '100%',
                        borderRadius: '4px',
                        background: src.critical > 0 
                          ? 'var(--rose-danger)' 
                          : src.high > 0 
                          ? 'var(--amber-warning)' 
                          : 'var(--cyan-primary)',
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Recent Alerts & Recent Incidents Section */}
      <div className="grid-2">
        {/* Recent Alerts Feed */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <AlertTriangle size={18} color="var(--amber-warning)" />
              <span>Recent Detection Alerts</span>
            </h3>
            <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('alerts')}>
              <span>View All</span>
              <ExternalLink size={12} />
            </button>
          </div>

          {summary?.alerts?.recent?.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No alerts currently triggered.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {summary?.alerts?.recent?.map((alert) => (
                <div 
                  key={alert.alert_id} 
                  style={{
                    padding: '12px 14px',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
                      <span className={`badge badge-${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                      <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{alert.title}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'flex', gap: '12px' }}>
                      <span>IP: <code style={{ color: 'var(--cyan-glow)' }}>{alert.source_ip || 'N/A'}</code></span>
                      <span>Rule: {alert.rule_name || 'Generic'}</span>
                    </div>
                  </div>
                  <span className={`badge badge-${alert.status.toLowerCase()}`}>{alert.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Member 3 Recent Incidents Feed */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <LifeBuoy size={18} color="var(--purple-accent)" />
              <span>Active Investigation Incidents</span>
            </h3>
            <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('incidents')}>
              <span>View All</span>
              <ExternalLink size={12} />
            </button>
          </div>

          {summary?.incidents?.recent?.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No incidents created yet. Promote an alert or create one directly!
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {summary?.incidents?.recent?.map((inc) => (
                <div 
                  key={inc.incident_id}
                  style={{
                    padding: '12px 14px',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
                      <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                      <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{inc.title}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'flex', gap: '12px' }}>
                      <span>Assigned: <strong style={{ color: 'var(--text-main)' }}>{inc.assigned_to_username || 'Unassigned'}</strong></span>
                      <span>IP: <code style={{ color: 'var(--cyan-glow)' }}>{inc.source_ip || 'N/A'}</code></span>
                    </div>
                  </div>
                  <span className={`badge badge-${inc.status.toLowerCase()}`}>{inc.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
