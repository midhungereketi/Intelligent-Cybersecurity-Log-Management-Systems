import React, { useState, useEffect, useMemo } from 'react';
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
  PieChart,
  Radio,
} from 'lucide-react';
import { api } from '../api';
import CountUp from './fx/CountUp';

const SEVERITY_COLORS = { CRITICAL: '#f43f5e', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#34d399' };

/** Smooth SVG path through points using Catmull-Rom → Bézier conversion. */
function smoothPath(points) {
  if (points.length < 2) return points.length ? `M${points[0][0]},${points[0][1]}` : '';
  let d = `M${points[0][0]},${points[0][1]}`;
  for (let i = 0; i < points.length - 1; i += 1) {
    const p0 = points[i - 1] || points[i];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x},${c1y} ${c2x},${c2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

function Sparkline({ values }) {
  const data = values.length > 1 ? values : [0, 0];
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => [(i / (data.length - 1)) * 96, 28 - (v / max) * 24]);
  const line = smoothPath(pts);
  return (
    <svg className="stat-spark" viewBox="0 0 96 30" aria-hidden="true">
      <path className="area" d={`${line} L96,30 L0,30 Z`} />
      <path className="line" d={line} />
    </svg>
  );
}

function StatCard({ tone, label, value, icon: Icon, foot, spark }) {
  return (
    <div className={`stat-card ${tone ? `stat-${tone}` : ''}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="stat-label">{label}</div>
          <div className="stat-value"><CountUp value={value} /></div>
        </div>
        <div className="stat-icon-wrap"><Icon size={20} /></div>
      </div>
      <div className="stat-foot">
        <span>{foot}</span>
        <Sparkline values={spark} />
      </div>
    </div>
  );
}

/** Radial gauge for the composite threat index (0-100). */
function ThreatGauge({ score }) {
  const level = score >= 60 ? { label: 'CRITICAL', color: '#f43f5e' }
    : score >= 30 ? { label: 'ELEVATED', color: '#fbbf24' }
    : { label: 'GUARDED', color: '#34d399' };
  const radius = 108;
  const arc = 2 * Math.PI * radius * 0.75; // 270° sweep
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const timer = setTimeout(() => setShown(score), 120);
    return () => clearTimeout(timer);
  }, [score]);

  return (
    <div className="gauge" style={{ '--gauge-color': level.color }}>
      <svg viewBox="0 0 260 260">
        <defs>
          <linearGradient id="gauge-grad" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="55%" stopColor="#818cf8" />
            <stop offset="100%" stopColor={level.color} />
          </linearGradient>
        </defs>
        <circle className="gauge-orbit" cx="130" cy="130" r="126" />
        <g className="gauge-ticks">
          {Array.from({ length: 28 }, (_, i) => {
            const angle = (135 + (i / 27) * 270) * (Math.PI / 180);
            return (
              <line key={i} x1={130 + Math.cos(angle) * 92} y1={130 + Math.sin(angle) * 92}
                x2={130 + Math.cos(angle) * (i % 3 === 0 ? 84 : 88)} y2={130 + Math.sin(angle) * (i % 3 === 0 ? 84 : 88)} />
            );
          })}
        </g>
        <circle className="gauge-track" cx="130" cy="130" r={radius}
          strokeDasharray={`${arc} ${2 * Math.PI * radius}`} transform="rotate(135 130 130)" />
        <circle className="gauge-value" cx="130" cy="130" r={radius} stroke="url(#gauge-grad)"
          strokeDasharray={`${arc} ${2 * Math.PI * radius}`} strokeDashoffset={arc * (1 - shown / 100)}
          transform="rotate(135 130 130)" />
      </svg>
      <div className="gauge-center">
        <small>THREAT INDEX</small>
        <strong><CountUp value={score} duration={1800} /></strong>
        <span>{level.label}</span>
      </div>
    </div>
  );
}

function TimelineChart({ data }) {
  const [hover, setHover] = useState(null);
  const W = 640;
  const H = 230;
  const pad = { l: 34, r: 12, t: 16, b: 28 };
  const max = Math.max(...data.map((d) => d.total), 1);
  const step = data.length > 1 ? (W - pad.l - pad.r) / (data.length - 1) : 0;
  const x = (i) => pad.l + i * step;
  const y = (v) => H - pad.b - (v / max) * (H - pad.t - pad.b);
  const pts = data.map((d, i) => [x(i), y(d.total)]);
  const line = smoothPath(pts);
  const barW = Math.max(Math.min(step * 0.42, 22), 4);

  return (
    <div className="chart-area" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Hourly event volume">
        <defs>
          <linearGradient id="line-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="60%" stopColor="#818cf8" />
            <stop offset="100%" stopColor="#ec4899" />
          </linearGradient>
          <linearGradient id="area-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(34,211,238,.35)" />
            <stop offset="100%" stopColor="rgba(139,92,246,0)" />
          </linearGradient>
          <linearGradient id="bar-hot" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(244,63,94,.75)" />
            <stop offset="100%" stopColor="rgba(244,63,94,.05)" />
          </linearGradient>
        </defs>
        <g className="chart-grid">
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <g key={f}>
              <line x1={pad.l} x2={W - pad.r} y1={y(max * f)} y2={y(max * f)} />
              <text className="chart-label" x={pad.l - 8} y={y(max * f) + 3} textAnchor="end">{Math.round(max * f)}</text>
            </g>
          ))}
        </g>
        {data.map((d, i) => {
          const hot = d.critical + d.high;
          if (!hot) return null;
          return (
            <rect key={`b${d.time}`} className="chart-bar" x={x(i) - barW / 2} y={y(hot)} width={barW}
              height={H - pad.b - y(hot)} rx="3" fill="url(#bar-hot)" style={{ animationDelay: `${0.4 + i * 0.05}s` }} />
          );
        })}
        <path className="chart-fill" d={`${line} L${x(data.length - 1)},${H - pad.b} L${x(0)},${H - pad.b} Z`} />
        <path className="chart-line" d={line} />
        {hover !== null && (
          <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={H - pad.b} stroke="rgba(103,232,249,.5)" strokeDasharray="3 4" />
        )}
        {data.map((d, i) => (
          <circle key={`d${d.time}`} className={`chart-dot ${d.critical ? 'hot' : ''}`} cx={x(i)} cy={y(d.total)}
            r={hover === i ? 6 : 3.5} style={{ animationDelay: `${1 + i * 0.05}s` }} />
        ))}
        {data.map((d, i) => (
          <rect key={`h${d.time}`} className="chart-hit" x={x(i) - step / 2} y={0} width={Math.max(step, 20)} height={H}
            onMouseEnter={() => setHover(i)} />
        ))}
        {data.map((d, i) => (i % Math.ceil(data.length / 8) === 0 || i === data.length - 1) && (
          <text key={`t${d.time}`} className="chart-label" x={x(i)} y={H - 8} textAnchor="middle">{d.time.slice(11, 16)}</text>
        ))}
      </svg>
      {hover !== null && data[hover] && (
        <div className="chart-tooltip" style={{ left: `${(x(hover) / W) * 100}%`, top: `${(y(data[hover].total) / H) * 100}%` }}>
          <strong>{data[hover].total.toLocaleString()} events</strong>
          <span>{data[hover].time.slice(0, 10)} · {data[hover].time.slice(11, 16)} UTC</span><br />
          <span style={{ color: SEVERITY_COLORS.CRITICAL }}>● {data[hover].critical} crit</span>{' '}
          <span style={{ color: SEVERITY_COLORS.HIGH }}>● {data[hover].high} high</span>
        </div>
      )}
    </div>
  );
}

function SeverityDonut({ bySeverity }) {
  const [focus, setFocus] = useState(null);
  const entries = Object.keys(SEVERITY_COLORS).map((k) => [k, bySeverity?.[k] ?? 0]);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  const r = 70;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const shown = focus ? entries.find(([k]) => k === focus) : null;

  return (
    <div className="donut">
      <div className="donut-wrap">
        <svg viewBox="0 0 170 170">
          <circle cx="85" cy="85" r={r} fill="none" stroke="rgba(148,163,255,.08)" strokeWidth="18" />
          {total > 0 && entries.map(([key, value]) => {
            const len = (value / total) * c;
            const seg = (
              <circle key={key} className="donut-seg" cx="85" cy="85" r={r} stroke={SEVERITY_COLORS[key]}
                strokeDasharray={`${Math.max(len - 3, 0)} ${c}`} strokeDashoffset={-offset}
                style={{ filter: `drop-shadow(0 0 6px ${SEVERITY_COLORS[key]})`, opacity: focus && focus !== key ? 0.3 : 1 }}
                onMouseEnter={() => setFocus(key)} onMouseLeave={() => setFocus(null)} />
            );
            offset += len;
            return seg;
          })}
        </svg>
        <div className="donut-center">
          <strong><CountUp value={shown ? shown[1] : total} duration={600} /></strong>
          <small>{shown ? shown[0] : 'TOTAL EVENTS'}</small>
        </div>
      </div>
      <div className="legend">
        {entries.map(([key, value]) => (
          <div key={key} className="legend-row" onMouseEnter={() => setFocus(key)} onMouseLeave={() => setFocus(null)}>
            <i style={{ background: SEVERITY_COLORS[key], color: SEVERITY_COLORS[key] }} />
            <span>{key.charAt(0) + key.slice(1).toLowerCase()}</span>
            <b>{total ? `${((value / total) * 100).toFixed(1)}%` : '0%'}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyState({ children }) {
  return <div className="empty-state"><div className="radar-mini" />{children}</div>;
}

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
        api.getEventsTimeline(24),
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

  // Composite 0-100 index: open alerts, active incidents and the share of critical/high events.
  const threatScore = useMemo(() => {
    if (!summary) return 0;
    const logsTotal = summary.logs?.total || 0;
    const hot = (summary.logs?.by_severity?.CRITICAL || 0) + (summary.logs?.by_severity?.HIGH || 0);
    const hotShare = logsTotal ? hot / logsTotal : 0;
    const raw = (summary.alerts?.open || 0) * 12 + (summary.incidents?.open || 0) * 8 + hotShare * 40;
    return Math.min(100, Math.round(raw));
  }, [summary]);

  const spark = (key) => timeline.map((t) => t[key] ?? 0);
  const maxSourceTotal = Math.max(...topSources.map((s) => s.total), 1);
  const topEventType = eventTypes[0];

  return (
    <div>
      <section className="hero-panel">
        <div className="hero-copy">
          <div className="hero-eyebrow"><span className="signal-pulse" /> COMMAND CENTER · LIVE</div>
          <h1 className="hero-title">Your security <span className="gradient-text">overview</span></h1>
          <p className="hero-sub">Your live picture of logs, detections and active investigations — streamed from MongoDB telemetry and PostgreSQL case records.</p>
          <div className="hero-actions">
            <button className="btn btn-primary" onClick={handleRunDetection} disabled={detecting}>
              <Zap size={15} className={detecting ? 'animate-spin' : ''} />
              <span>{detecting ? 'Scanning Logs...' : 'Trigger Detection Pass'}</span>
            </button>
            <button className="btn btn-secondary" onClick={fetchData} disabled={loading}>
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>
          <div className="hero-meta">
            <div><small>Events indexed</small><strong><CountUp value={summary?.logs?.total} /></strong></div>
            <div><small>Top event type</small><strong>{topEventType?.event_type || '—'}</strong></div>
            <div><small>Hottest source</small><strong style={{ fontFamily: 'var(--font-mono)', fontSize: '.95rem' }}>{topSources[0]?.source_ip || '—'}</strong></div>
            <div><small>Resolved alerts</small><strong><CountUp value={summary?.alerts?.resolved} /></strong></div>
          </div>
        </div>
        <div className="hero-gauge">
          <ThreatGauge score={threatScore} />
        </div>
      </section>

      {detectResult && (
        <div className="alert-banner banner-success">
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

      <div className="stat-grid">
        <StatCard label="Total Ingested Logs" value={summary?.logs?.total} icon={FileText} spark={spark('total')}
          foot={`High ${summary?.logs?.by_severity?.HIGH ?? 0} · Crit ${summary?.logs?.by_severity?.CRITICAL ?? 0}`} />
        <StatCard tone="danger" label="Security Alerts" value={summary?.alerts?.total} icon={ShieldAlert} spark={spark('critical')}
          foot={<><span style={{ color: 'var(--rose-danger)', fontWeight: 600 }}>{summary?.alerts?.open ?? 0} open</span> · {summary?.alerts?.resolved ?? 0} resolved</>} />
        <StatCard tone="warning" label="Incidents" value={summary?.incidents?.total} icon={LifeBuoy} spark={spark('high')}
          foot={<><span style={{ color: 'var(--amber-warning)', fontWeight: 600 }}>{summary?.incidents?.open ?? 0} active</span> · {summary?.incidents?.resolved ?? 0} resolved</>} />
        <StatCard tone="success" label="Correlated Threats" value={summary?.threats?.total} icon={Activity} spark={spark('low')}
          foot="Persistent attacker profiles" />
      </div>

      <div className="dash-grid">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title"><Activity size={18} /><span>Event Volume Timeline</span></h3>
            <span className="card-kicker">Hourly · last {timeline.length || 0} buckets</span>
          </div>
          {timeline.length === 0
            ? <EmptyState>No time-series data available yet. Ingest logs to generate charts.</EmptyState>
            : <TimelineChart data={timeline} />}
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title"><PieChart size={18} /><span>Severity Mix</span></h3>
            <span className="card-kicker">All logs</span>
          </div>
          <SeverityDonut bySeverity={summary?.logs?.by_severity} />
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: '18px' }}>
        <div className="card">
          <div className="card-header">
            <h3 className="card-title"><Radio size={18} /><span>Top Source IP Addresses</span></h3>
            <span className="card-kicker">Highest activity</span>
          </div>
          {topSources.length === 0 ? (
            <EmptyState>No source IP logs recorded yet.</EmptyState>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '4px' }}>
              {topSources.map((src, idx) => {
                const color = src.critical > 0 ? 'var(--rose-danger)' : src.high > 0 ? 'var(--amber-warning)' : 'var(--cyan-primary)';
                return (
                  <div key={src.source_ip} className="source-row">
                    <div className="source-row-top">
                      <span style={{ display: 'flex', alignItems: 'center' }}>
                        <span className="source-rank">{String(idx + 1).padStart(2, '0')}</span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{src.source_ip}</span>
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '.78rem' }}>{src.total.toLocaleString()} events</span>
                    </div>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${Math.max((src.total / maxSourceTotal) * 100, 5)}%`, background: color, color, animationDelay: `${0.2 + idx * 0.12}s` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title"><FileText size={18} /><span>Event Type Distribution</span></h3>
            <span className="card-kicker">{eventTypes.length} types</span>
          </div>
          {eventTypes.length === 0 ? (
            <EmptyState>No events ingested yet.</EmptyState>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '4px' }}>
              {eventTypes.slice(0, 6).map((et, idx) => {
                const max = eventTypes[0].count || 1;
                const hues = ['#22d3ee', '#818cf8', '#a78bfa', '#ec4899', '#34d399', '#fbbf24'];
                return (
                  <div key={et.event_type} className="source-row">
                    <div className="source-row-top">
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '.78rem' }}>{et.event_type}</span>
                      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '.78rem' }}>{et.count.toLocaleString()}</span>
                    </div>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${Math.max((et.count / max) * 100, 4)}%`, background: hues[idx], color: hues[idx], animationDelay: `${0.25 + idx * 0.1}s` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title"><AlertTriangle size={18} /><span>Recent Detection Alerts</span></h3>
            <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('alerts')}>
              <span>View All</span>
              <ExternalLink size={12} />
            </button>
          </div>
          {!summary?.alerts?.recent?.length ? (
            <EmptyState>No alerts currently triggered.</EmptyState>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {summary.alerts.recent.map((alert, idx) => (
                <div key={alert.alert_id} className="feed-item"
                  style={{ '--feed-c': SEVERITY_COLORS[alert.severity], animationDelay: `${0.1 + idx * 0.07}s` }}>
                  <div style={{ paddingLeft: '8px', minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' }}>
                      <span className={`badge badge-${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                      <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{alert.title}</span>
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                      <span>IP <code style={{ color: 'var(--cyan-glow)' }}>{alert.source_ip || 'N/A'}</code></span>
                      <span>Rule · {alert.rule_name || 'Generic'}</span>
                    </div>
                  </div>
                  <span className={`badge badge-${alert.status.toLowerCase()}`}>{alert.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title"><LifeBuoy size={18} /><span>Active Investigation Incidents</span></h3>
            <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('incidents')}>
              <span>View All</span>
              <ExternalLink size={12} />
            </button>
          </div>
          {!summary?.incidents?.recent?.length ? (
            <EmptyState>No incidents created yet. Promote an alert or create one directly!</EmptyState>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {summary.incidents.recent.map((inc, idx) => (
                <div key={inc.incident_id} className="feed-item"
                  style={{ '--feed-c': SEVERITY_COLORS[inc.severity], animationDelay: `${0.1 + idx * 0.07}s` }}>
                  <div style={{ paddingLeft: '8px', minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' }}>
                      <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                      <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{inc.title}</span>
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                      <span>Assigned · <strong style={{ color: 'var(--text-main)' }}>{inc.assigned_to_username || 'Unassigned'}</strong></span>
                      <span>IP <code style={{ color: 'var(--cyan-glow)' }}>{inc.source_ip || 'N/A'}</code></span>
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
