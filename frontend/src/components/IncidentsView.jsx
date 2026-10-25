import React, { useState, useEffect } from 'react';
import { 
  LifeBuoy, 
  Plus, 
  Filter, 
  User, 
  Calendar, 
  ShieldAlert, 
  CheckCircle, 
  Clock, 
  ArrowRight, 
  X, 
  Tag, 
  FileText, 
  AlertTriangle,
  Lock,
  ChevronRight,
  ShieldCheck,
  Activity,
  Send
} from 'lucide-react';
import { api } from '../api';

export default function IncidentsView({ prefillAlert, onClearPrefill }) {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filter state
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  // Active Incident Selection for Detail/Investigation view
  const [activeIncidentId, setActiveIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Create Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newIncident, setNewIncident] = useState({
    title: '',
    description: '',
    severity: 'HIGH',
    status: 'OPEN',
    assigned_to: '',
    alert_id: '',
    source_ip: '',
    tags: '',
  });

  // Action Logging form state inside Incident Detail
  const [actionForm, setActionForm] = useState({
    action_type: 'INVESTIGATION_STEP',
    action_details: '',
  });
  const [submittingAction, setSubmittingAction] = useState(false);

  // Available users for assignment
  const [users, setUsers] = useState([]);

  // Fetch users for assignment dropdowns.
  // Uses /api/users/assignable which is accessible to both ADMIN and ANALYST.
  // Returns only user_id and username — no sensitive fields are exposed.
  const fetchUsers = async () => {
    try {
      const res = await api.listAssignableUsers();
      setUsers(res || []);
    } catch {
      // Non-critical: assignee dropdown will be empty if this fails
    }
  };

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      const res = await api.listIncidents(params);
      setIncidents(res.items || []);
      setTotal(res.total || 0);

      // If active incident is selected, refresh its details too
      if (activeIncidentId) {
        fetchIncidentDetail(activeIncidentId);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch incidents');
    } finally {
      setLoading(false);
    }
  };

  const fetchIncidentDetail = async (id) => {
    setDetailLoading(true);
    try {
      const data = await api.getIncident(id);
      setIncidentDetail(data);
      setActiveIncidentId(id);
    } catch (err) {
      alert(`Failed to load incident detail: ${err.message}`);
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
    fetchIncidents();
  }, [statusFilter, severityFilter]);

  // Handle escalation prefill from AlertsView
  useEffect(() => {
    if (prefillAlert) {
      setNewIncident({
        title: `Incident: ${prefillAlert.title}`,
        description: `Escalated from Alert #${prefillAlert.alert_id} triggered by rule '${prefillAlert.rule_name || 'Detection'}'. Occurrence count: ${prefillAlert.occurrence_count}.`,
        severity: prefillAlert.severity,
        status: 'OPEN',
        assigned_to: '',
        alert_id: prefillAlert.alert_id,
        source_ip: prefillAlert.source_ip || '',
        tags: 'automated-detection, escalated-alert',
      });
      setShowCreateModal(true);
      onClearPrefill();
    }
  }, [prefillAlert]);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    try {
      const tagsArray = newIncident.tags
        ? newIncident.tags.split(',').map(t => t.trim()).filter(Boolean)
        : [];

      const payload = {
        title: newIncident.title,
        description: newIncident.description,
        severity: newIncident.severity,
        status: newIncident.status,
        source_ip: newIncident.source_ip || null,
        assigned_to: newIncident.assigned_to ? parseInt(newIncident.assigned_to, 10) : null,
        alert_id: newIncident.alert_id ? parseInt(newIncident.alert_id, 10) : null,
        tags: tagsArray,
      };

      const created = await api.createIncident(payload);
      setShowCreateModal(false);
      setNewIncident({
        title: '',
        description: '',
        severity: 'HIGH',
        status: 'OPEN',
        assigned_to: '',
        alert_id: '',
        source_ip: '',
        tags: '',
      });
      await fetchIncidents();
      fetchIncidentDetail(created.incident_id);
    } catch (err) {
      alert(`Failed to create incident: ${err.message}`);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (!incidentDetail) return;
    try {
      const updated = await api.updateIncident(incidentDetail.incident_id, { status: newStatus });
      setIncidentDetail(updated);
      fetchIncidents();
    } catch (err) {
      alert(`Status update failed: ${err.message}`);
    }
  };

  const handleAssigneeChange = async (userId) => {
    if (!incidentDetail) return;
    try {
      const updated = await api.updateIncident(incidentDetail.incident_id, { 
        assigned_to: userId ? parseInt(userId, 10) : null 
      });
      setIncidentDetail(updated);
      fetchIncidents();
    } catch (err) {
      alert(`Assignment failed: ${err.message}`);
    }
  };

  const handleAddAction = async (e) => {
    e.preventDefault();
    if (!actionForm.action_details.trim() || !incidentDetail) return;

    setSubmittingAction(true);
    try {
      await api.addIncidentAction(incidentDetail.incident_id, actionForm);
      setActionForm({ action_type: 'INVESTIGATION_STEP', action_details: '' });
      // Refresh details to see new timeline item
      await fetchIncidentDetail(incidentDetail.incident_id);
    } catch (err) {
      alert(`Failed to log action: ${err.message}`);
    } finally {
      setSubmittingAction(false);
    }
  };

  const getActionDotClass = (type) => {
    switch (type) {
      case 'CONTAINMENT':
      case 'REMEDIATION':
        return 'dot-danger';
      case 'STATUS_CHANGE':
        return 'dot-warning';
      case 'INVESTIGATION_STEP':
        return 'dot-success';
      default:
        return '';
    }
  };

  return (
    <div>
      {/* Header */}
      <div className="view-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', color: 'var(--text-main)' }}>
            Investigations
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '4px' }}>
            Incident triage, team assignment, forensic investigation notes, and containment action timeline.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
          <Plus size={16} />
          <span>New Incident</span>
        </button>
      </div>

      {error && (
        <div className="alert-banner banner-danger">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Main Split Grid: Left = Incident List, Right = Incident Investigation Workspace */}
      <div style={{ display: 'grid', gridTemplateColumns: activeIncidentId ? '1fr 1.35fr' : '1fr', gap: '24px' }}>
        {/* Left Column: List & Filter */}
        <div>
          {/* Filter Bar */}
          <div className="card" style={{ marginBottom: '16px', padding: '14px 18px' }}>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="form-label" style={{ marginBottom: 0, fontSize: '0.75rem' }}>Status:</span>
                <select
                  className="form-control"
                  style={{ width: '140px', padding: '6px 10px' }}
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <option value="">All Statuses</option>
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="form-label" style={{ marginBottom: 0, fontSize: '0.75rem' }}>Severity:</span>
                <select
                  className="form-control"
                  style={{ width: '130px', padding: '6px 10px' }}
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

          {/* Incidents Table / Cards */}
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Assignee</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                      Loading incidents...
                    </td>
                  </tr>
                ) : incidents.length === 0 ? (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                      No incidents found. Click "New Incident" to open one.
                    </td>
                  </tr>
                ) : (
                  incidents.map((inc) => {
                    const isSelected = inc.incident_id === activeIncidentId;
                    return (
                      <tr 
                        key={inc.incident_id}
                        onClick={() => fetchIncidentDetail(inc.incident_id)}
                        style={{
                          cursor: 'pointer',
                          background: isSelected ? 'rgba(6, 182, 212, 0.08)' : undefined,
                        }}
                      >
                        <td>
                          <div style={{ fontWeight: 600, color: isSelected ? 'var(--cyan-glow)' : 'var(--text-main)' }}>
                            #{inc.incident_id}: {inc.title}
                          </div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                            {inc.source_ip ? `IP: ${inc.source_ip}` : 'No IP attached'} • {inc.created_at?.slice(0, 10)}
                          </div>
                        </td>
                        <td>
                          <span className={`badge badge-${inc.severity.toLowerCase()}`}>
                            {inc.severity}
                          </span>
                        </td>
                        <td>
                          <span className={`badge badge-${inc.status.toLowerCase()}`}>
                            {inc.status}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.85rem', color: inc.assigned_to_username ? 'var(--text-main)' : 'var(--text-dim)' }}>
                            {inc.assigned_to_username || 'Unassigned'}
                          </span>
                        </td>
                        <td>
                          <ChevronRight size={16} color={isSelected ? 'var(--cyan-glow)' : 'var(--text-dim)'} />
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Detailed Investigation Studio */}
        {activeIncidentId && incidentDetail && (
          <div className="card" style={{ height: 'fit-content' }}>
            {/* Incident Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', paddingBottom: '16px', borderBottom: '1px solid var(--border-subtle)', marginBottom: '18px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <span className={`badge badge-${incidentDetail.severity.toLowerCase()}`}>{incidentDetail.severity}</span>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>Incident #{incidentDetail.incident_id}</span>
                </div>
                <h2 style={{ fontSize: '1.25rem', color: 'var(--text-main)' }}>{incidentDetail.title}</h2>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setActiveIncidentId(null)}>
                <X size={15} />
              </button>
            </div>

            {/* Quick Controls: Status & Assignment */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', marginBottom: '20px', background: 'rgba(255,255,255,0.02)', padding: '14px', borderRadius: 'var(--radius-sm)' }}>
              <div>
                <label className="form-label" style={{ fontSize: '0.7rem' }}>Incident Status</label>
                <select
                  className="form-control"
                  value={incidentDetail.status}
                  onChange={(e) => handleStatusChange(e.target.value)}
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.7rem' }}>Assigned Analyst</label>
                <select
                  className="form-control"
                  value={incidentDetail.assigned_to || ''}
                  onChange={(e) => handleAssigneeChange(e.target.value)}
                >
                  <option value="">Unassigned</option>
                  {users.map(u => (
                    <option key={u.user_id} value={u.user_id}>
                      {u.username} ({u.role_name})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Incident Description & Metadata */}
            <div style={{ marginBottom: '20px' }}>
              <label className="form-label">Description & Scope</label>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                {incidentDetail.description || 'No description entered.'}
              </p>
              
              <div style={{ display: 'flex', gap: '16px', marginTop: '12px', fontSize: '0.8rem', color: 'var(--text-dim)', flexWrap: 'wrap' }}>
                <span>Source IP: <code style={{ color: 'var(--cyan-glow)' }}>{incidentDetail.source_ip || 'None'}</code></span>
                <span>Created by: <strong style={{ color: 'var(--text-main)' }}>{incidentDetail.created_by_username || 'System'}</strong></span>
                <span>Reported: {incidentDetail.created_at?.slice(0, 19).replace('T', ' ')}</span>
              </div>

              {incidentDetail.tags?.length > 0 && (
                <div style={{ display: 'flex', gap: '6px', marginTop: '10px', flexWrap: 'wrap' }}>
                  {incidentDetail.tags.map((t, idx) => (
                    <span key={idx} className="tag-chip">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Linked Alerts Section */}
            {incidentDetail.alerts?.length > 0 && (
              <div style={{ marginBottom: '24px' }}>
                <label className="form-label">Correlated Security Alerts ({incidentDetail.alerts.length})</label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {incidentDetail.alerts.map((al) => (
                    <div 
                      key={al.alert_id} 
                      style={{
                        padding: '10px 12px',
                        background: 'rgba(244, 63, 94, 0.05)',
                        border: '1px solid rgba(244, 63, 94, 0.2)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>#{al.alert_id}: {al.title}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Rule: {al.rule_name || 'Generic'}</div>
                      </div>
                      <span className={`badge badge-${al.severity.toLowerCase()}`}>{al.severity}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Add Action Form */}
            <div style={{ marginBottom: '24px', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
              <label className="form-label" style={{ color: 'var(--cyan-glow)' }}>
                Record Response Action / Investigation Note
              </label>
              <form onSubmit={handleAddAction}>
                <div style={{ marginBottom: '12px' }}>
                  <select
                    className="form-control"
                    value={actionForm.action_type}
                    onChange={(e) => setActionForm({ ...actionForm, action_type: e.target.value })}
                  >
                    <option value="INVESTIGATION_STEP">INVESTIGATION_STEP - Triage Analysis Finding</option>
                    <option value="CONTAINMENT">CONTAINMENT - Host Isolation / Rule Blocking</option>
                    <option value="REMEDIATION">REMEDIATION - Credential Reset / Patch</option>
                    <option value="NOTE">NOTE - General Analyst Observation</option>
                    <option value="OTHER">OTHER - Miscellaneous Action</option>
                  </select>
                </div>
                <div style={{ marginBottom: '12px' }}>
                  <textarea
                    className="form-control"
                    rows="2"
                    placeholder="Describe forensic finding, containment step executed, or response action..."
                    value={actionForm.action_details}
                    onChange={(e) => setActionForm({ ...actionForm, action_details: e.target.value })}
                    required
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button type="submit" className="btn btn-primary btn-sm" disabled={submittingAction}>
                    <Send size={14} />
                    <span>{submittingAction ? 'Logging...' : 'Log Response Action'}</span>
                  </button>
                </div>
              </form>
            </div>

            {/* Response Action History Timeline */}
            <div>
              <label className="form-label">Response Action Timeline</label>
              <div className="timeline">
                {incidentDetail.actions?.length === 0 ? (
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No actions recorded yet.</div>
                ) : (
                  incidentDetail.actions?.map((act) => (
                    <div key={act.action_id} className={`timeline-item ${getActionDotClass(act.action_type)}`}>
                      <div className="timeline-dot">
                        <Activity size={16} />
                      </div>
                      <div className="timeline-content">
                        <div className="timeline-meta">
                          <span className={`badge badge-${act.action_type === 'CONTAINMENT' ? 'critical' : 'open'}`} style={{ fontSize: '0.65rem' }}>
                            {act.action_type}
                          </span>
                          <span>{act.performed_at?.slice(0, 19).replace('T', ' ')}</span>
                        </div>
                        <p style={{ fontSize: '0.875rem', color: 'var(--text-main)', marginTop: '4px' }}>
                          {act.action_details}
                        </p>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                          By: <strong style={{ color: 'var(--text-muted)' }}>{act.performed_by_username || 'System User'}</strong>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* New Incident Creation Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">
                <LifeBuoy size={18} color="var(--purple-accent)" />
                <span>Create Cybersecurity Incident</span>
              </h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowCreateModal(false)}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit}>
              <div className="form-group">
                <label className="form-label">Incident Title</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="e.g. Unauthorized Credential Stuffing Campaign"
                  value={newIncident.title}
                  onChange={(e) => setNewIncident({ ...newIncident, title: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Description & Context</label>
                <textarea
                  className="form-control"
                  rows="3"
                  placeholder="Details of the suspicious activity or threat pattern..."
                  value={newIncident.description}
                  onChange={(e) => setNewIncident({ ...newIncident, description: e.target.value })}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Severity</label>
                  <select
                    className="form-control"
                    value={newIncident.severity}
                    onChange={(e) => setNewIncident({ ...newIncident, severity: e.target.value })}
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Initial Status</label>
                  <select
                    className="form-control"
                    value={newIncident.status}
                    onChange={(e) => setNewIncident({ ...newIncident, status: e.target.value })}
                  >
                    <option value="OPEN">OPEN</option>
                    <option value="INVESTIGATING">INVESTIGATING</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Affected Source IP</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="e.g. 198.51.100.10"
                    value={newIncident.source_ip}
                    onChange={(e) => setNewIncident({ ...newIncident, source_ip: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Assign To</label>
                  <select
                    className="form-control"
                    value={newIncident.assigned_to}
                    onChange={(e) => setNewIncident({ ...newIncident, assigned_to: e.target.value })}
                  >
                    <option value="">Unassigned</option>
                    {users.map(u => (
                      <option key={u.user_id} value={u.user_id}>
                        {u.username} ({u.role_name})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Tags (Comma-separated)</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="ssh, lateral-movement, brute-force"
                  value={newIncident.tags}
                  onChange={(e) => setNewIncident({ ...newIncident, tags: e.target.value })}
                />
              </div>

              {newIncident.alert_id && (
                <div style={{ fontSize: '0.8rem', color: 'var(--cyan-glow)', marginBottom: '16px' }}>
                  Linked to Originating Alert #{newIncident.alert_id}
                </div>
              )}

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Create Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
