import React, { useState, useEffect } from 'react';
import {
  Users,
  Sliders,
  Server,
  HardDrive,
  Plus,
  X,
  AlertTriangle,
  Edit2,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api';

export default function AdminView() {
  const [activeTab, setActiveTab] = useState('users'); // 'users' | 'rules' | 'devices' | 'sources'
  
  // Data states
  const [users, setUsers] = useState([]);
  const [rules, setRules] = useState([]);
  const [devices, setDevices] = useState([]);
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Modals
  const [showUserModal, setShowUserModal] = useState(false);
  const [newUser, setNewUser] = useState({
    username: '',
    email: '',
    password: '',
    role_id: 2, // ANALYST default
  });

  const [showDeviceModal, setShowDeviceModal] = useState(false);
  const [newDevice, setNewDevice] = useState({
    device_name: '',
    ip_address: '',
    mac_address: '',
    device_type: 'FIREWALL',
    operating_system: 'Linux',
    location: 'Datacenter A',
    status: 'ACTIVE',
  });

  const [showSourceModal, setShowSourceModal] = useState(false);
  const [newSource, setNewSource] = useState({
    source_name: '',
    source_type: 'SYSLOG',
    ip_address: '',
    protocol: 'UDP',
    device_id: '',
  });

  const [editRule, setEditRule] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      if (activeTab === 'users') {
        const u = await api.listUsers();
        setUsers(u || []);
      } else if (activeTab === 'rules') {
        const r = await api.listRules();
        setRules(r || []);
      } else if (activeTab === 'devices') {
        const d = await api.listDevices();
        setDevices(d || []);
      } else if (activeTab === 'sources') {
        const [s, d] = await Promise.all([api.listSources(), api.listDevices()]);
        setSources(s || []);
        setDevices(d || []);
      }
    } catch (err) {
      setError(err.message || 'Failed to load administrative data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeTab]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      await api.createUser({
        ...newUser,
        role_id: parseInt(newUser.role_id, 10),
      });
      setShowUserModal(false);
      setNewUser({ username: '', email: '', password: '', role_id: 2 });
      fetchData();
    } catch (err) {
      alert(`Create user failed: ${err.message}`);
    }
  };

  const handleToggleUserActive = async (user) => {
    try {
      await api.updateUser(user.user_id, { is_active: !user.is_active });
      fetchData();
    } catch (err) {
      alert(`User status update failed: ${err.message}`);
    }
  };

  const handleCreateDevice = async (e) => {
    e.preventDefault();
    try {
      await api.createDevice(newDevice);
      setShowDeviceModal(false);
      setNewDevice({
        device_name: '',
        ip_address: '',
        mac_address: '',
        device_type: 'FIREWALL',
        operating_system: 'Linux',
        location: 'Datacenter A',
        status: 'ACTIVE',
      });
      fetchData();
    } catch (err) {
      alert(`Device registration failed: ${err.message}`);
    }
  };

  const handleCreateSource = async (e) => {
    e.preventDefault();
    try {
      await api.createSource({
        ...newSource,
        device_id: parseInt(newSource.device_id, 10),
      });
      setShowSourceModal(false);
      setNewSource({
        source_name: '',
        source_type: 'SYSLOG',
        ip_address: '',
        protocol: 'UDP',
        device_id: '',
      });
      fetchData();
    } catch (err) {
      alert(`Log source registration failed: ${err.message}`);
    }
  };

  const handleUpdateRule = async (e) => {
    e.preventDefault();
    if (!editRule) return;
    try {
      await api.updateRule(editRule.rule_id, {
        threshold: parseInt(editRule.threshold, 10),
        time_window_seconds: parseInt(editRule.time_window_seconds, 10),
        severity: editRule.severity,
        is_enabled: editRule.is_enabled,
      });
      setEditRule(null);
      fetchData();
    } catch (err) {
      alert(`Rule update failed: ${err.message}`);
    }
  };

  return (
    <div>
      <div className="view-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', color: 'var(--text-main)' }}>Administration</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '4px' }}>
            Manage team access, detection rules, devices and log sources.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={fetchData} disabled={loading}>
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="alert-banner banner-danger">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="tabs">
        <button className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`} onClick={() => setActiveTab('users')}>
          <Users size={16} />
          <span>Users & RBAC</span>
        </button>
        <button className={`tab-btn ${activeTab === 'rules' ? 'active' : ''}`} onClick={() => setActiveTab('rules')}>
          <Sliders size={16} />
          <span>Detection Rules</span>
        </button>
        <button className={`tab-btn ${activeTab === 'devices' ? 'active' : ''}`} onClick={() => setActiveTab('devices')}>
          <Server size={16} />
          <span>Devices</span>
        </button>
        <button className={`tab-btn ${activeTab === 'sources' ? 'active' : ''}`} onClick={() => setActiveTab('sources')}>
          <HardDrive size={16} />
          <span>Log Sources</span>
        </button>
      </div>

      {/* Tab 1: Users */}
      {activeTab === 'users' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '16px' }}>
            <button className="btn btn-primary" onClick={() => setShowUserModal(true)}>
              <Plus size={16} />
              <span>Register New User</span>
            </button>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>User ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.user_id}>
                    <td>#{u.user_id}</td>
                    <td style={{ fontWeight: 600 }}>{u.username}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{u.email}</td>
                    <td>
                      <span className={`badge ${u.role_name === 'ADMIN' ? 'badge-critical' : 'badge-open'}`}>
                        {u.role_name}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${u.is_active ? 'badge-low' : 'badge-closed'}`}>
                        {u.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td>
                      <button 
                        className={`btn btn-sm ${u.is_active ? 'btn-danger' : 'btn-success'}`}
                        onClick={() => handleToggleUserActive(u)}
                      >
                        {u.is_active ? 'Disable Account' : 'Activate'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Rules */}
      {activeTab === 'rules' && (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Rule Type</th>
                <th>Threshold</th>
                <th>Window (s)</th>
                <th>Severity</th>
                <th>Active</th>
                <th>Modify</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.rule_id}>
                  <td style={{ fontWeight: 600 }}>{r.rule_name}</td>
                  <td><code>{r.rule_type}</code></td>
                  <td>{r.threshold} hits</td>
                  <td>{r.time_window_seconds}s</td>
                  <td><span className={`badge badge-${r.severity.toLowerCase()}`}>{r.severity}</span></td>
                  <td><span className={`badge ${r.is_enabled ? 'badge-low' : 'badge-closed'}`}>{r.is_enabled ? 'Enabled' : 'Disabled'}</span></td>
                  <td>
                    <button className="btn btn-secondary btn-sm" onClick={() => setEditRule(r)}>
                      <Edit2 size={13} />
                      <span>Edit Rule</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 3: Devices */}
      {activeTab === 'devices' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '16px' }}>
            <button className="btn btn-primary" onClick={() => setShowDeviceModal(true)}>
              <Plus size={16} />
              <span>Register Device</span>
            </button>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Device ID</th>
                  <th>Device Name</th>
                  <th>Type</th>
                  <th>IP Address</th>
                  <th>Operating System</th>
                  <th>Location</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                      No devices registered in PostgreSQL yet.
                    </td>
                  </tr>
                ) : (
                  devices.map((d) => (
                    <tr key={d.device_id}>
                      <td>#{d.device_id}</td>
                      <td style={{ fontWeight: 600 }}>{d.device_name}</td>
                      <td>{d.device_type}</td>
                      <td><code>{d.ip_address || '-'}</code></td>
                      <td>{d.operating_system || '-'}</td>
                      <td>{d.location || '-'}</td>
                      <td><span className="badge badge-low">{d.status}</span></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 4: Sources */}
      {activeTab === 'sources' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '16px' }}>
            <button className="btn btn-primary" onClick={() => setShowSourceModal(true)}>
              <Plus size={16} />
              <span>Register Log Source</span>
            </button>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Source ID</th>
                  <th>Source Name</th>
                  <th>Type</th>
                  <th>IP Address</th>
                  <th>Protocol</th>
                  <th>Attached Device ID</th>
                </tr>
              </thead>
              <tbody>
                {sources.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                      No log sources registered in PostgreSQL yet.
                    </td>
                  </tr>
                ) : (
                  sources.map((s) => (
                    <tr key={s.source_id}>
                      <td>#{s.source_id}</td>
                      <td style={{ fontWeight: 600 }}>{s.source_name}</td>
                      <td>{s.source_type}</td>
                      <td><code>{s.ip_address || '-'}</code></td>
                      <td>{s.protocol || '-'}</td>
                      <td>Device #{s.device_id}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create User Modal */}
      {showUserModal && (
        <div className="modal-overlay" onClick={() => setShowUserModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">Register SOC Operator Account</h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowUserModal(false)}><X size={16} /></button>
            </div>
            <form onSubmit={handleCreateUser}>
              <div className="form-group">
                <label className="form-label">Username</label>
                <input
                  type="text"
                  className="form-control"
                  value={newUser.username}
                  onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input
                  type="email"
                  className="form-control"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Password (Min 8 Characters)</label>
                <input
                  type="password"
                  className="form-control"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  required
                  minLength={8}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Role</label>
                <select
                  className="form-control"
                  value={newUser.role_id}
                  onChange={(e) => setNewUser({ ...newUser, role_id: e.target.value })}
                >
                  <option value={2}>ANALYST</option>
                  <option value={1}>ADMIN</option>
                </select>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowUserModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Create User</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Register Device Modal */}
      {showDeviceModal && (
        <div className="modal-overlay" onClick={() => setShowDeviceModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">Register Network Device</h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowDeviceModal(false)}><X size={16} /></button>
            </div>
            <form onSubmit={handleCreateDevice}>
              <div className="form-group">
                <label className="form-label">Device Name</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="e.g. perimeter-fw-01"
                  value={newDevice.device_name}
                  onChange={(e) => setNewDevice({ ...newDevice, device_name: e.target.value })}
                  required
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Device Type</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="FIREWALL, SERVER, ROUTER"
                    value={newDevice.device_type}
                    onChange={(e) => setNewDevice({ ...newDevice, device_type: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">IP Address</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="192.168.1.1"
                    value={newDevice.ip_address}
                    onChange={(e) => setNewDevice({ ...newDevice, ip_address: e.target.value })}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowDeviceModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Save Device</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Register Source Modal */}
      {showSourceModal && (
        <div className="modal-overlay" onClick={() => setShowSourceModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">Register Log Source</h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowSourceModal(false)}><X size={16} /></button>
            </div>
            <form onSubmit={handleCreateSource}>
              <div className="form-group">
                <label className="form-label">Source Name</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="e.g. auth-syslog"
                  value={newSource.source_name}
                  onChange={(e) => setNewSource({ ...newSource, source_name: e.target.value })}
                  required
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Source Type</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="SYSLOG, AGENT, API"
                    value={newSource.source_type}
                    onChange={(e) => setNewSource({ ...newSource, source_type: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Attached Device</label>
                  <select
                    className="form-control"
                    value={newSource.device_id}
                    onChange={(e) => setNewSource({ ...newSource, device_id: e.target.value })}
                    required
                  >
                    <option value="">Select Device</option>
                    {devices.map(d => (
                      <option key={d.device_id} value={d.device_id}>
                        #{d.device_id} - {d.device_name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowSourceModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={devices.length === 0}>
                  Save Source
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Rule Modal */}
      {editRule && (
        <div className="modal-overlay" onClick={() => setEditRule(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">Modify Detection Rule: {editRule.rule_name}</h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setEditRule(null)}><X size={16} /></button>
            </div>
            <form onSubmit={handleUpdateRule}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Hit Threshold</label>
                  <input
                    type="number"
                    className="form-control"
                    min="1"
                    value={editRule.threshold}
                    onChange={(e) => setEditRule({ ...editRule, threshold: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Time Window (Seconds)</label>
                  <input
                    type="number"
                    className="form-control"
                    min="1"
                    value={editRule.time_window_seconds}
                    onChange={(e) => setEditRule({ ...editRule, time_window_seconds: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Severity Level</label>
                  <select
                    className="form-control"
                    value={editRule.severity}
                    onChange={(e) => setEditRule({ ...editRule, severity: e.target.value })}
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Rule Status</label>
                  <select
                    className="form-control"
                    value={editRule.is_enabled ? 'true' : 'false'}
                    onChange={(e) => setEditRule({ ...editRule, is_enabled: e.target.value === 'true' })}
                  >
                    <option value="true">Enabled</option>
                    <option value="false">Disabled</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setEditRule(null)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Save Changes</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
