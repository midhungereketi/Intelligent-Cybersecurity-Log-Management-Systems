/**
 * Centralized API client for Intelligent Cybersecurity Log Management System.
 * Supports token storage, automatic Bearer headers, and unified error handling.
 */

const API_BASE = '';

export function getStoredToken() {
  return localStorage.getItem('cs_access_token');
}

export function setStoredToken(token) {
  if (token) {
    localStorage.setItem('cs_access_token', token);
  } else {
    localStorage.removeItem('cs_access_token');
  }
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem('cs_user');
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(user) {
  if (user) {
    localStorage.setItem('cs_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('cs_user');
  }
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = { ...options.headers };

  const token = getStoredToken();
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    // If unauthorized, clear credentials
    setStoredToken(null);
    setStoredUser(null);
    if (!endpoint.includes('/api/auth/login')) {
      window.dispatchEvent(new Event('auth:unauthorized'));
    }
  }

  if (response.status === 204) {
    return null;
  }

  let data;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const backendUnavailable = [502, 503, 504].includes(response.status) && !data;
    const errorMsg = backendUnavailable
      ? 'Backend unavailable. Start FastAPI, MongoDB, and PostgreSQL before signing in.'
      : data?.detail || (typeof data === 'string' && data ? data : `Request failed with status ${response.status}`);
    const err = new Error(errorMsg);
    err.status = response.status;
    err.data = data;
    throw err;
  }

  return data;
}

export const api = {
  // Authentication (Member 2)
  login: (username, password) =>
    request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  logout: () =>
    request('/api/auth/logout', {
      method: 'POST',
    }),

  getMe: () => request('/api/auth/me'),

  // Analytics (Member 3)
  getDashboardSummary: () => request('/api/analytics/dashboard'),
  getEventsTimeline: (limit = 24) => request(`/api/analytics/events-timeline?limit=${limit}`),
  getTopSources: (limit = 10) => request(`/api/analytics/top-sources?limit=${limit}`),
  getEventTypes: () => request('/api/analytics/event-types'),

  // Logs (Member 1)
  listLogs: (params = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        q.append(k, v);
      }
    });
    return request(`/api/logs?${q.toString()}`);
  },

  createLogEvent: (event) =>
    request('/api/logs/events', {
      method: 'POST',
      body: JSON.stringify(event),
    }),

  uploadLogsFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/api/logs/upload', {
      method: 'POST',
      body: formData,
    });
  },

  // Devices & Sources (Member 1)
  listDevices: () => request('/api/devices'),
  createDevice: (payload) =>
    request('/api/devices', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listSources: (deviceId) =>
    request(deviceId ? `/api/sources?device_id=${deviceId}` : '/api/sources'),

  createSource: (payload) =>
    request('/api/sources', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Detection & Rules (Member 2)
  listRules: () => request('/api/rules'),
  updateRule: (ruleId, payload) =>
    request(`/api/rules/${ruleId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  createRule: (payload) =>
    request('/api/rules', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  runDetection: (payload = { limit: 2000 }) =>
    request('/api/detection/run', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Threats & Alerts (Member 2)
  listThreats: (params = {}) => {
    const q = new URLSearchParams(params);
    return request(`/api/threats?${q.toString()}`);
  },
  getThreat: (id) => request(`/api/threats/${id}`),

  listAlerts: (params = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        q.append(k, v);
      }
    });
    return request(`/api/alerts?${q.toString()}`);
  },
  getAlert: (id) => request(`/api/alerts/${id}`),
  acknowledgeAlert: (id) =>
    request(`/api/alerts/${id}/acknowledge`, { method: 'POST' }),
  resolveAlert: (id) =>
    request(`/api/alerts/${id}/resolve`, { method: 'POST' }),

  // User Management (Member 2 Admin)
  listUsers: () => request('/api/users'),
  listAssignableUsers: () => request('/api/users/assignable'),
  createUser: (payload) =>
    request('/api/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateUser: (userId, payload) =>
    request(`/api/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  // Incidents & Response Actions (Member 3)
  listIncidents: (params = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        q.append(k, v);
      }
    });
    return request(`/api/incidents?${q.toString()}`);
  },
  getIncident: (id) => request(`/api/incidents/${id}`),
  createIncident: (payload) =>
    request('/api/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateIncident: (id, payload) =>
    request(`/api/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  listIncidentActions: (id) => request(`/api/incidents/${id}/actions`),
  addIncidentAction: (id, payload) =>
    request(`/api/incidents/${id}/actions`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  linkAlertToIncident: (incidentId, alertId) =>
    request(`/api/incidents/${incidentId}/link-alert?alert_id=${alertId}`, {
      method: 'POST',
    }),
};
