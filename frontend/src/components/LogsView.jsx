import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Upload, 
  Plus, 
  ChevronRight, 
  ChevronLeft, 
  RefreshCw, 
  FileCheck, 
  AlertCircle, 
  Code2, 
  X,
  Filter
} from 'lucide-react';
import { api } from '../api';

export default function LogsView() {
  const [logs, setLogs] = useState([]);
  const [nextCursor, setNextCursor] = useState(null);
  const [cursorHistory, setCursorHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filters
  const [filters, setFilters] = useState({
    keyword: '',
    source_ip: '',
    event_type: '',
    severity: '',
    limit: 50,
  });

  // Upload modal state
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);

  // Manual event modal state
  const [showEventModal, setShowEventModal] = useState(false);
  const [manualEvent, setManualEvent] = useState({
    timestamp: new Date().toISOString(),
    source_ip: '198.51.100.10',
    event_type: 'LOGIN_FAILED',
    severity: 'HIGH',
    message: 'Manual test failure event',
    username: 'sec_analyst',
  });

  // Selected log detail drawer
  const [selectedLog, setSelectedLog] = useState(null);

  const fetchLogs = async (cursor = null, isBack = false) => {
    setLoading(true);
    setError(null);
    try {
      const params = { ...filters };
      if (cursor) {
        params.cursor = cursor;
      }
      const res = await api.listLogs(params);
      setLogs(res.items || []);
      
      if (!isBack && cursor) {
        setCursorHistory(prev => [...prev, cursor]);
      } else if (!cursor && !isBack) {
        setCursorHistory([]);
      }

      setNextCursor(res.next_cursor || null);
    } catch (err) {
      setError(err.message || 'Failed to search logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleFilterSubmit = (e) => {
    e.preventDefault();
    setCursorHistory([]);
    fetchLogs(null);
  };

  const handleNextPage = () => {
    if (nextCursor) {
      fetchLogs(nextCursor);
    }
  };

  const handlePrevPage = () => {
    if (cursorHistory.length > 0) {
      const newHistory = [...cursorHistory];
      newHistory.pop(); // Remove current
      const prev = newHistory[newHistory.length - 1] || null;
      setCursorHistory(newHistory);
      fetchLogs(prev, true);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!uploadFile) return;

    setUploading(true);
    setUploadResult(null);
    try {
      const res = await api.uploadLogsFile(uploadFile);
      setUploadResult(res);
      setUploadFile(null);
      fetchLogs();
    } catch (err) {
      alert(`Upload error: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const handleManualEventSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.createLogEvent(manualEvent);
      setShowEventModal(false);
      fetchLogs();
    } catch (err) {
      alert(`Event error: ${err.message}`);
    }
  };

  return (
    <div>
      {/* Page Title & Actions */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', color: '#fff' }}>Log Search & Ingestion</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '4px' }}>
            MongoDB indexed query engine with multi-format batch ingestion and cursor pagination.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn btn-secondary" onClick={() => setShowEventModal(true)}>
            <Plus size={15} />
            <span>Insert Single Event</span>
          </button>
          <button className="btn btn-primary" onClick={() => setShowUploadModal(true)}>
            <Upload size={15} />
            <span>Upload Log File</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ marginBottom: '20px', padding: '16px 20px' }}>
        <form onSubmit={handleFilterSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'flex-end' }}>
          <div style={{ flex: '1 1 200px' }}>
            <label className="form-label">Message Keyword</label>
            <input
              type="text"
              className="form-control"
              placeholder="e.g. failed, root, unauthorized"
              value={filters.keyword}
              onChange={(e) => setFilters({ ...filters, keyword: e.target.value })}
            />
          </div>

          <div style={{ flex: '1 1 150px' }}>
            <label className="form-label">Source IP</label>
            <input
              type="text"
              className="form-control"
              placeholder="e.g. 198.51.100.10"
              value={filters.source_ip}
              onChange={(e) => setFilters({ ...filters, source_ip: e.target.value })}
            />
          </div>

          <div style={{ flex: '1 1 150px' }}>
            <label className="form-label">Event Type</label>
            <input
              type="text"
              className="form-control"
              placeholder="LOGIN_FAILED, CONNECTION..."
              value={filters.event_type}
              onChange={(e) => setFilters({ ...filters, event_type: e.target.value.toUpperCase() })}
            />
          </div>

          <div style={{ flex: '1 1 130px' }}>
            <label className="form-label">Severity</label>
            <select
              className="form-control"
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            >
              <option value="">All Severities</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <Search size={15} />
              <span>Search</span>
            </button>
            <button 
              type="button" 
              className="btn btn-secondary" 
              onClick={() => {
                setFilters({ keyword: '', source_ip: '', event_type: '', severity: '', limit: 50 });
                fetchLogs(null);
              }}
            >
              Reset
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="alert-banner banner-danger">
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Logs Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Event Type</th>
              <th>Source IP</th>
              <th>User</th>
              <th>Message</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  Loading indexed log records...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
                  No logs matching the current filter criteria.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedLog(log)}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                    {log.timestamp}
                  </td>
                  <td>
                    <span className={`badge badge-${log.severity?.toLowerCase()}`}>
                      {log.severity}
                    </span>
                  </td>
                  <td style={{ fontWeight: 600 }}>{log.event_type}</td>
                  <td>
                    <code style={{ color: 'var(--cyan-glow)' }}>{log.source_ip}</code>
                  </td>
                  <td style={{ color: log.username ? 'var(--text-main)' : 'var(--text-dim)' }}>
                    {log.username || '-'}
                  </td>
                  <td style={{ maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.message}
                  </td>
                  <td>
                    <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); setSelectedLog(log); }}>
                      <Code2 size={13} />
                      <span>JSON</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Cursor Pagination Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '16px' }}>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>
          Showing {logs.length} results (Page {cursorHistory.length + 1})
        </span>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            className="btn btn-secondary btn-sm" 
            onClick={handlePrevPage} 
            disabled={cursorHistory.length === 0 || loading}
          >
            <ChevronLeft size={16} />
            <span>Previous</span>
          </button>
          <button 
            className="btn btn-secondary btn-sm" 
            onClick={handleNextPage} 
            disabled={!nextCursor || loading}
          >
            <span>Next Page</span>
            <ChevronRight size={16} />
          </button>
        </div>
      </div>

      {/* Log JSON Detail Modal */}
      {selectedLog && (
        <div className="modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">
                <Code2 size={18} color="var(--cyan-glow)" />
                <span>Log Event Details: {selectedLog.id}</span>
              </h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedLog(null)}>
                <X size={16} />
              </button>
            </div>
            <pre style={{
              background: '#090d16',
              padding: '16px',
              borderRadius: 'var(--radius-sm)',
              overflowX: 'auto',
              fontSize: '0.85rem',
              color: '#38bdf8',
            }}>
              {JSON.stringify(selectedLog, null, 2)}
            </pre>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedLog(null)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Upload File Modal */}
      {showUploadModal && (
        <div className="modal-overlay" onClick={() => setShowUploadModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">
                <Upload size={18} color="var(--cyan-glow)" />
                <span>Upload Batch Log File (Member 1 Ingestion)</span>
              </h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowUploadModal(false)}>
                <X size={16} />
              </button>
            </div>

            {uploadResult && (
              <div className="alert-banner banner-success" style={{ marginBottom: '16px' }}>
                <FileCheck size={18} />
                <div>
                  <strong>Upload Processed:</strong> {uploadResult.inserted} inserted, {uploadResult.rejected} rejected.
                </div>
              </div>
            )}

            <form onSubmit={handleUploadSubmit}>
              <div className="form-group">
                <label className="form-label">Supported Formats: .csv, .json, .jsonl, .ndjson</label>
                <input
                  type="file"
                  className="form-control"
                  accept=".csv,.json,.jsonl,.ndjson"
                  onChange={(e) => setUploadFile(e.target.files[0])}
                  required
                />
              </div>

              {uploadResult?.errors?.length > 0 && (
                <div style={{ marginTop: '16px' }}>
                  <label className="form-label" style={{ color: 'var(--rose-danger)' }}>Row Validation Errors</label>
                  <div style={{ maxHeight: '120px', overflowY: 'auto', background: '#0b1120', padding: '10px', borderRadius: '4px', fontSize: '0.75rem', color: '#fda4af' }}>
                    {uploadResult.errors.map((err, idx) => (
                      <div key={idx}>Row {err.row}: {err.error}</div>
                    ))}
                  </div>
                </div>
              )}

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowUploadModal(false)}>
                  Close
                </button>
                <button type="submit" className="btn btn-primary" disabled={uploading || !uploadFile}>
                  {uploading ? 'Processing Ingestion...' : 'Upload & Ingest'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Manual Event Injection Modal */}
      {showEventModal && (
        <div className="modal-overlay" onClick={() => setShowEventModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="card-title">
                <Plus size={18} color="var(--cyan-glow)" />
                <span>Inject Single Normalized Log Event</span>
              </h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowEventModal(false)}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleManualEventSubmit}>
              <div className="form-group">
                <label className="form-label">Source IP (IPv4 or IPv6)</label>
                <input
                  type="text"
                  className="form-control"
                  value={manualEvent.source_ip}
                  onChange={(e) => setManualEvent({ ...manualEvent, source_ip: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Event Type</label>
                  <input
                    type="text"
                    className="form-control"
                    value={manualEvent.event_type}
                    onChange={(e) => setManualEvent({ ...manualEvent, event_type: e.target.value.toUpperCase() })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Severity</label>
                  <select
                    className="form-control"
                    value={manualEvent.severity}
                    onChange={(e) => setManualEvent({ ...manualEvent, severity: e.target.value })}
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Message</label>
                <input
                  type="text"
                  className="form-control"
                  value={manualEvent.message}
                  onChange={(e) => setManualEvent({ ...manualEvent, message: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Username (Optional)</label>
                <input
                  type="text"
                  className="form-control"
                  value={manualEvent.username}
                  onChange={(e) => setManualEvent({ ...manualEvent, username: e.target.value })}
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowEventModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Insert Event
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
