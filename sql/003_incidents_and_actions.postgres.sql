-- Member 3: Incident Management and Response Action History schema.
-- Run against PostgreSQL after 001_devices_and_sources.postgres.sql and 002_auth_and_detection.postgres.sql.

CREATE TABLE IF NOT EXISTS incidents (
    incident_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    assigned_to BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    alert_id BIGINT REFERENCES alerts(alert_id) ON DELETE SET NULL,
    source_ip INET,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id BIGINT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id BIGINT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS actions (
    action_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    action_type VARCHAR(60) NOT NULL CHECK (action_type IN ('NOTE', 'CONTAINMENT', 'REMEDIATION', 'STATUS_CHANGE', 'ASSIGNMENT', 'INVESTIGATION_STEP', 'OTHER')),
    action_details TEXT NOT NULL,
    performed_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    performed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Performance and query indexes
CREATE INDEX IF NOT EXISTS incidents_status_idx ON incidents(status);
CREATE INDEX IF NOT EXISTS incidents_severity_idx ON incidents(severity);
CREATE INDEX IF NOT EXISTS incidents_assigned_to_idx ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS incidents_alert_id_idx ON incidents(alert_id);
CREATE INDEX IF NOT EXISTS incidents_created_at_idx ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS incident_alerts_alert_id_idx ON incident_alerts(alert_id);
CREATE INDEX IF NOT EXISTS actions_incident_id_idx ON actions(incident_id);
CREATE INDEX IF NOT EXISTS actions_performed_by_idx ON actions(performed_by);
CREATE INDEX IF NOT EXISTS actions_performed_at_idx ON actions(performed_at DESC);
