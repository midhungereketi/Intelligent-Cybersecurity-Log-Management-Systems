-- Member 2: Authentication, Authorization, Detection Rules, Threats, and Alerts schema.
-- Run against PostgreSQL after 001_devices_and_sources.postgres.sql.

CREATE TABLE IF NOT EXISTS roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(60) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id BIGINT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_name VARCHAR(120) NOT NULL UNIQUE,
    description TEXT,
    rule_type VARCHAR(60) NOT NULL,
    threshold INTEGER NOT NULL CHECK (threshold > 0),
    time_window_seconds INTEGER NOT NULL CHECK (time_window_seconds > 0),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threats (
    threat_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    threat_type VARCHAR(60) NOT NULL,
    source_ip INET,
    destination_ip INET,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    description TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES rules(rule_id) ON DELETE RESTRICT,
    threat_id BIGINT REFERENCES threats(threat_id) ON DELETE SET NULL,
    source_ip INET,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    deduplication_key VARCHAR(255) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Idempotency and processed events checkpointing:
CREATE TABLE IF NOT EXISTS processed_detection_events (
    event_id VARCHAR(64) NOT NULL,
    rule_id BIGINT NOT NULL REFERENCES rules(rule_id) ON DELETE CASCADE,
    alert_id BIGINT REFERENCES alerts(alert_id) ON DELETE SET NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id, rule_id)
);

-- Indexes for performance and constraint protection:
CREATE INDEX IF NOT EXISTS users_role_idx ON users(role_id);
CREATE INDEX IF NOT EXISTS rules_type_enabled_idx ON rules(rule_type, is_enabled);
CREATE INDEX IF NOT EXISTS threats_source_ip_idx ON threats(source_ip);
CREATE INDEX IF NOT EXISTS threats_type_idx ON threats(threat_type);
CREATE INDEX IF NOT EXISTS alerts_rule_idx ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS alerts_threat_idx ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS alerts_source_ip_idx ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts(status);
CREATE INDEX IF NOT EXISTS alerts_created_idx ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_dedup_idx ON alerts(deduplication_key);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_active_dedup_idx ON alerts(deduplication_key) WHERE status != 'RESOLVED';

-- Seed default roles:
INSERT INTO roles (role_name, description) VALUES
    ('ADMIN', 'System Administrator with full access to manage users, rules, threats, and alerts'),
    ('ANALYST', 'Security Analyst with access to view logs, threats, alerts, and acknowledge or resolve alerts')
ON CONFLICT (role_name) DO NOTHING;

-- Seed default detection rules:
INSERT INTO rules (rule_name, description, rule_type, threshold, time_window_seconds, severity, is_enabled, configuration) VALUES
    ('Repeated Failed Logins', 'Triggers when a source IP produces repeated failed authentication attempts within a short window', 'FAILED_LOGINS', 5, 300, 'HIGH', TRUE, '{"target_event": "LOGIN_FAILED"}'::jsonb),
    ('Possible Port Scan', 'Triggers when a source IP connects to multiple distinct destination ports within a short window', 'PORT_SCAN', 20, 60, 'HIGH', TRUE, '{"target_event": "CONNECTION"}'::jsonb),
    ('Excessive Activity from Single IP', 'Triggers when a single source IP generates an unusually high volume of log events in a short window', 'EXCESSIVE_ACTIVITY', 100, 60, 'MEDIUM', TRUE, '{}'::jsonb)
ON CONFLICT (rule_name) DO NOTHING;
