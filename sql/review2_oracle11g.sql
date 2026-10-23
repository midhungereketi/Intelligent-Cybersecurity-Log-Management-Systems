-- Intelligent Cybersecurity Log Management System
-- Review II: relational implementation for Oracle Database 11g
-- Run once in a clean project schema using SQL*Plus or SQL Developer (Run Script/F5).
-- Full event volume remains in MongoDB; SECURITY_LOG contains relational demo records.
-- All addresses and records below are synthetic. No real credentials are included.

WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET SERVEROUTPUT ON

-- 1. DDL and constraints ----------------------------------------------------
CREATE TABLE role_def (
    role_id NUMBER(10) CONSTRAINT pk_role_def PRIMARY KEY,
    role_name VARCHAR2(40) NOT NULL CONSTRAINT uq_role_name UNIQUE,
    description VARCHAR2(200)
);

CREATE TABLE app_user (
    user_id NUMBER(10) CONSTRAINT pk_app_user PRIMARY KEY,
    full_name VARCHAR2(100) NOT NULL,
    email VARCHAR2(150) NOT NULL CONSTRAINT uq_user_email UNIQUE,
    password_hash VARCHAR2(255) NOT NULL,
    role_id NUMBER(10) NOT NULL,
    status VARCHAR2(12) DEFAULT 'ACTIVE' NOT NULL,
    CONSTRAINT fk_user_role FOREIGN KEY (role_id) REFERENCES role_def(role_id),
    CONSTRAINT ck_user_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

CREATE TABLE device (
    device_id NUMBER(10) CONSTRAINT pk_device PRIMARY KEY,
    device_name VARCHAR2(100) NOT NULL CONSTRAINT uq_device_name UNIQUE,
    ip_address VARCHAR2(45),
    mac_address VARCHAR2(17),
    device_type VARCHAR2(50) NOT NULL,
    operating_system VARCHAR2(100),
    location VARCHAR2(100),
    status VARCHAR2(12) DEFAULT 'ACTIVE' NOT NULL,
    CONSTRAINT ck_device_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

CREATE TABLE log_source (
    source_id NUMBER(10) CONSTRAINT pk_log_source PRIMARY KEY,
    source_name VARCHAR2(100) NOT NULL,
    source_type VARCHAR2(50) NOT NULL,
    ip_address VARCHAR2(45),
    protocol VARCHAR2(20),
    device_id NUMBER(10) NOT NULL,
    CONSTRAINT fk_source_device FOREIGN KEY (device_id) REFERENCES device(device_id),
    CONSTRAINT uq_source_per_device UNIQUE (device_id, source_name)
);

CREATE TABLE security_log (
    log_id NUMBER(12) CONSTRAINT pk_security_log PRIMARY KEY,
    source_id NUMBER(10) NOT NULL,
    user_id NUMBER(10),
    event_time TIMESTAMP NOT NULL,
    log_level VARCHAR2(10) NOT NULL,
    event_type VARCHAR2(60) NOT NULL,
    message VARCHAR2(1000) NOT NULL,
    source_ip VARCHAR2(45) NOT NULL,
    destination_ip VARCHAR2(45),
    destination_port NUMBER(5),
    status VARCHAR2(12) DEFAULT 'NEW' NOT NULL,
    CONSTRAINT fk_log_source FOREIGN KEY (source_id) REFERENCES log_source(source_id),
    CONSTRAINT fk_log_user FOREIGN KEY (user_id) REFERENCES app_user(user_id),
    CONSTRAINT ck_log_level CHECK (log_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_log_status CHECK (status IN ('NEW', 'REVIEWED', 'ARCHIVED')),
    CONSTRAINT ck_destination_port CHECK (destination_port BETWEEN 1 AND 65535)
);

CREATE TABLE threat (
    threat_id NUMBER(10) CONSTRAINT pk_threat PRIMARY KEY,
    threat_name VARCHAR2(100) NOT NULL CONSTRAINT uq_threat_name UNIQUE,
    threat_type VARCHAR2(50) NOT NULL,
    severity VARCHAR2(10) NOT NULL,
    description VARCHAR2(500),
    threat_level NUMBER(3),
    source_ip VARCHAR2(45),
    detected_time TIMESTAMP,
    CONSTRAINT ck_threat_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_threat_level CHECK (threat_level BETWEEN 0 AND 100)
);

CREATE TABLE rule_def (
    rule_id NUMBER(10) CONSTRAINT pk_rule_def PRIMARY KEY,
    rule_name VARCHAR2(100) NOT NULL CONSTRAINT uq_rule_name UNIQUE,
    severity VARCHAR2(10) NOT NULL,
    description VARCHAR2(500),
    rule_condition VARCHAR2(500) NOT NULL,
    status VARCHAR2(12) DEFAULT 'ACTIVE' NOT NULL,
    created_date TIMESTAMP DEFAULT CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS TIMESTAMP) NOT NULL,
    CONSTRAINT ck_rule_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_rule_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

CREATE TABLE alert (
    alert_id NUMBER(12) CONSTRAINT pk_alert PRIMARY KEY,
    log_id NUMBER(12) NOT NULL,
    threat_id NUMBER(10),
    rule_id NUMBER(10) NOT NULL,
    severity VARCHAR2(10) NOT NULL,
    confidence_score NUMBER(5,2),
    status VARCHAR2(15) DEFAULT 'OPEN' NOT NULL,
    description VARCHAR2(500),
    alert_time TIMESTAMP DEFAULT CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS TIMESTAMP) NOT NULL,
    CONSTRAINT fk_alert_log FOREIGN KEY (log_id) REFERENCES security_log(log_id),
    CONSTRAINT fk_alert_threat FOREIGN KEY (threat_id) REFERENCES threat(threat_id),
    CONSTRAINT fk_alert_rule FOREIGN KEY (rule_id) REFERENCES rule_def(rule_id),
    CONSTRAINT uq_alert_log_rule UNIQUE (log_id, rule_id),
    CONSTRAINT ck_alert_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_alert_confidence CHECK (confidence_score BETWEEN 0 AND 100),
    CONSTRAINT ck_alert_status CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED'))
);

CREATE TABLE ml_model (
    model_id NUMBER(10) CONSTRAINT pk_ml_model PRIMARY KEY,
    model_name VARCHAR2(100) NOT NULL,
    model_type VARCHAR2(60) NOT NULL,
    version VARCHAR2(30),
    accuracy NUMBER(5,2),
    training_date TIMESTAMP,
    status VARCHAR2(12) DEFAULT 'INACTIVE' NOT NULL,
    CONSTRAINT ck_model_accuracy CHECK (accuracy BETWEEN 0 AND 100),
    CONSTRAINT ck_model_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

CREATE TABLE prediction (
    prediction_id NUMBER(12) CONSTRAINT pk_prediction PRIMARY KEY,
    model_id NUMBER(10) NOT NULL,
    log_id NUMBER(12) NOT NULL,
    predicted_threat VARCHAR2(100) NOT NULL,
    confidence_score NUMBER(5,2),
    prediction_time TIMESTAMP NOT NULL,
    CONSTRAINT fk_prediction_model FOREIGN KEY (model_id) REFERENCES ml_model(model_id),
    CONSTRAINT fk_prediction_log FOREIGN KEY (log_id) REFERENCES security_log(log_id),
    CONSTRAINT ck_prediction_confidence CHECK (confidence_score BETWEEN 0 AND 100)
);

CREATE TABLE incident (
    incident_id NUMBER(12) CONSTRAINT pk_incident PRIMARY KEY,
    log_id NUMBER(12),
    alert_id NUMBER(12),
    incident_name VARCHAR2(150) NOT NULL,
    description VARCHAR2(500),
    severity VARCHAR2(10) NOT NULL,
    assigned_to NUMBER(10),
    status VARCHAR2(15) DEFAULT 'OPEN' NOT NULL,
    created_time TIMESTAMP DEFAULT CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS TIMESTAMP) NOT NULL,
    resolved_time TIMESTAMP,
    CONSTRAINT fk_incident_log FOREIGN KEY (log_id) REFERENCES security_log(log_id),
    CONSTRAINT fk_incident_alert FOREIGN KEY (alert_id) REFERENCES alert(alert_id),
    CONSTRAINT fk_incident_assignee FOREIGN KEY (assigned_to) REFERENCES app_user(user_id),
    CONSTRAINT uq_incident_alert UNIQUE (alert_id),
    CONSTRAINT ck_incident_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_incident_status CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED'))
);

CREATE TABLE incident_action (
    action_id NUMBER(12) CONSTRAINT pk_incident_action PRIMARY KEY,
    incident_id NUMBER(12) NOT NULL,
    user_id NUMBER(10) NOT NULL,
    model_id NUMBER(10),
    action_type VARCHAR2(50) NOT NULL,
    action_description VARCHAR2(500) NOT NULL,
    action_time TIMESTAMP DEFAULT CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS TIMESTAMP) NOT NULL,
    result VARCHAR2(100),
    CONSTRAINT fk_action_incident FOREIGN KEY (incident_id) REFERENCES incident(incident_id),
    CONSTRAINT fk_action_user FOREIGN KEY (user_id) REFERENCES app_user(user_id),
    CONSTRAINT fk_action_model FOREIGN KEY (model_id) REFERENCES ml_model(model_id)
);

CREATE INDEX ix_log_ip_time ON security_log(source_ip, event_time);
CREATE INDEX ix_log_event_time ON security_log(event_type, event_time);
CREATE INDEX ix_alert_status_time ON alert(status, alert_time);
CREATE INDEX ix_incident_status ON incident(status);

CREATE SEQUENCE seq_alert START WITH 1000 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE seq_incident START WITH 1000 INCREMENT BY 1 NOCACHE;

-- 2. Triggers ---------------------------------------------------------------
CREATE OR REPLACE TRIGGER trg_alert_incident
AFTER INSERT ON alert
FOR EACH ROW
BEGIN
    IF :NEW.severity IN ('HIGH', 'CRITICAL') THEN
        INSERT INTO incident (
            incident_id, log_id, alert_id, incident_name, description,
            severity, assigned_to, status, created_time
        ) VALUES (
            seq_incident.NEXTVAL, :NEW.log_id, :NEW.alert_id,
            'Investigate alert ' || TO_CHAR(:NEW.alert_id),
            :NEW.description, :NEW.severity, NULL, 'OPEN',
            CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS TIMESTAMP)
        );
    END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_incident_resolved
BEFORE UPDATE OF status ON incident
FOR EACH ROW
BEGIN
    IF :NEW.status = 'RESOLVED' AND :OLD.status <> 'RESOLVED' THEN
        :NEW.resolved_time := CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS TIMESTAMP);
    ELSIF :NEW.status <> 'RESOLVED' THEN
        :NEW.resolved_time := NULL;
    END IF;
END;
/

-- 3. Meaningful synthetic data and DML -------------------------------------
INSERT INTO role_def VALUES (1, 'ADMIN', 'Manages users and rules');
INSERT INTO role_def VALUES (2, 'ANALYST', 'Investigates alerts');

-- Demo-only placeholders: replace with application-generated password hashes.
INSERT INTO app_user VALUES (101, 'Demo Admin', 'admin@example.invalid',
    'DEMO_HASH_NOT_FOR_LOGIN', 1, 'ACTIVE');
INSERT INTO app_user VALUES (102, 'Demo Analyst', 'analyst@example.invalid',
    'DEMO_HASH_NOT_FOR_LOGIN', 2, 'ACTIVE');

INSERT INTO device VALUES (201, 'auth-server-1', '203.0.113.10', NULL,
    'SERVER', 'Linux', 'Lab A', 'ACTIVE');
INSERT INTO device VALUES (202, 'edge-firewall-1', '203.0.113.20', NULL,
    'FIREWALL', 'Appliance OS', 'Lab A', 'ACTIVE');
INSERT INTO device VALUES (203, 'metrics-node-1', '203.0.113.30', NULL,
    'SERVER', 'Linux', 'Lab B', 'ACTIVE');

INSERT INTO log_source VALUES (301, 'authentication-service', 'APPLICATION',
    '203.0.113.10', 'HTTPS', 201);
INSERT INTO log_source VALUES (302, 'edge-firewall', 'NETWORK',
    '203.0.113.20', 'SYSLOG', 202);
INSERT INTO log_source VALUES (303, 'metrics-service', 'APPLICATION',
    '203.0.113.30', 'HTTPS', 203);

INSERT INTO security_log VALUES (401, 301, 102,
    TO_TIMESTAMP('2026-10-14 10:00:00', 'YYYY-MM-DD HH24:MI:SS'),
    'HIGH', 'LOGIN_FAILED', 'Incorrect password', '198.51.100.10', NULL, NULL, 'NEW');
INSERT INTO security_log VALUES (402, 301, 102,
    TO_TIMESTAMP('2026-10-14 10:01:00', 'YYYY-MM-DD HH24:MI:SS'),
    'HIGH', 'LOGIN_FAILED', 'Incorrect password', '198.51.100.10', NULL, NULL, 'NEW');
INSERT INTO security_log VALUES (403, 301, 102,
    TO_TIMESTAMP('2026-10-14 10:02:00', 'YYYY-MM-DD HH24:MI:SS'),
    'HIGH', 'LOGIN_FAILED', 'Incorrect password', '198.51.100.10', NULL, NULL, 'NEW');
INSERT INTO security_log VALUES (404, 301, 102,
    TO_TIMESTAMP('2026-10-14 10:03:00', 'YYYY-MM-DD HH24:MI:SS'),
    'LOW', 'LOGIN_SUCCESS', 'Successful login', '203.0.113.11', NULL, NULL, 'NEW');
INSERT INTO security_log VALUES (405, 302, NULL,
    TO_TIMESTAMP('2026-10-14 11:00:00', 'YYYY-MM-DD HH24:MI:SS'),
    'MEDIUM', 'FIREWALL_BLOCK', 'Blocked inbound connection',
    '198.51.100.20', '203.0.113.20', 22, 'NEW');
INSERT INTO security_log VALUES (406, 302, NULL,
    TO_TIMESTAMP('2026-10-14 11:01:00', 'YYYY-MM-DD HH24:MI:SS'),
    'MEDIUM', 'CONNECTION', 'Connection to port 22',
    '198.51.100.20', '203.0.113.20', 22, 'NEW');
INSERT INTO security_log VALUES (407, 302, NULL,
    TO_TIMESTAMP('2026-10-14 11:02:00', 'YYYY-MM-DD HH24:MI:SS'),
    'MEDIUM', 'CONNECTION', 'Connection to port 23',
    '198.51.100.20', '203.0.113.20', 23, 'NEW');
INSERT INTO security_log VALUES (408, 302, NULL,
    TO_TIMESTAMP('2026-10-14 11:03:00', 'YYYY-MM-DD HH24:MI:SS'),
    'HIGH', 'CONNECTION', 'Connection to port 24',
    '198.51.100.20', '203.0.113.20', 24, 'NEW');
INSERT INTO security_log VALUES (409, 301, 101,
    TO_TIMESTAMP('2026-10-14 12:00:00', 'YYYY-MM-DD HH24:MI:SS'),
    'LOW', 'ACCESS', 'Routine dashboard access', '203.0.113.12', NULL, NULL, 'NEW');
INSERT INTO security_log VALUES (410, 303, NULL,
    TO_TIMESTAMP('2026-10-14 12:05:00', 'YYYY-MM-DD HH24:MI:SS'),
    'LOW', 'HEARTBEAT', 'Routine metrics heartbeat',
    '203.0.113.30', NULL, NULL, 'NEW');

INSERT INTO threat VALUES (501, 'Repeated Login Failures', 'BRUTE_FORCE',
    'HIGH', 'Multiple failed logins from one address', 80, '198.51.100.10',
    TO_TIMESTAMP('2026-10-14 10:02:00', 'YYYY-MM-DD HH24:MI:SS'));
INSERT INTO threat VALUES (502, 'Port Scan Pattern', 'RECONNAISSANCE',
    'HIGH', 'One address contacts multiple destination ports', 75,
    '198.51.100.20', TO_TIMESTAMP('2026-10-14 11:03:00', 'YYYY-MM-DD HH24:MI:SS'));

INSERT INTO rule_def (rule_id, rule_name, severity, description, rule_condition, status)
VALUES (601, 'Failed Login Threshold', 'HIGH',
    'Three failed logins from one IP within ten minutes',
    'LOGIN_FAILED count >= 3 within 10 minutes', 'ACTIVE');
INSERT INTO rule_def (rule_id, rule_name, severity, description, rule_condition, status)
VALUES (602, 'Port Scan Threshold', 'HIGH',
    'Three distinct destination ports from one IP within ten minutes',
    'distinct destination_port count >= 3 within 10 minutes', 'ACTIVE');

-- Optional Review I ER entities are represented but no model is trained here.
INSERT INTO ml_model (model_id, model_name, model_type, version, status)
VALUES (801, 'Optional Future Model', 'CLASSIFIER', '0.0', 'INACTIVE');

-- The alert trigger automatically creates incident 1000 for this high alert.
INSERT INTO alert (alert_id, log_id, threat_id, rule_id, severity,
    confidence_score, status, description)
VALUES (701, 408, 502, 602, 'HIGH', 80, 'OPEN',
    'Three destination ports observed from 198.51.100.20');

INSERT INTO incident_action (action_id, incident_id, user_id, model_id,
    action_type, action_description, result)
VALUES (901, 1000, 102, NULL, 'INVESTIGATE',
    'Review firewall connection sequence', 'PENDING');

-- UPDATE: analyst reviews the triggering event and starts investigation.
UPDATE security_log SET status = 'REVIEWED' WHERE log_id = 408;
UPDATE incident_action SET result = 'IN_PROGRESS' WHERE action_id = 901;

-- DELETE: remove a temporary action entered during the demonstration.
INSERT INTO incident_action (action_id, incident_id, user_id, model_id,
    action_type, action_description, result)
VALUES (902, 1000, 102, NULL, 'NOTE', 'Temporary duplicate note', 'DRAFT');
DELETE FROM incident_action WHERE action_id = 902;
COMMIT;

-- 4. Business function and procedures -------------------------------------
CREATE OR REPLACE FUNCTION fn_failed_login_count (
    p_source_ip IN VARCHAR2,
    p_as_of IN TIMESTAMP,
    p_minutes IN NUMBER
) RETURN NUMBER IS
    l_count NUMBER;
BEGIN
    IF p_minutes < 1 THEN
        RAISE_APPLICATION_ERROR(-20001, 'Window must be at least one minute');
    END IF;
    SELECT COUNT(*) INTO l_count
    FROM security_log
    WHERE source_ip = p_source_ip
      AND event_type = 'LOGIN_FAILED'
      AND event_time > p_as_of - NUMTODSINTERVAL(p_minutes, 'MINUTE')
      AND event_time <= p_as_of;
    RETURN l_count;
END;
/

CREATE OR REPLACE PROCEDURE pr_create_alert (
    p_log_id IN NUMBER,
    p_rule_id IN NUMBER,
    p_threat_id IN NUMBER,
    p_confidence_score IN NUMBER
) IS
    l_severity rule_def.severity%TYPE;
BEGIN
    SELECT severity INTO l_severity
    FROM rule_def
    WHERE rule_id = p_rule_id AND status = 'ACTIVE';

    INSERT INTO alert (alert_id, log_id, threat_id, rule_id, severity,
        confidence_score, status, description)
    SELECT seq_alert.NEXTVAL, p_log_id, p_threat_id, p_rule_id, l_severity,
        p_confidence_score, 'OPEN', 'Generated by active detection rule'
    FROM dual
    WHERE NOT EXISTS (
        SELECT 1 FROM alert
        WHERE log_id = p_log_id AND rule_id = p_rule_id
    );
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        NULL; -- another run already created this log/rule alert
    WHEN NO_DATA_FOUND THEN
        RAISE_APPLICATION_ERROR(-20002, 'Rule does not exist or is inactive');
END;
/

CREATE OR REPLACE PROCEDURE pr_scan_failed_logins (
    p_window_start IN TIMESTAMP,
    p_window_end IN TIMESTAMP,
    p_threshold IN NUMBER
) IS
    CURSOR c_suspects IS
        SELECT source_ip, COUNT(*) AS failures
        FROM security_log
        WHERE event_type = 'LOGIN_FAILED'
          AND event_time BETWEEN p_window_start AND p_window_end
        GROUP BY source_ip
        HAVING COUNT(*) >= p_threshold;
    l_log_id security_log.log_id%TYPE;
BEGIN
    IF p_threshold < 1 OR p_window_start > p_window_end THEN
        RAISE_APPLICATION_ERROR(-20003, 'Invalid detection window or threshold');
    END IF;
    FOR suspect IN c_suspects LOOP
        SELECT log_id INTO l_log_id
        FROM (
            SELECT log_id
            FROM security_log
            WHERE source_ip = suspect.source_ip
              AND event_type = 'LOGIN_FAILED'
              AND event_time BETWEEN p_window_start AND p_window_end
            ORDER BY event_time DESC, log_id DESC
        )
        WHERE ROWNUM = 1;

        pr_create_alert(l_log_id, 601, 501,
            LEAST(100, suspect.failures * 20));
    END LOOP;
END;
/

-- Running this block twice should still leave one alert for log 403/rule 601.
BEGIN
    pr_scan_failed_logins(
        TO_TIMESTAMP('2026-10-14 10:00:00', 'YYYY-MM-DD HH24:MI:SS'),
        TO_TIMESTAMP('2026-10-14 10:10:00', 'YYYY-MM-DD HH24:MI:SS'),
        3
    );
    DBMS_OUTPUT.PUT_LINE('Failed login count = ' ||
        fn_failed_login_count('198.51.100.10',
            TO_TIMESTAMP('2026-10-14 10:03:00', 'YYYY-MM-DD HH24:MI:SS'), 10));
END;
/
COMMIT;

-- 5. SQL queries ------------------------------------------------------------
-- Q1: joins across alert, source log, rule, threat, and incident.
SELECT a.alert_id, l.source_ip, l.event_type, r.rule_name,
       t.threat_name, i.incident_id, i.status AS incident_status
FROM alert a
JOIN security_log l ON l.log_id = a.log_id
JOIN rule_def r ON r.rule_id = a.rule_id
LEFT JOIN threat t ON t.threat_id = a.threat_id
LEFT JOIN incident i ON i.alert_id = a.alert_id
ORDER BY a.alert_id;

-- Q2: grouping, aggregation, and HAVING for suspicious login activity.
SELECT source_ip, COUNT(*) AS failed_attempts,
       MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM security_log
WHERE event_type = 'LOGIN_FAILED'
GROUP BY source_ip
HAVING COUNT(*) >= 3
ORDER BY failed_attempts DESC;

-- Q3: subquery compares a device's log count with average per device.
SELECT d.device_id, d.device_name, COUNT(l.log_id) AS log_count
FROM device d
JOIN log_source s ON s.device_id = d.device_id
JOIN security_log l ON l.source_id = s.source_id
GROUP BY d.device_id, d.device_name
HAVING COUNT(l.log_id) > (
    SELECT AVG(device_count)
    FROM (
        SELECT COUNT(l2.log_id) AS device_count
        FROM device d2
        JOIN log_source s2 ON s2.device_id = d2.device_id
        JOIN security_log l2 ON l2.source_id = s2.source_id
        GROUP BY d2.device_id
    )
);

-- Q4: correlated subquery finds devices without any high-severity event.
SELECT d.device_id, d.device_name
FROM device d
WHERE NOT EXISTS (
    SELECT 1
    FROM log_source s JOIN security_log l ON l.source_id = s.source_id
    WHERE s.device_id = d.device_id
      AND l.log_level IN ('HIGH', 'CRITICAL')
);

-- Q5: event distribution for dashboard charts.
SELECT event_type, log_level, COUNT(*) AS event_count
FROM security_log
GROUP BY event_type, log_level
ORDER BY event_count DESC, event_type;

-- Q6: final verification of the cursor, procedures, and trigger.
SELECT a.log_id, a.rule_id, COUNT(*) AS alert_count
FROM alert a
WHERE a.log_id = 403 AND a.rule_id = 601
GROUP BY a.log_id, a.rule_id;

SELECT alert_id, incident_id, severity, status, resolved_time
FROM incident
ORDER BY incident_id;
