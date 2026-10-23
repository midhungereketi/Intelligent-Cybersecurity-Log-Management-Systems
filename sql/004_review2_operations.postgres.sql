-- Review II: stored function, explicit cursor procedure, trigger, and audit tables.
-- Apply after migrations 001-003. Safe to re-apply.

CREATE TABLE IF NOT EXISTS alert_status_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id BIGINT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    old_status VARCHAR(30) NOT NULL,
    new_status VARCHAR(30) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS alert_status_history_alert_idx ON alert_status_history(alert_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS incident_priority (
    incident_id BIGINT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0),
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION record_alert_status_change()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO alert_status_history (alert_id, old_status, new_status)
    VALUES (NEW.alert_id, OLD.status, NEW.status);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS alert_status_change_audit ON alerts;
CREATE TRIGGER alert_status_change_audit
AFTER UPDATE OF status ON alerts
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION record_alert_status_change();

-- A deterministic score that combines incident severity and correlated alerts.
CREATE OR REPLACE FUNCTION incident_risk_score(p_incident_id BIGINT)
RETURNS INTEGER LANGUAGE sql STABLE AS $$
    SELECT CASE i.severity
               WHEN 'CRITICAL' THEN 80
               WHEN 'HIGH' THEN 60
               WHEN 'MEDIUM' THEN 40
               ELSE 20
           END + 10 * (SELECT COUNT(*)::INTEGER
                         FROM incident_alerts ia
                        WHERE ia.incident_id = i.incident_id)
      FROM incidents i
     WHERE i.incident_id = p_incident_id;
$$;

-- An explicit cursor walks active cases and refreshes the materialized
-- prioritization table. Completed cases are removed from the active queue.
CREATE OR REPLACE PROCEDURE refresh_incident_priorities()
LANGUAGE plpgsql AS $$
DECLARE
    case_row RECORD;
    case_cursor CURSOR FOR
        SELECT incident_id FROM incidents
         WHERE status NOT IN ('RESOLVED', 'CLOSED')
         ORDER BY created_at, incident_id;
BEGIN
    DELETE FROM incident_priority p
     WHERE NOT EXISTS (
         SELECT 1 FROM incidents i
          WHERE i.incident_id = p.incident_id
            AND i.status NOT IN ('RESOLVED', 'CLOSED')
     );

    OPEN case_cursor;
    LOOP
        FETCH case_cursor INTO case_row;
        EXIT WHEN NOT FOUND;
        INSERT INTO incident_priority (incident_id, risk_score, calculated_at)
        VALUES (case_row.incident_id, incident_risk_score(case_row.incident_id), CURRENT_TIMESTAMP)
        ON CONFLICT (incident_id) DO UPDATE
          SET risk_score = EXCLUDED.risk_score,
              calculated_at = EXCLUDED.calculated_at;
    END LOOP;
    CLOSE case_cursor;
END;
$$;
