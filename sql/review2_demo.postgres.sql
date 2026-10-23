-- Review II executable DML, queries, function, procedure, cursor, and trigger.
-- Run after migrations 001-004. Every sample row is rolled back.
BEGIN;

DO $$
DECLARE
    sample_rule BIGINT;
    sample_alert BIGINT;
    sample_incident BIGINT;
    sample_action BIGINT;
    score INTEGER;
    audit_count INTEGER;
BEGIN
    SELECT rule_id INTO STRICT sample_rule FROM rules WHERE rule_name = 'Repeated Failed Logins';

    INSERT INTO alerts (rule_id, source_ip, severity, title, status,
                        deduplication_key, first_seen_at, last_seen_at)
    VALUES (sample_rule, '198.51.100.88', 'HIGH', 'Review II sample alert', 'OPEN',
            'review2-demo-unique', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    RETURNING alert_id INTO sample_alert;

    INSERT INTO incidents (title, severity, status, alert_id, source_ip)
    VALUES ('Review II sample incident', 'HIGH', 'OPEN', sample_alert, '198.51.100.88')
    RETURNING incident_id INTO sample_incident;

    INSERT INTO incident_alerts (incident_id, alert_id)
    VALUES (sample_incident, sample_alert);

    -- Modification invokes the status audit trigger.
    UPDATE alerts SET status = 'ACKNOWLEDGED' WHERE alert_id = sample_alert;

    -- Insert, modify and delete a response action in one transaction.
    INSERT INTO actions (incident_id, action_type, action_details)
    VALUES (sample_incident, 'NOTE', 'Initial review') RETURNING action_id INTO sample_action;
    UPDATE actions SET action_details = 'Analyst confirmed the failed-login pattern'
    WHERE action_id = sample_action;

    SELECT COUNT(*) INTO audit_count FROM alert_status_history
    WHERE alert_id = sample_alert AND old_status = 'OPEN' AND new_status = 'ACKNOWLEDGED';
    IF audit_count <> 1 THEN
        RAISE EXCEPTION 'Alert status trigger failed: % audit rows', audit_count;
    END IF;

    SELECT incident_risk_score(sample_incident) INTO score;
    IF score <> 70 THEN
        RAISE EXCEPTION 'Incident risk function returned %, expected 70', score;
    END IF;

    CALL refresh_incident_priorities();
    IF NOT EXISTS (SELECT 1 FROM incident_priority
                   WHERE incident_id = sample_incident AND risk_score = score) THEN
        RAISE EXCEPTION 'Cursor procedure did not refresh incident priority';
    END IF;

    -- Join with grouping and aggregation: incident, alert and action totals.
    IF NOT EXISTS (
        SELECT i.incident_id
          FROM incidents i
          JOIN incident_alerts ia ON ia.incident_id = i.incident_id
          JOIN alerts a ON a.alert_id = ia.alert_id
          LEFT JOIN actions act ON act.incident_id = i.incident_id
         WHERE i.incident_id = sample_incident AND a.status = 'ACKNOWLEDGED'
         GROUP BY i.incident_id
        HAVING COUNT(DISTINCT a.alert_id) = 1 AND COUNT(DISTINCT act.action_id) = 1
    ) THEN
        RAISE EXCEPTION 'Join and aggregate query failed';
    END IF;

    -- Subquery: active incidents with above-average risk.
    IF NOT EXISTS (
        SELECT 1 FROM incident_priority p
         WHERE p.incident_id = sample_incident
           AND p.risk_score >= (SELECT AVG(risk_score) FROM incident_priority)
    ) THEN
        RAISE EXCEPTION 'Risk subquery failed';
    END IF;

    DELETE FROM actions WHERE action_id = sample_action;
    IF EXISTS (SELECT 1 FROM actions WHERE action_id = sample_action) THEN
        RAISE EXCEPTION 'Action deletion failed';
    END IF;
    RAISE NOTICE 'Review II SQL checks passed: DML, join, aggregation, subquery, function, trigger, cursor procedure';
END;
$$;

ROLLBACK;
