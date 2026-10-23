-- Run after review2_oracle11g.sql in the same Oracle 11g schema.
-- It checks actual database state and rolls back the temporary trigger exercise.
-- A successful run prints REVIEW II ORACLE CHECKS PASSED.
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET SERVEROUTPUT ON

DECLARE
    v_count NUMBER;
    v_resolved_time TIMESTAMP;
BEGIN
    SELECT COUNT(*) INTO v_count FROM user_tables
    WHERE table_name IN ('ROLE_DEF', 'APP_USER', 'DEVICE', 'LOG_SOURCE',
                         'SECURITY_LOG', 'THREAT', 'RULE_DEF', 'ALERT',
                         'ML_MODEL', 'PREDICTION', 'INCIDENT', 'INCIDENT_ACTION');
    IF v_count <> 12 THEN
        RAISE_APPLICATION_ERROR(-20101, 'Expected 12 Review II tables, found ' || v_count);
    END IF;

    SELECT COUNT(*) INTO v_count FROM security_log;
    IF v_count <> 10 THEN
        RAISE_APPLICATION_ERROR(-20102, 'Expected 10 synthetic logs, found ' || v_count);
    END IF;

    SELECT fn_failed_login_count(
        '198.51.100.10',
        TO_TIMESTAMP('2026-10-14 10:03:00', 'YYYY-MM-DD HH24:MI:SS'), 10)
    INTO v_count FROM dual;
    IF v_count <> 3 THEN
        RAISE_APPLICATION_ERROR(-20103, 'Expected 3 failed logins, found ' || v_count);
    END IF;

    -- Re-running the cursor procedure must not create a duplicate alert.
    pr_scan_failed_logins(
        TO_TIMESTAMP('2026-10-14 10:00:00', 'YYYY-MM-DD HH24:MI:SS'),
        TO_TIMESTAMP('2026-10-14 10:10:00', 'YYYY-MM-DD HH24:MI:SS'), 3);
    SELECT COUNT(*) INTO v_count FROM alert WHERE log_id = 403 AND rule_id = 601;
    IF v_count <> 1 THEN
        RAISE_APPLICATION_ERROR(-20104, 'Expected one failed-login alert, found ' || v_count);
    END IF;

    SELECT COUNT(*) INTO v_count FROM incident i
    JOIN alert a ON a.alert_id = i.alert_id
    WHERE a.log_id = 403 AND a.rule_id = 601 AND i.severity = 'HIGH';
    IF v_count <> 1 THEN
        RAISE_APPLICATION_ERROR(-20105, 'High alert did not create exactly one incident');
    END IF;

    SELECT COUNT(*) INTO v_count FROM incident_action WHERE action_id = 902;
    IF v_count <> 0 THEN
        RAISE_APPLICATION_ERROR(-20106, 'DELETE demonstration left the temporary action');
    END IF;

    UPDATE incident SET status = 'RESOLVED' WHERE incident_id = 1000;
    SELECT resolved_time INTO v_resolved_time FROM incident WHERE incident_id = 1000;
    IF v_resolved_time IS NULL THEN
        RAISE_APPLICATION_ERROR(-20107, 'Resolution trigger did not set RESOLVED_TIME');
    END IF;

    DBMS_OUTPUT.PUT_LINE('REVIEW II ORACLE CHECKS PASSED');
    DBMS_OUTPUT.PUT_LINE('12 tables, 10 sample logs, 3 failed logins, one deduplicated alert, one linked incident, and resolution trigger verified.');
END;
/
ROLLBACK;
