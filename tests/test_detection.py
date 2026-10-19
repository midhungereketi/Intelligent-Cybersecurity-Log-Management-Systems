"""Tests for detection rules (failed logins, port scans, excessive activity), threat correlation, and alert deduplication."""

import unittest
from datetime import datetime, timedelta, timezone
from bson import ObjectId

from app.db import reset_db_override, set_db_override
from app.detection import (
    RuleDefinition,
    detect_excessive_activity,
    detect_failed_logins,
    detect_port_scans,
    execute_detection,
    process_match,
)
from tests.mock_db import MockDatabase


def _make_log(event_type: str, source_ip: str, ts: datetime, **extra) -> dict:
    d = {
        "_id": ObjectId(),
        "timestamp": ts,
        "source_ip": source_ip,
        "event_type": event_type,
        "severity": "HIGH" if event_type == "LOGIN_FAILED" else "LOW",
        "message": f"Log event for {event_type}",
    }
    d.update(extra)
    return d


class DetectionUnitTests(unittest.TestCase):
    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)
        self.base_time = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)

        # Reference rules from seed
        self.rule_failed_login = RuleDefinition(
            rule_id=1,
            rule_name="Repeated Failed Logins",
            rule_type="FAILED_LOGINS",
            threshold=5,
            time_window_seconds=300,
            severity="HIGH",
            is_enabled=True,
            configuration={"target_event": "LOGIN_FAILED"},
        )
        self.rule_port_scan = RuleDefinition(
            rule_id=2,
            rule_name="Possible Port Scan",
            rule_type="PORT_SCAN",
            threshold=20,
            time_window_seconds=60,
            severity="HIGH",
            is_enabled=True,
            configuration={"target_event": "CONNECTION"},
        )
        self.rule_excessive = RuleDefinition(
            rule_id=3,
            rule_name="Excessive Activity from Single IP",
            rule_type="EXCESSIVE_ACTIVITY",
            threshold=100,
            time_window_seconds=60,
            severity="MEDIUM",
            is_enabled=True,
            configuration={},
        )

    def tearDown(self):
        reset_db_override()

    def test_failed_logins_exceeding_threshold_triggers_alert(self):
        # 6 failed logins within 60 seconds (threshold is 5 in 300s)
        logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", self.base_time + timedelta(seconds=i * 10), username="admin")
            for i in range(6)
        ]
        matches = detect_failed_logins(logs, self.rule_failed_login)
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m.source_ip, "198.51.100.10")
        self.assertEqual(m.threat_type, "BRUTE_FORCE_AUTH")
        self.assertEqual(m.severity, "HIGH")
        self.assertEqual(len(m.qualifying_log_ids), 6)
        self.assertEqual(len(m.evidence), 6)
        self.assertIn("198.51.100.10", m.description)

    def test_failed_logins_below_threshold_does_not_trigger(self):
        # 4 failed logins (threshold is 5)
        logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", self.base_time + timedelta(seconds=i * 10))
            for i in range(4)
        ]
        matches = detect_failed_logins(logs, self.rule_failed_login)
        self.assertEqual(len(matches), 0)

    def test_failed_logins_outside_window_not_grouped(self):
        # 5 failed logins, but spaced 10 minutes apart (window is 300s / 5m)
        logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", self.base_time + timedelta(minutes=i * 10))
            for i in range(5)
        ]
        matches = detect_failed_logins(logs, self.rule_failed_login)
        self.assertEqual(len(matches), 0)

    def test_port_scan_exceeding_distinct_ports_triggers_alert(self):
        # 22 connections to distinct destination ports from 198.51.100.20 within 30s
        logs = [
            _make_log("CONNECTION", "198.51.100.20", self.base_time + timedelta(seconds=i), destination_port=1000 + i)
            for i in range(22)
        ]
        matches = detect_port_scans(logs, self.rule_port_scan)
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m.source_ip, "198.51.100.20")
        self.assertEqual(m.threat_type, "PORT_SCAN")
        self.assertEqual(len(m.qualifying_log_ids), 22)

    def test_ordinary_traffic_to_same_port_is_not_flagged_as_port_scan(self):
        # 50 connections from same IP, but all to destination port 443 (only 1 distinct port, threshold 20)
        logs = [
            _make_log("CONNECTION", "198.51.100.20", self.base_time + timedelta(seconds=i), destination_port=443)
            for i in range(50)
        ]
        matches = detect_port_scans(logs, self.rule_port_scan)
        self.assertEqual(len(matches), 0)

    def test_excessive_activity_triggers_alert(self):
        # 105 events from 198.51.100.30 within 40 seconds (threshold 100 in 60s)
        logs = [
            _make_log("ACCESS", "198.51.100.30", self.base_time + timedelta(milliseconds=i * 300))
            for i in range(105)
        ]
        matches = detect_excessive_activity(logs, self.rule_excessive)
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m.source_ip, "198.51.100.30")
        self.assertEqual(m.threat_type, "EXCESSIVE_TRAFFIC_BURST")
        self.assertEqual(m.severity, "MEDIUM")

    def test_malformed_logs_do_not_crash_detection(self):
        bad_logs = [
            {"not_a_valid_log": True},
            {"timestamp": "corrupt-date", "source_ip": "1.2.3.4", "event_type": "LOGIN_FAILED"},
            {"timestamp": self.base_time, "source_ip": None, "event_type": "LOGIN_FAILED"},
            {"timestamp": self.base_time, "source_ip": "1.2.3.4", "destination_port": "invalid_port"},
        ]
        # None of the detectors should raise exceptions
        self.assertEqual(detect_failed_logins(bad_logs, self.rule_failed_login), [])
        self.assertEqual(detect_port_scans(bad_logs, self.rule_port_scan), [])
        self.assertEqual(detect_excessive_activity(bad_logs, self.rule_excessive), [])

    def test_alert_deduplication_and_idempotency(self):
        logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", self.base_time + timedelta(seconds=i * 5))
            for i in range(6)
        ]
        matches = detect_failed_logins(logs, self.rule_failed_login)
        self.assertEqual(len(matches), 1)
        match = matches[0]

        conn = self.mock_db.get_connection()

        # First run: should create new OPEN alert
        res1 = process_match(conn, match)
        self.assertEqual(res1["action"], "created")
        alert_id = res1["alert_id"]
        self.assertEqual(res1["occurrence_count"], 6)

        alert_record = next(a for a in self.mock_db.alerts if a["alert_id"] == alert_id)
        self.assertEqual(alert_record["status"], "OPEN")
        self.assertEqual(alert_record["occurrence_count"], 6)

        # Threat should be correlated
        threat_record = next(t for t in self.mock_db.threats if t["source_ip"] == "198.51.100.10")
        self.assertEqual(threat_record["threat_type"], "BRUTE_FORCE_AUTH")

        # Second run with EXACT same historical events (replay): IDEMPOTENT NO-OP!
        res2 = process_match(conn, match)
        self.assertEqual(res2["action"], "unchanged")
        self.assertEqual(res2["alert_id"], alert_id)
        self.assertEqual(res2["occurrence_count"], 6)

        # Verify no duplicate alert was created in DB
        matching_alerts = [a for a in self.mock_db.alerts if a["deduplication_key"] == match.deduplication_key]
        self.assertEqual(len(matching_alerts), 1)
        self.assertEqual(matching_alerts[0]["occurrence_count"], 6)

        # Third run: 3 NEW failed login events arrive
        new_logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", self.base_time + timedelta(seconds=60 + i * 5))
            for i in range(3)
        ]
        all_logs = logs + new_logs
        match_updated = detect_failed_logins(all_logs, self.rule_failed_login)[0]

        res3 = process_match(conn, match_updated)
        self.assertEqual(res3["action"], "updated")
        self.assertEqual(res3["alert_id"], alert_id)
        # Occurrence count increments only by new events: 6 + 3 = 9!
        updated_alert = next(a for a in self.mock_db.alerts if a["alert_id"] == alert_id)
        self.assertEqual(updated_alert["occurrence_count"], 9)

    def test_resolved_alert_behavior_on_new_suspicious_activity(self):
        logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", self.base_time + timedelta(seconds=i * 5))
            for i in range(6)
        ]
        match1 = detect_failed_logins(logs, self.rule_failed_login)[0]
        conn = self.mock_db.get_connection()
        res1 = process_match(conn, match1)
        first_alert_id = res1["alert_id"]

        # Analyst resolves the first alert
        first_alert = next(a for a in self.mock_db.alerts if a["alert_id"] == first_alert_id)
        first_alert["status"] = "RESOLVED"

        # A new attack happens 2 hours later
        later_time = self.base_time + timedelta(hours=2)
        new_attack_logs = [
            _make_log("LOGIN_FAILED", "198.51.100.10", later_time + timedelta(seconds=i * 5))
            for i in range(6)
        ]
        match2 = detect_failed_logins(new_attack_logs, self.rule_failed_login)[0]
        res2 = process_match(conn, match2)

        # Because the previous alert was RESOLVED, a new OPEN alert should be created!
        self.assertEqual(res2["action"], "created")
        second_alert_id = res2["alert_id"]
        self.assertNotEqual(first_alert_id, second_alert_id)

        second_alert = next(a for a in self.mock_db.alerts if a["alert_id"] == second_alert_id)
        self.assertEqual(second_alert["status"], "OPEN")
        self.assertEqual(first_alert["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()
