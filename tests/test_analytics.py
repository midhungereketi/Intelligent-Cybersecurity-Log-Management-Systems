"""Unit tests for analytics endpoints."""

import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from mongomock import MongoClient

from app.auth import create_access_token, hash_password
from app.db import reset_db_override, set_db_override
from app.main import app
from tests.mock_db import MockDatabase


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)

        self.mongo_client = MongoClient()
        self.mock_logs = self.mongo_client.cybersecurity_logs.logs
        app.state.mongo = self.mongo_client
        app.state.logs = self.mock_logs

        self.client = TestClient(app)

        # Seed mock logs
        self.mock_logs.insert_many([
            {
                "timestamp": "2026-10-01T10:00:00Z",
                "source_ip": "198.51.100.10",
                "event_type": "LOGIN_FAILED",
                "severity": "HIGH",
                "message": "Failed login for admin",
            },
            {
                "timestamp": "2026-10-01T10:05:00Z",
                "source_ip": "198.51.100.10",
                "event_type": "LOGIN_FAILED",
                "severity": "HIGH",
                "message": "Failed login for admin",
            },
            {
                "timestamp": "2026-10-01T11:00:00Z",
                "source_ip": "198.51.100.20",
                "event_type": "CONNECTION",
                "severity": "LOW",
                "message": "Established connection",
            },
            {
                "timestamp": "2026-10-01T11:30:00Z",
                "source_ip": "198.51.100.30",
                "event_type": "PORT_SCAN",
                "severity": "CRITICAL",
                "message": "Rapid probe of multiple ports",
            },
        ])

        # Seed an admin user and generate auth token
        self.admin_pass_hash = hash_password("AdminSecurePass123!")
        self.admin_id = 1
        self.mock_db.users.append({
            "user_id": self.admin_id,
            "username": "admin_analytics",
            "email": "admin_analytics@example.com",
            "password_hash": self.admin_pass_hash,
            "role_id": 1,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })

        now_utc = datetime.now(timezone.utc)
        self.mock_db.alerts.append({
            "alert_id": 1,
            "rule_id": 1,
            "threat_id": None,
            "source_ip": "198.51.100.10",
            "severity": "HIGH",
            "title": "Test Alert",
            "description": "Test alert desc",
            "status": "OPEN",
            "deduplication_key": "rule_1:FAILED:198.51.100.10",
            "evidence": [],
            "occurrence_count": 2,
            "first_seen_at": now_utc,
            "last_seen_at": now_utc,
            "created_at": now_utc,
            "updated_at": now_utc,
        })
        self.mock_db.incidents.append({
            "incident_id": 1,
            "title": "Test Incident",
            "description": "Test desc",
            "severity": "HIGH",
            "status": "OPEN",
            "assigned_to": self.admin_id,
            "created_by": self.admin_id,
            "alert_id": None,
            "source_ip": "198.51.100.10",
            "tags": [],
            "evidence": [],
            "created_at": now_utc,
            "updated_at": now_utc,
            "resolved_at": None,
        })

        self.token = create_access_token(self.admin_id, "admin_analytics", "ADMIN")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        reset_db_override()
        self.mongo_client.close()

    def test_dashboard_summary(self):
        res = self.client.get("/api/analytics/dashboard", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["logs"]["total"], 4)
        self.assertEqual(data["logs"]["by_severity"]["HIGH"], 2)
        self.assertEqual(data["logs"]["by_severity"]["LOW"], 1)
        self.assertEqual(data["logs"]["by_severity"]["CRITICAL"], 1)
        self.assertGreaterEqual(data["alerts"]["total"], 1)
        self.assertGreaterEqual(data["incidents"]["total"], 1)
        self.assertIn("recent", data["alerts"])
        self.assertIn("recent", data["incidents"])

    def test_events_timeline(self):
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)
        first = items[0]
        self.assertIn("time", first)
        self.assertIn("total", first)
        self.assertIn("high", first)

    def test_events_timeline_date_objects(self):
        # Insert logs with Python datetime objects (as normalized by logs.normalize)
        self.mock_logs.insert_many([
            {
                "timestamp": datetime(2026, 10, 2, 14, 15, tzinfo=timezone.utc),
                "source_ip": "10.0.0.1",
                "event_type": "LOGIN_SUCCESS",
                "severity": "LOW",
                "message": "Auth ok",
            },
            {
                "timestamp": datetime(2026, 10, 2, 14, 45, tzinfo=timezone.utc),
                "source_ip": "10.0.0.2",
                "event_type": "FAILED_LOGIN",
                "severity": "CRITICAL",
                "message": "Auth failed",
            },
        ])
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertGreaterEqual(len(items), 2)
        # Check that the 2026-10-02T14 bucket exists and aggregated properly
        bucket_14 = next((i for i in items if i["time"] == "2026-10-02T14:00Z"), None)
        self.assertIsNotNone(bucket_14)
        self.assertEqual(bucket_14["total"], 2)
        self.assertEqual(bucket_14["critical"], 1)
        self.assertEqual(bucket_14["low"], 1)

    def test_top_sources(self):
        res = self.client.get("/api/analytics/top-sources", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)
        # 198.51.100.10 has 2 logs, so it should be first
        self.assertEqual(items[0]["source_ip"], "198.51.100.10")
        self.assertEqual(items[0]["total"], 2)

    def test_event_types(self):
        res = self.client.get("/api/analytics/event-types", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        types = {item["event_type"]: item["count"] for item in items}
        self.assertEqual(types.get("LOGIN_FAILED"), 2)
        self.assertEqual(types.get("CONNECTION"), 1)
        self.assertEqual(types.get("PORT_SCAN"), 1)


if __name__ == "__main__":
    unittest.main()
