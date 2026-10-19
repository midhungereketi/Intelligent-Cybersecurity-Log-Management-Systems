"""End-to-end integration tests for Member 1 ingestion -> Detection -> Threats & Alerts -> Member 3 Dashboard APIs."""

import json
import unittest
from datetime import datetime, timedelta, timezone

import mongomock
from fastapi.testclient import TestClient

from app.auth import create_access_token, hash_password
from app.db import reset_db_override, set_db_override
from app.logs import ingest, normalize
from app.main import app
from scripts.generate_logs import generate
from tests.mock_db import MockDatabase


class APIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)

        # Mock MongoDB
        self.mongo_client = mongomock.MongoClient()
        self.logs_collection = self.mongo_client.cybersecurity_logs.logs
        app.state.mongo = self.mongo_client
        app.state.logs = self.logs_collection

        # Seed Admin and Analyst accounts
        self.admin_pwd = "AdminStrongPass123!"
        self.analyst_pwd = "AnalystStrongPass123!"

        self.mock_db.users.append({
            "user_id": 1,
            "username": "superadmin",
            "email": "admin@cyber.local",
            "password_hash": hash_password(self.admin_pwd),
            "role_id": 1,  # ADMIN
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })
        self.mock_db.users.append({
            "user_id": 2,
            "username": "tier1analyst",
            "email": "analyst@cyber.local",
            "password_hash": hash_password(self.analyst_pwd),
            "role_id": 2,  # ANALYST
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })

        self.client = TestClient(app)

        # Tokens
        self.admin_token = create_access_token(1, "superadmin", "ADMIN")
        self.analyst_token = create_access_token(2, "tier1analyst", "ANALYST")

    def tearDown(self):
        reset_db_override()

    def test_full_pipeline_ingest_detect_alert_lifecycle(self):
        # 1. Generate and ingest 100 deterministic logs (contains 25 failed logins from 198.51.100.10,
        #    35 port scan events from 198.51.100.20, and 40 burst events from 198.51.100.30)
        raw_events = list(generate(count=100, seed=42))
        rows = [(idx + 1, ev) for idx, ev in enumerate(raw_events)]
        ingest_res = ingest(self.logs_collection, rows)
        self.assertEqual(ingest_res["inserted"], 100)
        self.assertEqual(ingest_res["rejected"], 0)

        # 2. Run detection endpoint with Analyst credentials
        resp_detect = self.client.post(
            "/api/detection/run",
            json={"limit": 500},
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_detect.status_code, 200)
        summary = resp_detect.json()
        self.assertEqual(summary["status"], "success")
        self.assertEqual(summary["logs_scanned"], 100)
        self.assertGreaterEqual(summary["alerts_created"], 2)

        # 3. Retrieve alerts via GET /api/alerts
        resp_alerts = self.client.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_alerts.status_code, 200)
        alerts_data = resp_alerts.json()
        self.assertIn("items", alerts_data)
        self.assertGreaterEqual(len(alerts_data["items"]), 2)

        # Find the failed login alert
        failed_login_alert = next(
            (a for a in alerts_data["items"] if a["source_ip"] == "198.51.100.10"),
            None,
        )
        self.assertIsNotNone(failed_login_alert)
        self.assertEqual(failed_login_alert["status"], "OPEN")
        self.assertEqual(failed_login_alert["severity"], "HIGH")
        self.assertGreaterEqual(len(failed_login_alert["evidence"]), 5)

        alert_id = failed_login_alert["alert_id"]

        # 4. View single alert details with GET /api/alerts/{alert_id}
        resp_detail = self.client.get(
            f"/api/alerts/{alert_id}",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_detail.status_code, 200)
        self.assertEqual(resp_detail.json()["alert_id"], alert_id)

        # 5. Acknowledge alert with POST /api/alerts/{alert_id}/acknowledge
        resp_ack = self.client.post(
            f"/api/alerts/{alert_id}/acknowledge",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_ack.status_code, 200)
        self.assertEqual(resp_ack.json()["status"], "ACKNOWLEDGED")

        # 6. Resolve alert with POST /api/alerts/{alert_id}/resolve
        resp_resolve = self.client.post(
            f"/api/alerts/{alert_id}/resolve",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_resolve.status_code, 200)
        self.assertEqual(resp_resolve.json()["status"], "RESOLVED")

        # 7. Cannot acknowledge a resolved alert
        resp_ack_again = self.client.post(
            f"/api/alerts/{alert_id}/acknowledge",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_ack_again.status_code, 400)

        # 8. Filter alerts by status
        resp_resolved = self.client.get(
            "/api/alerts?status=RESOLVED",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_resolved.status_code, 200)
        self.assertTrue(all(a["status"] == "RESOLVED" for a in resp_resolved.json()["items"]))

        # 9. Threat tracking via GET /api/threats
        resp_threats = self.client.get(
            "/api/threats",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_threats.status_code, 200)
        threats_data = resp_threats.json()
        self.assertGreaterEqual(len(threats_data["items"]), 1)

        threat_id = threats_data["items"][0]["threat_id"]
        resp_threat_detail = self.client.get(
            f"/api/threats/{threat_id}",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_threat_detail.status_code, 200)
        self.assertIn("alerts", resp_threat_detail.json())

    def test_rule_management_and_rbac(self):
        # List rules as Analyst
        resp_rules = self.client.get(
            "/api/rules",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_rules.status_code, 200)
        rules = resp_rules.json()
        self.assertEqual(len(rules), 3)

        rule_id = rules[0]["rule_id"]

        # Analyst tries to modify rule -> 403 Forbidden
        resp_analyst_patch = self.client.patch(
            f"/api/rules/{rule_id}",
            json={"threshold": 10},
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(resp_analyst_patch.status_code, 403)

        # Admin updates threshold
        resp_admin_patch = self.client.patch(
            f"/api/rules/{rule_id}",
            json={"threshold": 10},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(resp_admin_patch.status_code, 200)
        self.assertEqual(resp_admin_patch.json()["threshold"], 10)

        # Non-positive threshold rejected
        resp_bad_thresh = self.client.patch(
            f"/api/rules/{rule_id}",
            json={"threshold": 0},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(resp_bad_thresh.status_code, 422)

        # Admin creates new rule
        new_rule_payload = {
            "rule_name": "Custom SSH Brute Force",
            "description": "Custom rule",
            "rule_type": "FAILED_LOGINS",
            "threshold": 3,
            "time_window_seconds": 120,
            "severity": "CRITICAL",
            "is_enabled": True,
        }
        resp_create_rule = self.client.post(
            "/api/rules",
            json=new_rule_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(resp_create_rule.status_code, 201)
        self.assertEqual(resp_create_rule.json()["severity"], "CRITICAL")

    def test_member1_endpoints_remain_functional(self):
        # GET /health
        resp_health = self.client.get("/health")
        self.assertEqual(resp_health.status_code, 200)
        self.assertEqual(resp_health.json(), {"status": "ok"})

        # POST /api/logs/events
        event_payload = {
            "timestamp": "2026-10-01T12:00:00Z",
            "source_ip": "198.51.100.99",
            "event_type": "ACCESS",
            "severity": "LOW",
            "message": "Routine access",
        }
        resp_event = self.client.post("/api/logs/events", json=event_payload)
        self.assertEqual(resp_event.status_code, 201)
        self.assertEqual(resp_event.json()["source_ip"], "198.51.100.99")

        # GET /api/logs
        resp_logs = self.client.get("/api/logs?source_ip=198.51.100.99")
        self.assertEqual(resp_logs.status_code, 200)
        self.assertEqual(len(resp_logs.json()["items"]), 1)

        # GET /api/devices
        resp_devices = self.client.get("/api/devices")
        self.assertEqual(resp_devices.status_code, 200)


if __name__ == "__main__":
    unittest.main()
