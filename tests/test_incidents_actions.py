"""Unit and integration tests for Member 3 incident and action workflows."""

import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from mongomock import MongoClient

from app.auth import create_access_token, hash_password
from app.db import reset_db_override, set_db_override
from app.main import app
from tests.mock_db import MockDatabase


class IncidentActionTests(unittest.TestCase):
    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)

        self.mongo_client = MongoClient()
        self.mock_logs = self.mongo_client.cybersecurity_logs.logs
        app.state.mongo = self.mongo_client
        app.state.logs = self.mock_logs

        self.client = TestClient(app)

        # Seed admin and analyst
        self.admin_pass_hash = hash_password("AdminSecurePass123!")
        self.analyst_pass_hash = hash_password("AnalystSecurePass123!")

        self.admin_id = 1
        self.analyst_id = 2

        self.mock_db.users.append({
            "user_id": self.admin_id,
            "username": "admin_tester",
            "email": "admin@example.com",
            "password_hash": self.admin_pass_hash,
            "role_id": 1,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })

        self.mock_db.users.append({
            "user_id": self.analyst_id,
            "username": "analyst_tester",
            "email": "analyst@example.com",
            "password_hash": self.analyst_pass_hash,
            "role_id": 2,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })

        # Seed an alert
        now_utc = datetime.now(timezone.utc)
        self.alert_id = self.mock_db.next_alert_id()
        self.mock_db.alerts.append({
            "alert_id": self.alert_id,
            "rule_id": 1,
            "threat_id": None,
            "source_ip": "198.51.100.42",
            "severity": "HIGH",
            "title": "Brute Force Alert",
            "description": "Repeated failed logins",
            "status": "OPEN",
            "deduplication_key": "rule_1:FAILED_LOGINS:198.51.100.42",
            "evidence": ["log_1", "log_2"],
            "occurrence_count": 5,
            "first_seen_at": now_utc,
            "last_seen_at": now_utc,
            "created_at": now_utc,
            "updated_at": now_utc,
        })

        self.admin_token = create_access_token(self.admin_id, "admin_tester", "ADMIN")
        self.analyst_token = create_access_token(self.analyst_id, "analyst_tester", "ANALYST")

        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        self.analyst_headers = {"Authorization": f"Bearer {self.analyst_token}"}

    def tearDown(self):
        reset_db_override()
        self.mongo_client.close()

    def test_unauthenticated_requests_denied(self):
        res = self.client.get("/api/incidents")
        self.assertEqual(res.status_code, 401)
        res_post = self.client.post("/api/incidents", json={"title": "Test Incident"})
        self.assertEqual(res_post.status_code, 401)

    def test_create_incident_standalone(self):
        payload = {
            "title": "Suspicious Lateral Movement",
            "description": "Unusual SSH connections detected from internal workstation",
            "severity": "HIGH",
            "status": "OPEN",
            "assigned_to": self.analyst_id,
            "source_ip": "10.0.0.55",
            "tags": ["lateral-movement", "ssh"],
        }
        res = self.client.post("/api/incidents", json=payload, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["title"], "Suspicious Lateral Movement")
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["status"], "OPEN")
        self.assertEqual(data["assigned_to"], self.analyst_id)
        self.assertEqual(data["assigned_to_username"], "analyst_tester")
        self.assertEqual(data["tags"], ["lateral-movement", "ssh"])
        self.assertIsNotNone(data["incident_id"])

    def test_create_incident_from_alert(self):
        payload = {
            "title": "Investigation: Repeated Failed Logins",
            "description": "Originating from external scanner",
            "severity": "HIGH",
            "alert_id": self.alert_id,
            "assigned_to": self.analyst_id,
        }
        res = self.client.post("/api/incidents", json=payload, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["alert_id"], self.alert_id)
        # Should have inherited source_ip from alert if not provided
        self.assertEqual(data["source_ip"], "198.51.100.42")

        # Verify incident details include linked alert
        inc_id = data["incident_id"]
        detail_res = self.client.get(f"/api/incidents/{inc_id}", headers=self.analyst_headers)
        self.assertEqual(detail_res.status_code, 200)
        detail = detail_res.json()
        self.assertEqual(len(detail["alerts"]), 1)
        self.assertEqual(detail["alerts"][0]["alert_id"], self.alert_id)
        # Verify initial audit action recorded
        self.assertGreaterEqual(len(detail["actions"]), 1)
        self.assertEqual(detail["actions"][0]["action_type"], "STATUS_CHANGE")

    def test_update_incident_status_and_actions(self):
        # Create incident
        payload = {
            "title": "Potential Data Exfiltration",
            "severity": "CRITICAL",
            "status": "OPEN",
        }
        create_res = self.client.post("/api/incidents", json=payload, headers=self.admin_headers)
        self.assertEqual(create_res.status_code, 201)
        inc_id = create_res.json()["incident_id"]

        # 1. Update status to INVESTIGATING and assign to analyst
        patch_payload = {
            "status": "INVESTIGATING",
            "assigned_to": self.analyst_id,
        }
        patch_res = self.client.patch(f"/api/incidents/{inc_id}", json=patch_payload, headers=self.analyst_headers)
        self.assertEqual(patch_res.status_code, 200)
        data = patch_res.json()
        self.assertEqual(data["status"], "INVESTIGATING")
        self.assertEqual(data["assigned_to"], self.analyst_id)

        # 2. Add custom investigation action note
        action_payload = {
            "action_type": "INVESTIGATION_STEP",
            "action_details": "Isolated host 10.0.0.55 from VLAN and dumped memory.",
            "metadata": {"action_scope": "endpoint_isolation"},
        }
        act_res = self.client.post(f"/api/incidents/{inc_id}/actions", json=action_payload, headers=self.analyst_headers)
        self.assertEqual(act_res.status_code, 201)
        act_data = act_res.json()
        self.assertEqual(act_data["action_type"], "INVESTIGATION_STEP")
        self.assertEqual(act_data["performed_by_username"], "analyst_tester")

        # 3. Add containment action
        contain_payload = {
            "action_type": "CONTAINMENT",
            "action_details": "Revoked OAuth tokens and blocked malicious IP at perimeter firewall.",
            "metadata": {"ip_blocked": "198.51.100.42"},
        }
        contain_res = self.client.post(f"/api/incidents/{inc_id}/actions", json=contain_payload, headers=self.analyst_headers)
        self.assertEqual(contain_res.status_code, 201)

        # 4. Resolve incident
        resolve_res = self.client.patch(f"/api/incidents/{inc_id}", json={"status": "RESOLVED"}, headers=self.analyst_headers)
        self.assertEqual(resolve_res.status_code, 200)
        self.assertEqual(resolve_res.json()["status"], "RESOLVED")

        # 5. Verify action history in get incident
        get_res = self.client.get(f"/api/incidents/{inc_id}", headers=self.analyst_headers)
        actions = get_res.json()["actions"]
        # Expected actions: initial creation, status change to INVESTIGATING, assignment, investigation step, containment, status change to RESOLVED
        self.assertGreaterEqual(len(actions), 5)

    def test_list_and_filter_incidents(self):
        # Create 3 incidents with different severity and status
        self.client.post(
            "/api/incidents",
            json={"title": "Incident 1", "severity": "LOW", "status": "OPEN"},
            headers=self.analyst_headers,
        )
        self.client.post(
            "/api/incidents",
            json={"title": "Incident 2", "severity": "HIGH", "status": "INVESTIGATING", "assigned_to": self.analyst_id},
            headers=self.analyst_headers,
        )
        self.client.post(
            "/api/incidents",
            json={"title": "Incident 3", "severity": "CRITICAL", "status": "RESOLVED"},
            headers=self.analyst_headers,
        )

        # Filter by status OPEN
        res_open = self.client.get("/api/incidents?status=OPEN", headers=self.analyst_headers)
        self.assertEqual(res_open.status_code, 200)
        self.assertTrue(all(item["status"] == "OPEN" for item in res_open.json()["items"]))

        # Filter by severity HIGH
        res_high = self.client.get("/api/incidents?severity=HIGH", headers=self.analyst_headers)
        self.assertEqual(res_high.status_code, 200)
        self.assertTrue(all(item["severity"] == "HIGH" for item in res_high.json()["items"]))

        # Filter by assigned_to
        res_assigned = self.client.get(f"/api/incidents?assigned_to={self.analyst_id}", headers=self.analyst_headers)
        self.assertEqual(res_assigned.status_code, 200)
        self.assertTrue(all(item["assigned_to"] == self.analyst_id for item in res_assigned.json()["items"]))

    def test_invalid_input_validation(self):
        # Bad severity
        res = self.client.post("/api/incidents", json={"title": "Bad Sev", "severity": "EXTREME"}, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 422)

        # Bad status
        res = self.client.post("/api/incidents", json={"title": "Bad Status", "status": "PENDING"}, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 422)

        # Bad action type
        create_res = self.client.post("/api/incidents", json={"title": "Valid"}, headers=self.analyst_headers)
        inc_id = create_res.json()["incident_id"]
        res_act = self.client.post(f"/api/incidents/{inc_id}/actions", json={"action_type": "UNKNOWN_ACTION", "action_details": "test"}, headers=self.analyst_headers)
        self.assertEqual(res_act.status_code, 422)


if __name__ == "__main__":
    unittest.main()
