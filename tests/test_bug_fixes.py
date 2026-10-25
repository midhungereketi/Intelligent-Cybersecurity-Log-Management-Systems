"""Regression tests for bugs found in the full-project review."""

import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

from app.detection import get_checkpoint, save_checkpoint
from app.logs import ingest, parse_upload
from app.main import app
from tests import test_incidents_actions


class _FailingConnection:
    """Stands in for psycopg: every statement fails, savepoint use is recorded."""

    def __init__(self):
        self.savepoints = 0

    @contextmanager
    def transaction(self):
        self.savepoints += 1
        yield

    def execute(self, *_args, **_kwargs):
        raise RuntimeError("relation detection_checkpoints does not exist")


class CheckpointSavepointTests(unittest.TestCase):
    def test_checkpoint_errors_are_isolated_in_a_savepoint(self):
        conn = _FailingConnection()
        self.assertIsNone(get_checkpoint(conn, "default"))
        save_checkpoint(conn, "default", datetime.now(timezone.utc), "abc")
        # Without savepoints the swallowed error would abort the whole detection transaction
        self.assertEqual(conn.savepoints, 2)


class UploadParsingTests(unittest.TestCase):
    def test_malformed_jsonl_line_is_rejected_not_fatal(self):
        good = '{"timestamp": "2026-10-01T10:00:00Z", "source_ip": "198.51.100.10", ' \
               '"event_type": "LOGIN_FAILED", "severity": "HIGH", "message": "x"}'
        content = f"{good}\n{{not json\n{good}\n".encode()

        class Collection:
            inserted = []

            def insert_many(self, docs, ordered=True):
                self.inserted.extend(docs)

                class Result:
                    inserted_ids = list(range(len(docs)))
                return Result()

        result = ingest(Collection(), parse_upload(content, "events.jsonl"))
        self.assertEqual(result["inserted"], 2)
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["errors"][0]["row"], 2)


class ApiBugFixTests(unittest.TestCase):
    def setUp(self):
        test_incidents_actions.IncidentActionTests.setUp(self)

    def tearDown(self):
        test_incidents_actions.IncidentActionTests.tearDown(self)

    def _incident(self, **extra):
        payload = {"title": "Case", "severity": "HIGH", **extra}
        res = self.client.post("/api/incidents", json=payload, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def test_reopening_incident_clears_resolved_at(self):
        inc = self._incident()
        url = f"/api/incidents/{inc['incident_id']}"
        resolved = self.client.patch(url, json={"status": "RESOLVED"}, headers=self.analyst_headers).json()
        self.assertIsNotNone(resolved["resolved_at"])
        reopened = self.client.patch(url, json={"status": "INVESTIGATING"}, headers=self.analyst_headers).json()
        self.assertIsNone(reopened["resolved_at"])

    def test_explicit_null_unassigns_incident(self):
        inc = self._incident(assigned_to=self.analyst_id)
        url = f"/api/incidents/{inc['incident_id']}"
        res = self.client.patch(url, json={"assigned_to": None}, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(res.json()["assigned_to"])
        # Omitting the field still leaves the assignment unchanged
        self.client.patch(url, json={"assigned_to": self.analyst_id}, headers=self.analyst_headers)
        res = self.client.patch(url, json={"title": "Renamed"}, headers=self.analyst_headers)
        self.assertEqual(res.json()["assigned_to"], self.analyst_id)

    def test_invalid_incident_source_ip_is_422(self):
        res = self.client.post("/api/incidents", json={"title": "Bad", "source_ip": "not-an-ip"},
                               headers=self.analyst_headers)
        self.assertEqual(res.status_code, 422)

    def test_invalid_alert_and_threat_filters_are_422(self):
        for path in ("/api/alerts", "/api/threats"):
            self.assertEqual(self.client.get(f"{path}?start=yesterday", headers=self.analyst_headers).status_code, 422)
            self.assertEqual(self.client.get(f"{path}?source_ip=999.1.1.1", headers=self.analyst_headers).status_code, 422)
            self.assertEqual(
                self.client.get(f"{path}?start=2026-10-01T00:00:00Z", headers=self.analyst_headers).status_code, 200)

    def test_detection_rejects_unparseable_window(self):
        res = self.client.post("/api/detection/run", json={"start": "last week"}, headers=self.analyst_headers)
        self.assertEqual(res.status_code, 422)
        res = self.client.post("/api/detection/run",
                               json={"start": "2026-10-02T00:00:00Z", "end": "2026-10-01T00:00:00Z"},
                               headers=self.analyst_headers)
        self.assertEqual(res.status_code, 422)

    def test_login_expires_in_follows_configuration(self):
        with patch.dict("os.environ", {"JWT_EXPIRE_MINUTES": "15"}):
            res = self.client.post("/api/auth/login",
                                   json={"username": "analyst_tester", "password": "AnalystSecurePass123!"})
            self.assertEqual(res.status_code, 200, res.text)
            self.assertEqual(res.json()["expires_in"], 15 * 60)

    def test_dashboard_counts_investigating_and_contained_as_active(self):
        for status in ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"):
            self._incident(status=status)
        res = self.client.get("/api/analytics/dashboard", headers=self.analyst_headers)
        incidents = res.json()["incidents"]
        self.assertEqual(incidents["active"], 3)
        self.assertEqual(incidents["contained"], 1)
        self.assertEqual(incidents["resolved"], 1)

    def test_user_validation_rejects_ambiguous_usernames_and_bad_emails(self):
        base = {"password": "LongEnough123!", "role_id": 2}
        bad = [
            {"username": "someone@example.com", "email": "a@example.com"},
            {"username": "valid_name", "email": "not-an-email"},
        ]
        for payload in bad:
            res = self.client.post("/api/users", json={**base, **payload}, headers=self.admin_headers)
            self.assertEqual(res.status_code, 422, payload)
        ok = self.client.post("/api/users", json={**base, "username": "new.analyst", "email": "new@example.local"},
                              headers=self.admin_headers)
        self.assertEqual(ok.status_code, 201, ok.text)

    def test_health_reports_503_when_mongo_is_down(self):
        from pymongo.errors import ServerSelectionTimeoutError

        class Admin:
            @staticmethod
            def command(*_args):
                raise ServerSelectionTimeoutError("down")

        class DownClient:
            admin = Admin()

        app.state.mongo = DownClient()
        self.assertEqual(self.client.get("/health").status_code, 503)


if __name__ == "__main__":
    unittest.main()
