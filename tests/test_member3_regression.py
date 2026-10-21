"""Regression tests for Requirement 1 (timeline date handling), Requirement 2
(time-range search filters and Reset), and Requirement 4 (analyst assignable
users endpoint).

These tests exercise the backend through the FastAPI TestClient with
mongomock and the in-memory MockDatabase, so they run without a real
MongoDB or PostgreSQL instance.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient
from mongomock import MongoClient

from app.auth import create_access_token, hash_password
from app.db import reset_db_override, set_db_override
from app.logs import normalize
from app.main import app
from tests.mock_db import MockDatabase


def _seed_users(mock_db: MockDatabase):
    """Seed a standard admin + analyst pair into mock_db."""
    mock_db.users.append({
        "user_id": 1,
        "username": "admin_reg",
        "email": "admin_reg@example.local",
        "password_hash": hash_password("AdminSecurePass123!"),
        "role_id": 1,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_login_at": None,
    })
    mock_db.users.append({
        "user_id": 2,
        "username": "analyst_reg",
        "email": "analyst_reg@example.local",
        "password_hash": hash_password("AnalystSecurePass123!"),
        "role_id": 2,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_login_at": None,
    })


class TimelineRegressionTests(unittest.TestCase):
    """Requirement 1: timeline handles MongoDB Date objects, ISO strings, empty
    datasets, and invalid timestamps correctly."""

    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)
        _seed_users(self.mock_db)

        self.mongo_client = MongoClient()
        self.col = self.mongo_client.test_db.logs
        app.state.mongo = self.mongo_client
        app.state.logs = self.col

        self.client = TestClient(app)
        self.token = create_access_token(1, "admin_reg", "ADMIN")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        reset_db_override()
        self.mongo_client.close()

    # ── 1a: empty collection ────────────────────────────────────────────
    def test_timeline_empty_dataset(self):
        """GET /api/analytics/events-timeline returns [] when no logs exist."""
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), [])

    # ── 1b: ISO-8601 string timestamps (legacy / test-seeded data) ──────
    def test_timeline_string_timestamps(self):
        """Timeline aggregates correctly when timestamps are ISO-8601 strings."""
        self.col.insert_many([
            {
                "timestamp": "2026-10-01T10:00:00Z",
                "source_ip": "10.0.0.1",
                "event_type": "LOGIN_FAILED",
                "severity": "HIGH",
                "message": "string ts 1",
            },
            {
                "timestamp": "2026-10-01T10:30:00Z",
                "source_ip": "10.0.0.2",
                "event_type": "CONNECTION",
                "severity": "LOW",
                "message": "string ts 2",
            },
            {
                "timestamp": "2026-10-01T11:00:00Z",
                "source_ip": "10.0.0.3",
                "event_type": "PORT_SCAN",
                "severity": "CRITICAL",
                "message": "string ts 3",
            },
        ])
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 2)  # at least 2 distinct hours

        totals = {item["time"][:13]: item["total"] for item in items}
        self.assertEqual(totals.get("2026-10-01T10"), 2)
        self.assertEqual(totals.get("2026-10-01T11"), 1)

        # Chronological order
        times = [item["time"] for item in items]
        self.assertEqual(times, sorted(times))

        # Correct severity buckets
        hour10 = next(i for i in items if i["time"].startswith("2026-10-01T10"))
        self.assertEqual(hour10["high"], 1)
        self.assertEqual(hour10["low"], 1)

    # ── 1c: MongoDB Date objects (production path) ───────────────────────
    def test_timeline_date_objects(self):
        """Timeline handles BSON Date objects (datetime) stored by logs.normalize."""
        # normalize() stores timestamp as a datetime object
        events = [
            {
                "timestamp": datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc),
                "source_ip": "10.0.0.10",
                "event_type": "FIREWALL_BLOCK",
                "severity": "MEDIUM",
                "message": "datetime ts 1",
            },
            {
                "timestamp": datetime(2026, 10, 2, 9, 45, tzinfo=timezone.utc),
                "source_ip": "10.0.0.11",
                "event_type": "FIREWALL_BLOCK",
                "severity": "CRITICAL",
                "message": "datetime ts 2",
            },
        ]
        self.col.insert_many(events)

        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)

        hour09 = next((i for i in items if i["time"].startswith("2026-10-02T09")), None)
        self.assertIsNotNone(hour09, "Expected bucket for 2026-10-02T09 not found")
        self.assertEqual(hour09["total"], 2)
        self.assertEqual(hour09["critical"], 1)
        self.assertEqual(hour09["medium"], 1)

    # ── 1d: mixed Date + string timestamps ───────────────────────────────
    def test_timeline_mixed_timestamps(self):
        """Timeline merges Date-type and string-type buckets correctly."""
        self.col.insert_many([
            {
                "timestamp": datetime(2026, 10, 3, 14, 0, tzinfo=timezone.utc),
                "source_ip": "1.2.3.4",
                "event_type": "MALWARE",
                "severity": "HIGH",
                "message": "date type",
            },
            {
                "timestamp": "2026-10-03T14:30:00Z",
                "source_ip": "1.2.3.5",
                "event_type": "MALWARE",
                "severity": "LOW",
                "message": "string type",
            },
        ])
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()

        hour14 = next((i for i in items if i["time"].startswith("2026-10-03T14")), None)
        self.assertIsNotNone(hour14, "Expected merged bucket for 2026-10-03T14")
        self.assertEqual(hour14["total"], 2)
        self.assertEqual(hour14["high"], 1)
        self.assertEqual(hour14["low"], 1)

    # ── 1e: invalid / missing timestamp fields ────────────────────────────
    def test_timeline_invalid_timestamps_ignored(self):
        """Documents with missing or invalid timestamps are silently skipped."""
        self.col.insert_many([
            # No timestamp field at all
            {"source_ip": "1.2.3.4", "event_type": "SCAN", "severity": "HIGH", "message": "no ts"},
            # timestamp is an integer (invalid type)
            {"timestamp": 1234567890, "source_ip": "1.2.3.4", "event_type": "SCAN", "severity": "HIGH", "message": "int ts"},
            # valid string timestamp — should still appear
            {"timestamp": "2026-10-04T08:00:00Z", "source_ip": "1.2.3.5",
             "event_type": "CONNECTION", "severity": "LOW", "message": "valid"},
        ])
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()
        # Only the one valid log should produce a bucket
        totals_sum = sum(i["total"] for i in items)
        self.assertEqual(totals_sum, 1)

    # ── 1f: timeline time field format ───────────────────────────────────
    def test_timeline_time_field_ends_with_z(self):
        """Each timeline item's 'time' field ends with ':00Z'."""
        self.col.insert_one({
            "timestamp": "2026-10-05T12:00:00Z",
            "source_ip": "9.9.9.9",
            "event_type": "SCAN",
            "severity": "MEDIUM",
            "message": "format check",
        })
        res = self.client.get("/api/analytics/events-timeline", headers=self.headers)
        items = res.json()
        for item in items:
            self.assertTrue(item["time"].endswith(":00Z"),
                            f"Expected time ending in ':00Z', got: {item['time']}")


class TimeRangeSearchTests(unittest.TestCase):
    """Requirement 2: start/end time filters work correctly in the backend
    log search endpoint, including combined filters and invalid ranges."""

    def setUp(self):
        self.mongo_client = MongoClient()
        self.col = self.mongo_client.test_db.logs
        app.state.logs = self.col

        # Insert logs at known timestamps
        base = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
        rows = []
        for i in range(6):
            rows.append({
                "timestamp": base + timedelta(hours=i),
                "source_ip": "10.0.0.1",
                "event_type": "LOGIN_FAILED",
                "severity": "HIGH" if i % 2 == 0 else "LOW",
                "message": f"event {i}",
            })
        self.col.insert_many(rows)
        self.base = base

    def tearDown(self):
        self.mongo_client.close()
        app.state.logs = None

    def test_start_filter_narrows_results(self):
        from app.logs import search
        start = (self.base + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        result = search(self.col, start=start)
        # hours 2,3,4,5 -> 4 results
        self.assertEqual(len(result["items"]), 4)
        for item in result["items"]:
            self.assertGreaterEqual(item["timestamp"], start[:10])

    def test_end_filter_narrows_results(self):
        from app.logs import search
        end = (self.base + timedelta(hours=3)).isoformat().replace("+00:00", "Z")
        result = search(self.col, end=end)
        # hours 0,1,2,3 -> 4 results
        self.assertEqual(len(result["items"]), 4)

    def test_start_and_end_filter_combined(self):
        from app.logs import search
        start = (self.base + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        end = (self.base + timedelta(hours=3)).isoformat().replace("+00:00", "Z")
        result = search(self.col, start=start, end=end)
        # hours 1,2,3 -> 3 results
        self.assertEqual(len(result["items"]), 3)

    def test_time_filter_combined_with_severity(self):
        from app.logs import search
        start = (self.base + timedelta(hours=0)).isoformat().replace("+00:00", "Z")
        end = (self.base + timedelta(hours=5)).isoformat().replace("+00:00", "Z")
        result = search(self.col, start=start, end=end, severity="HIGH")
        # Even hours 0,2,4 -> 3 HIGH results
        self.assertEqual(len(result["items"]), 3)
        for item in result["items"]:
            self.assertEqual(item["severity"], "HIGH")

    def test_invalid_range_raises(self):
        from app.logs import search
        start = (self.base + timedelta(hours=5)).isoformat().replace("+00:00", "Z")
        end = (self.base + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        with self.assertRaises(ValueError):
            search(self.col, start=start, end=end)

    def test_empty_dataset_returns_empty(self):
        from app.logs import search
        empty_col = self.mongo_client.test_db.empty_logs
        result = search(empty_col)
        self.assertEqual(result["items"], [])
        self.assertIsNone(result["next_cursor"])


class AssignableUsersTests(unittest.TestCase):
    """Requirement 4: /api/users/assignable is accessible to analysts and returns
    only user_id and username."""

    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)
        _seed_users(self.mock_db)

        self.mongo_client = MongoClient()
        app.state.mongo = self.mongo_client
        app.state.logs = self.mongo_client.test_db.logs

        self.client = TestClient(app)
        self.admin_token = create_access_token(1, "admin_reg", "ADMIN")
        self.analyst_token = create_access_token(2, "analyst_reg", "ANALYST")

    def tearDown(self):
        reset_db_override()
        self.mongo_client.close()

    def test_admin_can_get_assignable_users(self):
        res = self.client.get(
            "/api/users/assignable",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)
        # Must have user_id and username
        for item in items:
            self.assertIn("user_id", item)
            self.assertIn("username", item)
            # Must NOT expose sensitive fields
            self.assertNotIn("password_hash", item)
            self.assertNotIn("email", item)

    def test_analyst_can_get_assignable_users(self):
        """Analysts must be able to retrieve the assignee list."""
        res = self.client.get(
            "/api/users/assignable",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)

    def test_unauthenticated_cannot_get_assignable_users(self):
        res = self.client.get("/api/users/assignable")
        self.assertEqual(res.status_code, 401)

    def test_assignable_returns_only_active_users(self):
        """Inactive users must not appear in the assignable list."""
        self.mock_db.users.append({
            "user_id": 99,
            "username": "inactive_one",
            "email": "inactive@example.local",
            "password_hash": hash_password("InaPass123!"),
            "role_id": 2,
            "is_active": False,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })
        res = self.client.get(
            "/api/users/assignable",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        items = res.json()
        usernames = [i["username"] for i in items]
        self.assertNotIn("inactive_one", usernames)

    def test_admin_users_endpoint_still_requires_admin(self):
        """Analyst must not be able to access the full /api/users listing."""
        res = self.client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
        )
        self.assertEqual(res.status_code, 403)


class ResetFilterTests(unittest.TestCase):
    """Requirement 2: verify that the reset path (cleared params) returns the
    full unfiltered result set via the backend API."""

    def setUp(self):
        self.mongo_client = MongoClient()
        self.col = self.mongo_client.test_db.logs
        app.state.logs = self.col

        # Insert 5 logs with known IPs and severities
        base = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)
        self.col.insert_many([
            {
                "timestamp": base + timedelta(minutes=i),
                "source_ip": f"10.0.0.{i + 1}",
                "event_type": "SCAN",
                "severity": "HIGH",
                "message": f"reset test {i}",
            }
            for i in range(5)
        ])

    def tearDown(self):
        self.mongo_client.close()
        app.state.logs = None

    def test_cleared_filters_return_all_results(self):
        from app.logs import search
        # Filtered: only 1 result
        filtered = search(self.col, source_ip="10.0.0.1")
        self.assertEqual(len(filtered["items"]), 1)

        # After reset (no filters): all 5 results
        reset_result = search(self.col)
        self.assertEqual(len(reset_result["items"]), 5)


if __name__ == "__main__":
    unittest.main()
