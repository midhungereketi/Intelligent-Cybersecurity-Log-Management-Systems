"""Verify the complete API lifecycle against real MongoDB and PostgreSQL.

Run migrations 001-003 first, and use a fresh disposable database. This script
uses the real FastAPI lifespan, MongoDB collection, and PostgreSQL connections.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app


def checked(response, status, label):
    if response.status_code != status:
        raise AssertionError(f"{label}: HTTP {response.status_code}, expected {status}: {response.text[:800]}")
    return response.json()


def main():
    username = os.environ["ADMIN_USERNAME"]
    password = os.environ["ADMIN_PASSWORD"]
    with psycopg.connect(os.environ["POSTGRES_DSN"]) as conn:
        analyst_role_id = conn.execute("SELECT role_id FROM roles WHERE role_name = 'ANALYST'").fetchone()[0]

    with TestClient(app) as client:
        checked(client.get("/health"), 200, "health")
        checked(client.get("/api/logs"), 401, "protected log search")
        admin_login = checked(client.post("/api/auth/login", json={"username": username, "password": password}), 200, "admin login")
        admin = {"Authorization": f"Bearer {admin_login['access_token']}"}
        analyst_user = checked(client.post("/api/users", headers=admin, json={
            "username": "live_analyst", "email": "live_analyst@example.invalid",
            "password": "LiveAnalystPass123!", "role_id": analyst_role_id,
        }), 201, "create analyst")
        analyst_id = analyst_user["user_id"]
        analyst_login = checked(client.post("/api/auth/login", json={
            "username": "live_analyst", "password": "LiveAnalystPass123!",
        }), 200, "analyst login")
        analyst = {"Authorization": f"Bearer {analyst_login['access_token']}"}
        checked(client.post("/api/devices", headers=analyst, json={
            "device_name": "forbidden-device", "device_type": "SERVER",
        }), 403, "analyst cannot create device")
        device = checked(client.post("/api/devices", headers=admin, json={
            "device_name": "live-firewall", "device_type": "FIREWALL",
        }), 201, "admin creates device")
        checked(client.post("/api/sources", headers=admin, json={
            "source_name": "live-syslog", "source_type": "SYSLOG", "device_id": device["device_id"],
        }), 201, "admin creates source")

        base = datetime.now(timezone.utc) - timedelta(minutes=2)
        ip = "198.51.100.77"
        records = [{
            "timestamp": (base + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": ip, "event_type": "LOGIN_FAILED", "severity": "HIGH",
            "message": f"Live verification failed login {i}", "username": "live_analyst",
        } for i in range(6)]
        payload = "\n".join(json.dumps(row) for row in records) + "\n"
        upload = checked(client.post("/api/logs/upload", headers=analyst,
                                     files={"file": ("events.jsonl", payload, "application/x-ndjson")}),
                         200, "log upload")
        assert upload["inserted"] == 6 and upload["rejected"] == 0, upload
        first = checked(client.get("/api/logs", headers=analyst, params={"source_ip": ip, "limit": 3}), 200, "indexed search")
        assert len(first["items"]) == 3 and first["next_cursor"], first
        second = checked(client.get("/api/logs", headers=analyst, params={
            "source_ip": ip, "limit": 3, "cursor": first["next_cursor"],
        }), 200, "cursor search")
        assert len(second["items"]) == 3 and not second["next_cursor"], second
        assert len({row["id"] for row in first["items"] + second["items"]}) == 6
        checked(client.get("/api/logs", headers=analyst, params={
            "source_ip": ip, "start": (base - timedelta(seconds=1)).isoformat(),
            "end": (base + timedelta(seconds=30)).isoformat(),
        }), 200, "time-filtered search")

        detection = checked(client.post("/api/detection/run", headers=analyst, json={"limit": 100}), 200, "detection")
        assert detection["alerts_created"] >= 1, detection
        alerts = checked(client.get("/api/alerts", headers=analyst), 200, "alerts")
        alert = next(row for row in alerts["items"] if row["source_ip"] == ip)
        assert len(alert["evidence"]) >= 5, alert
        alert_id = alert["alert_id"]
        checked(client.post(f"/api/alerts/{alert_id}/acknowledge", headers=analyst), 200, "acknowledge")

        assignable = checked(client.get("/api/users/assignable", headers=analyst), 200, "assignable users")
        assert any(row["user_id"] == analyst_id for row in assignable), assignable
        incident = checked(client.post("/api/incidents", headers=analyst, json={
            "title": "Live failed-login incident", "severity": "HIGH",
            "assigned_to": analyst_id, "alert_id": alert_id,
        }), 201, "create incident")
        incident_id = incident["incident_id"]
        checked(client.patch(f"/api/incidents/{incident_id}", headers=analyst,
                             json={"status": "INVESTIGATING"}), 200, "investigate incident")
        checked(client.post(f"/api/incidents/{incident_id}/actions", headers=analyst, json={
            "action_type": "CONTAINMENT", "action_details": "Blocked suspicious source IP",
        }), 201, "add response action")
        detail = checked(client.get(f"/api/incidents/{incident_id}", headers=analyst), 200, "incident detail")
        assert detail["status"] == "INVESTIGATING", detail
        actions = checked(client.get(f"/api/incidents/{incident_id}/actions", headers=analyst), 200, "action history")
        assert any(row["action_type"] == "CONTAINMENT" for row in actions), actions

        dashboard = checked(client.get("/api/analytics/dashboard", headers=analyst), 200, "dashboard")
        timeline = checked(client.get("/api/analytics/events-timeline", headers=analyst), 200, "timeline")
        assert dashboard and timeline, (dashboard, timeline)
        checked(client.post(f"/api/alerts/{alert_id}/resolve", headers=analyst), 200, "resolve alert")
        replay = checked(client.post("/api/detection/run", headers=analyst, json={"limit": 100}), 200, "detection replay")
        assert replay["alerts_created"] == 0, replay
        checked(client.patch(f"/api/incidents/{incident_id}", headers=analyst,
                             json={"status": "RESOLVED"}), 200, "resolve incident")
        print(json.dumps({
            "result": "PASS", "database_mode": "real MongoDB and PostgreSQL",
            "logs_uploaded": upload["inserted"], "alerts_created": detection["alerts_created"],
            "replay_alerts_created": replay["alerts_created"], "incident_id": incident_id,
            "checks": ["auth and RBAC", "SQL metadata", "upload and indexed search", "detection and evidence",
                       "alert triage", "incident assignment and actions", "dashboard and timeline", "deduplication"],
        }, indent=2))


if __name__ == "__main__":
    main()
