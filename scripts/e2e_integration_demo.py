"""End-to-End Integration Demonstration Script.

Executes the Phase 7 twelve-step verification sequence:
1. Initialize test environment and API
2. Login with test user
3. Obtain JWT access token
4. Submit suspicious logs via ingestion endpoint
5. Execute detection workflow
6. Retrieve resulting alert
7. Inspect alert evidence
8. Acknowledge alert
9. Resolve alert
10. Rerun detection and verify no duplicate alert is generated
11. Submit new qualifying event and verify new alert creation
12. Test protected endpoints with missing authentication and unauthorized roles
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("JWT_SECRET_KEY", "demo-secure-jwt-secret-key-32-chars-minimum!")

import mongomock
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.db import set_db_override
from app.main import app
from tests.mock_db import MockDatabase


def run_e2e_demo():
    print("=" * 70)
    print("STEP 1: Initializing Databases and Application State")
    print("=" * 70)

    mock_db = MockDatabase()
    set_db_override(mock_db.get_connection)

    mongo_client = mongomock.MongoClient()
    logs_col = mongo_client.cybersecurity_logs.logs
    app.state.mongo = mongo_client
    app.state.logs = logs_col

    # Seed users
    admin_pw = "AdminSecurePass2026!"
    analyst_pw = "AnalystSecurePass2026!"

    mock_db.users.append({
        "user_id": 1,
        "username": "admin_demo",
        "email": "admin@demo.local",
        "password_hash": hash_password(admin_pw),
        "role_id": 1,  # ADMIN
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_login_at": None,
    })
    mock_db.users.append({
        "user_id": 2,
        "username": "analyst_demo",
        "email": "analyst@demo.local",
        "password_hash": hash_password(analyst_pw),
        "role_id": 2,  # ANALYST
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_login_at": None,
    })

    client = TestClient(app)
    print("Database and FastAPI application state initialized.")

    print("\n" + "=" * 70)
    print("STEP 2 & 3: Logging In and Obtaining Authentication Tokens")
    print("=" * 70)

    resp_login = client.post("/api/auth/login", json={"username": "analyst_demo", "password": analyst_pw})
    print(f"POST /api/auth/login status: {resp_login.status_code}")
    login_data = resp_login.json()
    analyst_token = login_data["access_token"]
    print(f"Analyst Authenticated: {login_data['user']['username']} (Role: {login_data['user']['role_name']})")
    print(f"Access Token (prefix): {analyst_token[:35]}...")

    resp_admin_login = client.post("/api/auth/login", json={"username": "admin_demo", "password": admin_pw})
    admin_token = resp_admin_login.json()["access_token"]
    print(f"Admin Authenticated: {resp_admin_login.json()['user']['username']} (Role: {resp_admin_login.json()['user']['role_name']})")

    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    print("\n" + "=" * 70)
    print("STEP 4: Submitting Suspicious Logs via Ingestion Endpoint")
    print("=" * 70)

    base_time = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    attack_logs = [
        {
            "timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": "198.51.100.77",
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "username": "root",
            "message": f"SSH authentication failure attempt #{i+1}",
        }
        for i in range(6)
    ]

    for log_item in attack_logs:
        resp = client.post("/api/logs/events", json=log_item, headers=analyst_headers)
        print(f"  POST /api/logs/events -> {resp.status_code} (Inserted ID: {resp.json().get('id')})")

    print(f"Total logs in MongoDB: {logs_col.count_documents({})}")

    print("\n" + "=" * 70)
    print("STEP 5: Running Detection Workflow")
    print("=" * 70)

    resp_det = client.post("/api/detection/run", json={"limit": 500}, headers=analyst_headers)
    print(f"POST /api/detection/run status: {resp_det.status_code}")
    det_summary = resp_det.json()
    print("Detection Summary:", json.dumps(det_summary, indent=2))
    assert det_summary["alerts_created"] >= 1, "Expected at least 1 alert created"

    print("\n" + "=" * 70)
    print("STEP 6 & 7: Retrieving Resulting Alert and Inspecting Evidence")
    print("=" * 70)

    resp_alerts = client.get("/api/alerts?status=OPEN", headers=analyst_headers)
    print(f"GET /api/alerts?status=OPEN status: {resp_alerts.status_code}")
    alerts_list = resp_alerts.json()["items"]
    print(f"Total OPEN alerts found: {len(alerts_list)}")
    alert = next(a for a in alerts_list if a["source_ip"] == "198.51.100.77")
    alert_id = alert["alert_id"]
    print(f"Alert ID: {alert_id}")
    print(f"Title: {alert['title']}")
    print(f"Severity: {alert['severity']}")
    print(f"Status: {alert['status']}")
    print(f"Evidence Count: {len(alert['evidence'])}")
    print("Evidence Sample (first 2 entries):")
    for ev in alert["evidence"][:2]:
        print("  -", ev)

    print("\n" + "=" * 70)
    print("STEP 8: Acknowledging Alert with Authorized User")
    print("=" * 70)

    resp_ack = client.post(f"/api/alerts/{alert_id}/acknowledge", headers=analyst_headers)
    print(f"POST /api/alerts/{alert_id}/acknowledge status: {resp_ack.status_code}")
    print(f"New Status: {resp_ack.json()['status']}")
    assert resp_ack.json()["status"] == "ACKNOWLEDGED"

    print("\n" + "=" * 70)
    print("STEP 9: Resolving Alert with Authorized User")
    print("=" * 70)

    resp_res = client.post(f"/api/alerts/{alert_id}/resolve", headers=analyst_headers)
    print(f"POST /api/alerts/{alert_id}/resolve status: {resp_res.status_code}")
    print(f"New Status: {resp_res.json()['status']}")
    assert resp_res.json()["status"] == "RESOLVED"

    print("\n" + "=" * 70)
    print("STEP 10: Rerunning Detection on Same Logs (Deduplication / No Replay)")
    print("=" * 70)

    resp_det_replay = client.post("/api/detection/run", json={"limit": 500}, headers=analyst_headers)
    replay_summary = resp_det_replay.json()
    print("Replay Detection Summary:", json.dumps(replay_summary, indent=2))
    print(f"Alerts Created on Replay: {replay_summary['alerts_created']} (Must be 0!)")
    print(f"Alerts Unchanged on Replay: {replay_summary['alerts_unchanged']}")
    assert replay_summary["alerts_created"] == 0, "Duplicate alert created on replay!"

    # Verify database alert count
    all_alerts = client.get("/api/alerts", headers=analyst_headers).json()["items"]
    print(f"Total alerts in DB after replay: {len(all_alerts)} (Expected: 1)")
    assert len(all_alerts) == 1

    print("\n" + "=" * 70)
    print("STEP 11: Submitting New Attack Episode and Verifying New Alert")
    print("=" * 70)

    new_attack_time = base_time + timedelta(hours=2)
    new_logs = [
        {
            "timestamp": (new_attack_time + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": "198.51.100.77",
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "username": "admin",
            "message": f"New episode SSH attack attempt #{i+1}",
        }
        for i in range(6)
    ]
    for log_item in new_logs:
        client.post("/api/logs/events", json=log_item, headers=analyst_headers)

    resp_det_new = client.post("/api/detection/run", json={"limit": 500}, headers=analyst_headers)
    new_summary = resp_det_new.json()
    print("New Episode Detection Summary:", json.dumps(new_summary, indent=2))
    print(f"Alerts Created for New Episode: {new_summary['alerts_created']} (Expected: 1)")
    assert new_summary["alerts_created"] == 1

    all_alerts_updated = client.get("/api/alerts", headers=analyst_headers).json()["items"]
    print(f"Total alerts in DB after new episode: {len(all_alerts_updated)} (Expected: 2)")
    assert len(all_alerts_updated) == 2
    statuses = [a["status"] for a in all_alerts_updated]
    print(f"Alert Statuses: {statuses} (Expected: one RESOLVED, one OPEN)")
    assert "RESOLVED" in statuses and "OPEN" in statuses

    print("\n" + "=" * 70)
    print("STEP 12: Testing Protected Endpoints with Missing Auth & Insufficient Permissions")
    print("=" * 70)

    # 12.1 Unauthenticated requests
    resp_unauth = client.get("/api/logs")
    print(f"GET /api/logs without auth: {resp_unauth.status_code} (Expected: 401)")
    assert resp_unauth.status_code == 401

    resp_unauth_dev = client.get("/api/devices")
    print(f"GET /api/devices without auth: {resp_unauth_dev.status_code} (Expected: 401)")
    assert resp_unauth_dev.status_code == 401

    # 12.2 Analyst attempting Admin-only operation
    device_data = {
        "device_name": "Edge-Router-01",
        "ip_address": "192.168.1.1",
        "device_type": "Router",
        "status": "ACTIVE",
    }
    resp_analyst_dev = client.post("/api/devices", json=device_data, headers=analyst_headers)
    print(f"POST /api/devices by Analyst: {resp_analyst_dev.status_code} (Expected: 403 Forbidden)")
    assert resp_analyst_dev.status_code == 403

    # 12.3 Admin performing Admin-only operation
    resp_admin_dev = client.post("/api/devices", json=device_data, headers=admin_headers)
    print(f"POST /api/devices by Admin: {resp_admin_dev.status_code} (Expected: 201 Created)")
    assert resp_admin_dev.status_code == 201

    print("\n" + "=" * 70)
    print("END-TO-END DEMONSTRATION COMPLETE: ALL 12 STEPS PASSED PERFECTLY")
    print("=" * 70)


if __name__ == "__main__":
    run_e2e_demo()
