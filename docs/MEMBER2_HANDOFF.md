# Member 2 Handoff & Security Hardening Report

> Historical member handoff. The integrated implementation and current verification are documented in the [final project report](FINAL_PROJECT_REPORT.md).

**Project:** Intelligent Cybersecurity Log Management System  
**Owner:** Shraavanth (Member 2 — Security, RBAC, Detection & Backend Integration)  
**Branch:** `member2-shraavanth`  
**Status:** Complete backend implementation of authentication, role-based access control, secured Member 1 APIs, hardened JWT configuration, detection engine with large-dataset pagination & checkpointing, replay deduplication, and 46 automated tests.

---

## 1. Executive Summary

Member 2 has delivered the complete security detection, identity, and RBAC tier of the Intelligent Cybersecurity Log Management System. This release resolves the initial CI test collection and dependency failures, locks down all public administrative and ingestion routes with role-based permissions, eliminates insecure fallback secrets, resolves detection pagination bottlenecks for large volumes of logs, and fixes alert replay regressions after incident resolution.

---

## 2. Key Deliverables & Enhancements

| Area | Implementation & Fixes | Location |
| --- | --- | --- |
| **Dependencies & CI** | Added `cryptography>=42.0,<51` to `requirements.txt` and `httpx>=0.27,<1` to `requirements-dev.txt`. Fixed all test collection and import failures. | `requirements.txt`, `requirements-dev.txt` |
| **API Route Security (Phase 3)** | Enforced RBAC across all Member 1 routes (`/api/logs/events`, `/api/logs/upload`, `/api/logs`, `/api/devices`, `/api/sources`). Admin only for device/source mutations; Analyst or Admin for monitoring and ingestion; 401 for unauthenticated, 403 for unauthorized. | `app/main.py` |
| **JWT Secret Hardening (Phase 4)** | Removed hardcoded prototype secrets. Application fails fast on startup if `JWT_SECRET_KEY` is not configured. Sensitive files and keys excluded via `.gitignore`. Isolated test-safe configuration provided in `tests/__init__.py`. | `app/config.py`, `app/main.py`, `.env.example`, `.gitignore` |
| **Detection for Large Datasets (Phase 5)** | Implemented deterministic cursor-based pagination `[("timestamp", 1), ("_id", 1)]`, sliding window boundary overlap, and persistent watermark checkpointing in PostgreSQL table `detection_checkpoints`. Safely handles duplicate timestamps and datasets spanning multiple batches. | `app/detection.py`, `sql/002_auth_and_detection.postgres.sql` |
| **Alert Replay Deduplication (Phase 6)** | Resolved alert duplication bug: replaying resolved logs produces zero duplicate alerts. New attack episodes correctly generate new `OPEN` alerts while preserving resolved incident history. | `app/detection.py` |
| **E2E Integration Demo (Phase 7)** | Implemented comprehensive 12-step end-to-end integration test demonstrating ingest, detection, alert retrieval, evidence inspection, acknowledge, resolve, replay idempotency, and RBAC rejection. | `scripts/e2e_integration_demo.py` |
| **PostgreSQL vs Oracle Analysis (Phase 8)** | Detailed dialect and architectural comparison addressing course Review II guidelines. Outlines why PostgreSQL + MongoDB is superior for this SIEM design, and documents the exact demonstration strategy. | `docs/POSTGRES_VS_ORACLE_ANALYSIS.md` |
| **Automated Test Suite (Phase 9)** | 46 comprehensive automated unit and integration tests covering schema, auth, RBAC, detection rules, pagination, and alert lifecycle. | `tests/` |

---

## 3. Database Architecture & Schema

### PostgreSQL Schema (`sql/001_devices_and_sources.postgres.sql` & `sql/002_auth_and_detection.postgres.sql`)

1. **`device`**: Physical and virtual host inventory (`device_id`, `device_name`, `ip_address`, `mac_address`, `device_type`, `operating_system`, `location`, `status`).
2. **`log_source`**: Log emitting sensors (`source_id`, `source_name`, `source_type`, `ip_address`, `protocol`, `device_id`).
3. **`roles`**: System roles (`ADMIN`, `ANALYST`).
4. **`users`**: System accounts (`user_id`, `username`, `email`, `password_hash` via Argon2id, `role_id`, `is_active`, `last_login_at`).
5. **`rules`**: Detection rule definitions (`rule_id`, `rule_name`, `rule_type`, `threshold`, `time_window_seconds`, `severity`, `is_enabled`, `configuration`).
6. **`threats`**: Correlated attack patterns (`threat_id`, `threat_type`, `source_ip`, `destination_ip`, `severity`, `description`, `first_seen_at`, `last_seen_at`, `metadata`).
7. **`alerts`**: Actionable incident tickets (`alert_id`, `rule_id`, `threat_id`, `source_ip`, `severity`, `title`, `description`, `status`, `deduplication_key`, `evidence`, `occurrence_count`, `first_seen_at`, `last_seen_at`).
8. **`processed_detection_events`**: Idempotency ledger mapping `(event_id, rule_id, alert_id)`.
9. **`detection_checkpoints`**: Watermark tracker storing `(checkpoint_name, last_timestamp, last_event_id, updated_at)`.

---

## 4. Security & Role-Based Access Control (RBAC)

All endpoints (except `/health` and `/api/auth/login`) require the `Authorization: Bearer <token>` header.

### Permissions Matrix

| Endpoint | Method | Permitted Roles | Unauthenticated | Unauthorized Role |
| --- | --- | --- | --- | --- |
| `/health` | `GET` | Public | 200 OK | 200 OK |
| `/api/auth/login` | `POST` | Public | 200 OK (upon valid credentials) | 401 Unauthorized |
| `/api/auth/logout` | `POST` | Any Active User | 401 Unauthorized | 403 Forbidden |
| `/api/auth/me` | `GET` | Any Active User | 401 Unauthorized | 403 Forbidden |
| `/api/users` (CRUD) | `GET`, `POST`, `PATCH` | **Administrator Only** | 401 Unauthorized | 403 Forbidden |
| `/api/devices` | `GET` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/devices` | `POST` | **Administrator Only** | 401 Unauthorized | 403 Forbidden |
| `/api/sources` | `GET` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/sources` | `POST` | **Administrator Only** | 401 Unauthorized | 403 Forbidden |
| `/api/logs/events` | `POST` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/logs/upload` | `POST` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/logs` | `GET` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/rules` | `GET` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/rules` (CRUD) | `POST`, `PATCH` | **Administrator Only** | 401 Unauthorized | 403 Forbidden |
| `/api/threats` | `GET` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/alerts` | `GET` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/alerts/{id}/acknowledge` | `POST` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/alerts/{id}/resolve` | `POST` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |
| `/api/detection/run` | `POST` | Analyst, Administrator | 401 Unauthorized | 403 Forbidden |

---

## 5. Detection Engine Architecture

### Detection Rules Supported
1. **Rule A (`FAILED_LOGINS`)**: Detects repeated authentication failures from a single IP exceeding threshold within `time_window_seconds`.
2. **Rule B (`PORT_SCAN`)**: Detects single source IPs connecting to distinct destination ports exceeding threshold within `time_window_seconds`.
3. **Rule C (`EXCESSIVE_ACTIVITY`)**: Detects high-volume bursts from a single IP exceeding total log threshold within `time_window_seconds`.

### Large Dataset Pagination & Checkpoints
- Queries MongoDB using deterministic ordering `[("timestamp", 1), ("_id", 1)]`.
- Iterates over pages using composite cursor `{"$or": [{"timestamp": {"$gt": last_ts}}, {"timestamp": last_ts, "_id": {"$gt": last_id}}]}`.
- Re-reads trailing logs using a sliding window overlap equal to the maximum active rule window (`max_window_seconds`), guaranteeing no events are missed across batch boundaries.
- Records completion watermark in PostgreSQL `detection_checkpoints`.
- Preserves checkpoint integrity during failures: transaction rollback prevents watermark advancement past unprocessed logs.

### Alert Replay Deduplication
- Checks for active alerts with `deduplication_key` where `status != 'RESOLVED'`.
- Uses `processed_detection_events` to determine which event IDs in a match have been previously processed for that rule.
- If an alert is already `RESOLVED` and detection runs again on the same logs, `new_event_ids` is empty; the engine marks the result as `unchanged` and **does not create a duplicate alert**.
- When a new attack episode occurs, `new_event_ids` is populated, creating a fresh `OPEN` alert.

---

## 6. Verification and Demonstration

### Run All 46 Automated Tests
```powershell
python -m unittest discover -s tests -v
```

### Run Compilation Check
```powershell
python -m compileall -q app scripts tests
```

### Run 12-Step End-to-End Integration Demonstration
```powershell
python scripts/e2e_integration_demo.py
```

### Start API Server
```powershell
# Set mandatory environment variables
$env:JWT_SECRET_KEY = "your-secure-random-secret-key-at-least-32-chars"
$env:MONGO_URI = "mongodb://localhost:27017"
$env:MONGO_DATABASE = "cybersecurity_logs"
$env:POSTGRES_DSN = "postgresql://postgres:postgres@localhost:5432/cybersecurity"

uvicorn app.main:app --reload
```
Interactive documentation is available at `http://127.0.0.1:8000/docs`.
