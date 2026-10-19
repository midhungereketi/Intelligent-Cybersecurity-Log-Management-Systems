# Member 2 Handoff Report

**Project:** Intelligent Cybersecurity Log Management System  
**Owner:** Shraavanth (Member 2)  
**Branch:** `member2-shraavanth`  
**Status:** Complete backend implementation of authentication, role-based access control, detection engine, threat handling, alert APIs, and deterministic deduplication.

---

## 1. Executive Summary

Member 2 has implemented the security detection and identity tier of the Intelligent Cybersecurity Log Management System, integrating directly with Member 1's MongoDB log repository and PostgreSQL device metadata. The system preserves the hybrid database architecture, providing authenticated APIs and stable contracts for Member 3's upcoming React dashboard and incident investigation workflow.

---

## 2. Deliverables Summary

| Area | Implementation | Location |
| --- | --- | --- |
| **SQL Migrations** | PostgreSQL tables for `roles`, `users`, `rules`, `threats`, `alerts`, `processed_detection_events`, with indexes, constraints, and default seed data | `sql/002_auth_and_detection.postgres.sql` |
| **Password Hashing** | Secure Argon2id password derivation and constant-time verification using native `cryptography` | `app/auth.py` |
| **Token Management** | Signed RFC 7519 HS256 JWT tokens with expiration, claims validation, and server-side revocation cache | `app/auth.py` |
| **RBAC & Auth Dependencies** | Reusable FastAPI dependencies (`get_current_user`, `require_admin`, `require_analyst_or_admin`, `require_active_user`) | `app/auth.py` |
| **Rate Limiter** | Sliding window brute-force login protection by IP/username | `app/auth.py` |
| **Auth & User APIs** | `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, `/api/users` (CRUD + activation/role changes) | `app/routes_auth.py` |
| **Rule Management APIs** | `/api/rules` (list, get, create, patch) with parameter validation (thresholds, windows, severities) | `app/routes_rules.py` |
| **Detection Engine** | Testable detection algorithms for repeated failed logins, port scans, and excessive IP activity | `app/detection.py` |
| **Threat Correlation** | Automatic correlation and update of persistent threats in PostgreSQL `threats` table | `app/detection.py` |
| **Alert Deduplication & Idempotency** | Deterministic deduplication keying, active alert updates, occurrence counting, and replay checkpointing | `app/detection.py` |
| **Threat & Alert APIs** | `/api/threats`, `/api/alerts`, `/api/alerts/{id}/acknowledge`, `/api/alerts/{id}/resolve`, `/api/detection/run` | `app/routes_threats_alerts.py` |
| **Automated Test Suite** | 35 comprehensive automated tests covering schema, auth, detection, idempotency, and integration | `tests/` |

---

## 3. Database Architecture & Schema

### PostgreSQL Entities (`sql/002_auth_and_detection.postgres.sql`)

1. **`roles`**:
   - `role_id` (BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY)
   - `role_name` (VARCHAR(50) UNIQUE NOT NULL)
   - `description` (TEXT)
   - `created_at` (TIMESTAMPTZ)
   - Seeded: `ADMIN`, `ANALYST`

2. **`users`**:
   - `user_id` (BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY)
   - `username` (VARCHAR(60) UNIQUE NOT NULL)
   - `email` (VARCHAR(255) UNIQUE NOT NULL)
   - `password_hash` (VARCHAR(255) NOT NULL - Argon2id encoded)
   - `role_id` (BIGINT REFERENCES roles(role_id))
   - `is_active` (BOOLEAN DEFAULT TRUE)
   - `created_at`, `updated_at`, `last_login_at`

3. **`rules`**:
   - `rule_id` (BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY)
   - `rule_name` (VARCHAR(120) UNIQUE NOT NULL)
   - `rule_type` (`FAILED_LOGINS`, `PORT_SCAN`, `EXCESSIVE_ACTIVITY`)
   - `threshold` (INTEGER > 0)
   - `time_window_seconds` (INTEGER > 0)
   - `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
   - `is_enabled` (BOOLEAN DEFAULT TRUE)
   - `configuration` (JSONB)
   - `created_by` (BIGINT REFERENCES users(user_id))

4. **`threats`**:
   - `threat_id` (BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY)
   - `threat_type` (VARCHAR(60))
   - `source_ip` (INET), `destination_ip` (INET)
   - `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
   - `description` (TEXT), `first_seen_at`, `last_seen_at`, `metadata` (JSONB)

5. **`alerts`**:
   - `alert_id` (BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY)
   - `rule_id` (BIGINT REFERENCES rules(rule_id))
   - `threat_id` (BIGINT REFERENCES threats(threat_id))
   - `source_ip` (INET)
   - `severity`, `title`, `description`
   - `status` (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`)
   - `deduplication_key` (VARCHAR(255) NOT NULL, with partial unique index on active alerts)
   - `evidence` (JSONB structured array of log references)
   - `occurrence_count` (INTEGER >= 1)
   - `first_seen_at`, `last_seen_at`, `created_at`, `updated_at`

6. **`processed_detection_events`**:
   - `(event_id, rule_id)` (PRIMARY KEY composite)
   - Tracks processed MongoDB log IDs per detection rule to guarantee strict replay idempotency.

---

## 4. Security Detection Rules

The detection engine reads normalized logs from Member 1's MongoDB `logs` collection.

| Rule Family | Rule Type | Default Threshold | Default Window | Severity | Trigger Condition |
| --- | --- | --- | --- | --- | --- |
| **Rule A: Repeated Failed Logins** | `FAILED_LOGINS` | 5 attempts | 300 seconds | `HIGH` | `>= 5` events where `event_type == 'LOGIN_FAILED'` from the same `source_ip` within 300s window. Groups by source IP and captures usernames. |
| **Rule B: Possible Port Scan** | `PORT_SCAN` | 20 distinct ports | 60 seconds | `HIGH` | Connections from a `source_ip` targeting `>= 20` distinct destination ports within 60s. Ordinary multi-connection traffic to a single port (e.g. 443) does not trigger this rule. |
| **Rule C: Excessive IP Activity** | `EXCESSIVE_ACTIVITY` | 100 events | 60 seconds | `MEDIUM` | Unusually high volume of `>= 100` total log events from one `source_ip` within 60s. |

### Deduplication and Idempotency Design

- **Active Alerts**: When a match occurs, the engine checks for an existing active alert (`status != 'RESOLVED'`) using `deduplication_key = f"rule_{rule_id}:{rule_type}:{source_ip}"`.
- **Occurrence Counting**: Only *newly qualifying events* that have not been previously registered in `processed_detection_events` increment the `occurrence_count`.
- **Replay Protection**: Running detection against historical logs repeatedly produces **zero** duplicate alerts and **zero** count inflation.
- **Resolved Alerts**: Once an alert is transitioned to `RESOLVED`, any subsequent new attack episode creates a fresh `OPEN` alert record, preserving the historical record of the previous incident.

---

## 5. API Contracts for Member 3 (React Dashboard)

All protected endpoints expect the header:
```http
Authorization: Bearer <access_token>
```

### Authentication Endpoints
- `POST /api/auth/login`: `{ "username": "...", "password": "..." }` -> `{ "access_token": "...", "user": { ... } }`
- `POST /api/auth/logout`: Revokes token.
- `GET /api/auth/me`: Returns current user and role (`ADMIN` or `ANALYST`).

### Alert Endpoints
- `GET /api/alerts?status=OPEN&severity=HIGH&limit=50&offset=0`: Returns paginated list of alerts with rule names and summaries.
- `GET /api/alerts/{alert_id}`: Returns full alert details including structured log `evidence` references.
- `POST /api/alerts/{alert_id}/acknowledge`: Transitions status from `OPEN` to `ACKNOWLEDGED`.
- `POST /api/alerts/{alert_id}/resolve`: Transitions status to `RESOLVED`.

### Threat Endpoints
- `GET /api/threats?severity=HIGH&limit=50&offset=0`: Lists correlated threats.
- `GET /api/threats/{threat_id}`: Returns threat details with nested list of related alerts.

### Rule Endpoints (Admin only for modifications)
- `GET /api/rules`: Lists active and disabled rules.
- `PATCH /api/rules/{rule_id}`: Modifies threshold, window, severity, or enabled state.

### Detection Execution Endpoint
- `POST /api/detection/run`: `{ "limit": 2000, "start": "...", "end": "..." }` -> Runs detection batch and returns execution summary.

---

## 6. How to Run and Verify

```powershell
# 1. Run automated tests (8 Member 1 tests + 27 Member 2 tests = 35 tests total)
python -m unittest discover -s tests -v

# 2. Verify compilation
python -m compileall -q app scripts tests

# 3. Apply SQL migrations against live PostgreSQL (when available)
psql -d cybersecurity -f sql/001_devices_and_sources.postgres.sql
psql -d cybersecurity -f sql/002_auth_and_detection.postgres.sql

# 4. Start the API server
uvicorn app.main:app --reload
```
