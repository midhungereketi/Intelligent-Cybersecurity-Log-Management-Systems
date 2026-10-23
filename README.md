# Intelligent Cybersecurity Log Management System

This repository contains the Member 1 data pipeline for a three-member Database Systems project. It accepts security logs, stores them in MongoDB, supports indexed search, and provides a repeatable performance comparison. PostgreSQL tables and APIs manage device and log-source metadata.

The other members can add authentication, detection, alerts, analytics, and incident handling using the API described below.

For teammate and AI-agent handoff, see [Member 1 Handoff Report](docs/MEMBER1_HANDOFF.md) and [Member 2 Handoff Report](docs/MEMBER2_HANDOFF.md).

## Member deliverables

| Area | Member | Implementation |
| --- | --- | --- |
| Ingestion & Search | Member 1 | Single-event API and CSV/JSON/JSONL upload with MongoDB indexing and benchmark |
| SQL Device Metadata | Member 1 | PostgreSQL `device` and `log_source` tables and APIs |
| Authentication & RBAC | Member 2 | Argon2id hashing, RFC 7519 HS256 JWT, rate limiting, and secured Member 1 & 2 APIs |
| Relational Security Schema | Member 2 | PostgreSQL `roles`, `users`, `rules`, `threats`, `alerts`, `processed_detection_events`, `detection_checkpoints` |
| Security Detection Engine | Member 2 | Failed logins, port scan probes, excessive activity detection with checkpointing & pagination |
| Threat & Alert Management | Member 2 | Filterable, paginated alert & threat APIs with status transitions and replay deduplication |
| Incident & Action History | Member 3 | PostgreSQL `incidents`, `actions`, `incident_alerts`, lifecycle transitions, analyst assignment |
| Analytics & Metrics | Member 3 | Cross-database metrics, hourly event timeline, attacker IP rankings, log-type distributions |
| React SOC Console | Member 3 | Interactive dark-theme SOC dashboard with real-time analytics, log search, alert escalation, incident investigation |

## Setup

Requires Python 3.11+, MongoDB, PostgreSQL, and Node.js 18+. Apply the SQL migrations in order:
1. `sql/001_devices_and_sources.postgres.sql`
2. `sql/002_auth_and_detection.postgres.sql`
3. `sql/003_incidents_and_actions.postgres.sql`

### Environment Variables
Configure the mandatory environment variables (see `.env.example`):
- `JWT_SECRET_KEY`: Mandatory secure secret key (minimum 32 characters). The app fails fast on startup if this is missing.
- `MONGO_URI` and `MONGO_DATABASE`: MongoDB connection string and database name (`cybersecurity_logs`).
- `POSTGRES_DSN`: PostgreSQL connection DSN (`postgresql://user:password@localhost:5432/cybersecurity`).
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`: Optional credentials for bootstrapping the initial administrator account.

### Backend Setup
Apply the SQL migrations in order:
1. `sql/001_devices_and_sources.postgres.sql`
2. `sql/002_auth_and_detection.postgres.sql`
3. `sql/003_incidents_and_actions.postgres.sql`

```powershell
# 1. Backend environment setup
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 2. Copy and configure environment variables
Copy-Item .env.example .env

# 3. Apply SQL migrations
psql $env:POSTGRES_DSN -f sql/001_devices_and_sources.postgres.sql
psql $env:POSTGRES_DSN -f sql/002_auth_and_detection.postgres.sql
psql $env:POSTGRES_DSN -f sql/003_incidents_and_actions.postgres.sql

# 4. Start backend
uvicorn app.main:app --reload --port 8000
```
Open `http://127.0.0.1:8000/docs` for interactive OpenAPI documentation. Starting the API checks MongoDB connectivity, creates the required indexes, and bootstraps the initial administrator account from `.env`.

### Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to access the Security Operations Center dashboard.

## Log format

Each record requires `timestamp` (ISO 8601 with a timezone or BSON Date), `source_ip`, `event_type`, `severity`, and `message`. Severity is one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Optional fields are `source_id`, `device_id`, `username`, `log_source`, `destination_ip`, and `destination_port`. Timestamps are stored in UTC. Unknown fields are discarded during normalization.

```json
{
  "timestamp": "2026-10-01T10:00:00Z",
  "source_ip": "198.51.100.10",
  "event_type": "LOGIN_FAILED",
  "severity": "HIGH",
  "message": "Failed login for analyst",
  "username": "analyst"
}
```

The ingestion API does not check whether optional `source_id` or `device_id` values exist in PostgreSQL. The team should decide whether to enforce this at the API boundary once SQL ownership and the log-source workflow are integrated.

## API contract

| Method and path | Purpose | Access |
| --- | --- | --- |
| `GET /health` | Check MongoDB connection | Public |
| `POST /api/logs/events` | Insert one JSON event | Analyst / Admin |
| `POST /api/logs/upload` | Upload a multipart file named `file`; max 25 MB | Analyst / Admin |
| `GET /api/logs` | Search, time-filter (UTC start/end), and paginate logs | Analyst / Admin |
| `GET /api/devices` / `POST /api/devices` | List and create devices | Analyst / Admin |
| `GET /api/sources` / `POST /api/sources` | List and create log sources | Analyst / Admin |
| `POST /api/auth/login` | Authenticate user, returns HS256 JWT access token | Public |
| `POST /api/auth/logout` | Revoke current user's session token | Authenticated |
| `GET /api/auth/me` | Retrieve profile of currently authenticated user | Authenticated |
| `GET /api/users` / `POST /api/users` / `PATCH /api/users/{id}` | User management | Administrator only |
| `GET /api/users/assignable` | Minimal active user list (user_id, username) for assignee dropdowns | Analyst / Admin |
| `GET /api/rules` / `POST /api/rules` / `PATCH /api/rules/{id}` | Detection rule management and threshold configuration | Analyst / Admin |
| `GET /api/threats` / `GET /api/threats/{id}` | Threat records with correlated alerts and evidence | Analyst / Admin |
| `GET /api/alerts` / `GET /api/alerts/{id}` | Security alerts with status, severity, and evidence | Analyst / Admin |
| `POST /api/alerts/{id}/acknowledge` | Acknowledge active alert | Analyst / Admin |
| `POST /api/alerts/{id}/resolve` | Resolve alert | Analyst / Admin |
| `POST /api/detection/run` | Execute bounded security detection run | Analyst / Admin |
| `GET /api/incidents` / `POST /api/incidents` | List, filter, and create security incidents | Analyst / Admin |
| `GET /api/incidents/{id}` / `PATCH /api/incidents/{id}` | Get incident details and update status/assignment | Analyst / Admin |
| `GET /api/incidents/{id}/actions` / `POST /api/incidents/{id}/actions` | Response action audit timeline and recording | Analyst / Admin |
| `POST /api/incidents/{id}/link-alert` | Associate alert with incident | Analyst / Admin |
| `GET /api/analytics/dashboard` | Unified metrics overview across MongoDB and PostgreSQL | Analyst / Admin |
| `GET /api/analytics/events-timeline` | Hourly time-bucketed event counts (Date and ISO strings) | Analyst / Admin |
| `GET /api/analytics/top-sources` | Attacker IP rankings by volume and max severity | Analyst / Admin |
| `GET /api/analytics/event-types` | Event type distribution | Analyst / Admin |

Protected endpoints require the `Authorization: Bearer <token>` header obtained from `/api/auth/login`.

## Synthetic data and benchmark

Generate a small JSONL file, then upload it through the API:

```powershell
python scripts/generate_logs.py --count 1000 --output sample.jsonl
```

For large datasets, insert directly into MongoDB in batches without producing a large intermediate file:

```powershell
python scripts/generate_logs.py --count 1000000 --insert
python scripts/benchmark.py --source-ip 198.51.100.10 --repeats 5 --output benchmark.json
```

Start with 1,000 records and increase gradually according to available RAM and disk space. The benchmark reports the collection size, query, median time, and query plan for both a natural collection scan and the `source_ip_time` index. Run it after the dataset is loaded, on the same machine, and include the hardware and dataset size in the project report. `benchmark.json` contains environment-specific results and should not be committed as a universal performance claim.

## Team integration points

Member 2 can use `source_ip`, `event_type`, `timestamp`, `username`, and destination fields for detection rules, then store alert evidence using MongoDB log IDs as strings in SQL. SQL foreign keys cannot reference MongoDB documents. Member 3 can call `GET /api/logs` for the search table and use the metadata endpoints for device/source selection. Analytics endpoints should use MongoDB aggregation on the same normalized fields.

## Verification and automated tests

Install development dependencies and run the complete test suite (46 tests):

```powershell
pip install -r requirements-dev.txt
python -m compileall -q app scripts tests
python -m unittest discover -s tests -v
```

Execute the full 12-step end-to-end integration demonstration:

```powershell
python scripts/e2e_integration_demo.py
```

For database coursework considerations and the PostgreSQL vs Oracle 11g demonstration plan, see [PostgreSQL vs Oracle Analysis](docs/POSTGRES_VS_ORACLE_ANALYSIS.md).
