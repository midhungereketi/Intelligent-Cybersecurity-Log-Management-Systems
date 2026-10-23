# Intelligent Cybersecurity Log Management System

This three-member Database Systems project stores security logs in MongoDB, keeps users, alerts, and incidents in PostgreSQL, and provides a React Security Operations Center dashboard. It supports indexed log search, suspicious activity detection, alert triage, and incident response.

See the [detailed project report](docs/DETAILED_PROJECT_REPORT.md) for architecture, the complete operating workflow, requirements traceability, review criteria, tests, and demonstration steps. The [Member 1](docs/MEMBER1_HANDOFF.md), [Member 2](docs/MEMBER2_HANDOFF.md), and [Member 3](docs/MEMBER3_HANDOFF.md) handoffs preserve each member's implementation history. The [million-log benchmark](docs/MEMBER1_VERIFICATION.md) records measured indexed search performance.

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

Requires Python 3.11+, MongoDB 7, PostgreSQL 16, and Node.js 22. Create an empty PostgreSQL database before applying the migrations below.

### Environment Variables
Configure the mandatory environment variables (see `.env.example`):
- `JWT_SECRET_KEY`: Mandatory random signing secret. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`; the app fails fast if it is missing.
- `MONGO_URI` and `MONGO_DATABASE`: MongoDB connection string and database name (`cybersecurity_logs`).
- `POSTGRES_DSN`: PostgreSQL connection DSN (`postgresql://user:password@localhost:5432/cybersecurity`).
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`: Optional credentials for bootstrapping the initial administrator account.

### Backend Setup
Apply the SQL migrations in order:
1. `sql/001_devices_and_sources.postgres.sql`
2. `sql/002_auth_and_detection.postgres.sql`
3. `sql/003_incidents_and_actions.postgres.sql`
4. `sql/004_review2_operations.postgres.sql`

```powershell
# 1. Backend environment setup
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 2. Copy .env.example and fill in JWT_SECRET_KEY and ADMIN_PASSWORD
Copy-Item .env.example .env

# 3. Set the same PostgreSQL DSN in this shell; psql does not load .env
$env:POSTGRES_DSN = 'postgresql://postgres:postgres@localhost:5432/cybersecurity'

# 4. Apply SQL migrations
psql $env:POSTGRES_DSN -f sql/001_devices_and_sources.postgres.sql
psql $env:POSTGRES_DSN -f sql/002_auth_and_detection.postgres.sql
psql $env:POSTGRES_DSN -f sql/003_incidents_and_actions.postgres.sql
psql $env:POSTGRES_DSN -f sql/004_review2_operations.postgres.sql

# 5. Start backend
uvicorn app.main:app --reload --port 8000
```
Open `http://127.0.0.1:8000/docs` for interactive OpenAPI documentation. The backend loads `.env` from the repository root without overriding variables already set in the shell. Startup checks MongoDB, creates the required indexes, and bootstraps the initial administrator account.

### Frontend Setup
```powershell
cd frontend
npm ci
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

Optional `source_id` and `device_id` values are validated as positive integers but are not cross-checked against PostgreSQL when a log is ingested; use registered IDs when supplying them.

## API contract

| Method and path | Purpose | Access |
| --- | --- | --- |
| `GET /health` | Check MongoDB connection | Public |
| `POST /api/logs/events` | Insert one JSON event | Analyst / Admin |
| `POST /api/logs/upload` | Upload a multipart file named `file`; max 25 MB | Analyst / Admin |
| `GET /api/logs` | Search, time-filter (UTC start/end), and paginate logs | Analyst / Admin |
| `GET /api/devices` / `POST /api/devices` | List devices (Analyst/Admin); create devices (Admin) | Role-based |
| `GET /api/sources` / `POST /api/sources` | List sources (Analyst/Admin); create sources (Admin) | Role-based |
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

## Verification and automated tests

Install development dependencies and run the complete backend test suite:

```powershell
pip install -r requirements-dev.txt
python -m compileall -q app scripts tests
python -m unittest discover -s tests -v
```

Execute the 12-step mock-database integration demonstration:

```powershell
python scripts/e2e_integration_demo.py
```

The GitHub Actions pipeline also verifies the full API lifecycle against real MongoDB 7 and PostgreSQL 16, runs the million-log indexed-search benchmark, and exercises login, upload, search, detection, alert escalation, incident action, and dashboard in Chromium against those databases. To run the browser test locally after starting MongoDB and PostgreSQL, applying migrations, and configuring `.env`, run `cd frontend`, `npx playwright install chromium`, and `npm run test:e2e`.

For Review II, `sql/004_review2_operations.postgres.sql` adds an alert-status audit trigger, an incident risk-score function, and a procedure with an explicit cursor that refreshes incident priorities. `sql/review2_demo.postgres.sql` exercises insert/update/delete, joins, grouping, aggregation, a subquery, and those stored operations inside a rolled-back transaction. Run it with `psql $env:POSTGRES_DSN -v ON_ERROR_STOP=1 -f sql/review2_demo.postgres.sql` from the repository root.

For the separate Oracle 11g Review II script and its database verification steps, see the [Oracle guide](sql/ORACLE_REVIEW2_GUIDE.md). The working application uses PostgreSQL; the Oracle script is a standalone coursework demonstration. For the dialect comparison, see [PostgreSQL vs Oracle Analysis](docs/POSTGRES_VS_ORACLE_ANALYSIS.md).
