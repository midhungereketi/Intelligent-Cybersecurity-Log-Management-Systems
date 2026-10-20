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

## Setup

Requires Python 3.11+, MongoDB, and PostgreSQL. Apply the SQL migrations in order: `sql/001_devices_and_sources.postgres.sql` then `sql/002_auth_and_detection.postgres.sql`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Set environment variables before starting the application:
- `JWT_SECRET_KEY`: Mandatory secure secret key (minimum 32 characters). The app fails fast on startup if this is missing.
- `MONGO_URI` and `MONGO_DATABASE`: MongoDB connection string and database name.
- `POSTGRES_DSN`: PostgreSQL connection DSN.

See `.env.example` for sample environment definitions. Create the SQL database and run the migrations in order:
```powershell
psql -d cybersecurity -f sql/001_devices_and_sources.postgres.sql
psql -d cybersecurity -f sql/002_auth_and_detection.postgres.sql
```

Start the API:
```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for interactive OpenAPI documentation.

## Log format

Each record requires `timestamp` (ISO 8601 with a timezone), `source_ip`, `event_type`, `severity`, and `message`. Severity is one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Optional fields are `source_id`, `device_id`, `username`, `log_source`, `destination_ip`, and `destination_port`. Timestamps are stored in UTC. Unknown fields are discarded during normalization.

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

| Method and path | Purpose |
| --- | --- |
| `GET /health` | Check MongoDB connection |
| `POST /api/logs/events` | Insert one JSON event |
| `POST /api/logs/upload` | Upload a multipart file named `file`; maximum 25 MB by default |
| `GET /api/logs` | Search and paginate logs |
| `GET /api/devices` / `POST /api/devices` | List and create devices |
| `GET /api/sources` / `POST /api/sources` | List and create log sources |
| `POST /api/auth/login` | Authenticate user, returns HS256 JWT access token |
| `POST /api/auth/logout` | Revoke current user's session token |
| `GET /api/auth/me` | Retrieve profile of currently authenticated user |
| `GET /api/users` / `POST /api/users` / `PATCH /api/users/{id}` | User management (Administrator only) |
| `GET /api/rules` / `POST /api/rules` / `PATCH /api/rules/{id}` | Detection rule management and threshold configuration |
| `GET /api/threats` / `GET /api/threats/{id}` | Threat records with correlated alerts and evidence |
| `GET /api/alerts` / `GET /api/alerts/{id}` | Security alerts with status, severity, and evidence |
| `POST /api/alerts/{id}/acknowledge` | Acknowledge active alert (Analyst / Admin) |
| `POST /api/alerts/{id}/resolve` | Resolve alert (Analyst / Admin) |
| `POST /api/detection/run` | Execute bounded security detection run |

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
