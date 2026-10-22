# Intelligent Cybersecurity Log Management System

This repository contains the Member 1 data pipeline for a three-member Database Systems project. It accepts security logs, stores them in MongoDB, supports indexed search, and provides a repeatable performance comparison. PostgreSQL tables and APIs manage device and log-source metadata.

The other members can add authentication, detection, alerts, analytics, and incident handling using the API described below.

For teammate and AI-agent handoff, see [Member 1 Handoff Report](docs/MEMBER1_HANDOFF.md).
The live PostgreSQL/MongoDB check and one-million-log index benchmark are recorded in [Member 1 Verification](docs/MEMBER1_VERIFICATION.md).

## Member 1 deliverables

| Area | Implementation |
| --- | --- |
| Ingestion | Single-event API and CSV, JSON, or JSONL upload with validation and batches of 1,000 |
| Log storage | MongoDB `logs` collection with UTC timestamps and optional device/source IDs |
| Search | Time, IP, event type, severity, and keyword filters with stable cursor pagination |
| Indexes | Timestamp, source IP/time, event type/time, severity/time, and message text |
| Sample data | Deterministic generator with failed-login, port-scan, and activity-burst patterns |
| Performance | Indexed versus collection-scan benchmark; does not drop indexes |
| SQL metadata | PostgreSQL `device` and `log_source` tables and creation/list APIs |

## Setup

Requires Python 3.11+, MongoDB, and PostgreSQL for device/source endpoints. The log API can run without PostgreSQL; its metadata endpoints return 503 until `POSTGRES_DSN` is configured. The SQL script targets PostgreSQL. The review document also mentions Oracle 11g, so confirm the required SQL engine with the faculty before using the SQL migration.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Set `MONGO_URI`, `MONGO_DATABASE`, and `POSTGRES_DSN` as environment variables. The app does not automatically read `.env`; `.env.example` provides sample values to load through your shell or environment manager. Create the SQL database and run `sql/001_devices_and_sources.postgres.sql` with `psql` or a PostgreSQL client.

```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for interactive API documentation. Starting the API checks MongoDB connectivity and creates the required indexes.

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

For `GET /api/logs`, supported query parameters are `start`, `end`, `source_ip`, `event_type`, `severity`, `keyword`, `limit` (1–200), and `cursor`. The response contains `items` and `next_cursor`. Pass `next_cursor` unchanged in the next request with the same filters. The default limit is 50. Uploaded rows that fail validation are counted in `rejected`; up to 100 row errors are returned.

Example:

```text
GET /api/logs?source_ip=198.51.100.10&start=2026-10-01T00:00:00Z&limit=50
```

The current API has no authentication because Member 2 owns that module. Add their authentication and role checks before exposing this service beyond the local project environment.

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

Run the module tests with:

```powershell
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```
