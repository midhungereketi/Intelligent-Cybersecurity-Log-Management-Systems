# Member 1 Handoff Report

**Project:** Intelligent Cybersecurity Log Management System

**Owner:** Midhun (Member 1)

**Branch:** `member1-log-pipeline`

**Pull request:** https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/pull/1

**Status:** Member 1 implementation is committed and pushed. Integration with live databases and the other members' modules remains.

This report is for the other two members and their AI agents. It describes the code that exists, its tested behavior, the interfaces to use, and the decisions the team still needs to make. Use the repository source as the authority if this report and code ever differ.

**Current team status (22 October 2026):** Members 2 and 3 have since implemented their modules on separate branches. See [Team Remaining Work](TEAM_REMAINING_WORK.md) for the current integration and verification tasks; the original handoff sections below describe the Member 1 API contract.

## What Member 1 completed

| Deliverable | Location | Current behavior |
| --- | --- | --- |
| Log validation and normalization | `app/logs.py` | Requires timestamp, source IP, event type, severity, and message; converts timestamps to UTC; validates IPs and ports. |
| MongoDB ingestion | `app/logs.py`, `app/main.py` | Inserts one event or batches of up to 1,000 from CSV, JSON, or JSONL uploads. Reports rejected rows. |
| Indexed log search | `app/logs.py`, `app/main.py` | Filters by time, source IP, event type, severity, and message keyword; returns cursor-paginated results. |
| MongoDB indexes | `app/logs.py` | Creates time, source IP/time, event type/time, severity/time, and message text indexes at API startup. |
| Device and log-source metadata | `sql/001_devices_and_sources.postgres.sql`, `app/main.py` | Defines PostgreSQL tables and list/create API endpoints. |
| Synthetic dataset | `scripts/generate_logs.py` | Produces deterministic normal events and patterns for failed-login, port-scan, and activity-burst demonstrations. Supports JSONL output or batched direct insertion. |
| Query benchmark | `scripts/benchmark.py` | Compares a natural collection scan with the `source_ip_time` index without deleting indexes. Reports median time and query plans. |
| Setup and checks | `README.md`, `requirements*.txt`, `.github/workflows/member1-tests.yml`, `tests/test_logs.py` | Documents setup and runs automated tests in GitHub Actions. |

The application is a FastAPI backend. Member 3 can build the website against it; Member 2 can add authentication and detection to the same backend.

## Current data contract

MongoDB database name defaults to `cybersecurity_logs`; the collection is `logs`. Configure this with `MONGO_DATABASE`. Each log has:

| Field | Type and meaning |
| --- | --- |
| `id` | MongoDB ObjectId represented as a string in API responses. In MongoDB the field is `_id`. |
| `timestamp` | Required event time in UTC. API input must include a timezone; API output uses ISO 8601 with `Z`. |
| `ingested_at` | UTC time the backend accepted the event. |
| `source_ip` | Required validated IPv4 or IPv6 address. |
| `event_type` | Required uppercase event category, such as `LOGIN_FAILED` or `CONNECTION`. |
| `severity` | Required `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `message` | Required text, maximum 4,000 characters. |
| `source_id`, `device_id` | Optional positive SQL IDs; existence is not yet checked during log ingestion. |
| `username`, `log_source` | Optional text fields. |
| `destination_ip`, `destination_port` | Optional fields useful for port-scan detection. |

Example input:

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

Unknown input fields are discarded. If a teammate needs another field, coordinate the schema change with Member 1 before depending on it.

## Existing API

| Method | Path | Inputs and result |
| --- | --- | --- |
| `GET` | `/health` | Checks the MongoDB connection. |
| `POST` | `/api/logs/events` | JSON object containing one log; returns the stored log, HTTP 201. |
| `POST` | `/api/logs/upload` | Multipart field named `file` containing `.csv`, `.json`, `.jsonl`, or `.ndjson`; returns inserted and rejected counts plus up to 100 row errors. Default maximum file size is 25 MB. |
| `GET` | `/api/logs` | Search parameters: `start`, `end`, `source_ip`, `event_type`, `severity`, `keyword`, `limit`, `cursor`. Returns `items` and `next_cursor`. |
| `GET`, `POST` | `/api/devices` | List and create PostgreSQL devices. |
| `GET`, `POST` | `/api/sources` | List and create PostgreSQL log sources. `GET` accepts optional `device_id`. |

For pagination, request `GET /api/logs?limit=50` and pass the returned `next_cursor` with the **same filters** until it is `null`. The default page size is 50 and maximum is 200. The search order is newest event first, then newest MongoDB ID for equal timestamps. Keyword search uses MongoDB's text index on `message`.

An example response shape is:

```json
{
  "items": [
    {
      "id": "670000000000000000000001",
      "timestamp": "2026-10-01T10:00:00Z",
      "ingested_at": "2026-10-10T10:00:00Z",
      "source_ip": "198.51.100.10",
      "event_type": "LOGIN_FAILED",
      "severity": "HIGH",
      "message": "Failed login for analyst"
    }
  ],
  "next_cursor": null
}
```

The example ID and ingestion time above illustrate the format; they are not stored sample records.

## How to run and verify

From the repository root, create a Python 3.11+ environment and install `requirements.txt`. Start MongoDB. Set `MONGO_URI` and `MONGO_DATABASE`, then run `uvicorn app.main:app --reload`. The API documentation will be at `http://127.0.0.1:8000/docs`. PostgreSQL is needed for `/api/devices` and `/api/sources`: create a database, run `sql/001_devices_and_sources.postgres.sql`, and set `POSTGRES_DSN`. `.env.example` contains sample values, but the app does not load `.env` automatically.

Useful commands:

```powershell
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python scripts/verify_member1_live.py
python scripts/generate_logs.py --count 1000 --output sample.jsonl
python scripts/generate_logs.py --count 1000000 --insert
python scripts/benchmark.py --source-ip 198.51.100.10 --repeats 5 --output benchmark.json
```

Python compilation and **8 unit tests passed**. The [Member 1 live verification run](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/39795002781) applied migration 001 to PostgreSQL 16, checked real MongoDB ingestion/search/indexes, inserted **1,000,000 synthetic logs**, and saved a search benchmark. The measured result and its environment are in [Member 1 Verification](MEMBER1_VERIFICATION.md), with the raw [benchmark JSON](benchmarks/member1_1m_2026-10-22.json). The live test uses temporary SQL records and cleans up its own MongoDB test events. Benchmark timings are specific to the GitHub runner and query; do not present them as universal performance guarantees.

## Handoff to Member 2 and their AI agent

**Ownership:** SQL `ROLE`, `USER`, `RULE`, `THREAT`, and `ALERT`; password hashing and role checks; detection rules; alert evidence and alert APIs.

Build on `member1-log-pipeline` after it is reviewed or merged. Read `app/main.py`, `app/logs.py`, and the SQL migration first. Use the normalized MongoDB fields above for three rule families: repeated `LOGIN_FAILED` events, many destination ports from one source IP, and unusually high event volume from one source IP within a time window. Store MongoDB `id` values as strings in SQL alert evidence; SQL foreign keys cannot point into MongoDB. Attach the triggering rule, severity, detection time, source IP, and supporting log IDs to each alert. Make detection reruns idempotent so they do not create duplicate alerts.

Add authentication and authorization to write, upload, metadata, rule, alert, and investigation endpoints. The current Member 1 endpoints have no authentication and are intended for local development. Keep the existing log search response shape stable so Member 3 can integrate it.

**Acceptance check:** inserting a set of repeated failed-log events produces one explainable alert, rerunning detection does not duplicate it, and an analyst can retrieve the alert and its supporting log IDs.

## Handoff to Member 3 and their AI agent

**Ownership:** React website, search and upload interface, charts, alert and incident screens, SQL `INCIDENT` and `ACTION` records, and investigation workflow.

Build the log search table against `GET /api/logs`. Use `items` for rows and `next_cursor` for the next page; keep the current filters when paging. Use `POST /api/logs/upload` for the upload screen and display both inserted and rejected counts with row errors. Use the device and source list/create endpoints for metadata screens. Build dashboard aggregation endpoints on MongoDB's normalized fields rather than downloading all logs into the browser. Use Member 2's alert API for alert and evidence views. Record incident assignment, status, notes, and actions in SQL, and link an incident to relevant alert/log IDs.

The backend currently allows browser requests from `localhost:3000`, `localhost:5173`, and `127.0.0.1:5173`; coordinate any other development origin with Member 1. Do not assume the frontend can safely expose MongoDB or PostgreSQL credentials.

**Acceptance check:** a user can upload sample logs, filter and page through them, view charts produced by backend aggregation, open an alert, and record an incident action.

## Decisions and dependencies for the whole team

1. **Choose the SQL engine.** The review document proposes PostgreSQL in one section and describes Oracle 11g constraints in another. The current Member 1 migration and metadata endpoints use PostgreSQL. If the faculty requires Oracle 11g, port the SQL migration and database adapter before integrating SQL modules.
2. **Keep the log storage model consistent.** The review document includes a SQL `LOG` entity and also proposes MongoDB for high-volume logs. The current implementation stores full logs in MongoDB; SQL modules should store log ID references unless the team explicitly changes this design.
3. **Decide whether ML is required.** The review document calls advanced machine learning out of scope but includes `ML_MODEL` and `PREDICTION` entities. Treat these as optional until the faculty confirms the expectation.
4. **Integrate one working path first.** Demonstrate upload -> MongoDB search -> detection -> SQL alert -> dashboard -> incident action before expanding features.
5. **Finish the live demonstration.** Run MongoDB and the chosen SQL engine locally, apply the SQL schema, generate data in increasing sizes, and record real benchmark results.

The shared source of truth is the GitHub pull request linked above. Teammates can give this Markdown file to their AI agents as context, but each agent should inspect the current branch and code before making changes.
