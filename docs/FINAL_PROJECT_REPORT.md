# Final Project Report — Intelligent Cybersecurity Log Management System

**Team:** Midhun (Member 1), Shraavanth (Member 2), Lakshman (Member 3)  
**Integrated branch:** `main`  
**Date:** 24 October 2026

## Delivered system

The project is a working React/FastAPI security operations console backed by MongoDB and PostgreSQL. MongoDB stores normalized high-volume security events and provides timestamp, source IP, type, severity, and text indexes. PostgreSQL stores devices, log sources, users, roles, detection rules, threats, alerts, incidents, and response actions. The application joins these datasets at the API layer through log IDs and aggregates them for the dashboard.

| Owner | Delivered work |
| --- | --- |
| Member 1 — Midhun | Validated single and batch ingestion (CSV, JSON, JSONL), indexed filtering and cursor pagination, device/source metadata schema and API, deterministic data generator, one-million-log benchmark. |
| Member 2 — Shraavanth | Admin/analyst authentication and RBAC, Argon2id password hashing, JWT sessions, login rate limiting, SQL rules/threats/alerts schema, failed-login/port-scan/activity detection, evidence, deduplication, and alert triage. |
| Member 3 — Lakshman | SQL incidents, alert linkage and action history, incident status and assignment, cross-database analytics, React dashboard and investigation screens. |
| Integration | Resolved branch conflicts, restored safe local configuration, corrected dependencies and detection UI fields, and added a full live API and Chromium browser workflow. |

## Verified behavior

- The backend test suite has **79 passing tests**. Python compilation, frontend lint, and production build succeed.
- GitHub Actions applies SQL migrations 001–003 to PostgreSQL 16 and runs the complete API lifecycle using real PostgreSQL and MongoDB 7: login, RBAC, metadata, six-log upload, filtered and paginated search, detection and evidence, alert acknowledgment and resolution, incident assignment and actions, analytics, and detection replay without duplicate alerts.
- Chromium browser automation uses the running FastAPI and Vite servers with those real databases. It checks login, upload, indexed search, detection results, alert escalation, incident creation and response action, and dashboard navigation.
- The Member 1 live verification inserts **1,000,000 synthetic logs** and tests indexed queries. The recorded GitHub-run benchmark measured median **0.396 ms indexed** versus **188.423 ms collection scan** for its source-IP query. These times are specific to that CI runner and dataset; see [raw result](benchmarks/member1_1m_2026-10-22.json).

The [mock demonstration report](../report.md) remains as a historical result. Live database and browser checks are separate from that mock run. The GitHub Actions status for the final `main` commit is the current execution record.

## Run and demonstrate

Follow the [README setup](../README.md): start MongoDB and PostgreSQL, create the SQL database, apply migrations 001–003, copy `.env.example` to `.env`, set a random `JWT_SECRET_KEY` and admin password, start the backend, then run Vite. The React app is at `http://localhost:5173`; API documentation is at `http://127.0.0.1:8000/docs`.

For a faculty demo, sign in as the bootstrap admin, upload a small JSONL sample generated with `python scripts/generate_logs.py --count 1000 --output sample.jsonl`, filter events in Log Explorer, run Detection Engine, inspect and acknowledge an alert, escalate it to an incident, record an action, and show the dashboard. The benchmark can be reproduced separately with the README commands and sufficient database capacity.

## Scope note

The runnable application uses PostgreSQL for SQL features. The [Oracle 11g analysis](POSTGRES_VS_ORACLE_ANALYSIS.md) is supplementary coursework material, not a second running database backend. Advanced machine learning is outside this implementation; suspicious activity detection uses explainable SQL-configured rules.
