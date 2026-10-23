# Intelligent Cybersecurity Log Management System

## Detailed implementation and workflow report

**Team:** G. Midhun (Member 1), P. Satya Mani Shraavanth (Member 2), M. Lakshman Sai (Member 3)

**Course:** BCSE302L Database Systems Lab

**Repository:** https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems

**Report date:** 24 October 2026

This report explains the implemented three-member prototype, traces the Review I requirements and Review II database criteria to working artifacts, and gives a repeatable demonstration workflow. The application has passed its automated checks on GitHub `main`. The separate Oracle 11g Review II script is prepared and checked structurally, but a live Oracle execution result has not yet been captured. This distinction matters for an honest final submission.

## 1. Problem and delivered scope

Security logs arrive from applications, authentication systems, servers, and network devices in different formats. At high volume, manual review and unindexed searches delay investigations. This project centralizes those records, makes them searchable, and turns suspicious patterns into explainable alerts and incident-response records.

The delivered academic prototype accepts JSON, JSONL, NDJSON, and CSV events, validates and normalizes them, stores full logs in MongoDB, and uses PostgreSQL for relational security records. Its React console supports authenticated search, upload, analytics, detection, alert triage, incident assignment, and response actions. Rule-based detection covers repeated failed logins, possible port scans, and excessive activity. Enterprise clustering, automated blocking, packet capture, commercial integrations, and trained machine learning were explicitly outside the Review I scope.

## 2. Architecture and data ownership

```mermaid
flowchart LR
    B[React SOC console] --> A[FastAPI application]
    A --> M[(MongoDB logs collection)]
    A --> P[(PostgreSQL relational tables)]
    M --> D[Rule detection]
    P --> D
    D --> P
    M --> X[Analytics aggregation]
    P --> X
    X --> A
```

MongoDB stores the full normalized event: UTC event time, ingestion time, source IP, event type, severity, message, and optional user, device/source identifiers, destination IP, and port. PostgreSQL stores devices and log sources, roles and users, detection rules, threats and alerts, processing checkpoints, incidents and actions, plus Review II audit and priority tables. Alert evidence contains MongoDB log IDs as strings; a SQL foreign key cannot span the two databases. The API mediates this link and produces the combined dashboard response.

At startup, FastAPI checks MongoDB, creates the required indexes, and bootstraps an administrator only when credentials are configured. PostgreSQL schema migrations run separately before startup. The frontend calls the backend through Vite's local proxy. The databases are never accessed directly from browser code.

## 3. Complete operating workflow

1. **Prepare access.** An administrator account is bootstrapped from local configuration. Passwords are stored as Argon2id hashes. Login issues a signed JWT; role checks restrict user, device, and source administration.
2. **Collect and validate.** An analyst uploads a CSV/JSON/JSONL file or posts a single event. The API checks required fields, severity, IP address, timestamp timezone, and port range. Rejected rows are counted and reported. Accepted timestamps are normalized to UTC.
3. **Store and index.** Valid events are inserted into MongoDB in batches. Indexes cover descending timestamp, source IP plus timestamp, event type plus timestamp, severity plus timestamp, and message text. PostgreSQL holds the related device/source metadata.
4. **Search.** The analyst combines time, IP, type, severity, and keyword filters. The API returns limited pages with a cursor, avoiding a browser download of the entire collection.
5. **Detect.** A bounded detection run reads candidate logs and enabled SQL rule settings. It evaluates failed-login counts, distinct destination ports, and high-volume activity within configured windows. Checkpoint and deduplication records prevent replay from creating duplicate active alerts for the same event group.
6. **Explain and triage.** A match creates a SQL threat/alert with rule, severity, source IP, timestamps, and supporting MongoDB log IDs. Analysts inspect evidence, acknowledge alerts, or resolve them.
7. **Investigate.** An alert can be escalated to a SQL incident. Users assign an analyst, change incident status, link correlated alerts, and record timestamped response actions or notes.
8. **Analyze.** The dashboard combines MongoDB counts, severity/event distributions, hourly trends, and top source IPs with PostgreSQL alert, threat, and incident metrics. The React console renders the returned summaries and investigation lists.
9. **Audit and prioritize.** PostgreSQL migration 004 records alert status transitions with a trigger, calculates an incident risk score in a SQL function, and refreshes active incident priorities through a stored procedure with an explicit cursor. These database operations have a rollback-only Review II demo script.

Detection reports suspicious patterns. It does not establish that an attack occurred; the analyst makes that judgment after reviewing evidence.

## 4. Member contributions and branch history

| Member | Contribution | Branch |
| --- | --- | --- |
| Member 1, Midhun | MongoDB normalization, ingestion, indexed search, SQL device/source metadata, synthetic generator, and million-log benchmark | `member1-log-pipeline` |
| Member 2, Shraavanth | Authentication, RBAC, rate limiting, relational rules/threats/alerts, detection, evidence, and deduplication | `member2-shraavanth` |
| Member 3, Lakshman | Incident and action APIs, cross-database analytics, and React SOC console | `member3.1--lakshman` |
| Integrated result | Merge repairs, configuration and dependency fixes, live API and Chromium tests, Review II PostgreSQL operations, reports | `main` |

The GitHub repository retains `main` and the three member branches. `main` is the version to run and submit; the member branches preserve individual contributions.

## 5. Review I requirements traceability

| ID | Required behavior | Implementation and verification |
| --- | --- | --- |
| FR-01 | Secure login | `app/routes_auth.py`, `app/auth.py`; login in live API and browser tests |
| FR-02 | Role-based access | Admin/analyst dependencies; live test confirms unauthenticated and analyst restrictions |
| FR-03 | API and file ingestion | `app/main.py`, `app/logs.py`; JSON/CSV/JSONL/NDJSON support; browser upload test |
| FR-04 | Reject malformed records | `normalize` and `ingest`; row rejection/error counts; backend tests |
| FR-05 | Normalize records and time | UTC conversion and field normalization in `app/logs.py`; backend tests |
| FR-06 | Store logs in MongoDB | MongoDB `logs` collection; live database lifecycle test |
| FR-07 | Relational security records | Migrations 001-004 and SQL APIs; live PostgreSQL migration and lifecycle tests |
| FR-08 | Combined search filters | `app/logs.py` query composition; live filtered search and browser test |
| FR-09 | Paginated retrieval | Cursor tokens with timestamp and ObjectId ordering; live two-page test |
| FR-10 | Dashboard analytics | `app/routes_analytics.py` and React dashboard; live API and browser tests |
| FR-11 | Configurable detection rules | SQL `rules` table and `app/detection.py`; detection tests |
| FR-12 | Alerts with rule and evidence | SQL alert rows with JSONB evidence/log IDs; live alert evidence check |
| FR-13 | Investigation and notes | Alert OPEN/ACKNOWLEDGED/RESOLVED plus incident INVESTIGATING and action notes; live lifecycle and browser tests |
| FR-14 | Indexed performance comparison | One-million-log MongoDB benchmark and stored raw result |
| FR-15 | Synthetic normal and suspicious data | `scripts/generate_logs.py`; million-log CI job and smaller demonstration |

The Review I ER diagram includes optional ML_MODEL and PREDICTION entities, while the same review explicitly excludes advanced machine learning from the initial scope. The running application uses explainable rules. The Oracle coursework script retains inactive ML placeholder tables for ER coverage but does not claim a trained model.

## 6. Review II database criteria

| Evaluation item | Running PostgreSQL evidence | Separate Oracle 11g coursework evidence |
| --- | --- | --- |
| DDL and constraints | Migrations 001-004 define PK, FK, UNIQUE, CHECK, indexes | `sql/review2_oracle11g.sql` defines 12 ER-model tables and constraints |
| DML and population | `sql/review2_demo.postgres.sql` inserts, updates, deletes, then rolls back | Oracle script seeds ten synthetic logs and related rows, updates and deletes demonstration records |
| SQL queries | Demo verifies joins, grouping, aggregates, HAVING, and a subquery | Six review queries include joins, aggregates, grouping, and subqueries |
| Procedure and function | `refresh_incident_priorities` and `incident_risk_score` | `PR_CREATE_ALERT`, `PR_SCAN_FAILED_LOGINS`, `FN_FAILED_LOGIN_COUNT` |
| Cursor and triggers | Explicit incident cursor and alert-status audit trigger | Failed-login cursor plus high-alert and incident-resolution triggers |
| Viva explanation | Live CI evidence and this workflow | `sql/ORACLE_REVIEW2_GUIDE.md` explains run order, expected checks, and evidence capture |

The PostgreSQL Review II demo **has passed against PostgreSQL 16** in GitHub Actions. The Oracle SQL is a separate, one-time script for a clean Oracle 11g schema. Its object counts and structure have been checked in source, but no Oracle database execution is recorded yet. Run both `sql/review2_oracle11g.sql` and `sql/review2_oracle11g_verify.sql` in SQL Developer and save the actual output before claiming an Oracle pass. The original Review I pages and the existing combined Review II PDF have not been edited for this report.

## 7. Measured and automated results

| Check | Result | Evidence |
| --- | --- | --- |
| Backend suite | 79 tests passed | [Member 3 CI on main](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/40018839332) |
| Real database lifecycle | MongoDB 7 and PostgreSQL 16 checks passed, including migrations 001-004, upload, detection, triage, incidents, analytics, replay | Same Member 3 CI run, `live-system` job |
| Browser workflow | Chromium login, upload, search, detection, alert escalation, incident action, dashboard passed against real services | Same Member 3 CI run, `browser-e2e` job |
| Frontend | Lint command and production build passed | Same Member 3 CI run, `frontend-build` job |
| Review II PostgreSQL SQL | DML, join, aggregation, subquery, function, trigger, cursor procedure passed | Same Member 3 CI run, `live-system` job |
| Million-log evaluation | Live verification and benchmark job passed on `main` | [Member 1 CI on main](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/40018839393) |

The recorded source-IP benchmark used one million synthetic records on a GitHub-hosted Linux runner with four visible virtual CPUs and 15 GiB RAM. The specific query returned 50 rows from 25,000 matching records. Across five measured requests, the indexed median was **0.396 ms** and a forced collection scan median was **188.423 ms**; the query plan examined 50 versus 1,000,000 documents. This is about 475 times faster for that query and runner, not a universal system-wide speed guarantee. See [raw benchmark data](benchmarks/member1_1m_2026-10-22.json).

## 8. Reproduce the application locally

Prerequisites: Python 3.11+, Node.js 22, MongoDB 7, PostgreSQL 16, an empty `cybersecurity` SQL database, and `psql`. From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Edit `.env` with the local MongoDB URI, PostgreSQL DSN, a random `JWT_SECRET_KEY`, and a chosen `ADMIN_PASSWORD`. Do not commit `.env`. The backend loads this file, but `psql` does not; set the same DSN in the shell and apply each migration with errors treated as fatal:

```powershell
$env:POSTGRES_DSN = 'postgresql://postgres:postgres@localhost:5432/cybersecurity'
psql $env:POSTGRES_DSN -v ON_ERROR_STOP=1 -f sql/001_devices_and_sources.postgres.sql
psql $env:POSTGRES_DSN -v ON_ERROR_STOP=1 -f sql/002_auth_and_detection.postgres.sql
psql $env:POSTGRES_DSN -v ON_ERROR_STOP=1 -f sql/003_incidents_and_actions.postgres.sql
psql $env:POSTGRES_DSN -v ON_ERROR_STOP=1 -f sql/004_review2_operations.postgres.sql
psql $env:POSTGRES_DSN -v ON_ERROR_STOP=1 -f sql/review2_demo.postgres.sql
python -m uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open `http://localhost:5173`; API documentation is at `http://127.0.0.1:8000/docs`. Use the bootstrap admin credentials from `.env`. Generate a small sample file with `python scripts/generate_logs.py --count 1000 --output sample.jsonl`, then upload it in the Log Explorer. Start with a small dataset before running the million-log benchmark because that job uses substantial local storage and time.

## 9. Faculty demonstration sequence

1. Show the repository `main` and the three member branches, and identify each person's owned module.
2. Explain the MongoDB/PostgreSQL split, the absence of cross-database FKs, and the indexed MongoDB search path.
3. Log in as admin. Create an analyst, then show that the analyst cannot perform an admin-only operation.
4. Upload synthetic logs, show inserted/rejected counts, apply an IP/time/severity filter, and page through results.
5. Run detection, open the supporting evidence of a failed-login alert, acknowledge it, and rerun detection to show no duplicate active alert.
6. Escalate the alert, assign an analyst, record a response note/action, and show the incident and dashboard totals.
7. Show the one-million-log benchmark report and explain the exact query, index, measured environment, and query plan.
8. In PostgreSQL, run the rollback-only Review II demo and explain its function, cursor procedure, trigger, joins, and subquery.
9. If faculty asks for Oracle PL/SQL, run the separate Oracle script and verification script in a clean Oracle 11g schema. Show actual output, not the expected values printed in the Review II PDF.

## 10. Completion boundary

Within the Review I academic prototype scope, the integrated application and PostgreSQL Review II demonstration are implemented and passing. The Oracle 11g coursework artifact is prepared and packaged with a deterministic verification script. **An Oracle execution record is still required to state that the Oracle path is verified.** The project does not include enterprise deployment or trained ML because those were outside the stated scope.

## 11. Oracle lab execution record

The Oracle path needs one clean run in your accessible Oracle 11g environment. Use a dedicated schema so the one-time DDL cannot collide with unrelated tables. In SQL Developer, open `sql/review2_oracle11g.sql`, enable DBMS Output, and choose **Run Script (F5)**. Confirm the 12 tables, four indexes, two triggers, one function, and two procedures compile without errors. The script inserts the synthetic records and runs the six review queries.

Next, run `sql/review2_oracle11g_verify.sql` in the same connection. A passing run prints `REVIEW II ORACLE CHECKS PASSED`; it also checks the failed-login count of three, one alert after detection replay, linked incident creation, DELETE behavior, and resolved-time trigger. The verification rolls back its temporary incident update. Capture the script output, any compilation messages, and representative query result screens for the faculty review.

If either script reports an `ORA-` or `PLS-` error, record the exact message and line number, repair the script, then repeat from a clean schema. The expected values printed in the existing Review II PDF are not a substitute for actual execution output. Keep database passwords out of screenshots, the repository, and this report.
