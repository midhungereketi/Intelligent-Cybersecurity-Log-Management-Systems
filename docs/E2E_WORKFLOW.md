# End-to-end SOC workflow

The current, fully explained workflow is in the [detailed project report](DETAILED_PROJECT_REPORT.md). This page is a short checklist for demonstrating the integrated `main` branch.

1. Start MongoDB 7 and PostgreSQL 16, create the SQL database, configure `.env`, and apply migrations 001-004 as shown in the [README](../README.md).
2. Start FastAPI with `python -m uvicorn app.main:app --reload --port 8000`. In another terminal run `cd frontend`, `npm ci`, and `npm run dev`.
3. Sign in at `http://localhost:5173` using the bootstrap admin credentials configured locally. Create an analyst in Admin Management.
4. Upload a JSONL sample through Log Explorer. Check inserted/rejected counts, filter by IP/time/severity, and page through the result.
5. Run Detection Engine. Inspect the generated alert and its supporting MongoDB log IDs. Rerun detection to confirm that replay does not create a duplicate active alert.
6. Escalate an alert to an incident. Assign an analyst, change its status, and record a response action. Show the dashboard metrics and charts.
7. Run `sql/review2_demo.postgres.sql` using `psql -v ON_ERROR_STOP=1` to explain the SQL function, procedure, explicit cursor, trigger, DML, joins, grouping, and subquery. This demo rolls back its sample rows.
8. For Oracle 11g Review II evidence, follow the separate [Oracle guide](../sql/ORACLE_REVIEW2_GUIDE.md). Its script uses a dedicated clean schema and does not run the FastAPI backend.

Automated proof for the combined workflow is in the [Member 3 CI run on main](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/40018839332); the [Member 1 CI run](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/40018839393) includes the million-log benchmark.
