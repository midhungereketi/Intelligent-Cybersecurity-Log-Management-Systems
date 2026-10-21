# End-to-End SOC Workflow & Verification Guide

**Project:** Intelligent Cybersecurity Log Management System  
**Branch:** `member3-lakshman`  
**Purpose:** Comprehensive guide and verification walkthrough for the complete end-to-end SOC lifecycle across Member 1 (Log Pipeline), Member 2 (Detection & Auth), and Member 3 (Incident Response & UI).

---

## Architecture Overview

```mermaid
graph LR
    subgraph Member1[Member 1: Ingestion & Logs]
        L1[Log Generator / Upload] --> L2[MongoDB `cybersecurity_logs`]
        L3[PostgreSQL `devices`, `log_sources`]
    end

    subgraph Member2[Member 2: Detection & Auth]
        D1[Detection Engine `POST /api/detection/run`] --> D2[PostgreSQL `threats`, `alerts`]
        A1[Argon2id Auth & JWT] --> A2[PostgreSQL `users`, `roles`]
    end

    subgraph Member3[Member 3: Incident Response & SOC UI]
        I1[Incident Management `POST /api/incidents`] --> I2[PostgreSQL `incidents`, `actions`]
        AN1[Dual-Pipeline Analytics Engine] --> UI[React SOC Console]
    end

    L2 --> D1
    D2 --> I1
    L2 --> AN1
    D2 --> AN1
    I2 --> AN1
```

---

## 11-Step End-to-End Workflow Walkthrough

### Step 1: Environment Preparation & Migrations
1. Ensure MongoDB and PostgreSQL 16 are running locally or in Docker.
2. Configure `.env` from `.env.example`:
   ```bash
   cp .env.example .env
   ```
   Set:
   ```env
   MONGO_URI=mongodb://localhost:27017
   MONGO_DATABASE=cybersecurity_logs
   POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/cybersecurity_db
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=AdminSecurePass123!
   ADMIN_EMAIL=admin@cyber.local
   JWT_SECRET=your-32-byte-base64-or-hex-secret
   ```
3. Apply SQL migrations sequentially:
   ```bash
   psql $POSTGRES_DSN -f sql/001_devices_and_sources.postgres.sql
   psql $POSTGRES_DSN -f sql/002_auth_and_detection.postgres.sql
   psql $POSTGRES_DSN -f sql/003_incidents_and_actions.postgres.sql
   ```
   *Note: All 3 migrations use `IF NOT EXISTS` constructs and are safe to run repeatedly.*

---

### Step 2: Start Backend Services
```powershell
python -m uvicorn app.main:app --reload --port 8000
```
- MongoDB indexes on `logs` collection are verified and created on startup (`timestamp`, `source_ip`, `event_type`, `severity`).
- Admin user from `.env` is bootstrapped into PostgreSQL `users` table on startup if not already present.

---

### Step 3: Start Frontend Application
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

### Step 4: Administrator Authentication & Analyst Onboarding
1. Navigate to the login page at `http://localhost:5173/`.
2. Authenticate using the credentials configured in `.env` (`admin` / `AdminSecurePass123!`).
3. Navigate to **Admin View** (`/admin`) -> **User Management**.
4. Create an analyst account:
   - **Username:** `analyst_user`
   - **Email:** `analyst@example.com`
   - **Password:** `AnalystPass123!`
   - **Role:** `ANALYST` (Role ID `2`)
5. Log out and log back in as `analyst_user` to verify analyst role session.

---

### Step 5: Ingest Security Logs
Ingest a deterministic sample batch containing simulated security anomalies:
```powershell
python scripts/generate_logs.py --count 100 --seed 42 --insert
```
- Ingests 25 failed login events from IP `198.51.100.10`
- Ingests 35 rapid port scan probes from IP `198.51.100.20`
- Ingests 40 traffic burst events from IP `198.51.100.30`
- Timestamps are normalized as BSON Date / UTC ISO datetime objects.

---

### Step 6: Log Search & Time Filtering (LogsView)
1. In the React SOC UI, open **Logs** view.
2. Filter by:
   - **Severity:** `HIGH`
   - **Start Time (UTC):** `2026-10-01 00:00`
   - **End Time (UTC):** `2026-10-01 23:59`
3. Click **Filter**. The table updates to show only events within the specified time window.
4. Test validation: Enter an End Time earlier than Start Time. The form displays an inline error:
   `"Start time cannot be after end time."`
5. Click **Reset**: State and form fields clear, and the unfiltered log list re-renders immediately.

---

### Step 7: Trigger Security Detection Pass
1. Navigate to **Detection** view or click **Trigger Detection Pass** on the Dashboard.
2. Detection engine runs bounded analysis against unflagged MongoDB logs:
   - Identifies > 5 failed logins within 5 minutes for IP `198.51.100.10` -> Generates `FAILED_LOGINS` alert.
   - Identifies probes against > 10 distinct ports for IP `198.51.100.20` -> Generates `PORT_SCAN` alert.
   - Creates correlated threat records and inserts evidence arrays referencing log IDs.

---

### Step 8: Alert Triage & Escalation (AlertsView)
1. Open **Alerts** view.
2. Inspect the high-severity alert for `198.51.100.10` (`FAILED_LOGINS`).
3. Click **Acknowledge** (`POST /api/alerts/{id}/acknowledge`): Alert status transitions to `ACKNOWLEDGED`.
4. Click **Escalate to Incident**:
   - Opens the incident creation modal prefilled with alert title, severity (`HIGH`), source IP, and linked `alert_id`.

---

### Step 9: Incident Assignment via RBAC Safe Endpoint (IncidentsView)
1. In the Create Incident modal:
   - Assignee dropdown is populated via `GET /api/users/assignable`.
   - Analysts can access this endpoint without triggering 403 Forbidden errors.
   - Select `analyst_user` as the assignee.
2. Click **Create Incident** (`POST /api/incidents`):
   - Creates incident record with status `OPEN`.
   - Links alert to junction table `incident_alerts`.
   - Records an initial audit action in `actions`.

---

### Step 10: Investigation & Response Action Logging
1. Open the created incident in **Incidents** view.
2. Update status to `INVESTIGATING`:
   - System automatically logs a `STATUS_CHANGE` action in the timeline.
3. In the Action History panel, add a response action:
   - **Action Type:** `CONTAINMENT`
   - **Details:** `"Null-routed source IP 198.51.100.10 at border firewall BGP router."`
   - System records the action with timestamp and actor attribution (`analyst_user`).
4. Update incident status to `RESOLVED`:
   - Incident marked resolved; resolution timestamp recorded.

---

### Step 11: Real-Time Analytics & Dashboard Verification
1. Open **Dashboard** view (`/dashboard`).
2. Verify KPI cards:
   - **Total Logs:** Reflects 100 ingested logs.
   - **Total Incidents:** Shows active and resolved counts.
   - **Events Timeline Chart:** Renders hourly time buckets (e.g. `2026-10-01T10:00Z`) with stacked severity bars.
   - **Top Source IPs:** Correctly ranks `198.51.100.10`, `198.51.100.20`, and `198.51.100.30`.
   - **Recent Alerts & Incidents:** Displays latest activity.

---

## Automated Verification Suite

All endpoints, schema constraints, role permissions, and regression scenarios are validated offline using the automated test suite without requiring active external services:

```powershell
python -m unittest discover -s tests -v
```

**Results: 68/68 passed (100% pass rate)**
- SQL Schema Constraints & Migrations: 10 tests passed
- Argon2id & JWT Authentication: 8 tests passed
- Security Detection Engine & Deduplication: 9 tests passed
- Ingestion, Normalization, & Log Search: 8 tests passed
- Incidents & Action Audit Timeline: 6 tests passed
- Cross-Database Analytics: 5 tests passed
- Member 3 Regressions (Timeline Date/String, Time Filters, Assignable Users): 19 tests passed
- Full End-to-End API Integration Pipeline: 4 tests passed
