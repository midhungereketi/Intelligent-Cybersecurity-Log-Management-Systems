# Database Architecture Analysis: PostgreSQL vs. Oracle 11g

**Project:** Intelligent Cybersecurity Log Management System  
**Author:** Shraavanth (Member 2 — Security & Backend Integration)  
**Document Purpose:** Resolve architectural and coursework demonstration conflicts regarding PostgreSQL vs. Oracle 11g/PL/SQL.

---

## 1. Executive Summary

The backend of the **Intelligent Cybersecurity Log Management System** is architected on a hybrid database foundation:
- **MongoDB**: High-throughput distributed document store for raw, normalized security logs with compound indexing and flexible JSON payloads.
- **PostgreSQL**: ACID-compliant relational metadata store for roles, users, detection rules, persistent threats, security alerts, and event processing checkpoints.

While certain course Review II guidelines reference **Oracle 11g / PL/SQL**, the active codebase was developed with PostgreSQL. Directly replacing PostgreSQL with Oracle 11g would introduce severe regressions, break existing Member 1 and Member 2 database drivers, and compromise key features (such as `INET` networking primitives, `JSONB` structured alert evidence, and partial unique indexes for active alert deduplication).

This document details the dialect incompatibilities, migration impact, and a clear demonstration strategy for team and academic evaluation.

---

## 2. Technical Dialect & Feature Comparison

| Database Feature | PostgreSQL (Current Implementation) | Oracle 11g (Coursework Reference) | Incompatibility & Migration Impact |
| --- | --- | --- | --- |
| **Primary Keys & Auto-Increment** | `BIGINT GENERATED ALWAYS AS IDENTITY` | Requires separate `CREATE SEQUENCE` and `BEFORE INSERT FOR EACH ROW` PL/SQL trigger per table. | Oracle 11g lacks identity columns (introduced in Oracle 12c). Every table would require sequence and trigger boilerplate. |
| **Network IP Address Types** | Native `INET` type with subnet validation, CIDR math, and index optimization. | No native IP type. Requires `VARCHAR2(45)`. | Loss of native IP filtering, range queries, and database-level IP syntax validation. |
| **Structured Evidence & Config** | Native `JSONB` with binary parsing, json path extraction, and GIN indexing. | No native JSON type in Oracle 11g (introduced in 12c/19c). Requires `CLOB` or `VARCHAR2(4000)`. | Loss of database-level JSON validation; serialization must be handled entirely in application code without native indexing. |
| **Partial / Conditional Unique Indexes** | `CREATE UNIQUE INDEX ... WHERE status != 'RESOLVED'` | Oracle does not support `WHERE` clauses on indexes. | Critical for alert deduplication! Oracle requires function-based workaround: `CREATE UNIQUE INDEX ... (CASE WHEN status != 'RESOLVED' THEN deduplication_key END)`. |
| **Boolean Data Type** | Native `BOOLEAN` (`TRUE` / `FALSE`) | No boolean column type in Oracle SQL. | Columns like `is_active` and `is_enabled` must be converted to `NUMBER(1) CHECK (col IN (0,1))` or `CHAR(1)`. |
| **Timestamps & Timezones** | `TIMESTAMPTZ` (UTC normalized with microsecond precision) | `TIMESTAMP(6) WITH TIME ZONE` | Different timezone representation and string parsing formats between `psycopg` and `python-oracledb`. |
| **Python Database Driver** | `psycopg` (v3) with binary protocol and connection pooling | `python-oracledb` or deprecated `cx_Oracle` | Requires rewriting database connection management, parameter placeholder syntax (`%s` vs `:param`), and row factory structures. |
| **UPSERT Syntax** | `ON CONFLICT (col) DO UPDATE / DO NOTHING` | `MERGE INTO ... USING DUAL ...` | PostgreSQL native `ON CONFLICT` is used in checkpoints, seeds, and processed event tracking. Oracle requires verbose `MERGE` statements. |

---

## 3. Demonstration Strategy

To satisfy academic requirements while ensuring application integrity, the team adopts the following two-tier approach:

### Tier 1: Application Integration Demonstration (Primary)
- The running application, API endpoints, React dashboard (Member 3), and automated test suite execute against **PostgreSQL** (metadata) and **MongoDB** (log store).
- This reflects realistic, modern cybersecurity engineering architectures (similar to Elastic/OpenSearch + PostgreSQL or Splunk + relational metadata).
- Automated tests run against real PostgreSQL or an accurate transactional mock (`MockDatabase`) verifying constraints, foreign keys, and unique indexes.

### Tier 2: Academic Coursework Demonstration
- The PostgreSQL Review II scripts are `sql/004_review2_operations.postgres.sql` and `sql/review2_demo.postgres.sql`. GitHub Actions executes them against real PostgreSQL 16. They demonstrate DDL and constraints, meaningful DML and queries, a stored function, a stored procedure with an explicit cursor, and a status-audit trigger.
- A separate Oracle 11g implementation is supplied as `sql/review2_oracle11g.sql`, with an independent check script in `sql/review2_oracle11g_verify.sql`. It covers the relational model and Oracle PL/SQL rubric using a small synthetic dataset. Follow `sql/ORACLE_REVIEW2_GUIDE.md` to execute it in a clean Oracle schema. The Oracle script has not been verified against a live Oracle instance in this repository's CI and is not wired to the FastAPI application.

---

## 4. Migration Requirements if Oracle Execution is Mandated

If the academic panel explicitly mandates that the backend application must connect directly to an Oracle database:
1. **Driver Transition**: Replace `psycopg[binary]>=3.2` with `oracledb>=2.0` in `requirements.txt`.
2. **Query Refactoring**: Refactor all SQL queries in `app/main.py`, `app/routes_auth.py`, `app/routes_rules.py`, `app/routes_threats_alerts.py`, and `app/detection.py` to use Oracle `:param` binding instead of `%s`.
3. **Upsert Rewrites**: Convert all `ON CONFLICT` clauses to Oracle `MERGE INTO` statements.
4. **Boolean Normalization**: Map Python booleans to `1`/`0` across all database adapter layers.
5. **Team Approval**: Prior to executing this change, formal sign-off must be obtained from all 3 members because modifying the database layer impacts Member 1's device queries and Member 3's API contracts.
