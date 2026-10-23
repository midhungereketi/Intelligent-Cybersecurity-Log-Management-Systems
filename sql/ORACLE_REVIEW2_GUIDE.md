# Oracle 11g Review II execution guide

The production-style academic prototype runs on PostgreSQL and MongoDB. The separate [Oracle 11g script](review2_oracle11g.sql) demonstrates the Review II relational model and PL/SQL rubric with synthetic data. It does not replace PostgreSQL in the FastAPI application or synchronize its demo records with MongoDB.

Use a **clean, dedicated Oracle 11g schema**. `review2_oracle11g.sql` creates 12 tables, indexes, triggers, sequences, seed data, a failed-login count function, alert creation and cursor-scan procedures, and review queries. It is a one-time setup script: rerunning the whole file in the same schema will produce object-already-exists errors. Never run it in a schema containing valuable tables with these names.

1. Open the dedicated connection in Oracle SQL Developer. Enable DBMS Output and use **Run Script (F5)**, not Run Statement, on `review2_oracle11g.sql`. SQL*Plus can also run `@review2_oracle11g.sql`.
2. Confirm that object creation and PL/SQL compilation produced no errors. Record the six query result sets and the line `Failed login count = 3`.
3. Run [review2_oracle11g_verify.sql](review2_oracle11g_verify.sql) in the same schema with F5 or `@review2_oracle11g_verify.sql`. Success prints `REVIEW II ORACLE CHECKS PASSED`. The verification script rolls back its temporary incident status change.
4. Save the actual SQL Developer output or screenshots for the viva. The expected values in the Review II PDF are predictions from the seed data; only a successful database run establishes the actual result.

The verification checks 12 tables, 10 synthetic logs, three failed logins, detection replay without a duplicate alert, the high-alert incident trigger, the DELETE demonstration, and the resolved-time trigger. It deliberately uses sample IP ranges and placeholder password hashes. These users are **not** valid FastAPI login accounts.

If an error occurs, capture the Oracle error text and line number. Do not claim an Oracle execution pass until the script and verification both complete successfully in Oracle 11g.
