# Member 2 CSV demo data and local import

The six original CSV files in `demo_logs/member2/` came from commit `769d255` on `member2-shraavanth` (26 October 2026). The files were copied byte for byte. The branch's `.env.example` change and `database_inspection.txt` were not needed for the import.

| File | Rows | Import file |
| --- | ---: | --- |
| `01_brute_force.csv` | 6 | Original |
| `02_port_scan.csv` | 25 | Original |
| `03_excessive_activity.csv` | 150 | Original |
| `cybersecurity_demo_logs_150.csv` | 150 | `prepared/cybersecurity_demo_logs_150.csv` |
| `extended_security_logs_500.csv` | 500 | Original |
| `sample_security_logs.csv` | 20 | Original |

**Total: 851 imported rows.** The original 150-row file has `destination_port=0` on lines 64 and 125, both `ARP_CHANGE` events. Port 0 fails the application's 1–65535 validation. The prepared copy changes only those two fields to blank, meaning no destination port; the original is preserved. All other rows passed validation. There were no duplicate normalized rows within these files.

The application keeps its supported fields (timestamp, source IP, event type, severity, message, optional username, log source, destination IP, and destination port). Extra CSV columns such as protocol, action, status, hostname, source port, byte counts, and country are discarded by the existing normalization contract. Keep the original CSVs if those fields are needed for another analysis.

## Local run on 26 October 2026

The six files were uploaded once through the authenticated `/api/logs/upload` endpoint into the local MongoDB `cybersecurity_logs.logs` collection. Each upload returned zero rejected rows. MongoDB increased from 6 existing demo logs to **857 logs** and retained its search indexes.

The detection pass scanned 857 logs using the three PostgreSQL rules. It created alerts for the new failed-login source `203.0.113.10` and port-scan source `203.0.113.20`. The 150 excessive-activity events peak at 61 events in a 60-second window, below the initial threshold of 100. For this local demo, the enabled rule was changed to **50 events per 60 seconds** using the admin API. A second detection pass created the intended excessive-activity alert for `203.0.113.30`. Existing alert deduplication prevented a second alert for the previously loaded test logs. The resulting local PostgreSQL database has **4 alerts, 4 threats, and 1 incident**; the incident predates this import.

The rule threshold change and the inserted database rows are local data, not Git commits. Another computer needs its own database setup and must upload the six import files once. Reuploading them will duplicate logs because log ingestion does not deduplicate identical CSV rows.

The latest merge also introduced an in-memory PostgreSQL fallback with fixed demo accounts. This import was verified against the real PostgreSQL 16 server. The fallback was removed from `main` so a missing PostgreSQL connection returns HTTP 503 rather than silently using mock data. The two fail-closed checks are in `tests/test_db_fail_closed.py`.
