# Demo log files

These files contain **synthetic data only**. Upload them from **Logs → Upload Logs** in the CyberShield website.

| File | Rows | Use |
| --- | ---: | --- |
| `normal_activity.csv` | 80 | Routine sign-ins, access, connections, and firewall blocks |
| `suspicious_activity.jsonl` | 143 | 8 failed logins, 25 distinct port probes, and 110 rapid API requests |
| `full_demo.json` | 168 | One combined scenario for a complete demonstration |

Upload either the two separate files **or** `full_demo.json` to avoid duplicate records. Then open **Detection** and click **Trigger Detection Scan** to create alerts from the suspicious events. The default rules require 5 failed logins in 300 seconds, 20 distinct ports in 60 seconds, and 100 events from one IP in 60 seconds.

All addresses use reserved documentation IP ranges. To regenerate the files with fresh timestamps, run `python scripts/create_demo_logs.py` from the repository root.
