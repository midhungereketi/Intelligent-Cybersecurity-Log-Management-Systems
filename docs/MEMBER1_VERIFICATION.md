# Member 1 Live Verification and Benchmark

**Owner:** Midhun (Member 1)  
**Branch:** `member1-log-pipeline`  
**Verified commit:** `4dca3d2da3104802188d49bb4d89ff1552ef2cd5`  
**GitHub Actions run:** [Member 1 tests, push run 39795002781](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/39795002781)  
**Date:** 22 October 2026

The live CI job used MongoDB 7 and PostgreSQL 16 services. It applied `sql/001_devices_and_sources.postgres.sql`, then ran `scripts/verify_member1_live.py`. That script verified SQL device/source inserts and a join, MongoDB index creation, ingestion, text and time-filtered search, and cursor pagination across equal timestamps. The separate unit suite contains 8 passing tests.

The job then inserted **1,000,000 deterministic synthetic logs** with `scripts/generate_logs.py --count 1000000 --insert`. It benchmarked a query for `source_ip = 198.51.100.10`, sorted newest-first, returning 50 records. The query has 25,000 matching logs in this generated dataset. Each timing is the median of 5 Python/PyMongo requests on the same collection, with explicit hints to compare the `source_ip_time` index against a natural collection scan.

| Plan | Median request time | Documents examined in `explain` | Keys examined |
| --- | ---: | ---: | ---: |
| Forced collection scan | 188.423 ms | 1,000,000 | 0 |
| `source_ip_time` index | 0.396 ms | 50 | 50 |

The indexed request was about **475 times faster for this specific query on this runner**. The `explain` plans confirm that the indexed query used `IXSCAN` and fetched only the 50 returned documents. The raw result is [member1_1m_2026-10-22.json](benchmarks/member1_1m_2026-10-22.json); the CI artifact also contains the runner's host report.

The benchmark ran on a GitHub-hosted Linux runner with 4 visible AMD EPYC 9V45 virtual CPUs and 15 GiB memory. Timings will vary with hardware, cache state, data distribution, and query filters. This was a database/storage benchmark, not a full browser-to-alert-to-incident demonstration. Members 2 and 3 still need to integrate and verify their latest branches before the team can claim the full application works end to end.

To reproduce in a disposable environment, start MongoDB and PostgreSQL, set `MONGO_URI`, `MONGO_DATABASE`, and `POSTGRES_DSN`, apply migration 001, then run:

```powershell
pip install -r requirements-dev.txt
python scripts/verify_member1_live.py
python scripts/generate_logs.py --count 1000000 --insert
python scripts/benchmark.py --source-ip 198.51.100.10 --repeats 5 --output benchmark.json
```

Use a fresh database for an exact one-million-record comparison because the generator appends logs. The GitHub Actions job creates an isolated database on every run.
