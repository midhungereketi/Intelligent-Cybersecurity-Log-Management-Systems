# Team Remaining Work (22 October 2026)

Member 1's log pipeline is implemented and verified against live MongoDB 7 and PostgreSQL 16. See [Member 1 Verification](MEMBER1_VERIFICATION.md) for the one-million-log benchmark. The final application is not integrated yet. Keep the three member branches separate until the combined application passes its checks, then merge to `main` as the team planned.

## Member 2 — Shraavanth (`member2-shraavanth`)

Latest reviewed commit: `ee85d55308314bf5974c80edd828f7c96f1720e8`. His 46 backend tests pass and [latest CI](https://github.com/midhungereketi/Intelligent-Cybersecurity-Log-Management-Systems/actions/runs/39373276661) passed. Authentication, role checks, detection rules, alerts, checkpoints, and replay deduplication are implemented on this branch.

1. Help integrate this latest commit into Member 3's active branch. Confirm the merged `app/main.py` still requires authentication for log ingestion/search and device/source reads, and admin permission for device/source writes.
2. Confirm the merged `app/config.py` requires `JWT_SECRET_KEY` instead of using a built-in signing secret. Preserve the latest detection pagination, checkpoint, and resolved-alert deduplication changes from this branch.
3. Resolve or review the shared-file conflicts in `README.md`, `requirements.txt`, and `tests/test_api_integration.py`. Keep a compatible `cryptography` version range and the test-client dependency in the merged requirements.
4. Run the combined backend tests and a live MongoDB/PostgreSQL detection demonstration: suspicious logs should create an explainable alert, and rerunning detection should not duplicate it.

## Member 3 — Lakshman (`member3.1--lakshman`)

Latest reviewed commit: `a8072487199729f57c8a6e547adc48f919ab0b78`. The UI builds, and 68 backend tests pass after dependencies are corrected manually. The branch contains analytics, incident handling, action history, the dashboard, log time filtering, and assignable-user lookup.

1. Integrate Member 2's latest commit. The current branch still has older `app/main.py` and `app/config.py` code that leaves log/device endpoints unprotected and provides a fallback JWT secret. This is the highest-priority fix.
2. Fix `requirements.txt` and `requirements-dev.txt` so a fresh environment installs and runs all tests. The current `cryptography>=42,<44` range fails to import the Argon2id module used by `app/auth.py`; the current dev requirements omit the test-client dependency.
3. Change `.github/workflows/member3-ci.yml` to include the actual branch name `member3.1--lakshman` in its push trigger, then push and confirm both backend and frontend jobs pass. There has been no CI run on this branch.
4. Update `docs/E2E_WORKFLOW.md`: copying `.env.example` to `.env` alone does not load variables into the current Python process. Document shell environment variables or add explicit `.env` loading, and verify the instructions from a fresh checkout.
5. Run the full browser workflow with real MongoDB and PostgreSQL: login, upload, filtered search, detection, alert triage, incident assignment/action, and dashboard analytics. Record what passed and any remaining failures.

The latest Member 2 and Member 3 branches do not merge automatically. A merge simulation found conflicts in `README.md`, `requirements.txt`, and `tests/test_api_integration.py`. Resolve these before merging to `main`. The team also needs to confirm with the professor whether the final SQL submission should use PostgreSQL or the separate Oracle 11g Review II script.
