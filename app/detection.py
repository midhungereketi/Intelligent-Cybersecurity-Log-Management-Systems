"""Security detection engine: rules, correlation, alert generation, and idempotency."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import db_transaction, get_db_connection, json_param

logger = logging.getLogger("app.detection")


@dataclass
class RuleDefinition:
    rule_id: int
    rule_name: str
    rule_type: str
    threshold: int
    time_window_seconds: int
    severity: str
    is_enabled: bool
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionMatch:
    rule_id: int
    threat_type: str
    source_ip: str | None
    destination_ip: str | None
    severity: str
    title: str
    description: str
    first_seen_at: datetime
    last_seen_at: datetime
    qualifying_log_ids: list[str]
    evidence: list[dict[str, Any]]
    deduplication_key: str


def _to_utc_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _extract_log_summary(log: dict[str, Any]) -> dict[str, Any]:
    log_id = str(log.get("_id") or log.get("id") or "")
    ts = _to_utc_dt(log.get("timestamp"))
    return {
        "log_id": log_id,
        "timestamp": ts.isoformat() if ts else None,
        "source_ip": log.get("source_ip"),
        "destination_ip": log.get("destination_ip"),
        "destination_port": log.get("destination_port"),
        "event_type": log.get("event_type"),
        "severity": log.get("severity"),
        "username": log.get("username"),
        "message": log.get("message"),
    }


def detect_failed_logins(logs: list[dict[str, Any]], rule: RuleDefinition) -> list[DetectionMatch]:
    """Rule A: Repeated failed logins from a source IP within time_window_seconds."""
    matches: list[DetectionMatch] = []
    target_event = rule.configuration.get("target_event", "LOGIN_FAILED").upper()

    # Filter to failed login events with valid source IP and timestamp
    events = []
    for log in logs:
        try:
            if str(log.get("event_type", "")).upper() == target_event:
                ts = _to_utc_dt(log.get("timestamp"))
                ip = log.get("source_ip")
                if ts and ip:
                    events.append((ts, str(ip), log))
        except Exception as exc:
            logger.warning("Error parsing log in detect_failed_logins: %s", exc)
            continue

    # Group by source IP
    grouped: dict[str, list[tuple[datetime, str, dict[str, Any]]]] = defaultdict(list)
    for ts, ip, log in events:
        grouped[ip].append((ts, ip, log))

    window = timedelta(seconds=rule.time_window_seconds)

    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda x: x[0])
        n = len(ip_events)
        i = 0
        while i < n:
            window_start = ip_events[i][0]
            window_end = window_start + window
            current_window_events = []
            j = i
            while j < n and ip_events[j][0] <= window_end:
                current_window_events.append(ip_events[j])
                j += 1

            if len(current_window_events) >= rule.threshold:
                qualifying_logs = [item[2] for item in current_window_events]
                first_seen = current_window_events[0][0]
                last_seen = current_window_events[-1][0]
                qualifying_ids = [str(l.get("_id") or l.get("id")) for l in qualifying_logs]
                evidence = [_extract_log_summary(l) for l in qualifying_logs]
                usernames = sorted(list({l.get("username") for l in qualifying_logs if l.get("username")}))
                target_user_str = f" for user(s) {', '.join(usernames)}" if usernames else ""

                dedup_key = f"rule_{rule.rule_id}:failed_login:{ip}"
                matches.append(
                    DetectionMatch(
                        rule_id=rule.rule_id,
                        threat_type="BRUTE_FORCE_AUTH",
                        source_ip=ip,
                        destination_ip=None,
                        severity=rule.severity,
                        title=f"Repeated Failed Logins from {ip}",
                        description=(
                            f"Detected {len(qualifying_logs)} failed login attempts from {ip}"
                            f"{target_user_str} within {rule.time_window_seconds}s (threshold: {rule.threshold})."
                        ),
                        first_seen_at=first_seen,
                        last_seen_at=last_seen,
                        qualifying_log_ids=qualifying_ids,
                        evidence=evidence,
                        deduplication_key=dedup_key,
                    )
                )
                # Advance beyond this cluster
                i = j
            else:
                i += 1

    return matches


def detect_port_scans(logs: list[dict[str, Any]], rule: RuleDefinition) -> list[DetectionMatch]:
    """Rule B: Connections from a source IP to multiple distinct destination ports."""
    matches: list[DetectionMatch] = []
    window = timedelta(seconds=rule.time_window_seconds)

    # Filter events with valid source IP, destination port, and timestamp
    events = []
    for log in logs:
        try:
            ts = _to_utc_dt(log.get("timestamp"))
            ip = log.get("source_ip")
            port = log.get("destination_port")
            if ts and ip and port is not None:
                try:
                    port_num = int(port)
                    if 1 <= port_num <= 65535:
                        events.append((ts, str(ip), port_num, log))
                except (ValueError, TypeError):
                    continue
        except Exception as exc:
            logger.warning("Error parsing log in detect_port_scans: %s", exc)
            continue

    grouped: dict[str, list[tuple[datetime, str, int, dict[str, Any]]]] = defaultdict(list)
    for ts, ip, port_num, log in events:
        grouped[ip].append((ts, ip, port_num, log))

    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda x: x[0])
        n = len(ip_events)
        i = 0
        while i < n:
            window_start = ip_events[i][0]
            window_end = window_start + window
            current_window_events = []
            j = i
            while j < n and ip_events[j][0] <= window_end:
                current_window_events.append(ip_events[j])
                j += 1

            distinct_ports = {item[2] for item in current_window_events}
            if len(distinct_ports) >= rule.threshold:
                qualifying_logs = [item[3] for item in current_window_events]
                first_seen = current_window_events[0][0]
                last_seen = current_window_events[-1][0]
                qualifying_ids = [str(l.get("_id") or l.get("id")) for l in qualifying_logs]
                evidence = [_extract_log_summary(l) for l in qualifying_logs]
                dest_ips = list({l.get("destination_ip") for l in qualifying_logs if l.get("destination_ip")})
                dest_ip = dest_ips[0] if len(dest_ips) == 1 else None

                dedup_key = f"rule_{rule.rule_id}:port_scan:{ip}"
                matches.append(
                    DetectionMatch(
                        rule_id=rule.rule_id,
                        threat_type="PORT_SCAN",
                        source_ip=ip,
                        destination_ip=dest_ip,
                        severity=rule.severity,
                        title=f"Possible Port Scan from {ip}",
                        description=(
                            f"Detected probe to {len(distinct_ports)} distinct destination ports from {ip} "
                            f"within {rule.time_window_seconds}s (threshold: {rule.threshold} ports)."
                        ),
                        first_seen_at=first_seen,
                        last_seen_at=last_seen,
                        qualifying_log_ids=qualifying_ids,
                        evidence=evidence,
                        deduplication_key=dedup_key,
                    )
                )
                i = j
            else:
                i += 1

    return matches


def detect_excessive_activity(logs: list[dict[str, Any]], rule: RuleDefinition) -> list[DetectionMatch]:
    """Rule C: Unusually high event volume from a single source IP."""
    matches: list[DetectionMatch] = []
    window = timedelta(seconds=rule.time_window_seconds)

    events = []
    for log in logs:
        try:
            ts = _to_utc_dt(log.get("timestamp"))
            ip = log.get("source_ip")
            if ts and ip:
                events.append((ts, str(ip), log))
        except Exception as exc:
            logger.warning("Error parsing log in detect_excessive_activity: %s", exc)
            continue

    grouped: dict[str, list[tuple[datetime, str, dict[str, Any]]]] = defaultdict(list)
    for ts, ip, log in events:
        grouped[ip].append((ts, ip, log))

    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda x: x[0])
        n = len(ip_events)
        i = 0
        while i < n:
            window_start = ip_events[i][0]
            window_end = window_start + window
            current_window_events = []
            j = i
            while j < n and ip_events[j][0] <= window_end:
                current_window_events.append(ip_events[j])
                j += 1

            if len(current_window_events) >= rule.threshold:
                qualifying_logs = [item[2] for item in current_window_events]
                first_seen = current_window_events[0][0]
                last_seen = current_window_events[-1][0]
                qualifying_ids = [str(l.get("_id") or l.get("id")) for l in qualifying_logs]
                evidence = [_extract_log_summary(l) for l in qualifying_logs[:50]]  # Cap sample evidence

                dedup_key = f"rule_{rule.rule_id}:excessive_activity:{ip}"
                matches.append(
                    DetectionMatch(
                        rule_id=rule.rule_id,
                        threat_type="EXCESSIVE_TRAFFIC_BURST",
                        source_ip=ip,
                        destination_ip=None,
                        severity=rule.severity,
                        title=f"Excessive Event Activity from {ip}",
                        description=(
                            f"Detected high volume of {len(qualifying_logs)} events from {ip} "
                            f"within {rule.time_window_seconds}s (threshold: {rule.threshold} events)."
                        ),
                        first_seen_at=first_seen,
                        last_seen_at=last_seen,
                        qualifying_log_ids=qualifying_ids,
                        evidence=evidence,
                        deduplication_key=dedup_key,
                    )
                )
                i = j
            else:
                i += 1

    return matches


DETECTOR_REGISTRY = {
    "FAILED_LOGINS": detect_failed_logins,
    "PORT_SCAN": detect_port_scans,
    "EXCESSIVE_ACTIVITY": detect_excessive_activity,
}


def load_enabled_rules(conn: Any, rule_ids: list[int] | None = None) -> list[RuleDefinition]:
    """Load active detection rules from PostgreSQL."""
    if rule_ids:
        rows = conn.execute(
            """SELECT rule_id, rule_name, rule_type, threshold, time_window_seconds,
                      severity, is_enabled, configuration
               FROM rules
               WHERE is_enabled = TRUE AND rule_id = ANY(%s)
               ORDER BY rule_id""",
            (rule_ids,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT rule_id, rule_name, rule_type, threshold, time_window_seconds,
                      severity, is_enabled, configuration
               FROM rules
               WHERE is_enabled = TRUE
               ORDER BY rule_id"""
        ).fetchall()

    rules = []
    for r in rows:
        config = r.get("configuration")
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except Exception:
                config = {}
        elif not isinstance(config, dict):
            config = {}
        rules.append(
            RuleDefinition(
                rule_id=int(r["rule_id"]),
                rule_name=r["rule_name"],
                rule_type=r["rule_type"],
                threshold=int(r["threshold"]),
                time_window_seconds=int(r["time_window_seconds"]),
                severity=r["severity"],
                is_enabled=bool(r["is_enabled"]),
                configuration=config,
            )
        )
    return rules


def correlate_threat(conn: Any, match: DetectionMatch) -> int:
    """Find or create a Threat record for the detected suspicious pattern."""
    existing = None
    if match.source_ip:
        existing = conn.execute(
            """SELECT threat_id, first_seen_at, last_seen_at, severity
               FROM threats
               WHERE source_ip = %s AND threat_type = %s
               LIMIT 1""",
            (match.source_ip, match.threat_type),
        ).fetchone()

    metadata = {
        "rule_id": match.rule_id,
        "sample_evidence_count": len(match.qualifying_log_ids),
        "last_detection": match.title,
    }

    if existing:
        threat_id = existing["threat_id"]
        # Update last seen and description
        conn.execute(
            """UPDATE threats
               SET last_seen_at = GREATEST(last_seen_at, %s),
                   severity = %s,
                   description = %s,
                   metadata = %s
               WHERE threat_id = %s""",
            (match.last_seen_at, match.severity, match.description, json_param(metadata), threat_id),
        )
        return threat_id
    else:
        row = conn.execute(
            """INSERT INTO threats (threat_type, source_ip, destination_ip, severity,
                                    description, first_seen_at, last_seen_at, metadata)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING threat_id""",
            (
                match.threat_type,
                match.source_ip,
                match.destination_ip,
                match.severity,
                match.description,
                match.first_seen_at,
                match.last_seen_at,
                json_param(metadata),
            ),
        ).fetchone()
        return row["threat_id"]


def process_match(conn: Any, match: DetectionMatch) -> dict[str, Any]:
    """Persist alert and threat idempotently with deduplication and occurrence counting."""
    threat_id = correlate_threat(conn, match)

    # Check for an existing ACTIVE alert (OPEN or ACKNOWLEDGED) with this deduplication key
    active_alert = conn.execute(
        """SELECT alert_id, status, occurrence_count, first_seen_at, last_seen_at, evidence
           FROM alerts
           WHERE deduplication_key = %s AND status != 'RESOLVED'
           LIMIT 1""",
        (match.deduplication_key,),
    ).fetchone()

    # Determine which qualifying log events have already been recorded for this rule
    qualifying_ids = match.qualifying_log_ids
    already_processed_ids = set()
    if qualifying_ids:
        # Check already processed events
        processed_rows = conn.execute(
            """SELECT event_id FROM processed_detection_events
               WHERE rule_id = %s AND event_id = ANY(%s)""",
            (match.rule_id, qualifying_ids),
        ).fetchall()
        already_processed_ids = {r["event_id"] for r in processed_rows}

    new_event_ids = [eid for eid in qualifying_ids if eid not in already_processed_ids]

    now_utc = datetime.now(timezone.utc)

    if active_alert:
        alert_id = active_alert["alert_id"]
        # If there are NO new events, this was a replay of the exact same historical logs -> IDEMPOTENT NO-OP
        if not new_event_ids:
            return {
                "action": "unchanged",
                "alert_id": alert_id,
                "status": active_alert["status"],
                "occurrence_count": active_alert["occurrence_count"],
            }

        # Otherwise, increment occurrence_count by newly discovered events
        new_last_seen = max(active_alert["last_seen_at"], match.last_seen_at)
        existing_evidence = active_alert["evidence"]
        if isinstance(existing_evidence, str):
            try:
                existing_evidence = json.loads(existing_evidence)
            except Exception:
                existing_evidence = []
        elif not isinstance(existing_evidence, list):
            existing_evidence = []

        existing_ids = {item.get("log_id") for item in existing_evidence if isinstance(item, dict)}
        combined_evidence = list(existing_evidence)
        for ev in match.evidence:
            if ev.get("log_id") not in existing_ids:
                combined_evidence.append(ev)
                existing_ids.add(ev.get("log_id"))
        combined_evidence = combined_evidence[:100]  # Cap evidence size

        conn.execute(
            """UPDATE alerts
               SET last_seen_at = %s,
                   occurrence_count = occurrence_count + %s,
                   evidence = %s,
                   threat_id = COALESCE(threat_id, %s),
                   updated_at = %s
               WHERE alert_id = %s""",
            (new_last_seen, len(new_event_ids), json_param(combined_evidence), threat_id, now_utc, alert_id),
        )

        # Mark new events as processed
        for eid in new_event_ids:
            conn.execute(
                """INSERT INTO processed_detection_events (event_id, rule_id, alert_id)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (event_id, rule_id) DO NOTHING""",
                (eid, match.rule_id, alert_id),
            )

        return {
            "action": "updated",
            "alert_id": alert_id,
            "status": active_alert["status"],
            "new_events_added": len(new_event_ids),
        }

    else:
        # If no active alert exists (or previous was RESOLVED), create a new OPEN alert!
        row = conn.execute(
            """INSERT INTO alerts (rule_id, threat_id, source_ip, severity, title,
                                  description, status, deduplication_key, evidence,
                                  first_seen_at, last_seen_at, occurrence_count,
                                  created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, 'OPEN', %s, %s, %s, %s, %s, %s, %s)
               RETURNING alert_id, status, occurrence_count""",
            (
                match.rule_id,
                threat_id,
                match.source_ip,
                match.severity,
                match.title,
                match.description,
                match.deduplication_key,
                json_param(match.evidence[:100]),
                match.first_seen_at,
                match.last_seen_at,
                len(match.qualifying_log_ids),
                now_utc,
                now_utc,
            ),
        ).fetchone()

        alert_id = row["alert_id"]

        # Record processed events for idempotency
        for eid in match.qualifying_log_ids:
            conn.execute(
                """INSERT INTO processed_detection_events (event_id, rule_id, alert_id)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (event_id, rule_id) DO NOTHING""",
                (eid, match.rule_id, alert_id),
            )

        return {
            "action": "created",
            "alert_id": alert_id,
            "status": row["status"],
            "occurrence_count": row["occurrence_count"],
        }


def execute_detection(
    mongo_collection: Any,
    start: datetime | None = None,
    end: datetime | None = None,
    rule_ids: list[int] | None = None,
    limit: int = 5000,
) -> dict[str, Any]:
    """Execute the detection pipeline across enabled rules on candidate MongoDB logs."""
    # Build MongoDB query for bounded time window
    query: dict[str, Any] = {}
    time_filter: dict[str, Any] = {}
    if start:
        time_filter["$gte"] = _to_utc_dt(start)
    if end:
        time_filter["$lte"] = _to_utc_dt(end)
    if time_filter:
        query["timestamp"] = time_filter

    # Fetch logs from MongoDB
    records = list(mongo_collection.find(query).sort("timestamp", 1).limit(limit))

    alerts_created = 0
    alerts_updated = 0
    alerts_unchanged = 0
    matches_found = 0

    with db_transaction() as conn:
        rules = load_enabled_rules(conn, rule_ids)
        for rule in rules:
            detector_fn = DETECTOR_REGISTRY.get(rule.rule_type)
            if not detector_fn:
                logger.info("No registered detector for rule type: %s", rule.rule_type)
                continue

            try:
                rule_matches = detector_fn(records, rule)
            except Exception as exc:
                logger.error("Error executing detector for rule %d (%s): %s", rule.rule_id, rule.rule_name, exc)
                continue

            matches_found += len(rule_matches)
            for match in rule_matches:
                res = process_match(conn, match)
                if res["action"] == "created":
                    alerts_created += 1
                elif res["action"] == "updated":
                    alerts_updated += 1
                else:
                    alerts_unchanged += 1

    return {
        "status": "success",
        "logs_scanned": len(records),
        "rules_evaluated": len(rules),
        "matches_found": matches_found,
        "alerts_created": alerts_created,
        "alerts_updated": alerts_updated,
        "alerts_unchanged": alerts_unchanged,
    }
