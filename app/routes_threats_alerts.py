"""Threats, alerts, and detection execution API routes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from .auth import require_analyst_or_admin
from .db import db_transaction, get_db_connection
from .detection import execute_detection
from .logs import SEVERITIES

router = APIRouter(tags=["Threats, Alerts & Detection"])


class DetectionRunRequest(BaseModel):
    start: str | None = None
    end: str | None = None
    rule_ids: list[int] | None = None
    limit: int = Field(default=2000, ge=1, le=10000)


def _format_threat(row: dict[str, Any]) -> dict[str, Any]:
    metadata = row.get("metadata")
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}
    elif not isinstance(metadata, dict):
        metadata = {}

    return {
        "threat_id": row["threat_id"],
        "threat_type": row["threat_type"],
        "source_ip": str(row["source_ip"]) if row.get("source_ip") else None,
        "destination_ip": str(row["destination_ip"]) if row.get("destination_ip") else None,
        "severity": row["severity"],
        "description": row.get("description"),
        "first_seen_at": row["first_seen_at"].isoformat() if hasattr(row.get("first_seen_at"), "isoformat") else row.get("first_seen_at"),
        "last_seen_at": row["last_seen_at"].isoformat() if hasattr(row.get("last_seen_at"), "isoformat") else row.get("last_seen_at"),
        "metadata": metadata,
        "created_at": row["created_at"].isoformat() if hasattr(row.get("created_at"), "isoformat") else row.get("created_at"),
    }


def _format_alert(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = []
    elif not isinstance(evidence, list):
        evidence = []

    return {
        "alert_id": row["alert_id"],
        "rule_id": row["rule_id"],
        "rule_name": row.get("rule_name"),
        "threat_id": row.get("threat_id"),
        "source_ip": str(row["source_ip"]) if row.get("source_ip") else None,
        "severity": row["severity"],
        "title": row["title"],
        "description": row.get("description"),
        "status": row["status"],
        "deduplication_key": row["deduplication_key"],
        "occurrence_count": row["occurrence_count"],
        "first_seen_at": row["first_seen_at"].isoformat() if hasattr(row.get("first_seen_at"), "isoformat") else row.get("first_seen_at"),
        "last_seen_at": row["last_seen_at"].isoformat() if hasattr(row.get("last_seen_at"), "isoformat") else row.get("last_seen_at"),
        "created_at": row["created_at"].isoformat() if hasattr(row.get("created_at"), "isoformat") else row.get("created_at"),
        "updated_at": row["updated_at"].isoformat() if hasattr(row.get("updated_at"), "isoformat") else row.get("updated_at"),
        "evidence": evidence,
    }


# ================= Threats Endpoints =================


@router.get("/api/threats")
def list_threats(
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
    severity: str | None = None,
    threat_type: str | None = None,
    source_ip: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    clauses: list[str] = []
    params: list[Any] = []

    if severity:
        sev = severity.strip().upper()
        if sev not in SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid severity filter")
        clauses.append("severity = %s")
        params.append(sev)

    if threat_type:
        clauses.append("threat_type = %s")
        params.append(threat_type.strip())

    if source_ip:
        clauses.append("source_ip = %s")
        params.append(source_ip.strip())

    if start:
        clauses.append("last_seen_at >= %s")
        params.append(start)

    if end:
        clauses.append("first_seen_at <= %s")
        params.append(end)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with get_db_connection() as conn:
        count_sql = f"SELECT COUNT(*) AS total FROM threats {where_sql}"
        total_row = conn.execute(count_sql, params).fetchone()
        total = total_row["total"] if total_row else 0

        query_sql = f"SELECT * FROM threats {where_sql} ORDER BY last_seen_at DESC LIMIT %s OFFSET %s"
        threat_params = list(params) + [limit, offset]
        rows = conn.execute(query_sql, threat_params).fetchall()

        return {
            "items": [_format_threat(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


@router.get("/api/threats/{threat_id}")
def get_threat(
    threat_id: int,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    with get_db_connection() as conn:
        threat = conn.execute("SELECT * FROM threats WHERE threat_id = %s", (threat_id,)).fetchone()
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")

        alerts = conn.execute(
            """SELECT a.*, r.rule_name
               FROM alerts a
               LEFT JOIN rules r ON a.rule_id = r.rule_id
               WHERE a.threat_id = %s
               ORDER BY a.created_at DESC""",
            (threat_id,),
        ).fetchall()

        res = _format_threat(threat)
        res["alerts"] = [_format_alert(a) for a in alerts]
        return res


# ================= Alerts Endpoints =================


@router.get("/api/alerts")
def list_alerts(
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    severity: str | None = None,
    rule_id: int | None = None,
    source_ip: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    clauses: list[str] = []
    params: list[Any] = []

    if status_filter:
        st = status_filter.strip().upper()
        if st not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
            raise HTTPException(status_code=422, detail="status must be OPEN, ACKNOWLEDGED, or RESOLVED")
        clauses.append("a.status = %s")
        params.append(st)

    if severity:
        sev = severity.strip().upper()
        if sev not in SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid severity filter")
        clauses.append("a.severity = %s")
        params.append(sev)

    if rule_id is not None:
        clauses.append("a.rule_id = %s")
        params.append(rule_id)

    if source_ip:
        clauses.append("a.source_ip = %s")
        params.append(source_ip.strip())

    if start:
        clauses.append("a.last_seen_at >= %s")
        params.append(start)

    if end:
        clauses.append("a.first_seen_at <= %s")
        params.append(end)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with get_db_connection() as conn:
        count_sql = f"SELECT COUNT(*) AS total FROM alerts a {where_sql}"
        total_row = conn.execute(count_sql, params).fetchone()
        total = total_row["total"] if total_row else 0

        query_sql = f"""SELECT a.*, r.rule_name
                       FROM alerts a
                       LEFT JOIN rules r ON a.rule_id = r.rule_id
                       {where_sql}
                       ORDER BY a.created_at DESC
                       LIMIT %s OFFSET %s"""
        alert_params = list(params) + [limit, offset]
        rows = conn.execute(query_sql, alert_params).fetchall()

        return {
            "items": [_format_alert(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


@router.get("/api/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    with get_db_connection() as conn:
        row = conn.execute(
            """SELECT a.*, r.rule_name
               FROM alerts a
               LEFT JOIN rules r ON a.rule_id = r.rule_id
               WHERE a.alert_id = %s""",
            (alert_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return _format_alert(row)


@router.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    now_utc = datetime.now(timezone.utc)
    with db_transaction() as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        if alert["status"] == "RESOLVED":
            raise HTTPException(status_code=400, detail="Cannot acknowledge an already resolved alert")

        conn.execute(
            "UPDATE alerts SET status = 'ACKNOWLEDGED', updated_at = %s WHERE alert_id = %s",
            (now_utc, alert_id),
        )
        updated = conn.execute(
            """SELECT a.*, r.rule_name
               FROM alerts a
               LEFT JOIN rules r ON a.rule_id = r.rule_id
               WHERE a.alert_id = %s""",
            (alert_id,),
        ).fetchone()
        return _format_alert(updated)


@router.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    now_utc = datetime.now(timezone.utc)
    with db_transaction() as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        if alert["status"] == "RESOLVED":
            return _format_alert(alert)

        conn.execute(
            "UPDATE alerts SET status = 'RESOLVED', updated_at = %s WHERE alert_id = %s",
            (now_utc, alert_id),
        )
        updated = conn.execute(
            """SELECT a.*, r.rule_name
               FROM alerts a
               LEFT JOIN rules r ON a.rule_id = r.rule_id
               WHERE a.alert_id = %s""",
            (alert_id,),
        ).fetchone()
        return _format_alert(updated)


# ================= Manual Detection Trigger =================


@router.post("/api/detection/run")
def run_detection(
    request: Request,
    payload: DetectionRunRequest,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    logs_collection = getattr(request.app.state, "logs", None)
    if logs_collection is None:
        raise HTTPException(status_code=503, detail="MongoDB logs collection is unavailable")

    summary = execute_detection(
        mongo_collection=logs_collection,
        start=payload.start,
        end=payload.end,
        rule_ids=payload.rule_ids,
        limit=payload.limit,
    )
    return summary
