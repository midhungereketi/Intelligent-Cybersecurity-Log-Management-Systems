"""Incident management and response action history API routes."""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from .auth import require_analyst_or_admin
from .db import db_transaction, get_db_connection, json_param
from .logs import SEVERITIES

logger = logging.getLogger("app.routes_incidents_actions")

router = APIRouter(prefix="/api/incidents", tags=["Incidents & Actions"])

VALID_INCIDENT_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}
VALID_ACTION_TYPES = {
    "NOTE",
    "CONTAINMENT",
    "REMEDIATION",
    "STATUS_CHANGE",
    "ASSIGNMENT",
    "INVESTIGATION_STEP",
    "OTHER",
}


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = None
    severity: str = Field(default="HIGH")
    status: str = Field(default="OPEN")
    assigned_to: int | None = None
    alert_id: int | None = None
    source_ip: str | None = None
    tags: list[str] = Field(default_factory=list)
    evidence: list[Any] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    assigned_to: int | None = None
    tags: list[str] | None = None


class ActionCreate(BaseModel):
    action_type: str = Field(default="NOTE")
    action_details: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _format_incident(row: dict[str, Any]) -> dict[str, Any]:
    tags = row.get("tags")
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except Exception:
            tags = []
    elif not isinstance(tags, list):
        tags = []

    evidence = row.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = []
    elif not isinstance(evidence, list):
        evidence = []

    res = {
        "incident_id": row["incident_id"],
        "title": row["title"],
        "description": row.get("description"),
        "severity": row["severity"],
        "status": row["status"],
        "assigned_to": row.get("assigned_to"),
        "assigned_to_username": row.get("assigned_to_username"),
        "created_by": row.get("created_by"),
        "created_by_username": row.get("created_by_username"),
        "alert_id": row.get("alert_id"),
        "source_ip": str(row["source_ip"]) if row.get("source_ip") else None,
        "tags": tags,
        "evidence": evidence,
        "created_at": row["created_at"].isoformat() if hasattr(row.get("created_at"), "isoformat") else row.get("created_at"),
        "updated_at": row["updated_at"].isoformat() if hasattr(row.get("updated_at"), "isoformat") else row.get("updated_at"),
        "resolved_at": row["resolved_at"].isoformat() if hasattr(row.get("resolved_at"), "isoformat") and row.get("resolved_at") else row.get("resolved_at"),
    }
    if "actions" in row:
        res["actions"] = row["actions"]
    if "alerts" in row:
        res["alerts"] = row["alerts"]
    return res


def _format_action(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    elif not isinstance(meta, dict):
        meta = {}

    return {
        "action_id": row["action_id"],
        "incident_id": row["incident_id"],
        "action_type": row["action_type"],
        "action_details": row["action_details"],
        "performed_by": row.get("performed_by"),
        "performed_by_username": row.get("performed_by_username"),
        "metadata": meta,
        "performed_at": row["performed_at"].isoformat() if hasattr(row.get("performed_at"), "isoformat") else row.get("performed_at"),
    }


@router.get("")
def list_incidents(
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    severity: str | None = None,
    assigned_to: int | None = None,
    alert_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    clauses: list[str] = []
    params: list[Any] = []

    if status_filter:
        st = status_filter.strip().upper()
        if st not in VALID_INCIDENT_STATUSES:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(VALID_INCIDENT_STATUSES)}")
        clauses.append("i.status = %s")
        params.append(st)

    if severity:
        sev = severity.strip().upper()
        if sev not in SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid severity filter")
        clauses.append("i.severity = %s")
        params.append(sev)

    if assigned_to is not None:
        clauses.append("i.assigned_to = %s")
        params.append(assigned_to)

    if alert_id is not None:
        clauses.append("(i.alert_id = %s OR EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.incident_id = i.incident_id AND ia.alert_id = %s))")
        params.extend([alert_id, alert_id])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with get_db_connection() as conn:
        count_sql = f"SELECT COUNT(*) AS total FROM incidents i {where_sql}"
        total_row = conn.execute(count_sql, params).fetchone()
        total = total_row["total"] if total_row else 0

        query_sql = f"""SELECT i.*, 
                               u_assign.username AS assigned_to_username,
                               u_create.username AS created_by_username
                        FROM incidents i
                        LEFT JOIN users u_assign ON i.assigned_to = u_assign.user_id
                        LEFT JOIN users u_create ON i.created_by = u_create.user_id
                        {where_sql}
                        ORDER BY i.created_at DESC
                        LIMIT %s OFFSET %s"""
        incident_params = list(params) + [limit, offset]
        rows = conn.execute(query_sql, incident_params).fetchall()

        return {
            "items": [_format_incident(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


@router.post("", status_code=201)
def create_incident(
    payload: IncidentCreate,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    sev = payload.severity.strip().upper()
    if sev not in SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity value")

    st = payload.status.strip().upper()
    if st not in VALID_INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(VALID_INCIDENT_STATUSES)}")

    now_utc = datetime.now(timezone.utc)
    source_ip = payload.source_ip.strip() if payload.source_ip else None
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            raise HTTPException(status_code=422, detail="source_ip must be a valid IP address")
    evidence = list(payload.evidence)

    with db_transaction() as conn:
        # Check assigned user if specified
        if payload.assigned_to is not None:
            assignee = conn.execute("SELECT user_id FROM users WHERE user_id = %s", (payload.assigned_to,)).fetchone()
            if not assignee:
                raise HTTPException(status_code=404, detail="Assigned user not found")

        # If alert_id provided, inspect alert
        if payload.alert_id is not None:
            alert = conn.execute("SELECT * FROM alerts WHERE alert_id = %s", (payload.alert_id,)).fetchone()
            if not alert:
                raise HTTPException(status_code=404, detail="Referenced alert not found")
            if not source_ip and alert.get("source_ip"):
                source_ip = str(alert["source_ip"])
            if not evidence and alert.get("evidence"):
                ev = alert["evidence"]
                evidence = ev if isinstance(ev, list) else json.loads(ev) if isinstance(ev, str) else []

        insert_sql = """INSERT INTO incidents (title, description, severity, status, assigned_to, created_by,
                                               alert_id, source_ip, tags, evidence, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING *"""
        row = conn.execute(
            insert_sql,
            (
                payload.title.strip(),
                payload.description,
                sev,
                st,
                payload.assigned_to,
                current_user["user_id"],
                payload.alert_id,
                source_ip,
                json_param(payload.tags),
                json_param(evidence),
                now_utc,
                now_utc,
            ),
        ).fetchone()

        incident_id = row["incident_id"]

        # If alert_id was provided, link in incident_alerts table too
        if payload.alert_id is not None:
            conn.execute(
                "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (%s, %s, %s)",
                (incident_id, payload.alert_id, now_utc),
            )

        # Record initial audit action
        action_sql = """INSERT INTO actions (incident_id, action_type, action_details, performed_by, metadata, performed_at)
                        VALUES (%s, %s, %s, %s, %s, %s) RETURNING *"""
        init_details = f"Incident created with status '{st}' and severity '{sev}'"
        conn.execute(
            action_sql,
            (
                incident_id,
                "STATUS_CHANGE",
                init_details,
                current_user["user_id"],
                json_param({"initial_creation": True, "alert_id": payload.alert_id}),
                now_utc,
            ),
        )

        # Retrieve fully populated row
        full_row = conn.execute(
            """SELECT i.*, 
                      u_assign.username AS assigned_to_username,
                      u_create.username AS created_by_username
               FROM incidents i
               LEFT JOIN users u_assign ON i.assigned_to = u_assign.user_id
               LEFT JOIN users u_create ON i.created_by = u_create.user_id
               WHERE i.incident_id = %s""",
            (incident_id,),
        ).fetchone()

        return _format_incident(full_row)


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    with get_db_connection() as conn:
        row = conn.execute(
            """SELECT i.*, 
                      u_assign.username AS assigned_to_username,
                      u_create.username AS created_by_username
               FROM incidents i
               LEFT JOIN users u_assign ON i.assigned_to = u_assign.user_id
               LEFT JOIN users u_create ON i.created_by = u_create.user_id
               WHERE i.incident_id = %s""",
            (incident_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        # Get actions for this incident
        action_rows = conn.execute(
            """SELECT a.*, u.username AS performed_by_username
               FROM actions a
               LEFT JOIN users u ON a.performed_by = u.user_id
               WHERE a.incident_id = %s
               ORDER BY a.performed_at ASC""",
            (incident_id,),
        ).fetchall()

        # Get linked alerts
        alert_rows = conn.execute(
            """SELECT al.*, r.rule_name, ia.linked_at
               FROM incident_alerts ia
               JOIN alerts al ON ia.alert_id = al.alert_id
               LEFT JOIN rules r ON al.rule_id = r.rule_id
               WHERE ia.incident_id = %s
               ORDER BY ia.linked_at DESC""",
            (incident_id,),
        ).fetchall()

        formatted_alerts = []
        for ar in alert_rows:
            ev = ar.get("evidence")
            if isinstance(ev, str):
                try:
                    ev = json.loads(ev)
                except Exception:
                    ev = []
            elif not isinstance(ev, list):
                ev = []
            formatted_alerts.append({
                "alert_id": ar["alert_id"],
                "rule_name": ar.get("rule_name"),
                "severity": ar["severity"],
                "title": ar["title"],
                "status": ar["status"],
                "source_ip": str(ar["source_ip"]) if ar.get("source_ip") else None,
                "evidence": ev,
                "linked_at": ar["linked_at"].isoformat() if hasattr(ar.get("linked_at"), "isoformat") else ar.get("linked_at"),
            })

        res_dict = dict(row)
        res_dict["actions"] = [_format_action(a) for a in action_rows]
        res_dict["alerts"] = formatted_alerts
        return _format_incident(res_dict)


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    now_utc = datetime.now(timezone.utc)

    with db_transaction() as conn:
        existing = conn.execute("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Incident not found")

        updates: list[str] = []
        params: list[Any] = []
        actions_to_log: list[tuple[str, str, dict]] = []

        if payload.title is not None:
            updates.append("title = %s")
            params.append(payload.title.strip())

        if payload.description is not None:
            updates.append("description = %s")
            params.append(payload.description)

        if payload.severity is not None:
            sev = payload.severity.strip().upper()
            if sev not in SEVERITIES:
                raise HTTPException(status_code=422, detail="Invalid severity value")
            if sev != existing["severity"]:
                updates.append("severity = %s")
                params.append(sev)
                actions_to_log.append(
                    ("STATUS_CHANGE", f"Severity changed from {existing['severity']} to {sev}", {"old": existing["severity"], "new": sev})
                )

        if payload.status is not None:
            st = payload.status.strip().upper()
            if st not in VALID_INCIDENT_STATUSES:
                raise HTTPException(status_code=422, detail=f"status must be one of {sorted(VALID_INCIDENT_STATUSES)}")
            if st != existing["status"]:
                updates.append("status = %s")
                params.append(st)
                was_closed = existing["status"] in {"RESOLVED", "CLOSED"}
                if st in {"RESOLVED", "CLOSED"} and not was_closed:
                    updates.append("resolved_at = %s")
                    params.append(now_utc)
                elif st not in {"RESOLVED", "CLOSED"} and was_closed:
                    # Reopened: the case is no longer resolved
                    updates.append("resolved_at = %s")
                    params.append(None)
                actions_to_log.append(
                    ("STATUS_CHANGE", f"Status updated from {existing['status']} to {st}", {"old": existing["status"], "new": st})
                )

        if "assigned_to" in payload.model_fields_set and payload.assigned_to is None:
            # An explicit null clears the assignment
            if existing["assigned_to"] is not None:
                updates.append("assigned_to = %s")
                params.append(None)
                actions_to_log.append(("ASSIGNMENT", "Incident unassigned", {"assigned_to": None}))
        elif payload.assigned_to is not None:
            if payload.assigned_to != existing["assigned_to"]:
                assignee = conn.execute("SELECT user_id, username FROM users WHERE user_id = %s", (payload.assigned_to,)).fetchone()
                if not assignee:
                    raise HTTPException(status_code=404, detail="Assigned user not found")
                updates.append("assigned_to = %s")
                params.append(payload.assigned_to)
                actions_to_log.append(
                    ("ASSIGNMENT", f"Incident assigned to user '{assignee['username']}' (ID: {payload.assigned_to})", {"assigned_to": payload.assigned_to})
                )

        if payload.tags is not None:
            updates.append("tags = %s")
            params.append(json_param(payload.tags))

        if not updates:
            return get_incident(incident_id, current_user)

        updates.append("updated_at = %s")
        params.append(now_utc)
        params.append(incident_id)

        update_sql = f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = %s"
        conn.execute(update_sql, params)

        # Log audit actions
        for act_type, act_detail, act_meta in actions_to_log:
            conn.execute(
                """INSERT INTO actions (incident_id, action_type, action_details, performed_by, metadata, performed_at)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (incident_id, act_type, act_detail, current_user["user_id"], json_param(act_meta), now_utc),
            )

        updated_row = conn.execute(
            """SELECT i.*, 
                      u_assign.username AS assigned_to_username,
                      u_create.username AS created_by_username
               FROM incidents i
               LEFT JOIN users u_assign ON i.assigned_to = u_assign.user_id
               LEFT JOIN users u_create ON i.created_by = u_create.user_id
               WHERE i.incident_id = %s""",
            (incident_id,),
        ).fetchone()

        return _format_incident(updated_row)


@router.get("/{incident_id}/actions")
def list_actions(
    incident_id: int,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    with get_db_connection() as conn:
        existing = conn.execute("SELECT incident_id FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Incident not found")

        rows = conn.execute(
            """SELECT a.*, u.username AS performed_by_username
               FROM actions a
               LEFT JOIN users u ON a.performed_by = u.user_id
               WHERE a.incident_id = %s
               ORDER BY a.performed_at ASC""",
            (incident_id,),
        ).fetchall()

        return [_format_action(r) for r in rows]


@router.post("/{incident_id}/actions", status_code=201)
def add_action(
    incident_id: int,
    payload: ActionCreate,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    act_type = payload.action_type.strip().upper()
    if act_type not in VALID_ACTION_TYPES:
        raise HTTPException(status_code=422, detail=f"action_type must be one of {sorted(VALID_ACTION_TYPES)}")

    now_utc = datetime.now(timezone.utc)
    with db_transaction() as conn:
        existing = conn.execute("SELECT incident_id FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Incident not found")

        row = conn.execute(
            """INSERT INTO actions (incident_id, action_type, action_details, performed_by, metadata, performed_at)
               VALUES (%s, %s, %s, %s, %s, %s)
               RETURNING *""",
            (
                incident_id,
                act_type,
                payload.action_details.strip(),
                current_user["user_id"],
                json_param(payload.metadata),
                now_utc,
            ),
        ).fetchone()

        # Update incident's updated_at
        conn.execute("UPDATE incidents SET updated_at = %s WHERE incident_id = %s", (now_utc, incident_id))

        action_dict = dict(row)
        action_dict["performed_by_username"] = current_user.get("username")
        return _format_action(action_dict)


@router.post("/{incident_id}/link-alert")
def link_alert_to_incident(
    incident_id: int,
    alert_id: Annotated[int, Query(gt=0)],
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    now_utc = datetime.now(timezone.utc)
    with db_transaction() as conn:
        incident = conn.execute("SELECT incident_id FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        alert = conn.execute("SELECT alert_id, title FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        existing_link = conn.execute(
            "SELECT 1 FROM incident_alerts WHERE incident_id = %s AND alert_id = %s",
            (incident_id, alert_id),
        ).fetchone()

        if not existing_link:
            conn.execute(
                "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (%s, %s, %s)",
                (incident_id, alert_id, now_utc),
            )
            # Log action
            conn.execute(
                """INSERT INTO actions (incident_id, action_type, action_details, performed_by, metadata, performed_at)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    incident_id,
                    "INVESTIGATION_STEP",
                    f"Linked alert #{alert_id} ('{alert['title']}') to incident",
                    current_user["user_id"],
                    json_param({"alert_id": alert_id}),
                    now_utc,
                ),
            )
            conn.execute("UPDATE incidents SET updated_at = %s WHERE incident_id = %s", (now_utc, incident_id))

        return {"status": "linked", "incident_id": incident_id, "alert_id": alert_id}
