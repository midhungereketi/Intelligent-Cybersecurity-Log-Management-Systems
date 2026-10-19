"""Rule management API routes for detection rules."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .auth import require_admin, require_analyst_or_admin
from .db import db_transaction, get_db_connection, json_param
from .logs import SEVERITIES

router = APIRouter(prefix="/api/rules", tags=["Detection Rules"])

ALLOWED_RULE_TYPES = {"FAILED_LOGINS", "PORT_SCAN", "EXCESSIVE_ACTIVITY"}


class RuleCreate(BaseModel):
    rule_name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    rule_type: str = Field(min_length=1, max_length=60)
    threshold: int = Field(gt=0, description="Must be greater than 0")
    time_window_seconds: int = Field(gt=0, description="Must be greater than 0")
    severity: str = Field(default="HIGH")
    is_enabled: bool = True
    configuration: dict[str, Any] = Field(default_factory=dict)


class RuleUpdate(BaseModel):
    rule_name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    rule_type: str | None = Field(default=None, min_length=1, max_length=60)
    threshold: int | None = Field(default=None, gt=0)
    time_window_seconds: int | None = Field(default=None, gt=0)
    severity: str | None = None
    is_enabled: bool | None = None
    configuration: dict[str, Any] | None = None


def _format_rule(row: dict[str, Any]) -> dict[str, Any]:
    config = row.get("configuration")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}
    elif not isinstance(config, dict):
        config = {}

    return {
        "rule_id": row["rule_id"],
        "rule_name": row["rule_name"],
        "description": row.get("description"),
        "rule_type": row["rule_type"],
        "threshold": row["threshold"],
        "time_window_seconds": row["time_window_seconds"],
        "severity": row["severity"],
        "is_enabled": row["is_enabled"],
        "configuration": config,
        "created_by": row.get("created_by"),
        "created_at": row["created_at"].isoformat() if hasattr(row.get("created_at"), "isoformat") else row.get("created_at"),
        "updated_at": row["updated_at"].isoformat() if hasattr(row.get("updated_at"), "isoformat") else row.get("updated_at"),
    }


@router.get("")
def list_rules(current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)]):
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM rules ORDER BY rule_id").fetchall()
        return [_format_rule(r) for r in rows]


@router.get("/{rule_id}")
def get_rule(rule_id: int, current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)]):
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM rules WHERE rule_id = %s", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        return _format_rule(row)


@router.post("", status_code=201)
def create_rule(
    payload: RuleCreate,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)],
):
    severity = payload.severity.strip().upper()
    if severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail=f"Severity must be one of {sorted(list(SEVERITIES))}")

    rule_type = payload.rule_type.strip().upper()
    if rule_type not in ALLOWED_RULE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"rule_type must be one of {sorted(list(ALLOWED_RULE_TYPES))}",
        )

    now_utc = datetime.now(timezone.utc)
    try:
        with db_transaction() as conn:
            row = conn.execute(
                """INSERT INTO rules (rule_name, description, rule_type, threshold,
                                      time_window_seconds, severity, is_enabled,
                                      configuration, created_by, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING *""",
                (
                    payload.rule_name.strip(),
                    payload.description,
                    rule_type,
                    payload.threshold,
                    payload.time_window_seconds,
                    severity,
                    payload.is_enabled,
                    json_param(payload.configuration),
                    admin_user["user_id"],
                    now_utc,
                    now_utc,
                ),
            ).fetchone()
            return _format_rule(row)
    except psycopg.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Rule name already exists or violates constraint") from exc


@router.patch("/{rule_id}")
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)],
):
    with db_transaction() as conn:
        existing = conn.execute("SELECT * FROM rules WHERE rule_id = %s", (rule_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Rule not found")

        updates: list[str] = []
        params: list[Any] = []

        if payload.rule_name is not None:
            updates.append("rule_name = %s")
            params.append(payload.rule_name.strip())

        if payload.description is not None:
            updates.append("description = %s")
            params.append(payload.description)

        if payload.rule_type is not None:
            rule_type = payload.rule_type.strip().upper()
            if rule_type not in ALLOWED_RULE_TYPES:
                raise HTTPException(
                    status_code=422,
                    detail=f"rule_type must be one of {sorted(list(ALLOWED_RULE_TYPES))}",
                )
            updates.append("rule_type = %s")
            params.append(rule_type)

        if payload.threshold is not None:
            if payload.threshold <= 0:
                raise HTTPException(status_code=422, detail="threshold must be positive")
            updates.append("threshold = %s")
            params.append(payload.threshold)

        if payload.time_window_seconds is not None:
            if payload.time_window_seconds <= 0:
                raise HTTPException(status_code=422, detail="time_window_seconds must be positive")
            updates.append("time_window_seconds = %s")
            params.append(payload.time_window_seconds)

        if payload.severity is not None:
            sev = payload.severity.strip().upper()
            if sev not in SEVERITIES:
                raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(list(SEVERITIES))}")
            updates.append("severity = %s")
            params.append(sev)

        if payload.is_enabled is not None:
            updates.append("is_enabled = %s")
            params.append(payload.is_enabled)

        if payload.configuration is not None:
            updates.append("configuration = %s")
            params.append(json_param(payload.configuration))

        if not updates:
            return _format_rule(existing)

        now_utc = datetime.now(timezone.utc)
        updates.append("updated_at = %s")
        params.append(now_utc)
        params.append(rule_id)

        try:
            conn.execute(
                f"UPDATE rules SET {', '.join(updates)} WHERE rule_id = %s",
                params,
            )
            updated = conn.execute("SELECT * FROM rules WHERE rule_id = %s", (rule_id,)).fetchone()
            return _format_rule(updated)
        except psycopg.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Rule name already exists or violates constraint") from exc
