"""Analytics endpoints using Member 1's normalized log schema and Member 2/3 SQL tables."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request

from .auth import require_analyst_or_admin
from .db import get_db_connection

logger = logging.getLogger("app.routes_analytics")

router = APIRouter(prefix="/api/analytics", tags=["Analytics & Reporting"])


@router.get("/dashboard")
def get_dashboard_summary(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    """Unified analytics summary spanning MongoDB logs and PostgreSQL security entities."""
    logs_col = getattr(request.app.state, "logs", None)

    # 1. MongoDB Log Metrics
    total_logs = 0
    logs_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    logs_by_event_type: dict[str, int] = {}

    if logs_col is not None:
        try:
            total_logs = logs_col.count_documents({})
            sev_agg = logs_col.aggregate([
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
            ])
            for item in sev_agg:
                sev_name = item.get("_id")
                if sev_name in logs_by_severity:
                    logs_by_severity[sev_name] = item.get("count", 0)

            event_agg = logs_col.aggregate([
                {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 6},
            ])
            for item in event_agg:
                if item.get("_id"):
                    logs_by_event_type[item["_id"]] = item.get("count", 0)
        except Exception as exc:
            logger.warning("Error fetching MongoDB metrics: %s", exc)

    # 2. PostgreSQL Security Entities
    alerts_total = 0
    alerts_open = 0
    alerts_acknowledged = 0
    alerts_resolved = 0
    alerts_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    threats_total = 0
    incidents_total = 0
    incidents_open = 0
    incidents_investigating = 0
    incidents_resolved = 0
    incidents_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    recent_alerts: list[dict[str, Any]] = []
    recent_incidents: list[dict[str, Any]] = []

    try:
        with get_db_connection() as conn:
            # Alerts metrics
            alert_counts = conn.execute(
                """SELECT status, severity, COUNT(*) AS cnt 
                   FROM alerts 
                   GROUP BY status, severity"""
            ).fetchall()
            for row in alert_counts:
                cnt = row.get("cnt", row.get("total", 0))
                alerts_total += cnt
                st = row["status"]
                sev = row["severity"]
                if st == "OPEN":
                    alerts_open += cnt
                elif st == "ACKNOWLEDGED":
                    alerts_acknowledged += cnt
                elif st == "RESOLVED":
                    alerts_resolved += cnt
                if sev in alerts_by_severity:
                    alerts_by_severity[sev] += cnt

            # Threats count
            t_row = conn.execute("SELECT COUNT(*) AS cnt FROM threats").fetchone()
            threats_total = (t_row.get("cnt", t_row.get("total", 0)) if t_row else 0)

            # Incidents metrics
            inc_counts = conn.execute(
                """SELECT status, severity, COUNT(*) AS cnt 
                   FROM incidents 
                   GROUP BY status, severity"""
            ).fetchall()
            for row in inc_counts:
                cnt = row.get("cnt", row.get("total", 0))
                incidents_total += cnt
                st = row["status"]
                sev = row["severity"]
                if st == "OPEN":
                    incidents_open += cnt
                elif st == "INVESTIGATING":
                    incidents_investigating += cnt
                elif st in {"CONTAINED", "RESOLVED", "CLOSED"}:
                    incidents_resolved += cnt
                if sev in incidents_by_severity:
                    incidents_by_severity[sev] += cnt

            # Recent alerts
            al_rows = conn.execute(
                """SELECT a.alert_id, a.title, a.severity, a.status, a.source_ip, a.created_at, r.rule_name
                   FROM alerts a
                   LEFT JOIN rules r ON a.rule_id = r.rule_id
                   ORDER BY a.created_at DESC
                   LIMIT 5"""
            ).fetchall()
            for ar in al_rows:
                recent_alerts.append({
                    "alert_id": ar["alert_id"],
                    "title": ar["title"],
                    "severity": ar["severity"],
                    "status": ar["status"],
                    "source_ip": str(ar["source_ip"]) if ar.get("source_ip") else None,
                    "rule_name": ar.get("rule_name"),
                    "created_at": ar["created_at"].isoformat() if hasattr(ar.get("created_at"), "isoformat") else ar.get("created_at"),
                })

            # Recent incidents
            inc_rows = conn.execute(
                """SELECT i.incident_id, i.title, i.severity, i.status, i.source_ip, i.created_at, u.username AS assigned_to_username
                   FROM incidents i
                   LEFT JOIN users u ON i.assigned_to = u.user_id
                   ORDER BY i.created_at DESC
                   LIMIT 5"""
            ).fetchall()
            for ir in inc_rows:
                recent_incidents.append({
                    "incident_id": ir["incident_id"],
                    "title": ir["title"],
                    "severity": ir["severity"],
                    "status": ir["status"],
                    "source_ip": str(ir["source_ip"]) if ir.get("source_ip") else None,
                    "assigned_to_username": ir.get("assigned_to_username"),
                    "created_at": ir["created_at"].isoformat() if hasattr(ir.get("created_at"), "isoformat") else ir.get("created_at"),
                })
    except Exception as exc:
        logger.warning("Error fetching PostgreSQL summary metrics: %s", exc)

    return {
        "logs": {
            "total": total_logs,
            "by_severity": logs_by_severity,
            "by_event_type": logs_by_event_type,
        },
        "alerts": {
            "total": alerts_total,
            "open": alerts_open,
            "acknowledged": alerts_acknowledged,
            "resolved": alerts_resolved,
            "by_severity": alerts_by_severity,
            "recent": recent_alerts,
        },
        "threats": {
            "total": threats_total,
        },
        "incidents": {
            "total": incidents_total,
            "open": incidents_open,
            "investigating": incidents_investigating,
            "resolved": incidents_resolved,
            "by_severity": incidents_by_severity,
            "recent": recent_incidents,
        },
    }


@router.get("/events-timeline")
def get_events_timeline(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
    limit: Annotated[int, Query(ge=5, le=50)] = 24,
):
    """Time-series timeline of log events aggregated by hour or day."""
    logs_col = getattr(request.app.state, "logs", None)
    if logs_col is None:
        return []

    try:
        pipeline = [
            {
                "$project": {
                    "bucket": {"$substr": ["$timestamp", 0, 13]},  # YYYY-MM-DDTHH
                    "severity": "$severity",
                }
            },
            {
                "$group": {
                    "_id": "$bucket",
                    "total": {"$sum": 1},
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}
                    },
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}
                    },
                }
            },
            {"$sort": {"_id": -1}},
            {"$limit": limit},
        ]
        results = list(logs_col.aggregate(pipeline))
        results.sort(key=lambda x: x["_id"])
        return [
            {
                "time": r["_id"] + ":00Z" if len(r["_id"]) == 13 else r["_id"],
                "total": r["total"],
                "critical": r["critical"],
                "high": r["high"],
                "medium": r["medium"],
                "low": r["low"],
            }
            for r in results
        ]
    except Exception as exc:
        logger.warning("Failed to aggregate events timeline: %s", exc)
        return []


@router.get("/top-sources")
def get_top_sources(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
):
    """Top source IP addresses with event counts and severity breakdown."""
    logs_col = getattr(request.app.state, "logs", None)
    if logs_col is None:
        return []

    try:
        pipeline = [
            {
                "$group": {
                    "_id": "$source_ip",
                    "total": {"$sum": 1},
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}
                    },
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}
                    },
                }
            },
            {"$sort": {"total": -1}},
            {"$limit": limit},
        ]
        results = list(logs_col.aggregate(pipeline))
        return [
            {
                "source_ip": r["_id"],
                "total": r["total"],
                "critical": r["critical"],
                "high": r["high"],
                "medium": r["medium"],
                "low": r["low"],
            }
            for r in results
        ]
    except Exception as exc:
        logger.warning("Failed to aggregate top sources: %s", exc)
        return []


@router.get("/event-types")
def get_event_types_distribution(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    """Breakdown of all event types in log store."""
    logs_col = getattr(request.app.state, "logs", None)
    if logs_col is None:
        return []

    try:
        pipeline = [
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        results = list(logs_col.aggregate(pipeline))
        return [{"event_type": r["_id"], "count": r["count"]} for r in results if r.get("_id")]
    except Exception as exc:
        logger.warning("Failed to aggregate event types: %s", exc)
        return []
