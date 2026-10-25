"""Normalization, MongoDB indexing, ingestion, and query logic."""

from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from bson import ObjectId
from pymongo import ASCENDING, DESCENDING

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
INDEXES = [
    ([("timestamp", DESCENDING), ("_id", DESCENDING)], "timestamp_desc"),
    ([("source_ip", ASCENDING), ("timestamp", DESCENDING), ("_id", DESCENDING)], "source_ip_time"),
    ([("event_type", ASCENDING), ("timestamp", DESCENDING), ("_id", DESCENDING)], "event_type_time"),
    ([("severity", ASCENDING), ("timestamp", DESCENDING), ("_id", DESCENDING)], "severity_time"),
    ([("message", "text")], "message_text"),
]


def ensure_indexes(collection: Any) -> None:
    for keys, name in INDEXES:
        collection.create_index(keys, name=name)


def _utc_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO 8601 date and time") from exc
    else:
        raise ValueError("timestamp is required and must be an ISO 8601 date and time")
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return dt.astimezone(timezone.utc)


def _ip(value: Any, field: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address") from exc


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("log must be a JSON object")
    for field in ("source_ip", "event_type", "severity", "message"):
        if not isinstance(raw.get(field), str) or not raw[field].strip():
            raise ValueError(f"{field} is required")
    severity = raw["severity"].strip().upper()
    if severity not in SEVERITIES:
        raise ValueError("severity must be LOW, MEDIUM, HIGH, or CRITICAL")
    event_type = raw["event_type"].strip().upper()
    if len(event_type) > 80 or len(raw["message"]) > 4000:
        raise ValueError("event_type or message exceeds maximum length")
    out = {
        "timestamp": _utc_timestamp(raw.get("timestamp")),
        "ingested_at": datetime.now(timezone.utc),
        "source_ip": _ip(raw["source_ip"], "source_ip"),
        "event_type": event_type,
        "severity": severity,
        "message": raw["message"].strip(),
    }
    for field in ("source_id", "device_id"):
        value = raw.get(field)
        if value not in (None, ""):
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{field} must be a positive integer") from exc
            if number < 1:
                raise ValueError(f"{field} must be a positive integer")
            out[field] = number
    for field in ("username", "log_source"):
        value = raw.get(field)
        if value not in (None, ""):
            if not isinstance(value, str) or len(value) > 120:
                raise ValueError(f"{field} must be text of at most 120 characters")
            out[field] = value.strip()
    if raw.get("destination_ip") not in (None, ""):
        out["destination_ip"] = _ip(raw["destination_ip"], "destination_ip")
    if raw.get("destination_port") not in (None, ""):
        try:
            port = int(raw["destination_port"])
        except (TypeError, ValueError) as exc:
            raise ValueError("destination_port must be an integer between 1 and 65535") from exc
        if not 1 <= port <= 65535:
            raise ValueError("destination_port must be an integer between 1 and 65535")
        out["destination_port"] = port
    return out


def parse_upload(content: bytes, filename: str) -> Iterable[tuple[int, dict[str, Any]]]:
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("upload must be UTF-8") from exc
    suffix = filename.lower().rsplit(".", 1)[-1]
    if suffix == "csv":
        reader = csv.DictReader(io.StringIO(decoded))
        if not reader.fieldnames:
            raise ValueError("CSV must contain a header row")
        for row_number, row in enumerate(reader, start=2):
            yield row_number, row
    elif suffix == "json":
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON at line {exc.lineno}") from exc
        if not isinstance(data, list):
            raise ValueError("JSON upload must be an array of log objects")
        for row_number, row in enumerate(data, start=1):
            yield row_number, row
    elif suffix in {"jsonl", "ndjson"}:
        for row_number, line in enumerate(decoded.splitlines(), start=1):
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    # Earlier batches may already be stored, so aborting here would
                    # report failure for a partial insert. Reject just this line.
                    row = None
                yield row_number, row
    else:
        raise ValueError("supported file types are CSV, JSON, and JSONL")


def ingest(collection: Any, rows: Iterable[tuple[int, dict[str, Any]]], batch_size: int = 1000) -> dict[str, Any]:
    inserted = 0
    rejected = 0
    errors: list[dict[str, Any]] = []
    batch: list[dict[str, Any]] = []
    for row_number, raw in rows:
        try:
            batch.append(normalize(raw))
        except ValueError as exc:
            rejected += 1
            if len(errors) < 100:
                errors.append({"row": row_number, "error": "invalid log row"})
            continue
        if len(batch) >= batch_size:
            result = collection.insert_many(batch, ordered=True)
            inserted += len(result.inserted_ids)
            batch = []
    if batch:
        result = collection.insert_many(batch, ordered=True)
        inserted += len(result.inserted_ids)
    return {"inserted": inserted, "rejected": rejected, "errors": errors, "errors_truncated": rejected > len(errors)}


def _encode_cursor(record: dict[str, Any]) -> str:
    timestamp = record["timestamp"]
    # PyMongo returns naive UTC datetimes unless tz_aware is configured.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    payload = {"timestamp": timestamp.isoformat(), "id": str(record["_id"])}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def _decode_cursor(value: str) -> tuple[datetime, ObjectId]:
    try:
        payload = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        timestamp = _utc_timestamp(payload["timestamp"])
        object_id = ObjectId(payload["id"])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("invalid cursor") from exc
    return timestamp, object_id


def serialize(record: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for key, value in record.items():
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            value = value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        elif isinstance(value, ObjectId):
            value = str(value)
        out["id" if key == "_id" else key] = value
    return out


def search(collection: Any, *, start: str | None = None, end: str | None = None,
           source_ip: str | None = None, event_type: str | None = None,
           severity: str | None = None, keyword: str | None = None,
           limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    clauses: list[dict[str, Any]] = []
    window: dict[str, Any] = {}
    if start:
        window["$gte"] = _utc_timestamp(start)
    if end:
        window["$lte"] = _utc_timestamp(end)
    if window:
        if "$gte" in window and "$lte" in window and window["$gte"] > window["$lte"]:
            raise ValueError("start must not be after end")
        clauses.append({"timestamp": window})
    if source_ip:
        clauses.append({"source_ip": _ip(source_ip, "source_ip")})
    if event_type:
        clauses.append({"event_type": event_type.strip().upper()})
    if severity:
        severity = severity.strip().upper()
        if severity not in SEVERITIES:
            raise ValueError("invalid severity")
        clauses.append({"severity": severity})
    if keyword:
        if len(keyword) > 120:
            raise ValueError("keyword exceeds maximum length")
        clauses.append({"$text": {"$search": keyword}})
    if cursor:
        cursor_time, cursor_id = _decode_cursor(cursor)
        clauses.append({"$or": [
            {"timestamp": {"$lt": cursor_time}},
            {"timestamp": cursor_time, "_id": {"$lt": cursor_id}},
        ]})
    query = {"$and": clauses} if clauses else {}
    records = list(collection.find(query).sort([("timestamp", DESCENDING), ("_id", DESCENDING)]).limit(limit + 1))
    has_more = len(records) > limit
    records = records[:limit]
    return {"items": [serialize(r) for r in records], "next_cursor": _encode_cursor(records[-1]) if has_more else None}
