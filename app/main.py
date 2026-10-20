"""HTTP contract for Member 1 and Member 2 backend features."""

import logging
from contextlib import asynccontextmanager
from typing import Annotated, Any

import psycopg
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from pymongo import MongoClient

from .auth import hash_password, require_admin, require_analyst_or_admin
from .config import (
    admin_bootstrap_email,
    admin_bootstrap_password,
    admin_bootstrap_username,
    jwt_secret_key,
    max_upload_bytes,
    mongo_database,
    mongo_uri,
    postgres_dsn,
)
from .db import get_db_connection
from .logs import ensure_indexes, ingest, normalize, parse_upload, search, serialize
from .routes_auth import router as auth_router
from .routes_rules import router as rules_router
from .routes_threats_alerts import router as threats_alerts_router

logger = logging.getLogger("app.main")


def _bootstrap_admin():
    username = admin_bootstrap_username()
    password = admin_bootstrap_password()
    if not username or not password:
        return
    email = admin_bootstrap_email() or f"{username}@localhost"
    try:
        with get_db_connection() as conn:
            admin_role = conn.execute("SELECT role_id FROM roles WHERE role_name = 'ADMIN'").fetchone()
            if not admin_role:
                return
            existing = conn.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email)).fetchone()
            if not existing:
                hashed = hash_password(password)
                conn.execute(
                    """INSERT INTO users (username, email, password_hash, role_id, is_active)
                       VALUES (%s, %s, %s, %s, TRUE)""",
                    (username, email, hashed, admin_role["role_id"]),
                )
                logger.info("Bootstrapped initial administrator account: %s", username)
    except Exception as exc:
        logger.debug("Admin bootstrap skipped or failed: %s", exc)


@asynccontextmanager
async def lifespan(application: FastAPI):
    # Fail fast if required production JWT signing secret is missing
    jwt_secret_key()
    client = MongoClient(mongo_uri(), serverSelectionTimeoutMS=3000)
    application.state.mongo = client
    application.state.logs = client[mongo_database()].logs
    try:
        client.admin.command("ping")
        ensure_indexes(application.state.logs)
        _bootstrap_admin()
        yield
    finally:
        client.close()


app = FastAPI(title="Cybersecurity Log Management & Detection System", version="2.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(rules_router)
app.include_router(threats_alerts_router)


def _sql_connection():
    return get_db_connection()


class DeviceIn(BaseModel):
    device_name: str = Field(min_length=1, max_length=120)
    ip_address: str | None = None
    mac_address: str | None = Field(default=None, max_length=17)
    device_type: str = Field(min_length=1, max_length=60)
    operating_system: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    status: str = Field(default="ACTIVE", pattern="^(ACTIVE|INACTIVE)$")


class SourceIn(BaseModel):
    source_name: str = Field(min_length=1, max_length=120)
    source_type: str = Field(min_length=1, max_length=60)
    ip_address: str | None = None
    protocol: str | None = Field(default=None, max_length=30)
    device_id: int = Field(gt=0)


@app.get("/health")
def health():
    app.state.mongo.admin.command("ping")
    return {"status": "ok"}


@app.post("/api/logs/events", status_code=201)
def create_event(
    event: dict,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)] = None,
):
    try:
        normalized = normalize(event)
    except ValueError:
        raise HTTPException(422, "invalid event payload")
    result = app.state.logs.insert_one(normalized)
    normalized["_id"] = result.inserted_id
    return serialize(normalized)


@app.post("/api/logs/upload")
async def upload_logs(
    file: Annotated[UploadFile, File()],
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)] = None,
):
    content = await file.read(max_upload_bytes() + 1)
    if len(content) > max_upload_bytes():
        raise HTTPException(413, "upload exceeds MAX_UPLOAD_BYTES")
    try:
        return ingest(app.state.logs, parse_upload(content, file.filename or ""))
    except ValueError:
        raise HTTPException(422, "invalid upload payload")


@app.get("/api/logs")
def list_logs(
    start: str | None = None,
    end: str | None = None,
    source_ip: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    keyword: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)] = None,
):
    try:
        return search(app.state.logs, start=start, end=end, source_ip=source_ip,
                      event_type=event_type, severity=severity, keyword=keyword,
                      limit=limit, cursor=cursor)
    except ValueError:
        raise HTTPException(422, "invalid query filters")


@app.get("/api/devices")
def list_devices(
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)] = None,
):
    with _sql_connection() as conn:
        return conn.execute("SELECT * FROM device ORDER BY device_id").fetchall()


@app.post("/api/devices", status_code=201)
def create_device(
    payload: DeviceIn,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)] = None,
):
    try:
        with _sql_connection() as conn:
            return conn.execute(
                """INSERT INTO device (device_name, ip_address, mac_address, device_type,
                   operating_system, location, status) VALUES (%s, %s, %s, %s, %s, %s, %s)
                   RETURNING *""",
                (payload.device_name, payload.ip_address, payload.mac_address,
                 payload.device_type, payload.operating_system, payload.location, payload.status),
            ).fetchone()
    except psycopg.IntegrityError as exc:
        raise HTTPException(409, "device name already exists or values violate a constraint") from exc
    except psycopg.DataError as exc:
        raise HTTPException(422, "invalid device field") from exc


@app.get("/api/sources")
def list_sources(
    device_id: int | None = None,
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)] = None,
):
    with _sql_connection() as conn:
        if device_id is None:
            return conn.execute("SELECT * FROM log_source ORDER BY source_id").fetchall()
        return conn.execute("SELECT * FROM log_source WHERE device_id = %s ORDER BY source_id", (device_id,)).fetchall()


@app.post("/api/sources", status_code=201)
def create_source(
    payload: SourceIn,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)] = None,
):
    try:
        with _sql_connection() as conn:
            return conn.execute(
                """INSERT INTO log_source (source_name, source_type, ip_address, protocol, device_id)
                   VALUES (%s, %s, %s, %s, %s) RETURNING *""",
                (payload.source_name, payload.source_type, payload.ip_address,
                 payload.protocol, payload.device_id),
            ).fetchone()
    except psycopg.IntegrityError as exc:
        raise HTTPException(409, "device does not exist or source name is duplicated") from exc
    except psycopg.DataError as exc:
        raise HTTPException(422, "invalid source field") from exc

