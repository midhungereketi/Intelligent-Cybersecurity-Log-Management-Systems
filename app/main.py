"""HTTP contract for Member 1. Member 2 can add authentication middleware later."""

from contextlib import asynccontextmanager
from typing import Annotated

import psycopg
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from pymongo import MongoClient

from .config import max_upload_bytes, mongo_database, mongo_uri, postgres_dsn
from .logs import ensure_indexes, ingest, normalize, parse_upload, search, serialize


@asynccontextmanager
async def lifespan(application: FastAPI):
    client = MongoClient(mongo_uri(), serverSelectionTimeoutMS=3000)
    application.state.mongo = client
    application.state.logs = client[mongo_database()].logs
    try:
        client.admin.command("ping")
        ensure_indexes(application.state.logs)
        yield
    finally:
        client.close()


app = FastAPI(title="Cybersecurity Log API - Member 1", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _sql_connection():
    dsn = postgres_dsn()
    if not dsn:
        raise HTTPException(503, "POSTGRES_DSN is not configured")
    try:
        return psycopg.connect(dsn, row_factory=dict_row)
    except psycopg.OperationalError as exc:
        raise HTTPException(503, "PostgreSQL is unavailable") from exc


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
def create_event(event: dict):
    try:
        normalized = normalize(event)
    except ValueError:
        raise HTTPException(422, "invalid event payload")
    result = app.state.logs.insert_one(normalized)
    normalized["_id"] = result.inserted_id
    return serialize(normalized)


@app.post("/api/logs/upload")
async def upload_logs(file: Annotated[UploadFile, File()]):
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
):
    try:
        return search(app.state.logs, start=start, end=end, source_ip=source_ip,
                      event_type=event_type, severity=severity, keyword=keyword,
                      limit=limit, cursor=cursor)
    except ValueError:
        raise HTTPException(422, "invalid query filters")


@app.get("/api/devices")
def list_devices():
    with _sql_connection() as conn:
        return conn.execute("SELECT * FROM device ORDER BY device_id").fetchall()


@app.post("/api/devices", status_code=201)
def create_device(payload: DeviceIn):
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
def list_sources(device_id: int | None = None):
    with _sql_connection() as conn:
        if device_id is None:
            return conn.execute("SELECT * FROM log_source ORDER BY source_id").fetchall()
        return conn.execute("SELECT * FROM log_source WHERE device_id = %s ORDER BY source_id", (device_id,)).fetchall()


@app.post("/api/sources", status_code=201)
def create_source(payload: SourceIn):
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
