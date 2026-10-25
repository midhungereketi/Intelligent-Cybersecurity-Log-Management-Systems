"""Database connection management and repository helpers for PostgreSQL."""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Any, Callable, Generator

import psycopg
from fastapi import HTTPException
from psycopg.rows import dict_row

from .config import postgres_dsn

logger = logging.getLogger("app.db")

_db_override: Callable[[], Any] | None = None
_fallback_mock_db: Any | None = None


def set_db_override(override_fn: Callable[[], Any] | None) -> None:
    """Set a custom connection provider for testing."""
    global _db_override
    _db_override = override_fn


def reset_db_override() -> None:
    """Reset the database connection provider to default."""
    global _db_override
    _db_override = None


def _get_fallback_mock_db():
    global _fallback_mock_db
    if _fallback_mock_db is None:
        from tests.mock_db import MockDatabase
        _fallback_mock_db = MockDatabase()
        from .auth import hash_password
        # Seed default administrative and analyst accounts
        _fallback_mock_db.users.append({
            "user_id": _fallback_mock_db.next_user_id(),
            "username": "admin",
            "email": "admin@cybershield.local",
            "password_hash": hash_password("admin123"),
            "role_id": 1,  # ADMIN
            "is_active": True,
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
            "last_login_at": None,
        })
        _fallback_mock_db.users.append({
            "user_id": _fallback_mock_db.next_user_id(),
            "username": "analyst",
            "email": "analyst@cybershield.local",
            "password_hash": hash_password("analyst123"),
            "role_id": 2,  # ANALYST
            "is_active": True,
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
            "last_login_at": None,
        })
        _fallback_mock_db.devices.extend([
            {
                "device_id": 1,
                "device_name": "perimeter-fw-01",
                "ip_address": "198.51.100.1",
                "mac_address": "00:1A:2B:3C:4D:5E",
                "device_type": "FIREWALL",
                "operating_system": "FortiOS 7.4",
                "location": "US-East-DC",
                "status": "ACTIVE",
            },
            {
                "device_id": 2,
                "device_name": "auth-server-01",
                "ip_address": "192.0.2.10",
                "mac_address": "00:1A:2B:3C:4D:5F",
                "device_type": "SERVER",
                "operating_system": "Ubuntu 22.04 LTS",
                "location": "HQ-Server-Room",
                "status": "ACTIVE",
            },
        ])
        _fallback_mock_db.sources.extend([
            {
                "source_id": 1,
                "source_name": "firewall-syslog",
                "source_type": "SYSLOG",
                "ip_address": "198.51.100.1",
                "protocol": "UDP/514",
                "device_id": 1,
            },
            {
                "source_id": 2,
                "source_name": "auth-audit",
                "source_type": "AUDITD",
                "ip_address": "192.0.2.10",
                "protocol": "TCP/6514",
                "device_id": 2,
            },
        ])
    return _fallback_mock_db


_postgres_available: bool | None = None


def get_db_connection():
    """Get a PostgreSQL database connection with dictionary rows, falling back to mock DB if unavailable."""
    global _postgres_available
    if _db_override is not None:
        return _db_override()

    dsn = postgres_dsn()
    if dsn and _postgres_available is not False:
        try:
            conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=1)
            _postgres_available = True
            return conn
        except (psycopg.OperationalError, Exception) as exc:
            _postgres_available = False
            logger.warning("PostgreSQL is unavailable (%s). Falling back to built-in in-memory database mock.", exc)

    return _get_fallback_mock_db().get_connection()


@contextmanager
def db_transaction() -> Generator[Any, None, None]:
    """Context manager for executing transactions with automatic commit and rollback."""
    conn = get_db_connection()
    try:
        with conn:
            yield conn
    finally:
        # In case conn is not closed by the context
        if hasattr(conn, "close") and not getattr(conn, "closed", False):
            try:
                conn.close()
            except Exception:
                pass


def json_param(data: Any) -> str:
    """Safely serialize an object for JSONB SQL parameters."""
    if isinstance(data, str):
        return data
    return json.dumps(data)
