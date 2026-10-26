"""Database connection management and repository helpers for PostgreSQL."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Callable, Generator

import psycopg
from fastapi import HTTPException
from psycopg.rows import dict_row

from .config import postgres_dsn

_db_override: Callable[[], Any] | None = None


def set_db_override(override_fn: Callable[[], Any] | None) -> None:
    """Set a custom connection provider for testing."""
    global _db_override
    _db_override = override_fn


def reset_db_override() -> None:
    """Reset the database connection provider to default."""
    global _db_override
    _db_override = None


def get_db_connection():
    """Get a PostgreSQL database connection with dictionary rows."""
    if _db_override is not None:
        return _db_override()

    dsn = postgres_dsn()
    if not dsn:
        raise HTTPException(503, "POSTGRES_DSN is not configured")
    try:
        return psycopg.connect(dsn, row_factory=dict_row)
    except psycopg.OperationalError as exc:
        raise HTTPException(503, "PostgreSQL is unavailable") from exc


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
