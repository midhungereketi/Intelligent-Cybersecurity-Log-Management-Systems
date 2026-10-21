"""Authentication and user management API routes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from .auth import (
    check_login_rate_limit,
    create_access_token,
    get_current_user,
    hash_password,
    record_login_failure,
    require_admin,
    require_analyst_or_admin,
    reset_login_rate_limit,
    revoke_token,
    verify_password,
)
from .db import db_transaction, get_db_connection

logger = logging.getLogger("app.routes_auth")

router = APIRouter(tags=["Authentication & Users"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=60)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=200)
    role_id: int = Field(gt=0)
    is_active: bool = True


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, min_length=5, max_length=255)
    role_id: int | None = Field(default=None, gt=0)
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=200)


def _sanitize_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "email": row["email"],
        "role_id": row["role_id"],
        "role_name": row.get("role_name"),
        "is_active": row["is_active"],
        "created_at": row["created_at"].isoformat() if hasattr(row.get("created_at"), "isoformat") else row.get("created_at"),
        "updated_at": row["updated_at"].isoformat() if hasattr(row.get("updated_at"), "isoformat") else row.get("updated_at"),
        "last_login_at": row["last_login_at"].isoformat() if hasattr(row.get("last_login_at"), "isoformat") else row.get("last_login_at"),
    }


@router.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    rate_limit_key = f"{client_ip}:{payload.username}"

    # Check brute-force rate limit
    check_login_rate_limit(rate_limit_key)

    with get_db_connection() as conn:
        user = conn.execute(
            """SELECT u.user_id, u.username, u.email, u.password_hash, u.role_id,
                      r.role_name, u.is_active, u.created_at, u.updated_at, u.last_login_at
               FROM users u
               JOIN roles r ON u.role_id = r.role_id
               WHERE u.username = %s OR u.email = %s""",
            (payload.username, payload.username),
        ).fetchone()

    if not user or not verify_password(payload.password, user["password_hash"]):
        record_login_failure(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # Success: reset rate limit and record login time
    reset_login_rate_limit(rate_limit_key)
    now_utc = datetime.now(timezone.utc)
    try:
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = %s, updated_at = %s WHERE user_id = %s",
                (now_utc, now_utc, user["user_id"]),
            )
    except Exception as exc:
        logger.warning("Could not update last_login_at for user %d: %s", user["user_id"], exc)

    token = create_access_token(user["user_id"], user["username"], user["role_name"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600,
        "user": _sanitize_user(user),
    }


@router.post("/api/auth/logout")
def logout(current_user: Annotated[dict[str, Any], Depends(get_current_user)]):
    jti = current_user.get("_jti")
    exp = current_user.get("_exp")
    if jti:
        revoke_token(jti, exp)
    return {"status": "ok", "message": "Successfully logged out"}


@router.get("/api/auth/me")
def get_me(current_user: Annotated[dict[str, Any], Depends(get_current_user)]):
    return _sanitize_user(current_user)


# ================= User Management Endpoints (Admin Only) =================


@router.get("/api/users")
def list_users(admin_user: Annotated[dict[str, Any], Depends(require_admin)]):
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT u.user_id, u.username, u.email, u.role_id, r.role_name,
                      u.is_active, u.created_at, u.updated_at, u.last_login_at
               FROM users u
               JOIN roles r ON u.role_id = r.role_id
               ORDER BY u.user_id"""
        ).fetchall()
        return [_sanitize_user(r) for r in rows]


@router.get("/api/users/assignable")
def list_assignable_users(
    current_user: Annotated[dict[str, Any], Depends(require_analyst_or_admin)],
):
    """Return the minimum user info needed to populate assignee dropdowns.

    Accessible to both ADMIN and ANALYST roles.  Only active users are
    returned, and only ``user_id`` and ``username`` are exposed — no
    password hashes, emails, tokens, or other sensitive fields.
    """
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT u.user_id, u.username
               FROM users u
               WHERE u.is_active = TRUE
               ORDER BY u.username"""
        ).fetchall()
        return [{"user_id": r["user_id"], "username": r["username"]} for r in rows]


@router.post("/api/users", status_code=201)
def create_user(
    payload: UserCreate,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)],
):
    try:
        hashed = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    now_utc = datetime.now(timezone.utc)
    try:
        with db_transaction() as conn:
            # Check role existence
            role = conn.execute("SELECT role_id, role_name FROM roles WHERE role_id = %s", (payload.role_id,)).fetchone()
            if not role:
                raise HTTPException(status_code=422, detail="Specified role_id does not exist")

            row = conn.execute(
                """INSERT INTO users (username, email, password_hash, role_id, is_active, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   RETURNING user_id, username, email, role_id, is_active, created_at, updated_at, last_login_at""",
                (payload.username, payload.email, hashed, payload.role_id, payload.is_active, now_utc, now_utc),
            ).fetchone()
            row["role_name"] = role["role_name"]
            return _sanitize_user(row)
    except psycopg.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Username or email already exists") from exc


@router.get("/api/users/{user_id}")
def get_user(
    user_id: int,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)],
):
    with get_db_connection() as conn:
        user = conn.execute(
            """SELECT u.user_id, u.username, u.email, u.role_id, r.role_name,
                      u.is_active, u.created_at, u.updated_at, u.last_login_at
               FROM users u
               JOIN roles r ON u.role_id = r.role_id
               WHERE u.user_id = %s""",
            (user_id,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return _sanitize_user(user)


@router.patch("/api/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    admin_user: Annotated[dict[str, Any], Depends(require_admin)],
):
    # Prevent admin from deactivating or demoting themselves
    if admin_user["user_id"] == user_id:
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own administrator account")
        if payload.role_id is not None and payload.role_id != admin_user["role_id"]:
            raise HTTPException(status_code=400, detail="Cannot change your own administrator role")

    with db_transaction() as conn:
        user = conn.execute("SELECT * FROM users WHERE user_id = %s", (user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        updates: list[str] = []
        params: list[Any] = []

        if payload.email is not None:
            updates.append("email = %s")
            params.append(payload.email)

        if payload.role_id is not None:
            role = conn.execute("SELECT role_id FROM roles WHERE role_id = %s", (payload.role_id,)).fetchone()
            if not role:
                raise HTTPException(status_code=422, detail="Specified role_id does not exist")
            updates.append("role_id = %s")
            params.append(payload.role_id)

        if payload.is_active is not None:
            updates.append("is_active = %s")
            params.append(payload.is_active)

        if payload.password is not None:
            try:
                hashed = hash_password(payload.password)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            updates.append("password_hash = %s")
            params.append(hashed)

        if not updates:
            # Nothing to update
            return _sanitize_user(
                conn.execute(
                    """SELECT u.user_id, u.username, u.email, u.role_id, r.role_name,
                              u.is_active, u.created_at, u.updated_at, u.last_login_at
                       FROM users u
                       JOIN roles r ON u.role_id = r.role_id
                       WHERE u.user_id = %s""",
                    (user_id,),
                ).fetchone()
            )

        now_utc = datetime.now(timezone.utc)
        updates.append("updated_at = %s")
        params.append(now_utc)
        params.append(user_id)

        try:
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE user_id = %s",
                params,
            )
            updated = conn.execute(
                """SELECT u.user_id, u.username, u.email, u.role_id, r.role_name,
                          u.is_active, u.created_at, u.updated_at, u.last_login_at
                   FROM users u
                   JOIN roles r ON u.role_id = r.role_id
                   WHERE u.user_id = %s""",
                (user_id,),
            ).fetchone()
            return _sanitize_user(updated)
        except psycopg.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Email already exists or violates constraint") from exc
