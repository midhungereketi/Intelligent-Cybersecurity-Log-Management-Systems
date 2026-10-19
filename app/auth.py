"""Authentication, authorization, Argon2id hashing, and JWT token management."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from fastapi import Depends, Header, HTTPException, Request, status

from .config import (
    jwt_algorithm,
    jwt_expire_minutes,
    jwt_secret_key,
    login_rate_limit_max,
    login_rate_limit_window_seconds,
)
from .db import get_db_connection

logger = logging.getLogger("app.auth")

# In-memory token revocation cache (JTI -> expiry_timestamp)
_REVOKED_TOKENS: dict[str, float] = {}

# In-memory rate limiting cache (identifier -> list of failed attempt timestamps)
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def hash_password(password: str) -> str:
    """Hash a password using Argon2id with a cryptographically secure random salt."""
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    salt = os.urandom(16)
    kdf = Argon2id(salt=salt, length=32, iterations=1, lanes=4, memory_cost=65536)
    key = kdf.derive(password.encode("utf-8"))
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"$argon2id$v=19$m=65536,t=1,p=4${salt_b64}${key_b64}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash."""
    if not isinstance(password, str) or not isinstance(hashed, str):
        return False
    parts = hashed.split("$")
    # Expected format: ['', 'argon2id', 'v=19', 'm=65536,t=1,p=4', salt_b64, key_b64]
    if len(parts) != 6 or parts[1] != "argon2id":
        return False
    try:
        salt = base64.b64decode(parts[4])
        expected_key = base64.b64decode(parts[5])
        kdf = Argon2id(salt=salt, length=32, iterations=1, lanes=4, memory_cost=65536)
        kdf.verify(password.encode("utf-8"), expected_key)
        return True
    except (InvalidKey, ValueError, TypeError, Exception):
        return False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(user_id: int | str, username: str, role_name: str, expires_delta_seconds: int | None = None) -> str:
    """Create a signed RFC 7519 HS256 JWT access token."""
    now = time.time()
    if expires_delta_seconds is None:
        expires_delta_seconds = jwt_expire_minutes() * 60
    exp = int(now + expires_delta_seconds)

    header = {"alg": jwt_algorithm(), "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role_name,
        "iat": int(now),
        "exp": exp,
        "jti": str(uuid.uuid4()),
    }

    header_segment = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")

    signature = hmac.new(jwt_secret_key().encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_segment = _b64url_encode(signature)

    return f"{header_segment}.{payload_segment}.{signature_segment}"


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and strictly validate an HS256 JWT access token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token structure")

    header_segment, payload_segment, signature_segment = parts
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    expected_sig = hmac.new(jwt_secret_key().encode("utf-8"), signing_input, hashlib.sha256).digest()

    try:
        actual_sig = _b64url_decode(signature_segment)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature encoding")

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")

    try:
        payload_bytes = _b64url_decode(payload_segment)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token payload")

    # Check expiration
    now = time.time()
    exp = payload.get("exp")
    if exp is None or now > exp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

    # Check revocation
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    return payload


def revoke_token(jti: str, exp: float | None = None) -> None:
    """Mark a JWT token ID as revoked until its expiration."""
    clean_revocation_cache()
    if exp is None:
        exp = time.time() + (jwt_expire_minutes() * 60)
    _REVOKED_TOKENS[jti] = float(exp)


def is_token_revoked(jti: str) -> bool:
    """Check if a token has been revoked."""
    exp = _REVOKED_TOKENS.get(jti)
    if exp is None:
        return False
    if time.time() > exp:
        del _REVOKED_TOKENS[jti]
        return False
    return True


def clean_revocation_cache() -> None:
    """Purge expired tokens from the revocation cache."""
    now = time.time()
    expired_keys = [k for k, exp in _REVOKED_TOKENS.items() if now > exp]
    for k in expired_keys:
        _REVOKED_TOKENS.pop(k, None)


def check_login_rate_limit(identifier: str) -> None:
    """Check whether too many failed login attempts have occurred for this identifier."""
    now = time.time()
    window = login_rate_limit_window_seconds()
    max_attempts = login_rate_limit_max()

    attempts = [t for t in _LOGIN_ATTEMPTS.get(identifier, []) if now - t < window]
    _LOGIN_ATTEMPTS[identifier] = attempts

    if len(attempts) >= max_attempts:
        logger.warning("Rate limit exceeded for login attempts: %s", identifier)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )


def record_login_failure(identifier: str) -> None:
    """Record a failed login attempt for rate limiting."""
    now = time.time()
    window = login_rate_limit_window_seconds()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(identifier, []) if now - t < window]
    attempts.append(now)
    _LOGIN_ATTEMPTS[identifier] = attempts
    logger.warning("Failed login attempt recorded for: %s (attempt %d)", identifier, len(attempts))


def reset_login_rate_limit(identifier: str) -> None:
    """Reset rate limit tracking upon successful authentication."""
    _LOGIN_ATTEMPTS.pop(identifier, None)


def get_current_user(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    """Dependency: retrieve and validate the currently authenticated user from Bearer token."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    payload = decode_access_token(token)

    try:
        user_id = int(payload["sub"])
    except (ValueError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user identifier in token")

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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account not found")

    if not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    # Attach token JTI for logout capability
    user["_jti"] = payload.get("jti")
    user["_exp"] = payload.get("exp")
    return user


def require_active_user(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    """Dependency: ensure user is active."""
    if not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")
    return user


def require_admin(user: Annotated[dict[str, Any], Depends(require_active_user)]) -> dict[str, Any]:
    """Dependency: require administrator role."""
    if user.get("role_name") != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privilege required",
        )
    return user


def require_analyst_or_admin(user: Annotated[dict[str, Any], Depends(require_active_user)]) -> dict[str, Any]:
    """Dependency: require either analyst or administrator role."""
    if user.get("role_name") not in {"ADMIN", "ANALYST"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or Administrator privilege required",
        )
    return user
