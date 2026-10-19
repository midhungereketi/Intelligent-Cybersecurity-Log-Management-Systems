"""Tests for authentication, Argon2id hashing, JWT validation, rate limiting, and RBAC."""

import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth import (
    check_login_rate_limit,
    create_access_token,
    decode_access_token,
    get_current_user,
    hash_password,
    is_token_revoked,
    record_login_failure,
    require_admin,
    require_analyst_or_admin,
    reset_login_rate_limit,
    revoke_token,
    verify_password,
)
from app.db import reset_db_override, set_db_override
from app.main import app
from tests.mock_db import MockDatabase


class AuthUnitTests(unittest.TestCase):
    def setUp(self):
        self.mock_db = MockDatabase()
        set_db_override(self.mock_db.get_connection)
        # Seed an admin and an analyst user
        self.admin_pwd = "AdminSecurePass123!"
        self.analyst_pwd = "AnalystSecurePass123!"

        self.mock_db.users.append({
            "user_id": 1,
            "username": "admin_user",
            "email": "admin@example.local",
            "password_hash": hash_password(self.admin_pwd),
            "role_id": 1,  # ADMIN
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })
        self.mock_db.users.append({
            "user_id": 2,
            "username": "analyst_user",
            "email": "analyst@example.local",
            "password_hash": hash_password(self.analyst_pwd),
            "role_id": 2,  # ANALYST
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })
        self.mock_db.users.append({
            "user_id": 3,
            "username": "inactive_user",
            "email": "inactive@example.local",
            "password_hash": hash_password("InactivePass123!"),
            "role_id": 2,  # ANALYST
            "is_active": False,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
        })

        self.client = TestClient(app)

    def tearDown(self):
        reset_db_override()

    def test_argon2id_password_hashing(self):
        raw = "MySuperSecretPassword#2026"
        hashed = hash_password(raw)
        self.assertTrue(hashed.startswith("$argon2id$v=19$m=65536,t=1,p=4$"))
        self.assertTrue(verify_password(raw, hashed))
        self.assertFalse(verify_password("WrongPassword123", hashed))
        self.assertFalse(verify_password("", hashed))

    def test_argon2id_rejects_short_password(self):
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_jwt_lifecycle_and_tamper_detection(self):
        token = create_access_token(user_id=1, username="admin_user", role_name="ADMIN", expires_delta_seconds=60)
        claims = decode_access_token(token)
        self.assertEqual(claims["sub"], "1")
        self.assertEqual(claims["username"], "admin_user")
        self.assertEqual(claims["role"], "ADMIN")

        # Test tampering
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}wrongsig.{parts[2]}"
        with self.assertRaises(HTTPException) as ctx:
            decode_access_token(tampered_token)
        self.assertEqual(ctx.exception.status_code, 401)

        # Test expiration
        expired_token = create_access_token(user_id=1, username="admin_user", role_name="ADMIN", expires_delta_seconds=-10)
        with self.assertRaises(HTTPException) as ctx:
            decode_access_token(expired_token)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("expired", ctx.exception.detail)

    def test_token_revocation(self):
        token = create_access_token(user_id=1, username="admin_user", role_name="ADMIN")
        claims = decode_access_token(token)
        jti = claims["jti"]
        self.assertFalse(is_token_revoked(jti))

        revoke_token(jti)
        self.assertTrue(is_token_revoked(jti))

        with self.assertRaises(HTTPException) as ctx:
            decode_access_token(token)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("revoked", ctx.exception.detail)

    def test_login_rate_limiting(self):
        test_key = "127.0.0.1:brute_test"
        reset_login_rate_limit(test_key)

        for _ in range(5):
            record_login_failure(test_key)

        with self.assertRaises(HTTPException) as ctx:
            check_login_rate_limit(test_key)
        self.assertEqual(ctx.exception.status_code, 429)

        # Resetting restores access
        reset_login_rate_limit(test_key)
        # Should not raise
        check_login_rate_limit(test_key)

    def test_login_api_endpoints(self):
        # 1. Valid login
        resp = self.client.post("/api/auth/login", json={"username": "admin_user", "password": self.admin_pwd})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["username"], "admin_user")
        self.assertEqual(data["user"]["role_name"], "ADMIN")
        self.assertNotIn("password_hash", data["user"])

        token = data["access_token"]

        # 2. Invalid password
        resp_bad = self.client.post("/api/auth/login", json={"username": "admin_user", "password": "WrongPassword!"})
        self.assertEqual(resp_bad.status_code, 401)

        # 3. Unknown user
        resp_unknown = self.client.post("/api/auth/login", json={"username": "nonexistent", "password": "AnyPassword!"})
        self.assertEqual(resp_unknown.status_code, 401)

        # 4. Deactivated user
        resp_inactive = self.client.post("/api/auth/login", json={"username": "inactive_user", "password": "InactivePass123!"})
        self.assertEqual(resp_inactive.status_code, 403)

        # 5. GET /api/auth/me
        resp_me = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp_me.status_code, 200)
        self.assertEqual(resp_me.json()["username"], "admin_user")

        # 6. POST /api/auth/logout
        resp_logout = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp_logout.status_code, 200)

        # 7. Post-logout token rejection
        resp_me_again = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp_me_again.status_code, 401)

    def test_unauthenticated_access_denied(self):
        resp = self.client.get("/api/auth/me")
        self.assertEqual(resp.status_code, 401)

    def test_role_authorization_and_user_admin(self):
        # Admin login
        admin_login = self.client.post("/api/auth/login", json={"username": "admin_user", "password": self.admin_pwd}).json()
        admin_token = admin_login["access_token"]

        # Analyst login
        analyst_login = self.client.post("/api/auth/login", json={"username": "analyst_user", "password": self.analyst_pwd}).json()
        analyst_token = analyst_login["access_token"]

        # Admin can list users
        resp_admin_list = self.client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(resp_admin_list.status_code, 200)
        self.assertGreaterEqual(len(resp_admin_list.json()), 2)

        # Analyst cannot list users (403 Forbidden)
        resp_analyst_list = self.client.get("/api/users", headers={"Authorization": f"Bearer {analyst_token}"})
        self.assertEqual(resp_analyst_list.status_code, 403)

        # Admin can create a new user
        new_user_payload = {
            "username": "new_analyst",
            "email": "new_analyst@example.local",
            "password": "NewAnalystSecurePass1!",
            "role_id": 2,
            "is_active": True,
        }
        resp_create = self.client.post("/api/users", json=new_user_payload, headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(resp_create.status_code, 201)
        created = resp_create.json()
        self.assertEqual(created["username"], "new_analyst")
        self.assertNotIn("password_hash", created)

        # Analyst cannot create users
        resp_analyst_create = self.client.post("/api/users", json=new_user_payload, headers={"Authorization": f"Bearer {analyst_token}"})
        self.assertEqual(resp_analyst_create.status_code, 403)

        # Admin cannot deactivate self
        resp_self_deact = self.client.patch(
            f"/api/users/{admin_login['user']['user_id']}",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(resp_self_deact.status_code, 400)

        # Admin cannot demote self
        resp_self_demote = self.client.patch(
            f"/api/users/{admin_login['user']['user_id']}",
            json={"role_id": 2},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(resp_self_demote.status_code, 400)


if __name__ == "__main__":
    unittest.main()
