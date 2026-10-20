"""Test suite package initialization with safe test-only configuration."""

import os

# Safe, isolated secret key for running automated tests
os.environ.setdefault("JWT_SECRET_KEY", "test-safe-isolated-secret-key-for-unit-testing-32-chars")
os.environ.setdefault("APP_ENV", "testing")
