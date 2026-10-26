"""The running app must never replace PostgreSQL with demo accounts."""

import unittest
from unittest.mock import patch

import psycopg
from fastapi import HTTPException

from app.db import get_db_connection


class DatabaseAvailabilityTests(unittest.TestCase):
    def test_missing_postgres_configuration_returns_503(self):
        with patch("app.db.postgres_dsn", return_value=None):
            with self.assertRaises(HTTPException) as context:
                get_db_connection()
        self.assertEqual(context.exception.status_code, 503)

    def test_postgres_outage_returns_503(self):
        with patch("app.db.postgres_dsn", return_value="postgresql://example/unused"):
            with patch("app.db.psycopg.connect", side_effect=psycopg.OperationalError("offline")):
                with self.assertRaises(HTTPException) as context:
                    get_db_connection()
        self.assertEqual(context.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
