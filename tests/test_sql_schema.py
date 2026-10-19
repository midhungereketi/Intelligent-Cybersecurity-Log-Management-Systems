"""Tests for SQL schema migrations, constraints, and relational definitions."""

import re
import unittest
from pathlib import Path


class SQLSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.migration_001 = cls.repo_root / "sql" / "001_devices_and_sources.postgres.sql"
        cls.migration_002 = cls.repo_root / "sql" / "002_auth_and_detection.postgres.sql"
        cls.migration_003 = cls.repo_root / "sql" / "003_incidents_and_actions.postgres.sql"

    def test_migration_files_exist(self):
        self.assertTrue(self.migration_001.is_file(), "001_devices_and_sources.postgres.sql must exist")
        self.assertTrue(self.migration_002.is_file(), "002_auth_and_detection.postgres.sql must exist")
        self.assertTrue(self.migration_003.is_file(), "003_incidents_and_actions.postgres.sql must exist")

    def test_non_destructive_migrations(self):
        content_001 = self.migration_001.read_text(encoding="utf-8")
        content_002 = self.migration_002.read_text(encoding="utf-8")
        content_003 = self.migration_003.read_text(encoding="utf-8")
        self.assertNotIn("DROP TABLE", content_001.upper())
        self.assertNotIn("DROP TABLE", content_002.upper())
        self.assertNotIn("DROP TABLE", content_003.upper())
        self.assertNotIn("DROP DATABASE", content_002.upper())
        self.assertNotIn("DROP DATABASE", content_003.upper())

    def test_002_defines_required_tables(self):
        sql = self.migration_002.read_text(encoding="utf-8")
        required_tables = ["roles", "users", "rules", "threats", "alerts", "processed_detection_events"]
        for tbl in required_tables:
            with self.subTest(table=tbl):
                pattern = rf"CREATE TABLE (?:IF NOT EXISTS )?{tbl}\b"
                self.assertRegex(sql, re.compile(pattern, re.IGNORECASE))

    def test_003_defines_required_tables(self):
        sql = self.migration_003.read_text(encoding="utf-8")
        required_tables = ["incidents", "incident_alerts", "actions"]
        for tbl in required_tables:
            with self.subTest(table=tbl):
                pattern = rf"CREATE TABLE (?:IF NOT EXISTS )?{tbl}\b"
                self.assertRegex(sql, re.compile(pattern, re.IGNORECASE))

    def test_incidents_table_constraints(self):
        sql = self.migration_003.read_text(encoding="utf-8")
        self.assertRegex(sql, re.compile(r"severity\s+VARCHAR\(\d+\)\s+NOT NULL\s+CHECK\s*\(\s*severity\s+IN", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"status\s+VARCHAR\(\d+\)\s+NOT NULL\s+DEFAULT\s+'OPEN'", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"assigned_to\s+BIGINT\s+REFERENCES\s+users\s*\(\s*user_id\s*\)", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"alert_id\s+BIGINT\s+REFERENCES\s+alerts\s*\(\s*alert_id\s*\)", re.IGNORECASE))

    def test_actions_table_constraints(self):
        sql = self.migration_003.read_text(encoding="utf-8")
        self.assertRegex(sql, re.compile(r"incident_id\s+BIGINT\s+NOT NULL\s+REFERENCES\s+incidents", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"action_type\s+VARCHAR\(\d+\)\s+NOT NULL\s+CHECK\s*\(\s*action_type\s+IN", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"performed_by\s+BIGINT\s+REFERENCES\s+users\s*\(\s*user_id\s*\)", re.IGNORECASE))

    def test_users_table_constraints(self):
        sql = self.migration_002.read_text(encoding="utf-8")
        # Check primary key, foreign key, unique constraints
        self.assertRegex(sql, re.compile(r"username\s+VARCHAR\(\d+\)\s+NOT NULL\s+UNIQUE", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"email\s+VARCHAR\(\d+\)\s+NOT NULL\s+UNIQUE", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"password_hash\s+VARCHAR\(\d+\)\s+NOT NULL", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"role_id\s+BIGINT\s+NOT NULL\s+REFERENCES\s+roles", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"is_active\s+BOOLEAN\s+NOT NULL\s+DEFAULT\s+TRUE", re.IGNORECASE))

    def test_rules_table_constraints(self):
        sql = self.migration_002.read_text(encoding="utf-8")
        self.assertRegex(sql, re.compile(r"threshold\s+INTEGER\s+NOT NULL\s+CHECK\s*\(\s*threshold\s*>\s*0\s*\)", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"time_window_seconds\s+INTEGER\s+NOT NULL\s+CHECK\s*\(\s*time_window_seconds\s*>\s*0\s*\)", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"severity\s+VARCHAR\(\d+\)\s+NOT NULL\s+CHECK\s*\(\s*severity\s+IN", re.IGNORECASE))

    def test_alerts_table_constraints_and_deduplication(self):
        sql = self.migration_002.read_text(encoding="utf-8")
        self.assertRegex(sql, re.compile(r"status\s+VARCHAR\(\d+\)\s+NOT NULL\s+DEFAULT\s+'OPEN'", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"CHECK\s*\(\s*status\s+IN\s*\(\s*'OPEN'\s*,\s*'ACKNOWLEDGED'\s*,\s*'RESOLVED'\s*\)\s*\)", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"deduplication_key\s+VARCHAR\(\d+\)\s+NOT NULL", re.IGNORECASE))
        self.assertRegex(sql, re.compile(r"CREATE\s+UNIQUE\s+INDEX\s+(?:IF NOT EXISTS\s+)?alerts_active_dedup_idx", re.IGNORECASE))

    def test_seeds_roles_and_rules(self):
        sql = self.migration_002.read_text(encoding="utf-8")
        self.assertIn("'ADMIN'", sql)
        self.assertIn("'ANALYST'", sql)
        self.assertIn("Repeated Failed Logins", sql)
        self.assertIn("Possible Port Scan", sql)
        self.assertIn("Excessive Activity from Single IP", sql)


if __name__ == "__main__":
    unittest.main()
