"""Smoke-test Member 1 against real MongoDB and PostgreSQL instances.

Run migration 001 before this script. It uses a transaction for SQL records and
removes only its own MongoDB records, so it is safe to rerun in a test database.
"""

import os
import sys
from pathlib import Path

import psycopg
from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import mongo_database, mongo_uri
from app.logs import ensure_indexes, ingest, search


def check_postgres() -> None:
    dsn = os.environ["POSTGRES_DSN"]
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO device (device_name, device_type, status)
                   VALUES ('member1-live-check', 'SERVER', 'ACTIVE')
                   RETURNING device_id"""
            )
            device_id = cur.fetchone()[0]
            cur.execute(
                """INSERT INTO log_source (source_name, source_type, device_id)
                   VALUES ('member1-live-source', 'SYSLOG', %s)
                   RETURNING source_id""",
                (device_id,),
            )
            source_id = cur.fetchone()[0]
            cur.execute(
                """SELECT d.device_name, s.source_name
                   FROM device d JOIN log_source s ON s.device_id = d.device_id
                   WHERE d.device_id = %s AND s.source_id = %s""",
                (device_id, source_id),
            )
            assert cur.fetchone() == ("member1-live-check", "member1-live-source")
        conn.rollback()
    print("PostgreSQL migration 001: insert, foreign key, and join passed")


def check_mongo() -> None:
    marker = "member1-live-check"
    with MongoClient(mongo_uri(), serverSelectionTimeoutMS=5000) as client:
        collection = client[mongo_database()].logs
        client.admin.command("ping")
        ensure_indexes(collection)
        expected = {"timestamp_desc", "source_ip_time", "event_type_time", "severity_time", "message_text"}
        assert expected.issubset(collection.index_information())
        rows = [
            (i, {
                "timestamp": "2026-10-01T10:00:00Z",
                "source_ip": "198.51.100.246",
                "event_type": "LOGIN_FAILED",
                "severity": "HIGH",
                "message": f"{marker} suspicious login {i}",
                "log_source": marker,
            }) for i in range(1, 4)
        ]
        try:
            result = ingest(collection, rows)
            assert result["inserted"] == 3 and result["rejected"] == 0
            first = search(collection, source_ip="198.51.100.246", limit=2)
            assert len(first["items"]) == 2 and first["next_cursor"]
            second = search(collection, source_ip="198.51.100.246", limit=2,
                            cursor=first["next_cursor"])
            assert len(second["items"]) == 1 and second["next_cursor"] is None
            assert len({item["id"] for item in first["items"] + second["items"]}) == 3
            text = search(collection, keyword="suspicious", source_ip="198.51.100.246")
            assert len(text["items"]) == 3
            window = search(collection, source_ip="198.51.100.246",
                            start="2026-10-01T11:00:00Z")
            assert window["items"] == []
        finally:
            collection.delete_many({"log_source": marker})
    print("MongoDB: indexes, ingestion, text search, time filter, and cursor pagination passed")


if __name__ == "__main__":
    check_postgres()
    check_mongo()
