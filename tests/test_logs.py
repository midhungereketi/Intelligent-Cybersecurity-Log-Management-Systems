import json
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

import mongomock
from bson import ObjectId

from app.logs import _decode_cursor, _encode_cursor, ingest, normalize, parse_upload, search
from app.main import app, create_event, list_logs
from scripts.generate_logs import generate


def sample(**changes):
    result = {
        "timestamp": "2026-10-01T10:00:00+05:30",
        "source_ip": "198.51.100.10",
        "event_type": "login_failed",
        "severity": "high",
        "message": "Failed login",
    }
    result.update(changes)
    return result


class FakeCursor:
    def __init__(self, records):
        self.records = records

    def sort(self, fields):
        self.records.sort(key=lambda r: (r["timestamp"], r["_id"]), reverse=True)
        return self

    def limit(self, count):
        return self.records[:count]


class FakeCollection:
    def __init__(self, records=None):
        self.records = records or []
        self.query = None

    def insert_many(self, batch, ordered=True):
        self.records.extend(batch)
        result = Mock()
        result.inserted_ids = [ObjectId() for _ in batch]
        return result

    def find(self, query):
        self.query = query
        return FakeCursor(list(self.records))


class LogTests(unittest.TestCase):
    def test_normalizes_timestamp_and_optional_fields(self):
        event = normalize(sample(destination_port="443", destination_ip="203.0.113.5", source_id="7"))
        self.assertEqual(event["timestamp"], datetime(2026, 10, 1, 4, 30, tzinfo=timezone.utc))
        self.assertEqual(event["event_type"], "LOGIN_FAILED")
        self.assertEqual(event["severity"], "HIGH")
        self.assertEqual(event["source_id"], 7)
        self.assertEqual(event["destination_port"], 443)

    def test_rejects_bad_time_ip_and_port(self):
        for changed in ({"timestamp": "2026-10-01T10:00:00"},
                        {"source_ip": "not-an-ip"}, {"destination_port": 70000}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                normalize(sample(**changed))

    def test_parses_csv_json_and_jsonl(self):
        self.assertEqual(len(list(parse_upload(json.dumps([sample()]).encode(), "events.json"))), 1)
        self.assertEqual(len(list(parse_upload((json.dumps(sample()) + "\n").encode(), "events.jsonl"))), 1)
        csv_data = b"timestamp,source_ip,event_type,severity,message\n2026-10-01T10:00:00Z,198.51.100.10,LOGIN_FAILED,HIGH,Failed login\n"
        self.assertEqual(len(list(parse_upload(csv_data, "events.csv"))), 1)

    def test_ingest_reports_invalid_rows_without_discarding_valid_rows(self):
        collection = FakeCollection()
        report = ingest(collection, [(1, sample()), (2, sample(source_ip="bad")), (3, sample())], batch_size=1)
        self.assertEqual((report["inserted"], report["rejected"]), (2, 1))
        self.assertEqual(report["errors"][0]["row"], 2)

    def test_search_builds_filters_and_cursor(self):
        timestamp = datetime(2026, 10, 1, tzinfo=timezone.utc)
        records = [{"_id": ObjectId(), "timestamp": timestamp, "source_ip": "198.51.100.10"} for _ in range(3)]
        collection = FakeCollection(records)
        first = search(collection, source_ip="198.51.100.10", severity="high", limit=2)
        self.assertEqual(len(first["items"]), 2)
        self.assertIsNotNone(first["next_cursor"])
        search(collection, cursor=first["next_cursor"])
        self.assertIn("$or", collection.query["$and"][-1])
        self.assertEqual(_decode_cursor(_encode_cursor(records[0]))[0], timestamp)

    def test_generator_is_deterministic_and_contains_detection_patterns(self):
        first = list(generate(100, seed=5))
        self.assertEqual(first, list(generate(100, seed=5)))
        self.assertEqual(sum(r["source_ip"] == "198.51.100.10" for r in first), 25)
        self.assertEqual(sum(r["source_ip"] == "198.51.100.20" for r in first), 35)

    def test_real_query_shape_filters_and_paginates_with_mongomock(self):
        collection = mongomock.MongoClient().demo.logs
        rows = [(index, sample(timestamp=f"2026-10-01T10:00:{index:02d}Z")) for index in range(5)]
        self.assertEqual(ingest(collection, rows)["inserted"], 5)
        first = search(collection, source_ip="198.51.100.10", start="2026-10-01T10:00:01Z", limit=2)
        second = search(collection, source_ip="198.51.100.10", start="2026-10-01T10:00:01Z",
                        limit=2, cursor=first["next_cursor"])
        ids = [item["id"] for item in first["items"] + second["items"]]
        self.assertEqual(len(ids), 4)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIsNone(second["next_cursor"])

    def test_api_handlers_insert_and_search(self):
        app.state.logs = mongomock.MongoClient().demo.logs
        created = create_event(sample())
        self.assertEqual(created["severity"], "HIGH")
        result = list_logs(source_ip="198.51.100.10", start=None, end=None, event_type=None,
                           severity=None, keyword=None, limit=50, cursor=None)
        self.assertEqual(len(result["items"]), 1)


if __name__ == "__main__":
    unittest.main()
