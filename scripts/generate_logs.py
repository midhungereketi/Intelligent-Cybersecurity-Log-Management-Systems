"""Generate deterministic synthetic logs as JSONL or insert them in batches."""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import mongo_database, mongo_uri
from app.logs import ensure_indexes, normalize


def generate(count: int, seed: int = 42):
    rng = random.Random(seed)
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    events = ["LOGIN_SUCCESS", "LOGIN_FAILED", "ACCESS", "FIREWALL_BLOCK", "CONNECTION"]
    for i in range(count):
        event = rng.choices(events, weights=[30, 15, 25, 10, 20])[0]
        source_ip = f"192.0.2.{1 + rng.randrange(200)}"
        port = rng.choice([22, 80, 443, 3306, 5432])
        if i % 1000 in range(25):
            event, source_ip = "LOGIN_FAILED", "198.51.100.10"
        elif i % 1000 in range(25, 60):
            event, source_ip, port = "CONNECTION", "198.51.100.20", 1000 + i % 1000
        elif i % 1000 in range(60, 100):
            source_ip = "198.51.100.30"
        yield {
            "timestamp": (base + timedelta(seconds=i)).isoformat(),
            "source_ip": source_ip,
            "destination_ip": "203.0.113.5",
            "destination_port": port,
            "event_type": event,
            "severity": "HIGH" if event == "LOGIN_FAILED" else "LOW",
            "message": f"Synthetic {event.lower().replace('_', ' ')} event {i}",
            "username": f"user{rng.randrange(100)}",
            "log_source": "synthetic-generator",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, help="write JSONL to this path")
    parser.add_argument("--insert", action="store_true", help="insert directly into MongoDB")
    args = parser.parse_args()
    if args.count < 1 or (args.output is None and not args.insert) or (args.output and args.insert):
        parser.error("provide a positive --count and exactly one of --output or --insert")
    if args.output:
        with args.output.open("w", encoding="utf-8") as handle:
            for row in generate(args.count, args.seed):
                handle.write(json.dumps(row) + "\n")
        print(f"Wrote {args.count} synthetic logs to {args.output}")
        return
    with MongoClient(mongo_uri(), serverSelectionTimeoutMS=3000) as client:
        collection = client[mongo_database()].logs
        ensure_indexes(collection)
        batch = []
        for row in generate(args.count, args.seed):
            batch.append(normalize(row))
            if len(batch) == 1000:
                collection.insert_many(batch)
                batch.clear()
        if batch:
            collection.insert_many(batch)
        print(f"Inserted {args.count} synthetic logs")


if __name__ == "__main__":
    main()
