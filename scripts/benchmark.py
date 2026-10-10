"""Measure indexed search against a natural collection scan without changing indexes."""

import argparse
import json
import sys
import time
from pathlib import Path

from pymongo import DESCENDING, MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import mongo_database, mongo_uri
from app.logs import ensure_indexes


def run(collection, query, hint, repeats):
    durations = []
    plan = collection.database.command(
        "explain",
        {"find": collection.name, "filter": query, "sort": {"timestamp": DESCENDING},
         "limit": 50, "hint": dict(hint) if isinstance(hint, list) else hint},
        verbosity="executionStats",
    )
    for _ in range(repeats):
        started = time.perf_counter()
        list(collection.find(query).sort("timestamp", DESCENDING).limit(50).hint(hint))
        durations.append((time.perf_counter() - started) * 1000)
    return {
        "hint": hint,
        "median_ms": sorted(durations)[len(durations) // 2],
        "execution_stats": plan.get("executionStats", {}),
        "winning_plan": plan.get("queryPlanner", {}).get("winningPlan", {}),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-ip", default="198.51.100.10")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path, help="save JSON results")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    with MongoClient(mongo_uri(), serverSelectionTimeoutMS=3000) as client:
        collection = client[mongo_database()].logs
        ensure_indexes(collection)
        query = {"source_ip": args.source_ip}
        report = {
            "collection_count": collection.estimated_document_count(),
            "query": query,
            "repeats": args.repeats,
            "collection_scan": run(collection, query, [("$natural", 1)], args.repeats),
            "indexed": run(collection, query, "source_ip_time", args.repeats),
        }
    rendered = json.dumps(report, indent=2, default=str)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Saved benchmark to {args.output}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
