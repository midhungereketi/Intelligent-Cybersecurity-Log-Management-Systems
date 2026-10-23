"""Create small, upload-ready synthetic log files for a CyberShield demo."""

from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "demo_logs"
FIELDS = (
    "timestamp", "source_ip", "destination_ip", "destination_port",
    "event_type", "severity", "message", "username", "log_source",
)


def event(when, source_ip, event_type, severity, message, *, port=443,
          username="", log_source="web-gateway", destination_ip="203.0.113.10"):
    return {
        "timestamp": when.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": port,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "username": username,
        "log_source": log_source,
    }


def main():
    rng = random.Random(20261024)
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=10)
    OUT.mkdir(exist_ok=True)

    normal = []
    users = ("alice", "bob", "charlie", "diana", "eva")
    for i in range(80):
        kind = rng.choices(
            ("LOGIN_SUCCESS", "ACCESS", "CONNECTION", "FIREWALL_BLOCK"),
            weights=(30, 35, 25, 10),
        )[0]
        username = rng.choice(users)
        normal.append(event(
            base + timedelta(seconds=i * 6),
            f"192.0.2.{10 + rng.randrange(35)}", kind,
            "MEDIUM" if kind == "FIREWALL_BLOCK" else "LOW",
            {
                "LOGIN_SUCCESS": f"Successful sign-in for {username}",
                "ACCESS": f"{username} accessed the reporting portal",
                "CONNECTION": "Allowed outbound HTTPS connection",
                "FIREWALL_BLOCK": "Firewall blocked an unsolicited inbound request",
            }[kind],
            username=username,
        ))
    with (OUT / "normal_activity.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(normal)

    suspicious = []
    auth_start = base + timedelta(minutes=2)
    for i in range(8):
        suspicious.append(event(
            auth_start + timedelta(seconds=i * 12), "198.51.100.10", "LOGIN_FAILED",
            "HIGH", f"Invalid password for admin (attempt {i + 1})",
            port=22, username="admin", log_source="ssh-auth",
        ))
    scan_start = base + timedelta(minutes=4)
    for i in range(25):
        port = 2000 + i
        suspicious.append(event(
            scan_start + timedelta(seconds=i), "198.51.100.20", "CONNECTION",
            "MEDIUM", f"Connection probe to TCP port {port}",
            port=port, log_source="network-sensor",
        ))
    volume_start = base + timedelta(minutes=6)
    for i in range(110):
        suspicious.append(event(
            volume_start + timedelta(milliseconds=i * 400),
            "198.51.100.30", "ACCESS", "LOW",
            f"High-frequency API request {i + 1}",
            username="api-client", log_source="api-gateway",
        ))
    with (OUT / "suspicious_activity.jsonl").open("w", encoding="utf-8") as handle:
        for row in suspicious:
            handle.write(json.dumps(row) + "\n")

    mixed = normal[:25] + suspicious[:8] + suspicious[8:33] + suspicious[33:]
    mixed.sort(key=lambda row: row["timestamp"])
    with (OUT / "full_demo.json").open("w", encoding="utf-8") as handle:
        json.dump(mixed, handle, indent=2)
        handle.write("\n")

    print(f"Created {len(normal)} CSV rows, {len(suspicious)} JSONL rows, "
          f"and {len(mixed)} JSON rows in {OUT}")


if __name__ == "__main__":
    main()
