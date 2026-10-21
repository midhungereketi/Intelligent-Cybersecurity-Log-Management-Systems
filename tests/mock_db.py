"""In-memory database mock supporting PostgreSQL syntax, constraints, and transactions for tests."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any


class MockCursor:
    def __init__(self, db: MockDatabase, query: str, params: tuple | list | None):
        self.db = db
        self.query = query.strip()
        self.params = list(params) if params else []
        self._results = self._execute()

    def fetchone(self) -> dict[str, Any] | None:
        if self._results:
            return self._results.pop(0)
        return None

    def fetchall(self) -> list[dict[str, Any]]:
        res = list(self._results)
        self._results.clear()
        return res

    def _execute(self) -> list[dict[str, Any]]:
        q = self.query
        p = self.params

        # SELECT roles
        if "FROM roles" in q:
            if "WHERE role_name = %s" in q:
                return [r for r in self.db.roles if r["role_name"] == p[0]]
            if "WHERE role_id = %s" in q:
                return [r for r in self.db.roles if r["role_id"] == p[0]]
            return list(self.db.roles)

        # SELECT users
        if "FROM users u" in q or "FROM users" in q:
            if "WHERE u.username = %s OR u.email = %s" in q or "WHERE username = %s OR email = %s" in q:
                val = p[0]
                return [u for u in self.db.get_users_with_roles() if u["username"] == val or u["email"] == val]
            if "WHERE u.user_id = %s" in q or "WHERE user_id = %s" in q:
                uid = int(p[0])
                return [u for u in self.db.get_users_with_roles() if u["user_id"] == uid]
            # /api/users/assignable — only active users, return minimal fields
            if "WHERE u.is_active = TRUE" in q:
                active = [u for u in self.db.get_users_with_roles() if u.get("is_active")]
                active.sort(key=lambda u: u["username"])
                return active
            return self.db.get_users_with_roles()

        # INSERT users
        if q.startswith("INSERT INTO users"):
            username, email, password_hash, role_id, is_active = p[0], p[1], p[2], p[3], p[4]
            now_utc = datetime.now(timezone.utc)
            # check uniqueness
            if any(u["username"] == username for u in self.db.users):
                import psycopg
                raise psycopg.IntegrityError("username unique violation")
            if any(u["email"] == email for u in self.db.users):
                import psycopg
                raise psycopg.IntegrityError("email unique violation")
            new_id = self.db.next_user_id()
            user = {
                "user_id": new_id,
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "role_id": role_id,
                "is_active": is_active,
                "created_at": now_utc,
                "updated_at": now_utc,
                "last_login_at": None,
            }
            self.db.users.append(user)
            role = next((r for r in self.db.roles if r["role_id"] == role_id), None)
            res = dict(user)
            res["role_name"] = role["role_name"] if role else "ANALYST"
            return [res]

        # UPDATE users
        if q.startswith("UPDATE users"):
            if "SET last_login_at" in q:
                # UPDATE users SET last_login_at = %s, updated_at = %s WHERE user_id = %s
                last_login, updated_at, uid = p[0], p[1], int(p[2])
                for u in self.db.users:
                    if u["user_id"] == uid:
                        u["last_login_at"] = last_login
                        u["updated_at"] = updated_at
                return []
            else:
                # Dynamic update
                uid = int(p[-1])
                user = next((u for u in self.db.users if u["user_id"] == uid), None)
                if not user:
                    return []
                # parse params from query
                param_idx = 0
                if "email = %s" in q:
                    user["email"] = p[param_idx]
                    param_idx += 1
                if "role_id = %s" in q:
                    user["role_id"] = p[param_idx]
                    param_idx += 1
                if "is_active = %s" in q:
                    user["is_active"] = p[param_idx]
                    param_idx += 1
                if "password_hash = %s" in q:
                    user["password_hash"] = p[param_idx]
                    param_idx += 1
                if "updated_at = %s" in q:
                    user["updated_at"] = p[param_idx]
                return [user]

        # SELECT rules
        if "FROM rules" in q:
            if "WHERE rule_id = %s" in q:
                rid = int(p[0])
                return [r for r in self.db.rules if r["rule_id"] == rid]
            if "WHERE is_enabled = TRUE AND rule_id = ANY(%s)" in q:
                rids = set(p[0])
                return [r for r in self.db.rules if r["is_enabled"] and r["rule_id"] in rids]
            if "WHERE is_enabled = TRUE" in q:
                return [r for r in self.db.rules if r["is_enabled"]]
            return list(self.db.rules)

        # INSERT rules
        if q.startswith("INSERT INTO rules"):
            rule_name = p[0]
            if any(r["rule_name"] == rule_name for r in self.db.rules):
                import psycopg
                raise psycopg.IntegrityError("rule_name unique violation")
            new_id = self.db.next_rule_id()
            now_utc = datetime.now(timezone.utc)
            rule = {
                "rule_id": new_id,
                "rule_name": rule_name,
                "description": p[1],
                "rule_type": p[2],
                "threshold": int(p[3]),
                "time_window_seconds": int(p[4]),
                "severity": p[5],
                "is_enabled": bool(p[6]),
                "configuration": p[7] if isinstance(p[7], dict) else json.loads(p[7]) if isinstance(p[7], str) else {},
                "created_by": p[8],
                "created_at": now_utc,
                "updated_at": now_utc,
            }
            self.db.rules.append(rule)
            return [rule]

        # UPDATE rules
        if q.startswith("UPDATE rules"):
            rid = int(p[-1])
            rule = next((r for r in self.db.rules if r["rule_id"] == rid), None)
            if not rule:
                return []
            param_idx = 0
            if "rule_name = %s" in q:
                rule["rule_name"] = p[param_idx]
                param_idx += 1
            if "description = %s" in q:
                rule["description"] = p[param_idx]
                param_idx += 1
            if "rule_type = %s" in q:
                rule["rule_type"] = p[param_idx]
                param_idx += 1
            if "threshold = %s" in q:
                rule["threshold"] = int(p[param_idx])
                param_idx += 1
            if "time_window_seconds = %s" in q:
                rule["time_window_seconds"] = int(p[param_idx])
                param_idx += 1
            if "severity = %s" in q:
                rule["severity"] = p[param_idx]
                param_idx += 1
            if "is_enabled = %s" in q:
                rule["is_enabled"] = bool(p[param_idx])
                param_idx += 1
            if "configuration = %s" in q:
                cfg = p[param_idx]
                rule["configuration"] = cfg if isinstance(cfg, dict) else json.loads(cfg) if isinstance(cfg, str) else {}
                param_idx += 1
            if "updated_at = %s" in q:
                rule["updated_at"] = p[param_idx]
            return [rule]

        # SELECT threats
        if "FROM threats" in q:
            if "COUNT(*)" in q:
                filtered = self.db.filter_threats(q, p)
                return [{"total": len(filtered), "cnt": len(filtered)}]
            if "WHERE threat_id = %s" in q:
                tid = int(p[0])
                return [t for t in self.db.threats if t["threat_id"] == tid]
            if "WHERE source_ip = %s AND threat_type = %s" in q:
                sip, ttype = p[0], p[1]
                return [t for t in self.db.threats if t["source_ip"] == sip and t["threat_type"] == ttype]
            return self.db.filter_threats(q, p)

        # INSERT threats
        if q.startswith("INSERT INTO threats"):
            new_id = self.db.next_threat_id()
            now_utc = datetime.now(timezone.utc)
            threat = {
                "threat_id": new_id,
                "threat_type": p[0],
                "source_ip": p[1],
                "destination_ip": p[2],
                "severity": p[3],
                "description": p[4],
                "first_seen_at": p[5],
                "last_seen_at": p[6],
                "metadata": p[7] if isinstance(p[7], dict) else json.loads(p[7]) if isinstance(p[7], str) else {},
                "created_at": now_utc,
            }
            self.db.threats.append(threat)
            return [threat]

        # UPDATE threats
        if q.startswith("UPDATE threats"):
            tid = int(p[-1])
            threat = next((t for t in self.db.threats if t["threat_id"] == tid), None)
            if threat:
                threat["last_seen_at"] = max(threat["last_seen_at"], p[0])
                threat["severity"] = p[1]
                threat["description"] = p[2]
                meta = p[3]
                threat["metadata"] = meta if isinstance(meta, dict) else json.loads(meta) if isinstance(meta, str) else {}
            return []

        # SELECT alerts
        if "FROM alerts" in q:
            if "GROUP BY status, severity" in q:
                counts: dict[tuple[str, str], int] = {}
                for a in self.db.alerts:
                    key = (a["status"], a["severity"])
                    counts[key] = counts.get(key, 0) + 1
                return [{"status": k[0], "severity": k[1], "cnt": v} for k, v in counts.items()]
            if "COUNT(*)" in q:
                filtered = self.db.filter_alerts(q, p)
                return [{"total": len(filtered)}]
            if "WHERE deduplication_key = %s AND status != 'RESOLVED'" in q:
                key = p[0]
                matches = [a for a in self.db.alerts if a["deduplication_key"] == key and a["status"] != "RESOLVED"]
                return matches[:1]
            if "WHERE a.alert_id = %s" in q or "WHERE alert_id = %s" in q:
                aid = int(p[0])
                return [a for a in self.db.get_alerts_with_rules() if a["alert_id"] == aid]
            if "WHERE a.threat_id = %s" in q:
                tid = int(p[0])
                return [a for a in self.db.get_alerts_with_rules() if a.get("threat_id") == tid]
            return self.db.filter_alerts(q, p)

        # INSERT alerts
        if q.startswith("INSERT INTO alerts"):
            new_id = self.db.next_alert_id()
            now_utc = datetime.now(timezone.utc)
            evidence_val = p[7]
            evidence = evidence_val if isinstance(evidence_val, list) else json.loads(evidence_val) if isinstance(evidence_val, str) else []
            alert = {
                "alert_id": new_id,
                "rule_id": int(p[0]),
                "threat_id": int(p[1]) if p[1] is not None else None,
                "source_ip": p[2],
                "severity": p[3],
                "title": p[4],
                "description": p[5],
                "status": "OPEN",
                "deduplication_key": p[6],
                "evidence": evidence,
                "first_seen_at": p[8],
                "last_seen_at": p[9],
                "occurrence_count": int(p[10]),
                "created_at": p[11] if len(p) > 11 else now_utc,
                "updated_at": p[12] if len(p) > 12 else now_utc,
            }
            # Uniqueness check for active alerts
            if any(a["deduplication_key"] == alert["deduplication_key"] and a["status"] != "RESOLVED" for a in self.db.alerts):
                import psycopg
                raise psycopg.IntegrityError("active alert deduplication_key unique violation")
            self.db.alerts.append(alert)
            return [alert]

        # UPDATE alerts
        if q.startswith("UPDATE alerts"):
            aid = int(p[-1])
            alert = next((a for a in self.db.alerts if a["alert_id"] == aid), None)
            if not alert:
                return []
            if "SET status = 'ACKNOWLEDGED'" in q:
                alert["status"] = "ACKNOWLEDGED"
                alert["updated_at"] = p[0]
            elif "SET status = 'RESOLVED'" in q:
                alert["status"] = "RESOLVED"
                alert["updated_at"] = p[0]
            elif "SET last_seen_at = %s" in q:
                alert["last_seen_at"] = p[0]
                alert["occurrence_count"] += int(p[1])
                ev = p[2]
                alert["evidence"] = ev if isinstance(ev, list) else json.loads(ev) if isinstance(ev, str) else []
                if p[3] is not None:
                    alert["threat_id"] = p[3]
                alert["updated_at"] = p[4]
            return [alert]

        # SELECT processed_detection_events
        if "FROM processed_detection_events" in q:
            rid = int(p[0])
            eids = set(p[1])
            found = [
                {"event_id": ev_id}
                for (ev_id, r_id) in self.db.processed_events
                if r_id == rid and ev_id in eids
            ]
            return found

        # INSERT processed_detection_events
        if q.startswith("INSERT INTO processed_detection_events"):
            eid, rid, aid = p[0], int(p[1]), p[2]
            self.db.processed_events.add((eid, rid))
            return []

        # devices & sources
        if "FROM device" in q:
            return list(self.db.devices)
        if q.startswith("INSERT INTO device"):
            new_id = len(self.db.devices) + 1
            row = {
                "device_id": new_id,
                "device_name": p[0],
                "ip_address": p[1],
                "mac_address": p[2],
                "device_type": p[3],
                "operating_system": p[4],
                "location": p[5],
                "status": p[6],
            }
            self.db.devices.append(row)
            return [row]
        if "FROM log_source" in q:
            if "WHERE device_id = %s" in q:
                return [s for s in self.db.sources if s["device_id"] == int(p[0])]
            return list(self.db.sources)
        if q.startswith("INSERT INTO log_source"):
            new_id = len(self.db.sources) + 1
            row = {
                "source_id": new_id,
                "source_name": p[0],
                "source_type": p[1],
                "ip_address": p[2],
                "protocol": p[3],
                "device_id": int(p[4]),
            }
            self.db.sources.append(row)
            return [row]

        # SELECT incidents
        if "FROM incidents" in q:
            if "GROUP BY status, severity" in q:
                counts_inc: dict[tuple[str, str], int] = {}
                for inc_item in self.db.incidents:
                    k_inc = (inc_item["status"], inc_item["severity"])
                    counts_inc[k_inc] = counts_inc.get(k_inc, 0) + 1
                return [{"status": k[0], "severity": k[1], "cnt": v} for k, v in counts_inc.items()]
            if "COUNT(*)" in q:
                filtered_inc = self.db.filter_incidents(q, p)
                return [{"total": len(filtered_inc)}]
            if "WHERE i.incident_id = %s" in q or "WHERE incident_id = %s" in q:
                iid = int(p[0])
                return [i for i in self.db.get_incidents_with_users() if i["incident_id"] == iid]
            return self.db.filter_incidents(q, p)

        # INSERT incidents
        if q.startswith("INSERT INTO incidents"):
            new_id = self.db.next_incident_id()
            now_utc = datetime.now(timezone.utc)
            tags_val = p[8]
            tags = tags_val if isinstance(tags_val, list) else json.loads(tags_val) if isinstance(tags_val, str) else []
            ev_val = p[9]
            evidence = ev_val if isinstance(ev_val, list) else json.loads(ev_val) if isinstance(ev_val, str) else []
            inc = {
                "incident_id": new_id,
                "title": p[0],
                "description": p[1],
                "severity": p[2],
                "status": p[3],
                "assigned_to": int(p[4]) if p[4] is not None else None,
                "created_by": int(p[5]) if p[5] is not None else None,
                "alert_id": int(p[6]) if p[6] is not None else None,
                "source_ip": p[7],
                "tags": tags,
                "evidence": evidence,
                "created_at": p[10] if len(p) > 10 else now_utc,
                "updated_at": p[11] if len(p) > 11 else now_utc,
                "resolved_at": None,
            }
            self.db.incidents.append(inc)
            return [inc]

        # UPDATE incidents
        if q.startswith("UPDATE incidents"):
            iid = int(p[-1])
            inc = next((i for i in self.db.incidents if i["incident_id"] == iid), None)
            if not inc:
                return []
            param_idx = 0
            if "title = %s" in q:
                inc["title"] = p[param_idx]
                param_idx += 1
            if "description = %s" in q:
                inc["description"] = p[param_idx]
                param_idx += 1
            if "severity = %s" in q:
                inc["severity"] = p[param_idx]
                param_idx += 1
            if "status = %s" in q:
                inc["status"] = p[param_idx]
                param_idx += 1
            if "resolved_at = %s" in q:
                inc["resolved_at"] = p[param_idx]
                param_idx += 1
            if "assigned_to = %s" in q:
                inc["assigned_to"] = int(p[param_idx]) if p[param_idx] is not None else None
                param_idx += 1
            if "tags = %s" in q:
                tg = p[param_idx]
                inc["tags"] = tg if isinstance(tg, list) else json.loads(tg) if isinstance(tg, str) else []
                param_idx += 1
            if "updated_at = %s" in q:
                inc["updated_at"] = p[param_idx]
            return [inc]

        # SELECT actions
        if "FROM actions" in q:
            if "WHERE a.incident_id = %s" in q or "WHERE incident_id = %s" in q:
                iid = int(p[0])
                acts = [a for a in self.db.actions if a["incident_id"] == iid]
                res_act = []
                for a in acts:
                    d = dict(a)
                    user = next((u for u in self.db.users if u["user_id"] == a.get("performed_by")), None)
                    d["performed_by_username"] = user["username"] if user else None
                    res_act.append(d)
                res_act.sort(key=lambda x: x["performed_at"])
                return res_act
            return list(self.db.actions)

        # INSERT actions
        if q.startswith("INSERT INTO actions"):
            new_id = self.db.next_action_id()
            now_utc = datetime.now(timezone.utc)
            meta_val = p[4]
            metadata = meta_val if isinstance(meta_val, dict) else json.loads(meta_val) if isinstance(meta_val, str) else {}
            act = {
                "action_id": new_id,
                "incident_id": int(p[0]),
                "action_type": p[1],
                "action_details": p[2],
                "performed_by": int(p[3]) if p[3] is not None else None,
                "metadata": metadata,
                "performed_at": p[5] if len(p) > 5 else now_utc,
            }
            self.db.actions.append(act)
            return [act]

        # SELECT incident_alerts
        if "FROM incident_alerts" in q:
            if "WHERE ia.incident_id = %s" in q or "WHERE incident_id = %s" in q:
                iid = int(p[0])
                links = [ia for ia in self.db.incident_alerts if ia["incident_id"] == iid]
                res_alerts = []
                for link in links:
                    aid = link["alert_id"]
                    al = next((a for a in self.db.get_alerts_with_rules() if a["alert_id"] == aid), None)
                    if al:
                        d = dict(al)
                        d["linked_at"] = link["linked_at"]
                        res_alerts.append(d)
                return res_alerts
            if "WHERE incident_id = %s AND alert_id = %s" in q:
                iid, aid = int(p[0]), int(p[1])
                return [ia for ia in self.db.incident_alerts if ia["incident_id"] == iid and ia["alert_id"] == aid]
            return list(self.db.incident_alerts)

        # INSERT incident_alerts
        if q.startswith("INSERT INTO incident_alerts"):
            iid, aid, linked_at = int(p[0]), int(p[1]), p[2]
            self.db.incident_alerts.append({"incident_id": iid, "alert_id": aid, "linked_at": linked_at})
            return []

        return []


class MockConnection:
    def __init__(self, db: MockDatabase):
        self.db = db
        self.closed = False

    def execute(self, query: str, params: tuple | list | None = None) -> MockCursor:
        return MockCursor(self.db, query, params)

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class MockDatabase:
    def __init__(self):
        self._user_counter = 100
        self._rule_counter = 10
        self._threat_counter = 200
        self._alert_counter = 300

        self.roles = [
            {"role_id": 1, "role_name": "ADMIN", "description": "Administrator", "created_at": datetime.now(timezone.utc)},
            {"role_id": 2, "role_name": "ANALYST", "description": "Security Analyst", "created_at": datetime.now(timezone.utc)},
        ]
        self.users = []
        self.rules = [
            {
                "rule_id": 1,
                "rule_name": "Repeated Failed Logins",
                "description": "Failed authentication threshold",
                "rule_type": "FAILED_LOGINS",
                "threshold": 5,
                "time_window_seconds": 300,
                "severity": "HIGH",
                "is_enabled": True,
                "configuration": {"target_event": "LOGIN_FAILED"},
                "created_by": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
            {
                "rule_id": 2,
                "rule_name": "Possible Port Scan",
                "description": "Port scanning threshold",
                "rule_type": "PORT_SCAN",
                "threshold": 20,
                "time_window_seconds": 60,
                "severity": "HIGH",
                "is_enabled": True,
                "configuration": {"target_event": "CONNECTION"},
                "created_by": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
            {
                "rule_id": 3,
                "rule_name": "Excessive Activity from Single IP",
                "description": "Excessive volume threshold",
                "rule_type": "EXCESSIVE_ACTIVITY",
                "threshold": 100,
                "time_window_seconds": 60,
                "severity": "MEDIUM",
                "is_enabled": True,
                "configuration": {},
                "created_by": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
        ]
        self.threats = []
        self.alerts = []
        self.processed_events: set[tuple[str, int]] = set()
        self.devices = []
        self.sources = []
        self.incidents = []
        self.actions = []
        self.incident_alerts = []
        self._incident_counter = 400
        self._action_counter = 500

    def get_connection(self) -> MockConnection:
        return MockConnection(self)

    def next_user_id(self) -> int:
        self._user_counter += 1
        return self._user_counter

    def next_rule_id(self) -> int:
        self._rule_counter += 1
        return self._rule_counter

    def next_threat_id(self) -> int:
        self._threat_counter += 1
        return self._threat_counter

    def next_alert_id(self) -> int:
        self._alert_counter += 1
        return self._alert_counter

    def next_incident_id(self) -> int:
        self._incident_counter += 1
        return self._incident_counter

    def next_action_id(self) -> int:
        self._action_counter += 1
        return self._action_counter

    def get_users_with_roles(self) -> list[dict[str, Any]]:
        res = []
        for u in self.users:
            role = next((r for r in self.roles if r["role_id"] == u["role_id"]), None)
            d = dict(u)
            d["role_name"] = role["role_name"] if role else "ANALYST"
            res.append(d)
        return res

    def get_alerts_with_rules(self) -> list[dict[str, Any]]:
        res = []
        for a in self.alerts:
            rule = next((r for r in self.rules if r["rule_id"] == a["rule_id"]), None)
            d = dict(a)
            d["rule_name"] = rule["rule_name"] if rule else None
            res.append(d)
        return res

    def get_incidents_with_users(self) -> list[dict[str, Any]]:
        res = []
        for inc in self.incidents:
            d = dict(inc)
            assignee = next((u for u in self.users if u["user_id"] == inc.get("assigned_to")), None)
            creator = next((u for u in self.users if u["user_id"] == inc.get("created_by")), None)
            d["assigned_to_username"] = assignee["username"] if assignee else None
            d["created_by_username"] = creator["username"] if creator else None
            res.append(d)
        return res

    def filter_threats(self, query: str, params: list[Any]) -> list[dict[str, Any]]:
        results = list(self.threats)
        # Apply filters if in params
        for p in params:
            if isinstance(p, str) and p in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                results = [t for t in results if t["severity"] == p]
            elif isinstance(p, str) and any(p == t.get("source_ip") for t in results):
                results = [t for t in results if t.get("source_ip") == p]
            elif isinstance(p, str) and any(p == t.get("threat_type") for t in results):
                results = [t for t in results if t.get("threat_type") == p]
        results.sort(key=lambda t: t["last_seen_at"], reverse=True)
        # check for LIMIT and OFFSET in params
        limit = 50
        offset = 0
        if "LIMIT %s OFFSET %s" in query:
            limit = int(params[-2])
            offset = int(params[-1])
            results = results[offset : offset + limit]
        return results

    def filter_alerts(self, query: str, params: list[Any]) -> list[dict[str, Any]]:
        alerts = self.get_alerts_with_rules()
        for p in params:
            if isinstance(p, str) and p in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
                alerts = [a for a in alerts if a["status"] == p]
            elif isinstance(p, str) and p in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                alerts = [a for a in alerts if a["severity"] == p]
            elif isinstance(p, int) and any(a["rule_id"] == p for a in alerts):
                alerts = [a for a in alerts if a["rule_id"] == p]
            elif isinstance(p, str) and any(a.get("source_ip") == p for a in alerts):
                alerts = [a for a in alerts if a.get("source_ip") == p]
        alerts.sort(key=lambda a: a["created_at"], reverse=True)
        if "LIMIT %s OFFSET %s" in query:
            limit = int(params[-2])
            offset = int(params[-1])
            alerts = alerts[offset : offset + limit]
        return alerts

    def filter_incidents(self, query: str, params: list[Any]) -> list[dict[str, Any]]:
        incidents = self.get_incidents_with_users()
        for p in params:
            if isinstance(p, str) and p in {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}:
                incidents = [i for i in incidents if i["status"] == p]
            elif isinstance(p, str) and p in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                incidents = [i for i in incidents if i["severity"] == p]
            elif isinstance(p, int):
                if "assigned_to = %s" in query:
                    incidents = [i for i in incidents if i.get("assigned_to") == p]
                elif "alert_id = %s" in query:
                    incidents = [
                        i for i in incidents
                        if i.get("alert_id") == p or any(ia["incident_id"] == i["incident_id"] and ia["alert_id"] == p for ia in self.incident_alerts)
                    ]
        incidents.sort(key=lambda a: a["created_at"], reverse=True)
        if "LIMIT %s OFFSET %s" in query:
            limit = int(params[-2])
            offset = int(params[-1])
            incidents = incidents[offset : offset + limit]
        return incidents
