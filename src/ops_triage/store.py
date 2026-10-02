"""SQLite persistence: events, triage decisions and delivery attempts (the audit trail)."""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime

from .models import Event, Triage

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id TEXT PRIMARY KEY, source TEXT, fingerprint TEXT, title TEXT, body TEXT, service TEXT,
  reported_severity TEXT, labels TEXT, received_at TEXT, dup_count INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_events_fp ON events(fingerprint, received_at);
CREATE TABLE IF NOT EXISTS triage(
  event_id TEXT PRIMARY KEY, category TEXT, severity TEXT, team TEXT, confidence REAL, summary TEXT,
  reasoning TEXT, runbook TEXT, needs_human INTEGER, policy_notes TEXT, trace TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS deliveries(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, route TEXT, destination TEXT, status TEXT,
  attempts INTEGER, response_code INTEGER, error TEXT, payload TEXT, created_at TEXT);
"""
_WORDS = re.compile(r"[a-z]{3,}")


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def _tokens(title: str) -> set[str]:
    return set(_WORDS.findall(title.lower()))


class Store:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(SCHEMA)

    def _run(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._db.execute(sql, params)
            self._db.commit()
            return cur

    def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, params).fetchall()]

    # ---- events
    def add_event(self, e: Event) -> None:
        self._run("INSERT INTO events(id,source,fingerprint,title,body,service,reported_severity,labels,received_at)"
                  " VALUES(?,?,?,?,?,?,?,?,?)",
                  (e.id, e.source, e.fingerprint, e.title, e.body, e.service, e.reported_severity,
                   json.dumps(e.labels), _iso(e.received_at)))

    def find_recent_duplicate(self, fingerprint: str, since: datetime) -> str | None:
        rows = self._all("SELECT id FROM events WHERE fingerprint=? AND received_at>=? ORDER BY received_at DESC LIMIT 1",
                         (fingerprint, _iso(since)))
        return rows[0]["id"] if rows else None

    def bump_duplicate(self, event_id: str) -> None:
        self._run("UPDATE events SET dup_count = dup_count + 1 WHERE id=?", (event_id,))

    def similar(self, title: str, limit: int = 3, min_score: float = 0.4) -> list[dict]:
        """Past, already-triaged incidents with a similar title (Jaccard overlap on words)."""
        mine = _tokens(title)
        rows = self._all("SELECT e.title, t.category, t.severity, t.team FROM events e JOIN triage t ON t.event_id=e.id "
                         "ORDER BY e.received_at DESC LIMIT 500")
        scored = []
        for row in rows:
            theirs = _tokens(row["title"])
            union = mine | theirs
            score = len(mine & theirs) / len(union) if union else 0.0
            if score >= min_score:
                scored.append({**row, "similarity": round(score, 2)})
        return sorted(scored, key=lambda r: -r["similarity"])[:limit]

    # ---- triage
    def add_triage(self, event_id: str, t: Triage, trace: list[dict]) -> None:
        self._run("INSERT OR REPLACE INTO triage VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (event_id, t.category, t.severity, t.team, t.confidence, t.summary, t.reasoning, t.runbook,
                   int(t.needs_human), json.dumps(t.policy_notes), json.dumps(trace), _iso(datetime.now().astimezone())))

    # ---- deliveries
    def add_delivery(self, event_id: str, route: str, destination: str, status: str, attempts: int,
                     code: int | None, error: str | None, payload: dict) -> int:
        cur = self._run("INSERT INTO deliveries(event_id,route,destination,status,attempts,response_code,error,"
                        "payload,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (event_id, route, destination, status, attempts, code, error, json.dumps(payload),
                         _iso(datetime.now().astimezone())))
        return int(cur.lastrowid)

    def update_delivery(self, delivery_id: int, status: str, attempts: int, code: int | None, error: str | None) -> None:
        self._run("UPDATE deliveries SET status=?, attempts=attempts+?, response_code=?, error=? WHERE id=?",
                  (status, attempts, code, error, delivery_id))

    def deliveries(self, status: str | None = None, event_id: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM deliveries WHERE 1=1", []
        if status:
            sql += " AND status=?"
            params.append(status)
        if event_id:
            sql += " AND event_id=?"
            params.append(event_id)
        rows = self._all(sql + " ORDER BY id", tuple(params))
        for row in rows:
            row["payload"] = json.loads(row["payload"])
        return rows

    # ---- reporting
    def recent(self, limit: int = 50) -> list[dict]:
        rows = self._all("SELECT e.id, e.source, e.title, e.service, e.reported_severity, e.dup_count, e.received_at, "
                         "t.category, t.severity, t.team, t.confidence, t.summary, t.needs_human, t.policy_notes "
                         "FROM events e LEFT JOIN triage t ON t.event_id=e.id ORDER BY e.received_at DESC LIMIT ?", (limit,))
        for row in rows:
            row["needs_human"] = bool(row["needs_human"])
            row["policy_notes"] = json.loads(row["policy_notes"] or "[]")
        return rows

    def stats(self) -> dict:
        def counts(sql: str) -> dict:
            return {r["k"]: r["n"] for r in self._all(sql)}

        return {
            "events": self._all("SELECT COUNT(*) AS n FROM events")[0]["n"],
            "duplicates_suppressed": self._all("SELECT COALESCE(SUM(dup_count),0) AS n FROM events")[0]["n"],
            "needs_human": self._all("SELECT COUNT(*) AS n FROM triage WHERE needs_human=1")[0]["n"],
            "by_category": counts("SELECT category AS k, COUNT(*) AS n FROM triage GROUP BY category"),
            "by_severity": counts("SELECT severity AS k, COUNT(*) AS n FROM triage GROUP BY severity"),
            "deliveries": counts("SELECT status AS k, COUNT(*) AS n FROM deliveries GROUP BY status"),
        }
