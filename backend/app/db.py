"""SQLite storage for scan records and their status events. Standard library only."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DATA_DIR", "/data")) / "assessments.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    scope_notes TEXT NOT NULL DEFAULT '',
    credentials_provided INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'created',   -- created | authorized | running | completed | failed
    authorized INTEGER NOT NULL DEFAULT 0,
    authorized_at TEXT,
    authorized_by TEXT,
    authorization_statement TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    report TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    at TEXT NOT NULL,
    agent TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}'
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)
        # A restart kills the background task, so anything still "running" can never finish.
        conn.execute("UPDATE scans SET status='failed', error='Backend restarted during the run', "
                     "finished_at=? WHERE status='running'", (now(),))


def create_scan(target_url: str, scope_notes: str, credentials_provided: bool) -> str:
    scan_id = uuid.uuid4().hex
    with connect() as conn:
        conn.execute("INSERT INTO scans (id, target_url, scope_notes, credentials_provided, created_at) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (scan_id, target_url, scope_notes, int(credentials_provided), now()))
    return scan_id


def get_scan(scan_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _to_dict(row) if row else None


def list_scans(limit: int = 30) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT id, target_url, status, created_at, finished_at FROM scans "
                            "ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def update_scan(scan_id: str, **fields) -> None:
    if "report" in fields and fields["report"] is not None:
        fields["report"] = json.dumps(fields["report"])
    columns = ", ".join(f"{name}=?" for name in fields)
    with connect() as conn:
        conn.execute(f"UPDATE scans SET {columns} WHERE id=?", (*fields.values(), scan_id))


def any_running() -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM scans WHERE status='running'").fetchone() is not None


def add_event(scan_id: str, agent: str, message: str, data: dict | None = None) -> None:
    with connect() as conn:
        conn.execute("INSERT INTO events (scan_id, at, agent, message, data) VALUES (?, ?, ?, ?, ?)",
                     (scan_id, now(), agent, message, json.dumps(data or {})))


def get_events(scan_id: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT at, agent, message, data FROM events WHERE scan_id=? ORDER BY id",
                            (scan_id,)).fetchall()
    return [dict(row) | {"data": json.loads(row["data"])} for row in rows]


def _to_dict(row: sqlite3.Row) -> dict:
    scan = dict(row)
    scan["authorized"] = bool(scan["authorized"])
    scan["credentials_provided"] = bool(scan["credentials_provided"])
    scan["report"] = json.loads(scan["report"]) if scan["report"] else None
    return scan
