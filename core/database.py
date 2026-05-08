"""
core/database.py
================
SQLite storage for scan sessions and findings.
"""
import sqlite3, json, os
from datetime import datetime
from typing import List, Optional
from core.scanner import Finding


class ScanDatabase:
    def __init__(self):
        db_dir = os.path.join(os.path.expanduser("~"), ".phantom_recon")
        os.makedirs(db_dir, exist_ok=True)
        self.db_path = os.path.join(db_dir, "scans.db")
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target     TEXT NOT NULL,
                started_at TEXT,
                ended_at   TEXT,
                modules    TEXT DEFAULT '[]',
                status     TEXT DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                category   TEXT,
                key_name   TEXT,
                value      TEXT,
                severity   TEXT DEFAULT 'info',
                timestamp  TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
        """)
        self._conn.commit()

    def new_session(self, target: str, modules: List[str]) -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = self._conn.execute(
            "INSERT INTO sessions (target, started_at, modules) VALUES (?,?,?)",
            (target, now, json.dumps(modules))
        )
        self._conn.commit()
        return cur.lastrowid

    def end_session(self, session_id: int):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._conn.execute(
            "UPDATE sessions SET ended_at=?, status='completed' WHERE id=?",
            (now, session_id)
        )
        self._conn.commit()

    def save_finding(self, session_id: int, f: Finding):
        self._conn.execute(
            "INSERT INTO findings (session_id,category,key_name,value,severity,timestamp) VALUES (?,?,?,?,?,?)",
            (session_id, f.category, f.key, f.value, f.severity, f.timestamp)
        )
        self._conn.commit()

    def list_sessions(self):
        return self._conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC"
        ).fetchall()

    def load_findings(self, session_id: int) -> List[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE session_id=? ORDER BY id",
            (session_id,)
        ).fetchall()
        results = []
        for r in rows:
            f = Finding(r["category"], r["key_name"], r["value"], r["severity"])
            f.timestamp = r["timestamp"]
            results.append(f)
        return results

    def export_json(self, session_id: int) -> str:
        sess = self._conn.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        findings = self.load_findings(session_id)
        return json.dumps({
            "session": dict(sess),
            "findings": [f.to_dict() for f in findings],
        }, ensure_ascii=False, indent=2)

    def count_findings(self, session_id: int) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE session_id=?",
            (session_id,)
        ).fetchone()[0]

    def close(self):
        self._conn.close()
