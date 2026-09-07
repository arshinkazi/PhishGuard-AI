"""
db.py
-----
Minimal SQLite persistence layer for PhishGuard AI's scan history.

Kept deliberately dependency-free (stdlib sqlite3 only) so the whole
project runs with `pip install -r requirements.txt` and no external
database server -- appropriate for a lightweight, deployable demo.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent / "scans.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    prediction      TEXT    NOT NULL,       -- 'phishing' | 'legitimate'
    confidence      REAL    NOT NULL,       -- 0.0 - 1.0
    top_feature     TEXT,                   -- top SHAP feature name
    scanned_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Context-managed SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create the scans table if it does not already exist."""
    with get_connection() as conn:
        conn.execute(SCHEMA)
    logger.info("Database ready at %s", DB_PATH)


def save_scan(url: str, prediction: str, confidence: float, top_feature: str) -> int:
    """Insert one scan result and return its new row id."""
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (url, prediction, confidence, top_feature) "
            "VALUES (?, ?, ?, ?)",
            (url, prediction, confidence, top_feature),
        )
        return cursor.lastrowid


def get_history(limit: int = 25) -> list[dict]:
    """Return the most recent `limit` scans, newest first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, url, prediction, confidence, top_feature, scanned_at "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def clear_history() -> None:
    """Wipe all scan history (used by the 'Clear history' UI action)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM scans")
    logger.info("Scan history cleared.")
