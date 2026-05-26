import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "callshield.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row

    # Enable better concurrency
    conn.execute("PRAGMA busy_timeout = 30000")

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # High-performance tuning (large dataset optimized)
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-200000")
    conn.execute("PRAGMA mmap_size=30000000000")
    conn.execute("PRAGMA wal_autocheckpoint=1000")
    conn.execute("PRAGMA locking_mode=NORMAL")
    conn.execute("PRAGMA read_uncommitted=1")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_numbers_number ON raw_numbers(number)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_changed_numbers_queued_at ON changed_numbers(queued_at)")

    return conn


def now():
    return datetime.now(timezone.utc).isoformat()


def queue_changed_number(conn, number, reason):
    # Fast path: avoid useless writes
    existing = conn.execute(
        "SELECT reason FROM changed_numbers WHERE number = ?",
        (number,)
    ).fetchone()

    if existing and str(existing["reason"] or "") == reason:
        return
    conn.execute(
        """
        INSERT INTO changed_numbers(number, reason, queued_at)
        VALUES (?, ?, ?)
        ON CONFLICT(number) DO UPDATE SET
            reason = excluded.reason,
            queued_at = excluded.queued_at
        """,
        (number, reason, now())
    )


def mark_changed_processed(conn, number):
    conn.execute(
        """
        DELETE FROM changed_numbers
        WHERE number = ?
        """,
        (number,)
    )
