from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_DB_BYTES = 128 * 1024 * 1024
MAX_RECORDS = 10000
RETRY_LIMIT = 3
RETRY_DELAY_SECONDS = 30


@dataclass(frozen=True)
class DeliveryLease:
    delivery_id: str
    run_id: int
    attempt: int
    state: str
    terminal: bool
    subject_json: str | None
    policy_id: str | None
    target_url: str | None


class DeliveryStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = self._validate_path(db_path)
        self._init_db()

    @staticmethod
    def _validate_path(path: Path) -> Path:
        if not path.is_absolute():
            raise ValueError("delivery database path must be absolute")
        parent = path.parent.resolve(strict=True)
        st = parent.stat()
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("delivery database parent must be a directory")
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError("delivery database parent must be owner-controlled and not group/world writable")
        if path.is_symlink():
            raise ValueError("delivery database must not be a symlink")
        if path.exists():
            fst = path.stat()
            if not stat.S_ISREG(fst.st_mode):
                raise ValueError("delivery database must be a regular file")
            if fst.st_uid != os.geteuid() or fst.st_mode & 0o022:
                raise ValueError("delivery database must be owner-controlled and not group/world writable")
            if fst.st_size > MAX_DB_BYTES:
                raise ValueError("delivery database exceeds configured bound")
        resolved = parent / path.name
        if not resolved.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(resolved, flags, 0o600)
            os.close(fd)
        created = resolved.stat(follow_symlinks=False)
        if not stat.S_ISREG(created.st_mode) or created.st_uid != os.geteuid():
            raise ValueError("delivery database must remain an owner-controlled regular file")
        os.chmod(resolved, 0o600)
        return resolved

    def _connect(self) -> sqlite3.Connection:
        current = self._db_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_mode & 0o077
            or current.st_size > MAX_DB_BYTES
        ):
            raise RuntimeError("delivery database ownership, mode, or size changed")
        conn = sqlite3.connect(self._db_path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    run_id INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    last_attempt_epoch INTEGER NOT NULL,
                    subject_json TEXT,
                    policy_id TEXT,
                    target_url TEXT,
                    terminal INTEGER NOT NULL DEFAULT 0,
                    publication_started INTEGER NOT NULL DEFAULT 0,
                    publication_observed INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    created_epoch INTEGER NOT NULL,
                    updated_epoch INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS deliveries_updated_idx ON deliveries(updated_epoch);
                """
            )

    def acquire(self, *, delivery_id: str, run_id: int) -> DeliveryLease:
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                count = conn.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0]
                if count >= MAX_RECORDS:
                    conn.execute("ROLLBACK")
                    raise RuntimeError("delivery store record bound reached")
                conn.execute(
                    """
                    INSERT INTO deliveries(
                        delivery_id, run_id, state, attempt, last_attempt_epoch,
                        created_epoch, updated_epoch
                    ) VALUES (?, ?, 'PROCESSING', 1, ?, ?, ?)
                    """,
                    (delivery_id, run_id, now, now, now),
                )
                conn.execute("COMMIT")
                os.chmod(self._db_path, 0o600)
                return DeliveryLease(delivery_id, run_id, 1, "PROCESSING", False, None, None, None)

            if int(row["run_id"]) != run_id:
                conn.execute("ROLLBACK")
                raise RuntimeError("webhook delivery id was reused for a different workflow run")
            if int(row["terminal"]) == 1:
                conn.execute("COMMIT")
                return self._lease(row)
            if int(row["publication_started"]) == 1:
                conn.execute("COMMIT")
                return self._lease(row)
            if row["state"] != "RETRYABLE":
                conn.execute("COMMIT")
                return self._lease(row)
            attempt = int(row["attempt"])
            last_attempt = int(row["last_attempt_epoch"])
            if attempt >= RETRY_LIMIT:
                conn.execute(
                    """
                    UPDATE deliveries
                    SET state='BLOCKED', terminal=1, error_code='retry_budget_exhausted',
                        updated_epoch=?
                    WHERE delivery_id=?
                    """,
                    (now, delivery_id),
                )
                exhausted = conn.execute(
                    "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
                ).fetchone()
                conn.execute("COMMIT")
                return self._lease(exhausted)
            if now - last_attempt < RETRY_DELAY_SECONDS:
                conn.execute("COMMIT")
                return self._lease(row)
            next_attempt = attempt + 1
            conn.execute(
                """
                UPDATE deliveries
                SET state='PROCESSING', attempt=?, last_attempt_epoch=?, updated_epoch=?, error_code=NULL
                WHERE delivery_id=?
                """,
                (next_attempt, now, now, delivery_id),
            )
            row2 = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            conn.execute("COMMIT")
            return self._lease(row2)

    def bind_subject(
        self,
        *,
        delivery_id: str,
        subject: dict[str, Any],
        policy_id: str,
        target_url: str,
    ) -> None:
        rendered = json.dumps(subject, separators=(",", ":"), sort_keys=True)
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._require_mutable(conn, delivery_id)
            if row["state"] != "PROCESSING":
                conn.execute("ROLLBACK")
                raise RuntimeError("delivery is not in PROCESSING state")
            conn.execute(
                """
                UPDATE deliveries
                SET subject_json=?, policy_id=?, target_url=?, updated_epoch=?
                WHERE delivery_id=?
                """,
                (rendered, policy_id, target_url, now, delivery_id),
            )
            conn.execute("COMMIT")

    def mark_retryable(self, *, delivery_id: str, error_code: str) -> None:
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._require_mutable(conn, delivery_id)
            if int(row["publication_started"]) == 1:
                conn.execute("ROLLBACK")
                raise RuntimeError("cannot retry after publication started")
            conn.execute(
                "UPDATE deliveries SET state='RETRYABLE', error_code=?, updated_epoch=? WHERE delivery_id=?",
                (error_code[:128], now, delivery_id),
            )
            conn.execute("COMMIT")

    def mark_blocked(self, *, delivery_id: str, error_code: str) -> None:
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._require_mutable(conn, delivery_id)
            if int(row["publication_started"]) == 1:
                conn.execute("ROLLBACK")
                raise RuntimeError("cannot mark blocked after publication started")
            conn.execute(
                """
                UPDATE deliveries
                SET state='BLOCKED', terminal=1, error_code=?, updated_epoch=?
                WHERE delivery_id=?
                """,
                (error_code[:128], now, delivery_id),
            )
            conn.execute("COMMIT")

    def begin_publication(self, *, delivery_id: str) -> DeliveryLease:
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._require_mutable(conn, delivery_id)
            if (
                row["state"] != "PROCESSING"
                or row["subject_json"] is None
                or row["policy_id"] is None
            ):
                conn.execute("ROLLBACK")
                raise RuntimeError("delivery lacks bound subject/policy before publication")
            conn.execute(
                """
                UPDATE deliveries
                SET state='PUBLISHING', publication_started=1, updated_epoch=?
                WHERE delivery_id=?
                """,
                (now, delivery_id),
            )
            row2 = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            conn.execute("COMMIT")
            return self._lease(row2)

    def complete_publication(self, *, delivery_id: str) -> None:
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            if row is None or int(row["publication_started"]) != 1:
                conn.execute("ROLLBACK")
                raise RuntimeError("publication completion lacks durable publication intent")
            conn.execute(
                """
                UPDATE deliveries
                SET state='SUCCESS', terminal=1, publication_observed=1, updated_epoch=?
                WHERE delivery_id=?
                """,
                (now, delivery_id),
            )
            conn.execute("COMMIT")

    def load(self, delivery_id: str) -> DeliveryLease | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            return None if row is None else self._lease(row)

    @staticmethod
    def _lease(row: sqlite3.Row) -> DeliveryLease:
        return DeliveryLease(
            delivery_id=str(row["delivery_id"]),
            run_id=int(row["run_id"]),
            attempt=int(row["attempt"]),
            state=str(row["state"]),
            terminal=bool(row["terminal"]),
            subject_json=row["subject_json"],
            policy_id=row["policy_id"],
            target_url=row["target_url"],
        )

    @staticmethod
    def _require_mutable(conn: sqlite3.Connection, delivery_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("delivery record does not exist")
        if int(row["terminal"]) == 1:
            raise RuntimeError("delivery is already terminal")
        return row
