"""Persistence for the single operator account. Tests use the memory store."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from .operator_auth import as_utc


def _test_mode() -> bool:
    return os.getenv("SIEM_TEST_MODE", "").strip().lower() in {"1", "true", "yes"}


class MemoryStore:
    def __init__(self):
        self.secrets: dict[str, str] = {}
        self.passkeys: dict[str, dict] = {}
        self.recovery: dict[str, datetime | None] = {}
        self.sessions: dict[str, dict] = {}
        self.challenges: dict[str, dict] = {}
        self.attempts: list[tuple] = []
        self.audit_rows: list[tuple] = []

    def get_secret(self, name: str) -> str | None:
        return self.secrets.get(name)

    def put_secret(self, name: str, value: str) -> None:
        self.secrets[name] = value

    def delete_secret(self, name: str) -> None:
        self.secrets.pop(name, None)

    def add_passkey(self, credential_id: str, public_key: str, sign_count: int) -> None:
        self.passkeys[credential_id] = {
            "credential_id": credential_id,
            "public_key": public_key,
            "sign_count": int(sign_count),
        }

    def list_passkeys(self) -> list[dict]:
        return list(self.passkeys.values())

    def get_passkey(self, credential_id: str) -> dict | None:
        row = self.passkeys.get(credential_id)
        return dict(row) if row else None

    def set_sign_count(self, credential_id: str, count: int) -> None:
        if credential_id in self.passkeys:
            self.passkeys[credential_id]["sign_count"] = int(count)

    def replace_recovery(self, hashes: list[str]) -> None:
        self.recovery = {item: None for item in hashes}

    def consume_recovery(self, code_hash: str) -> bool:
        if code_hash not in self.recovery or self.recovery[code_hash] is not None:
            return False
        self.recovery[code_hash] = datetime.now(timezone.utc)
        return True

    def put_challenge(self, row_id: str, kind: str, challenge: str, payload: str, expires_at: datetime) -> None:
        self._drop_expired_challenges()
        self.challenges[row_id] = {
            "id": row_id,
            "kind": kind,
            "challenge": challenge,
            "payload": payload,
            "expires_at": expires_at,
        }

    def pop_challenge(self, row_id: str) -> dict | None:
        row = self.challenges.pop(row_id, None)
        if not row:
            return None
        if as_utc(row["expires_at"]) <= datetime.now(timezone.utc):
            return None
        return row

    def put_session(self, row: dict) -> None:
        self.sessions[row["token_hash"]] = dict(row)

    def get_session(self, token_hash: str) -> dict | None:
        row = self.sessions.get(token_hash)
        return dict(row) if row else None

    def touch_session(self, token_hash: str, seen: datetime, flags: str | None = None, limited: bool | None = None) -> None:
        row = self.sessions.get(token_hash)
        if not row:
            return
        row["last_seen"] = seen
        if flags is not None:
            row["flags"] = flags
        if limited is not None:
            row["limited"] = limited

    def delete_session(self, token_hash: str) -> None:
        self.sessions.pop(token_hash, None)

    def delete_all_sessions(self) -> None:
        self.sessions.clear()

    def record_attempt(self, ip: str, action: str, success: bool) -> None:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=2)
        self.attempts = [item for item in self.attempts if item[3] >= cutoff]
        self.attempts.append((ip, action, success, now))

    def failure_count(self, ip: str, action: str, window_seconds: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return sum(
            1 for item_ip, item_action, success, at in self.attempts
            if item_ip == ip and item_action == action and not success and at >= cutoff
        )

    def clear_failures(self, ip: str, action: str) -> None:
        self.attempts = [
            item for item in self.attempts
            if not (item[0] == ip and item[1] == action and not item[2])
        ]

    def audit(self, ip: str, action: str, detail: str) -> None:
        self.audit_rows.append((datetime.now(timezone.utc), ip, action, detail[:300]))

    def _drop_expired_challenges(self) -> None:
        now = datetime.now(timezone.utc)
        self.challenges = {
            key: row for key, row in self.challenges.items()
            if as_utc(row["expires_at"]) > now
        }


class PostgresStore:
    def _run(self, fn, write: bool = True):
        from psycopg2 import extras
        from .database_pg import get_conn, return_conn

        conn = get_conn()
        try:
            cursor = conn.cursor(cursor_factory=extras.DictCursor)
            result = fn(cursor)
            if write:
                conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            return_conn(conn)

    def get_secret(self, name: str) -> str | None:
        def fn(cursor):
            cursor.execute("SELECT value FROM operator_secrets WHERE name = %s", (name,))
            row = cursor.fetchone()
            return row["value"] if row else None
        return self._run(fn, write=False)

    def put_secret(self, name: str, value: str) -> None:
        def fn(cursor):
            cursor.execute(
                """
                INSERT INTO operator_secrets (name, value, updated_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP
                """,
                (name, value),
            )
        self._run(fn)

    def delete_secret(self, name: str) -> None:
        def fn(cursor):
            cursor.execute("DELETE FROM operator_secrets WHERE name = %s", (name,))
        self._run(fn)

    def add_passkey(self, credential_id: str, public_key: str, sign_count: int) -> None:
        def fn(cursor):
            cursor.execute(
                """
                INSERT INTO operator_passkeys (credential_id, public_key, sign_count)
                VALUES (%s, %s, %s)
                ON CONFLICT (credential_id) DO UPDATE SET public_key = EXCLUDED.public_key, sign_count = EXCLUDED.sign_count
                """,
                (credential_id, public_key, int(sign_count)),
            )
        self._run(fn)

    def list_passkeys(self) -> list[dict]:
        def fn(cursor):
            cursor.execute("SELECT credential_id, public_key, sign_count FROM operator_passkeys ORDER BY created_at")
            return [dict(row) for row in cursor.fetchall()]
        return self._run(fn, write=False)

    def get_passkey(self, credential_id: str) -> dict | None:
        def fn(cursor):
            cursor.execute(
                "SELECT credential_id, public_key, sign_count FROM operator_passkeys WHERE credential_id = %s",
                (credential_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        return self._run(fn, write=False)

    def set_sign_count(self, credential_id: str, count: int) -> None:
        def fn(cursor):
            cursor.execute(
                "UPDATE operator_passkeys SET sign_count = %s WHERE credential_id = %s",
                (int(count), credential_id),
            )
        self._run(fn)

    def replace_recovery(self, hashes: list[str]) -> None:
        def fn(cursor):
            cursor.execute("DELETE FROM operator_recovery")
            for code_hash in hashes:
                cursor.execute(
                    "INSERT INTO operator_recovery (code_hash) VALUES (%s)",
                    (code_hash,),
                )
        self._run(fn)

    def consume_recovery(self, code_hash: str) -> bool:
        def fn(cursor):
            cursor.execute(
                """
                UPDATE operator_recovery SET used_at = CURRENT_TIMESTAMP
                WHERE code_hash = %s AND used_at IS NULL
                """,
                (code_hash,),
            )
            return cursor.rowcount == 1
        return self._run(fn)

    def put_challenge(self, row_id: str, kind: str, challenge: str, payload: str, expires_at: datetime) -> None:
        def fn(cursor):
            cursor.execute("DELETE FROM auth_challenges WHERE expires_at <= CURRENT_TIMESTAMP")
            cursor.execute(
                """
                INSERT INTO auth_challenges (id, kind, challenge, payload, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, challenge = EXCLUDED.challenge,
                    payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at
                """,
                (row_id, kind, challenge, payload, expires_at),
            )
        self._run(fn)

    def pop_challenge(self, row_id: str) -> dict | None:
        def fn(cursor):
            cursor.execute(
                "DELETE FROM auth_challenges WHERE id = %s RETURNING id, kind, challenge, payload, expires_at",
                (row_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            if as_utc(item["expires_at"]) <= datetime.now(timezone.utc):
                return None
            return item
        return self._run(fn)

    def put_session(self, row: dict) -> None:
        def fn(cursor):
            cursor.execute(
                """
                INSERT INTO operator_sessions
                    (token_hash, created_at, last_seen, expires_at, client_ip, user_agent, limited, flags)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row["token_hash"], row["created_at"], row["last_seen"], row["expires_at"],
                    row["client_ip"], row.get("user_agent") or "", bool(row.get("limited")), row.get("flags") or "",
                ),
            )
        self._run(fn)

    def get_session(self, token_hash: str) -> dict | None:
        def fn(cursor):
            cursor.execute("SELECT * FROM operator_sessions WHERE token_hash = %s", (token_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None
        return self._run(fn, write=False)

    def touch_session(self, token_hash: str, seen: datetime, flags: str | None = None, limited: bool | None = None) -> None:
        def fn(cursor):
            if flags is None and limited is None:
                cursor.execute(
                    "UPDATE operator_sessions SET last_seen = %s WHERE token_hash = %s",
                    (seen, token_hash),
                )
                return
            cursor.execute(
                """
                UPDATE operator_sessions
                SET last_seen = %s,
                    flags = COALESCE(%s, flags),
                    limited = COALESCE(%s, limited)
                WHERE token_hash = %s
                """,
                (seen, flags, limited, token_hash),
            )
        self._run(fn)

    def delete_session(self, token_hash: str) -> None:
        def fn(cursor):
            cursor.execute("DELETE FROM operator_sessions WHERE token_hash = %s", (token_hash,))
        self._run(fn)

    def delete_all_sessions(self) -> None:
        def fn(cursor):
            cursor.execute("DELETE FROM operator_sessions")
        self._run(fn)

    def record_attempt(self, ip: str, action: str, success: bool) -> None:
        def fn(cursor):
            cursor.execute(
                "DELETE FROM auth_attempts WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '2 days'"
            )
            cursor.execute(
                "INSERT INTO auth_attempts (ip, action, success) VALUES (%s, %s, %s)",
                (ip, action, success),
            )
        self._run(fn)

    def failure_count(self, ip: str, action: str, window_seconds: int) -> int:
        def fn(cursor):
            cursor.execute(
                """
                SELECT COUNT(*) AS n FROM auth_attempts
                WHERE ip = %s AND action = %s AND success = FALSE
                  AND created_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 second')
                """,
                (ip, action, int(window_seconds)),
            )
            row = cursor.fetchone()
            return int(row["n"] if row else 0)
        return self._run(fn, write=False)

    def clear_failures(self, ip: str, action: str) -> None:
        def fn(cursor):
            cursor.execute(
                "DELETE FROM auth_attempts WHERE ip = %s AND action = %s AND success = FALSE",
                (ip, action),
            )
        self._run(fn)

    def audit(self, ip: str, action: str, detail: str) -> None:
        def fn(cursor):
            cursor.execute(
                "INSERT INTO auth_audit (ip, action, detail) VALUES (%s, %s, %s)",
                (ip, action, (detail or "")[:300]),
            )
        self._run(fn)


def init_auth_schema(cursor) -> None:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS operator_passkeys (
            credential_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            sign_count BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS operator_secrets (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS operator_recovery (
            code_hash TEXT PRIMARY KEY,
            used_at TIMESTAMPTZ
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS operator_sessions (
            token_hash TEXT PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT NOT NULL DEFAULT '',
            limited BOOLEAN NOT NULL DEFAULT FALSE,
            flags TEXT NOT NULL DEFAULT ''
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_challenges (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            challenge TEXT NOT NULL DEFAULT '',
            payload TEXT NOT NULL DEFAULT '',
            expires_at TIMESTAMPTZ NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id BIGSERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            action TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_time
        ON auth_attempts (ip, action, created_at DESC)
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_audit (
            id BIGSERIAL PRIMARY KEY,
            at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        )
    """)


_store = None


def get_store():
    global _store
    if _store is None:
        _store = MemoryStore() if _test_mode() else PostgresStore()
    return _store


def reset_store(store=None) -> None:
    global _store
    _store = store if store is not None else (MemoryStore() if _test_mode() else None)
