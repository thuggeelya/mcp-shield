"""SQLite-backed audit storage for MCP Shield proxy events.

Provides durable, queryable storage for:
- Request/response audit events (tool calls, resource reads, etc.)
- Tool snapshots (schema + security findings at discovery time)
- Individual security findings
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from mcp_shield.models.enums import AuditAction, RiskTier  # noqa: F401


@dataclass
class AuditEvent:
    """A single audit log entry."""

    timestamp: str
    client_id: str
    action: str
    tool_name: str = ""
    arguments_hash: str = ""
    arguments_summary: str = ""
    risk_tier: str = "unknown"
    blocked: bool = False
    block_reason: str = ""
    duration_ms: int = 0
    security_score: float = 100.0
    id: Optional[int] = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    client_id       TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    tool_name       TEXT    NOT NULL DEFAULT '',
    arguments_hash  TEXT    NOT NULL DEFAULT '',
    arguments_summary TEXT  NOT NULL DEFAULT '',
    risk_tier       TEXT    NOT NULL DEFAULT 'unknown',
    blocked         INTEGER NOT NULL DEFAULT 0,
    block_reason    TEXT    NOT NULL DEFAULT '',
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    security_score  REAL    NOT NULL DEFAULT 100.0
);

CREATE TABLE IF NOT EXISTS tool_snapshots (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp               TEXT    NOT NULL,
    tool_name               TEXT    NOT NULL,
    description_hash        TEXT    NOT NULL DEFAULT '',
    input_schema_json       TEXT    NOT NULL DEFAULT '{}',
    security_findings_json  TEXT    NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS security_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    finding_id  TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT ''
);
"""


class AuditDB:
    """SQLite audit database with WAL mode for concurrent reads."""

    def __init__(self, db_path: str | Path) -> None:
        path = Path(db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._conn: Optional[sqlite3.Connection] = None

    def open(self) -> None:
        """Open the database connection and ensure schema exists."""
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> AuditDB:
        self.open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not opened — call open() or use context manager")
        return self._conn

    # ── Write operations ─────────────────────────────────────────────

    def log_event(self, event: AuditEvent) -> int:
        """Insert an audit event and return its row ID."""
        cur = self._db.execute(
            """INSERT INTO audit_events
               (timestamp, client_id, action, tool_name, arguments_hash,
                arguments_summary, risk_tier, blocked, block_reason,
                duration_ms, security_score)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.timestamp,
                event.client_id,
                event.action,
                event.tool_name,
                event.arguments_hash,
                event.arguments_summary,
                event.risk_tier,
                int(event.blocked),
                event.block_reason,
                event.duration_ms,
                event.security_score,
            ),
        )
        self._db.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def save_tool_snapshot(
        self,
        tool_name: str,
        description_hash: str,
        input_schema: Dict[str, Any],
        security_findings: Sequence[Dict[str, Any]],
    ) -> int:
        """Save a point-in-time snapshot of a tool's schema and findings."""
        cur = self._db.execute(
            """INSERT INTO tool_snapshots
               (timestamp, tool_name, description_hash, input_schema_json,
                security_findings_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                _now_iso(),
                tool_name,
                description_hash,
                json.dumps(input_schema, default=str),
                json.dumps(list(security_findings), default=str),
            ),
        )
        self._db.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def save_finding(
        self,
        finding_id: str,
        severity: str,
        category: str,
        title: str,
        tool_name: str = "",
        description: str = "",
    ) -> int:
        """Persist a single security finding."""
        cur = self._db.execute(
            """INSERT INTO security_findings
               (timestamp, finding_id, severity, category, title,
                tool_name, description)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (_now_iso(), finding_id, severity, category, title, tool_name, description),
        )
        self._db.commit()
        return cur.lastrowid  # type: ignore[return-value]

    # ── Read operations ──────────────────────────────────────────────

    def get_events(
        self,
        *,
        limit: int = 50,
        tool_name: str | None = None,
        risk_tier: str | None = None,
        client_id: str | None = None,
        blocked: bool | None = None,
    ) -> List[AuditEvent]:
        """Retrieve audit events with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if tool_name is not None:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if risk_tier is not None:
            clauses.append("risk_tier = ?")
            params.append(risk_tier)
        if client_id is not None:
            clauses.append("client_id = ?")
            params.append(client_id)
        if blocked is not None:
            clauses.append("blocked = ?")
            params.append(int(blocked))

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM audit_events{where} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self._db.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]

    def get_latest_snapshots(self) -> Dict[str, Dict[str, Any]]:
        """Return the most recent snapshot for each tool.

        Returns a dict keyed by tool_name with values containing
        description_hash, input_schema_json, and timestamp.
        """
        rows = self._db.execute(
            """SELECT t1.* FROM tool_snapshots t1
               INNER JOIN (
                   SELECT tool_name, MAX(id) AS max_id
                   FROM tool_snapshots GROUP BY tool_name
               ) t2 ON t1.id = t2.max_id"""
        ).fetchall()
        return {
            row["tool_name"]: {
                "description_hash": row["description_hash"],
                "input_schema_json": row["input_schema_json"],
                "timestamp": row["timestamp"],
            }
            for row in rows
        }

    def get_stats(self, since: str | None = None) -> Dict[str, Any]:
        """Aggregate statistics over audit events.

        *since* is an ISO-8601 timestamp; events before it are excluded.
        """
        where = ""
        params: list[Any] = []
        if since:
            where = " WHERE timestamp >= ?"
            params.append(since)

        row = self._db.execute(
            f"""SELECT
                COUNT(*)                          AS total,
                SUM(CASE WHEN action='call_tool' THEN 1 ELSE 0 END)  AS tool_calls,
                SUM(blocked)                      AS blocked,
                COUNT(DISTINCT tool_name)          AS unique_tools,
                COUNT(DISTINCT client_id)          AS unique_clients,
                AVG(duration_ms)                   AS avg_duration_ms
            FROM audit_events{where}""",
            params,
        ).fetchone()

        # Breakdown by action
        action_rows = self._db.execute(
            f"SELECT action, COUNT(*) AS cnt FROM audit_events{where} GROUP BY action",
            params,
        ).fetchall()

        # Breakdown by risk tier
        risk_rows = self._db.execute(
            f"SELECT risk_tier, COUNT(*) AS cnt FROM audit_events{where} GROUP BY risk_tier",
            params,
        ).fetchall()

        return {
            "total": row["total"] or 0,
            "tool_calls": row["tool_calls"] or 0,
            "blocked": row["blocked"] or 0,
            "unique_tools": row["unique_tools"] or 0,
            "unique_clients": row["unique_clients"] or 0,
            "avg_duration_ms": round(row["avg_duration_ms"] or 0, 1),
            "by_action": {r["action"]: r["cnt"] for r in action_rows},
            "by_risk": {r["risk_tier"]: r["cnt"] for r in risk_rows},
        }

    def export_events(
        self,
        *,
        limit: int = 10_000,
        since: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Export events as plain dicts (for JSON/CSV serialization)."""
        where = ""
        params: list[Any] = []
        if since:
            where = " WHERE timestamp >= ?"
            params.append(since)

        sql = f"SELECT * FROM audit_events{where} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self._db.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


# ── Helpers ──────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        timestamp=row["timestamp"],
        client_id=row["client_id"],
        action=row["action"],
        tool_name=row["tool_name"],
        arguments_hash=row["arguments_hash"],
        arguments_summary=row["arguments_summary"],
        risk_tier=row["risk_tier"],
        blocked=bool(row["blocked"]),
        block_reason=row["block_reason"],
        duration_ms=row["duration_ms"],
        security_score=row["security_score"],
    )
