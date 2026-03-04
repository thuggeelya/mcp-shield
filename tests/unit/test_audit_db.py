"""Tests for mcp_shield.storage.audit_db — SQLite audit storage."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from mcp_shield.storage.audit_db import (
    AuditAction,
    AuditDB,
    AuditEvent,
    RiskTier,
)


def _event(**kw) -> AuditEvent:
    defaults = {
        "timestamp": "2025-01-15T10:00:00+00:00",
        "client_id": "stdio",
        "action": AuditAction.CALL_TOOL,
    }
    defaults.update(kw)
    return AuditEvent(**defaults)


class TestAuditDBCreation:
    def test_creates_db_file(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path):
            assert db_path.exists()

    def test_creates_parent_dirs(self, tmp_path: Path):
        db_path = tmp_path / "sub" / "dir" / "audit.db"
        with AuditDB(db_path):
            assert db_path.exists()

    def test_expands_tilde(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        with AuditDB("~/test_audit.db"):
            assert (tmp_path / "test_audit.db").exists()

    def test_wal_mode_enabled(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            conn = sqlite3.connect(str(db_path))
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            assert mode == "wal"

    def test_schema_tables_exist(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path):
            conn = sqlite3.connect(str(db_path))
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            conn.close()
            assert "audit_events" in tables
            assert "tool_snapshots" in tables
            assert "security_findings" in tables


class TestLogEvent:
    def test_insert_and_retrieve(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            ev = _event(tool_name="read_file", duration_ms=42)
            row_id = db.log_event(ev)
            assert row_id >= 1

            events = db.get_events()
            assert len(events) == 1
            assert events[0].tool_name == "read_file"
            assert events[0].duration_ms == 42
            assert events[0].client_id == "stdio"

    def test_multiple_events(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            for i in range(5):
                db.log_event(_event(tool_name=f"tool_{i}"))
            events = db.get_events()
            assert len(events) == 5

    def test_blocked_event(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(blocked=True, block_reason="rate_limit"))
            events = db.get_events()
            assert events[0].blocked is True
            assert events[0].block_reason == "rate_limit"


class TestGetEventsFilters:
    def test_filter_by_tool_name(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(tool_name="read_file"))
            db.log_event(_event(tool_name="write_file"))
            db.log_event(_event(tool_name="read_file"))

            events = db.get_events(tool_name="read_file")
            assert len(events) == 2
            assert all(e.tool_name == "read_file" for e in events)

    def test_filter_by_risk_tier(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(risk_tier=RiskTier.READ))
            db.log_event(_event(risk_tier=RiskTier.WRITE_EXTERNAL))
            db.log_event(_event(risk_tier=RiskTier.READ))

            events = db.get_events(risk_tier="read")
            assert len(events) == 2

    def test_filter_by_client_id(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(client_id="alice"))
            db.log_event(_event(client_id="bob"))

            events = db.get_events(client_id="alice")
            assert len(events) == 1
            assert events[0].client_id == "alice"

    def test_filter_by_blocked(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(blocked=False))
            db.log_event(_event(blocked=True, block_reason="denied"))
            db.log_event(_event(blocked=False))

            events = db.get_events(blocked=True)
            assert len(events) == 1
            assert events[0].blocked is True

    def test_limit_events(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            for i in range(10):
                db.log_event(_event(tool_name=f"tool_{i}"))
            events = db.get_events(limit=3)
            assert len(events) == 3

    def test_empty_db_returns_empty_list(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            events = db.get_events()
            assert events == []


class TestGetStats:
    def test_stats_aggregation(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(
                action=AuditAction.CALL_TOOL, tool_name="a", duration_ms=100,
            ))
            db.log_event(_event(
                action=AuditAction.CALL_TOOL, tool_name="b", duration_ms=200,
                blocked=True,
            ))
            db.log_event(_event(
                action=AuditAction.LIST_TOOLS, tool_name="", duration_ms=50,
            ))

            stats = db.get_stats()
            assert stats["total"] == 3
            assert stats["tool_calls"] == 2
            assert stats["blocked"] == 1
            assert stats["unique_clients"] == 1
            assert stats["avg_duration_ms"] > 0
            assert AuditAction.CALL_TOOL in stats["by_action"]
            assert AuditAction.LIST_TOOLS in stats["by_action"]

    def test_stats_since_filter(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(timestamp="2025-01-01T00:00:00+00:00"))
            db.log_event(_event(timestamp="2025-06-01T00:00:00+00:00"))

            stats = db.get_stats(since="2025-03-01T00:00:00+00:00")
            assert stats["total"] == 1

    def test_stats_empty_db(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            stats = db.get_stats()
            assert stats["total"] == 0
            assert stats["tool_calls"] == 0
            assert stats["blocked"] == 0
            assert stats["by_action"] == {}


class TestToolSnapshots:
    def test_save_tool_snapshot(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            row_id = db.save_tool_snapshot(
                tool_name="read_file",
                description_hash="abc123",
                input_schema={"type": "object"},
                security_findings=[{"id": "P-001", "severity": "high"}],
            )
            assert row_id >= 1


class TestSecurityFindings:
    def test_save_finding(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            row_id = db.save_finding(
                finding_id="P-001",
                severity="critical",
                category="poisoning",
                title="Hidden content detected",
                tool_name="evil_tool",
                description="Found HTML comment",
            )
            assert row_id >= 1


class TestExportEvents:
    def test_export_returns_dicts(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(tool_name="test"))
            exported = db.export_events()
            assert len(exported) == 1
            assert isinstance(exported[0], dict)
            assert exported[0]["tool_name"] == "test"

    def test_export_since_filter(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        with AuditDB(db_path) as db:
            db.log_event(_event(timestamp="2025-01-01T00:00:00+00:00"))
            db.log_event(_event(timestamp="2025-06-01T00:00:00+00:00"))

            exported = db.export_events(since="2025-03-01T00:00:00+00:00")
            assert len(exported) == 1


class TestEnums:
    def test_audit_action_values(self):
        assert AuditAction.CALL_TOOL == "call_tool"
        assert AuditAction.LIST_TOOLS == "list_tools"
        assert AuditAction.LIST_RESOURCES == "list_resources"
        assert AuditAction.READ_RESOURCE == "read_resource"
        assert AuditAction.LIST_PROMPTS == "list_prompts"
        assert AuditAction.GET_PROMPT == "get_prompt"

    def test_risk_tier_values(self):
        assert RiskTier.READ == "read"
        assert RiskTier.WRITE_REVERSIBLE == "write_reversible"
        assert RiskTier.WRITE_EXTERNAL == "write_external"
        assert RiskTier.WRITE_SENSITIVE == "write_sensitive"
        assert RiskTier.UNKNOWN == "unknown"
