"""Tests for CLI commands — proxy_cmd and audit_cmd."""

from __future__ import annotations

import json
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from mcp_shield.cli.audit_cmd import audit_group, _parse_since
from mcp_shield.cli.proxy_cmd import _parse_tokens, proxy_cmd
from mcp_shield.storage.audit_db import AuditAction, AuditDB, AuditEvent


# ── _parse_tokens ────────────────────────────────────────────────────


class TestParseTokens:
    def test_single_token(self):
        result = _parse_tokens(("admin:secret123",))
        assert result == {"admin": "secret123"}

    def test_multiple_tokens(self):
        result = _parse_tokens(("alice:tok-a", "bob:tok-b"))
        assert result == {"alice": "tok-a", "bob": "tok-b"}

    def test_empty_tuple(self):
        result = _parse_tokens(())
        assert result == {}

    def test_token_with_colon_in_value(self):
        result = _parse_tokens(("svc:key:with:colons",))
        assert result == {"svc": "key:with:colons"}

    def test_no_colon_raises(self):
        with pytest.raises(click.BadParameter, match="CLIENT_ID:TOKEN"):
            _parse_tokens(("bad-token",))

    def test_empty_client_id_raises(self):
        with pytest.raises(click.BadParameter, match="non-empty"):
            _parse_tokens((":secret",))

    def test_empty_token_raises(self):
        with pytest.raises(click.BadParameter, match="non-empty"):
            _parse_tokens(("admin:",))


# ── proxy_cmd validation ─────────────────────────────────────────────


class TestProxyCmdValidation:
    def test_auth_without_token_errors(self):
        runner = CliRunner()
        result = runner.invoke(proxy_cmd, [
            "echo hello", "--auth", "bearer",
        ])
        assert result.exit_code != 0
        assert "requires at least one --token" in result.output

    def test_auth_api_key_without_token_errors(self):
        runner = CliRunner()
        result = runner.invoke(proxy_cmd, [
            "echo hello", "--auth", "api_key",
        ])
        assert result.exit_code != 0
        assert "requires at least one --token" in result.output

    def test_invalid_token_format_errors(self):
        runner = CliRunner()
        result = runner.invoke(proxy_cmd, [
            "echo hello", "--auth", "bearer", "--token", "no-colon",
        ])
        assert result.exit_code != 0


# ── _parse_since ─────────────────────────────────────────────────────


class TestParseSince:
    def test_hours(self):
        result = _parse_since("1h")
        assert "T" in result  # ISO format

    def test_days(self):
        result = _parse_since("7d")
        assert "T" in result

    def test_weeks(self):
        result = _parse_since("4w")
        assert "T" in result

    def test_months(self):
        result = _parse_since("1m")
        assert "T" in result

    def test_invalid_format_raises(self):
        with pytest.raises(click.BadParameter, match="Invalid time range"):
            _parse_since("abc")

    def test_invalid_unit_raises(self):
        with pytest.raises(click.BadParameter, match="Invalid time range"):
            _parse_since("10x")

    def test_no_number_raises(self):
        with pytest.raises(click.BadParameter, match="Invalid time range"):
            _parse_since("h")

    def test_overflow_since_rejected(self):
        """Extremely large --since values must be rejected, not overflow."""
        with pytest.raises(click.BadParameter, match="exceeds maximum"):
            _parse_since("999999999d")

    def test_10_years_rejected(self):
        """Values exceeding 10 years must be rejected."""
        with pytest.raises(click.BadParameter, match="exceeds maximum"):
            _parse_since("3700d")

    def test_just_under_10_years_accepted(self):
        """3650d (just under 10 years) should be accepted."""
        result = _parse_since("3650d")
        assert "T" in result


# ── audit show ───────────────────────────────────────────────────────


def _seed_db(db_path: Path) -> None:
    """Create an audit DB with sample events."""
    db = AuditDB(db_path)
    db.open()
    db.log_event(AuditEvent(
        timestamp="2025-06-01T10:00:00+00:00",
        client_id="stdio",
        action=AuditAction.CALL_TOOL,
        tool_name="read_file",
        duration_ms=42,
    ))
    db.log_event(AuditEvent(
        timestamp="2025-06-01T10:01:00+00:00",
        client_id="stdio",
        action=AuditAction.CALL_TOOL,
        tool_name="write_file",
        blocked=True,
        block_reason="tool_denied",
        duration_ms=5,
    ))
    db.log_event(AuditEvent(
        timestamp="2025-06-01T10:02:00+00:00",
        client_id="stdio",
        action=AuditAction.LIST_TOOLS,
        duration_ms=10,
    ))
    db.close()


class TestAuditShow:
    def test_show_with_events(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        _seed_db(db_path)

        runner = CliRunner()
        result = runner.invoke(audit_group, ["--db", str(db_path), "show"])
        assert result.exit_code == 0
        assert "3 events shown" in result.output
        assert "call_tool" in result.output

    def test_show_empty_db(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        AuditDB(db_path).open()  # just create
        AuditDB(db_path).close() if False else None
        # Create and close properly
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, ["--db", str(db_path), "show"])
        assert result.exit_code == 0
        assert "No audit events found" in result.output

    def test_show_blocked_filter(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        _seed_db(db_path)

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "show", "--blocked",
        ])
        assert result.exit_code == 0
        assert "1 events shown" in result.output

    def test_show_tool_filter(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        _seed_db(db_path)

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "show", "--tool", "read_file",
        ])
        assert result.exit_code == 0
        assert "1 events shown" in result.output


# ── audit export ─────────────────────────────────────────────────────


class TestAuditExport:
    def test_export_json(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        out_path = tmp_path / "export.json"
        _seed_db(db_path)

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "export", "-o", str(out_path),
        ])
        assert result.exit_code == 0
        assert "Exported 3 events" in result.output
        data = json.loads(out_path.read_text())
        assert len(data) == 3

    def test_export_csv(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        out_path = tmp_path / "export.csv"
        _seed_db(db_path)

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "export", "-f", "csv", "-o", str(out_path),
        ])
        assert result.exit_code == 0
        assert "Exported 3 events" in result.output
        lines = out_path.read_text().strip().split("\n")
        assert len(lines) == 4  # header + 3 rows

    def test_export_empty_db(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "export", "-o", str(tmp_path / "out.json"),
        ])
        assert result.exit_code == 0
        assert "No events to export" in result.output


# ── audit stats ──────────────────────────────────────────────────────


class TestAuditStats:
    def test_stats_with_events(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        _seed_db(db_path)

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "stats", "--since", "999d",
        ])
        assert result.exit_code == 0
        assert "Total events" in result.output

    def test_stats_empty_db(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "stats",
        ])
        assert result.exit_code == 0
        assert "No events" in result.output

    def test_stats_invalid_since(self, tmp_path: Path):
        db_path = tmp_path / "audit.db"
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "stats", "--since", "invalid",
        ])
        assert result.exit_code != 0


# ── Adversarial input validation ────────────────────────────────────


class TestAdversarialInputs:
    """Tests for malicious / edge-case inputs that should be rejected."""

    def test_negative_last_rejected(self, tmp_path: Path):
        """--last -1 must be rejected by IntRange(min=1)."""
        db_path = tmp_path / "audit.db"
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "show", "--last", "-1",
        ])
        assert result.exit_code != 0

    def test_zero_last_rejected(self, tmp_path: Path):
        """--last 0 must be rejected (min is 1)."""
        db_path = tmp_path / "audit.db"
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "show", "--last", "0",
        ])
        assert result.exit_code != 0

    def test_negative_rate_limit_rejected(self):
        """--rate-limit -1 must be rejected by IntRange(min=0)."""
        runner = CliRunner()
        result = runner.invoke(proxy_cmd, [
            "echo hello", "--rate-limit", "-1",
        ])
        assert result.exit_code != 0

    def test_since_overflow_rejected(self, tmp_path: Path):
        """--since 999999999d must be rejected, not cause overflow."""
        db_path = tmp_path / "audit.db"
        db = AuditDB(db_path)
        db.open()
        db.close()

        runner = CliRunner()
        result = runner.invoke(audit_group, [
            "--db", str(db_path), "stats", "--since", "999999999d",
        ])
        assert result.exit_code != 0
