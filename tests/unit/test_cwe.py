"""Tests for mcp_shield.security.cwe — CWE mapping."""

from __future__ import annotations

import pytest
from io import StringIO

from mcp_shield.security.cwe import (
    CHECK_CWE,
    CWE_NAMES,
    cwe_for_check,
    cwe_label,
)
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport


# ── cwe_for_check ────────────────────────────────────────────────────


class TestCweForCheck:
    """Verify CWE mapping for all SEC-* checks."""

    def test_sec001_code_injection(self):
        assert cwe_for_check("SEC-001") == ["CWE-94"]

    def test_sec002_injection_vectors(self):
        result = cwe_for_check("SEC-002")
        assert "CWE-78" in result
        assert "CWE-89" in result
        assert "CWE-22" in result

    def test_sec003_meta_check_empty(self):
        assert cwe_for_check("SEC-003") == []

    def test_sec004_dangerous_ops(self):
        result = cwe_for_check("SEC-004")
        assert "CWE-78" in result
        assert "CWE-250" in result

    def test_sec005_write_scope(self):
        assert cwe_for_check("SEC-005") == ["CWE-434"]

    def test_sec006_idempotency(self):
        assert cwe_for_check("SEC-006") == ["CWE-352"]

    def test_sec007_cost_risk(self):
        assert cwe_for_check("SEC-007") == ["CWE-770"]

    def test_comp_check_returns_empty(self):
        assert cwe_for_check("COMP-001") == []

    def test_adv_check_returns_empty(self):
        assert cwe_for_check("ADV-001") == []

    def test_unknown_check_returns_empty(self):
        assert cwe_for_check("UNKNOWN-999") == []


# ── cwe_label ────────────────────────────────────────────────────────


class TestCweLabel:
    """Verify CWE label formatting."""

    def test_known_cwe(self):
        assert cwe_label("CWE-78") == "CWE-78: OS Command Injection"

    def test_known_cwe_sql(self):
        assert cwe_label("CWE-89") == "CWE-89: SQL Injection"

    def test_unknown_cwe_returns_id_only(self):
        assert cwe_label("CWE-999") == "CWE-999"

    def test_all_named_cwes_have_labels(self):
        """Every CWE in CWE_NAMES produces a formatted label."""
        for cwe_id, name in CWE_NAMES.items():
            label = cwe_label(cwe_id)
            assert cwe_id in label
            assert name in label


# ── CWE in CheckResult metadata ─────────────────────────────────────


class TestCweInMetadata:
    """Verify CWE IDs propagate through CheckResult metadata."""

    def test_metadata_with_cwe_ids(self):
        r = CheckResult(
            check_id="SEC-002",
            outcome=Outcome.WARN,
            message="Found 5 injection vectors",
            severity="high",
            metadata={"cwe_ids": cwe_for_check("SEC-002")},
        )
        assert r.metadata["cwe_ids"] == ["CWE-78", "CWE-89", "CWE-22"]

    def test_metadata_empty_cwe_for_comp(self):
        r = CheckResult(
            check_id="COMP-001",
            outcome=Outcome.PASS,
            message="OK",
            metadata={"cwe_ids": cwe_for_check("COMP-001")},
        )
        assert r.metadata["cwe_ids"] == []


# ── CWE in terminal output ──────────────────────────────────────────


class TestCweInTerminal:
    """Verify CWE appears in terminal rendered message."""

    def test_cwe_appended_to_warn_message(self):
        from rich.console import Console
        from mcp_shield.reporting.terminal import render

        report = SuiteReport(server_target="test")
        report.results = [
            CheckResult(
                "SEC-002", Outcome.WARN, "Found 3 injection vectors",
                severity="high",
                metadata={"cwe_ids": ["CWE-78", "CWE-89"]},
            ),
        ]
        report.count()

        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        render(report, console=console)
        output = buf.getvalue()
        assert "CWE-78" in output
        assert "CWE-89" in output

    def test_no_cwe_for_pass(self):
        from rich.console import Console
        from mcp_shield.reporting.terminal import render

        report = SuiteReport(server_target="test")
        report.results = [
            CheckResult(
                "COMP-001", Outcome.PASS, "OK",
                severity="info",
                metadata={"cwe_ids": ["CWE-78"]},  # shouldn't show for PASS
            ),
        ]
        report.count()

        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        render(report, console=console)
        output = buf.getvalue()
        assert "CWE-78" not in output


# ── CWE in recommendations ──────────────────────────────────────────


class TestCweInRecommendations:
    """Verify CWE IDs in generated recommendations."""

    def test_recommendation_has_cwe_ids(self):
        from mcp_shield.reporting.recommendations import generate_recommendations

        report = SuiteReport(server_target="test")
        report.results = [
            CheckResult(
                "SEC-004", Outcome.FAIL, "Found 1 dangerous operation(s)",
                severity="medium",
                details=["  [high] Destructive operation: delete_file"],
            ),
        ]
        report.count()

        recs = generate_recommendations(report)
        assert len(recs.items) > 0
        rec = recs.items[0]
        assert "CWE-78" in rec.cwe_ids
        assert "CWE-250" in rec.cwe_ids

    def test_recommendation_dict_has_cwe_ids(self):
        from mcp_shield.reporting.recommendations import (
            generate_recommendations,
            recommendations_to_dict,
        )

        report = SuiteReport(server_target="test")
        report.results = [
            CheckResult(
                "SEC-002", Outcome.WARN, "Found 1 injection vector(s)",
                severity="high",
                details=["  [high] Potential injection vector: tool.field"],
            ),
        ]
        report.count()

        recs = generate_recommendations(report)
        d = recommendations_to_dict(recs)
        assert d["items"][0]["cwe_ids"] == ["CWE-78", "CWE-89", "CWE-22"]
