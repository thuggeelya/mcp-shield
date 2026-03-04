"""Tests for mcp_shield.reporting.sarif_report — SARIF 2.1.0 output."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mcp_shield.reporting.sarif_report import (
    _outcome_to_level,
    _severity_to_cvss,
    _extract_tool_names,
    render_sarif,
    to_sarif,
    write_sarif,
)
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport


# ── Helpers ──────────────────────────────────────────────────────────


def _sample_report() -> SuiteReport:
    """Report with mixed outcomes for SARIF testing."""
    r = SuiteReport(
        server_target="npx -y @modelcontextprotocol/server-filesystem /tmp",
        server_name="TestServer",
        server_version="0.1.0",
        timestamp="2026-01-01T00:00:00Z",
    )
    r.results = [
        CheckResult(
            "COMP-001", Outcome.PASS, "Handshake OK",
            severity="critical", duration_ms=10,
        ),
        CheckResult(
            "SEC-001", Outcome.FAIL, "Found 2 poisoning indicator(s)",
            severity="critical", duration_ms=50,
            details=["  [medium] Hidden instruction: malicious_tool"],
            metadata={"cwe_ids": ["CWE-94"]},
        ),
        CheckResult(
            "SEC-002", Outcome.WARN, "Found 3 injection vectors",
            severity="high", duration_ms=20,
            details=[
                "  [high] Potential injection vector: read_file.path",
                "  [high] Potential injection vector: run_query.sql",
            ],
            metadata={"cwe_ids": ["CWE-78", "CWE-89", "CWE-22"]},
        ),
        CheckResult(
            "SEC-003", Outcome.WARN, "Security score: 60/100",
            severity="medium", duration_ms=5,
            metadata={"score": 60.0, "findings_count": 5, "cwe_ids": []},
        ),
        CheckResult(
            "COMP-002", Outcome.SKIP, "Skipped",
            severity="info", duration_ms=0,
        ),
    ]
    r.count()
    return r


def _empty_report() -> SuiteReport:
    """Report with only PASS results."""
    r = SuiteReport(server_target="test", server_name="Empty", timestamp="2026-01-01T00:00:00Z")
    r.results = [
        CheckResult("COMP-001", Outcome.PASS, "OK", severity="info"),
    ]
    r.count()
    return r


# ── SARIF structure ──────────────────────────────────────────────────


class TestSarifStructure:
    """Verify top-level SARIF structure."""

    def test_sarif_version(self):
        sarif = to_sarif(_sample_report())
        assert sarif["version"] == "2.1.0"

    def test_sarif_schema(self):
        sarif = to_sarif(_sample_report())
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_sarif_has_runs(self):
        sarif = to_sarif(_sample_report())
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_driver(self):
        sarif = to_sarif(_sample_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "mcp-shield"
        assert driver["version"] == "0.1.0"
        assert "mcp-shield" in driver["informationUri"]

    def test_sarif_supported_taxonomies(self):
        sarif = to_sarif(_sample_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert any(t["name"] == "CWE" for t in driver["supportedTaxonomies"])

    def test_sarif_taxonomies_section(self):
        sarif = to_sarif(_sample_report())
        taxonomies = sarif["runs"][0]["taxonomies"]
        assert len(taxonomies) == 1
        assert taxonomies[0]["name"] == "CWE"
        assert taxonomies[0]["organization"] == "MITRE"


# ── Rules ────────────────────────────────────────────────────────────


class TestSarifRules:
    """Verify SARIF rules from check results."""

    def test_rules_from_fail_warn_only(self):
        sarif = to_sarif(_sample_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        # SEC-001 (FAIL), SEC-002 (WARN), SEC-003 (WARN) — but not COMP-001 (PASS) or COMP-002 (SKIP)
        assert "SEC-001" in rule_ids
        assert "SEC-002" in rule_ids
        assert "SEC-003" in rule_ids
        assert "COMP-001" not in rule_ids
        assert "COMP-002" not in rule_ids

    def test_rule_has_name(self):
        sarif = to_sarif(_sample_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sec001 = next(r for r in rules if r["id"] == "SEC-001")
        assert sec001["name"] == "ToolPoisoning"

    def test_rule_has_help_uri(self):
        sarif = to_sarif(_sample_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sec001 = next(r for r in rules if r["id"] == "SEC-001")
        assert "checks.md" in sec001["helpUri"]

    def test_rule_has_security_severity(self):
        sarif = to_sarif(_sample_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sec001 = next(r for r in rules if r["id"] == "SEC-001")
        assert sec001["properties"]["security-severity"] == "9.5"  # critical

    def test_rule_cwe_relationships(self):
        sarif = to_sarif(_sample_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sec001 = next(r for r in rules if r["id"] == "SEC-001")
        assert "relationships" in sec001
        rels = sec001["relationships"]
        assert len(rels) == 1
        assert rels[0]["target"]["id"] == "94"
        assert rels[0]["target"]["toolComponent"]["name"] == "CWE"

    def test_rule_no_cwe_no_relationships(self):
        sarif = to_sarif(_sample_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sec003 = next(r for r in rules if r["id"] == "SEC-003")
        assert "relationships" not in sec003


# ── Results ──────────────────────────────────────────────────────────


class TestSarifResults:
    """Verify SARIF results filtering and structure."""

    def test_results_only_fail_warn_error(self):
        sarif = to_sarif(_sample_report())
        results = sarif["runs"][0]["results"]
        rule_ids = {r["ruleId"] for r in results}
        assert "SEC-001" in rule_ids
        assert "SEC-002" in rule_ids
        assert "SEC-003" in rule_ids
        assert "COMP-001" not in rule_ids  # PASS
        assert "COMP-002" not in rule_ids  # SKIP

    def test_result_level_fail(self):
        sarif = to_sarif(_sample_report())
        results = sarif["runs"][0]["results"]
        sec001 = next(r for r in results if r["ruleId"] == "SEC-001")
        assert sec001["level"] == "error"

    def test_result_level_warn(self):
        sarif = to_sarif(_sample_report())
        results = sarif["runs"][0]["results"]
        sec002 = next(r for r in results if r["ruleId"] == "SEC-002")
        assert sec002["level"] == "warning"

    def test_result_has_message(self):
        sarif = to_sarif(_sample_report())
        results = sarif["runs"][0]["results"]
        sec001 = next(r for r in results if r["ruleId"] == "SEC-001")
        assert "poisoning" in sec001["message"]["text"]

    def test_result_logical_locations(self):
        sarif = to_sarif(_sample_report())
        results = sarif["runs"][0]["results"]
        sec001 = next(r for r in results if r["ruleId"] == "SEC-001")
        locs = sec001["locations"]
        assert len(locs) >= 1
        ll = locs[0]["logicalLocations"][0]
        assert ll["name"] == "malicious_tool"
        assert "mcp://" in ll["fullyQualifiedName"]
        assert ll["kind"] == "function"

    def test_result_server_location_when_no_tools(self):
        sarif = to_sarif(_sample_report())
        results = sarif["runs"][0]["results"]
        sec003 = next(r for r in results if r["ruleId"] == "SEC-003")
        locs = sec003["locations"]
        ll = locs[0]["logicalLocations"][0]
        assert ll["kind"] == "module"
        assert ll["name"] == "TestServer"


# ── Empty report ─────────────────────────────────────────────────────


class TestSarifEmptyReport:
    """Verify SARIF output for reports with no findings."""

    def test_empty_report_valid_sarif(self):
        sarif = to_sarif(_empty_report())
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


# ── Mappings ─────────────────────────────────────────────────────────


class TestOutcomeToLevel:
    """Verify outcome-to-level mapping."""

    def test_fail_to_error(self):
        assert _outcome_to_level(Outcome.FAIL) == "error"

    def test_error_to_error(self):
        assert _outcome_to_level(Outcome.ERROR) == "error"

    def test_warn_to_warning(self):
        assert _outcome_to_level(Outcome.WARN) == "warning"

    def test_pass_to_note(self):
        assert _outcome_to_level(Outcome.PASS) == "note"

    def test_skip_to_note(self):
        assert _outcome_to_level(Outcome.SKIP) == "note"


class TestSeverityToCvss:
    """Verify severity-to-CVSS mapping."""

    def test_critical(self):
        assert _severity_to_cvss("critical") == "9.5"

    def test_high(self):
        assert _severity_to_cvss("high") == "8.0"

    def test_medium(self):
        assert _severity_to_cvss("medium") == "5.5"

    def test_low(self):
        assert _severity_to_cvss("low") == "2.0"

    def test_info(self):
        assert _severity_to_cvss("info") == "1.0"

    def test_unknown(self):
        assert _severity_to_cvss("unknown") == "1.0"


# ── Tool extraction ──────────────────────────────────────────────────


class TestExtractToolNames:
    """Verify tool name extraction from detail lines."""

    def test_extract_single_tool(self):
        r = CheckResult("SEC-004", Outcome.FAIL, "test", details=["  [high] Destructive: delete_file"])
        assert _extract_tool_names(r) == ["delete_file"]

    def test_extract_dotted_tool(self):
        r = CheckResult("SEC-002", Outcome.WARN, "test", details=["  [high] Injection: tool.field"])
        assert _extract_tool_names(r) == ["tool"]

    def test_no_details(self):
        r = CheckResult("SEC-003", Outcome.WARN, "test")
        assert _extract_tool_names(r) == []


# ── Render / Write ───────────────────────────────────────────────────


class TestRenderSarif:
    """Verify render_sarif returns valid JSON."""

    def test_render_returns_json_string(self):
        result = render_sarif(_sample_report())
        parsed = json.loads(result)
        assert parsed["version"] == "2.1.0"

    def test_render_pretty_printed(self):
        result = render_sarif(_sample_report())
        assert "\n" in result  # pretty-printed


class TestWriteSarif:
    """Verify write_sarif file output."""

    def test_write_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.sarif"
            write_sarif(_sample_report(), path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["version"] == "2.1.0"

    def test_write_traversal_blocked(self):
        with pytest.raises(ValueError, match="traversal"):
            write_sarif(_sample_report(), "../../../etc/report.sarif")

    def test_write_missing_parent(self):
        with pytest.raises(ValueError, match="Parent directory"):
            write_sarif(_sample_report(), "/nonexistent/dir/report.sarif")
