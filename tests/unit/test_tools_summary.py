"""Tests for tool discovery and ToolSummary in reports."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from mcp_shield.reporting.json_report import to_dict
from mcp_shield.reporting.terminal import render
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport, ToolSummary


def _report_with_tools() -> SuiteReport:
    r = SuiteReport(server_target="test", server_name="TestServer", timestamp="2026-01-01T00:00:00Z")
    r.results = [
        CheckResult("COMP-001", Outcome.PASS, "OK", severity="critical"),
    ]
    r.tools = [
        ToolSummary("delete_file", "Permanently delete a file", "write_sensitive"),
        ToolSummary("send_email", "Send an email message", "write_external"),
        ToolSummary("write_file", "Write content to a file", "write_reversible"),
        ToolSummary("read_file", "Read file contents", "read"),
        ToolSummary("magic_tool", "", "unknown"),
    ]
    r.count()
    return r


# ── ToolSummary dataclass ────────────────────────────────────────────


class TestToolSummary:
    def test_defaults(self):
        t = ToolSummary("foo")
        assert t.name == "foo"
        assert t.description == ""
        assert t.risk_tier == "unknown"

    def test_with_values(self):
        t = ToolSummary("bar", "does stuff", "read")
        assert t.risk_tier == "read"


# ── Tools in terminal output ────────────────────────────────────────


class TestToolsTerminal:
    def test_tools_section_rendered(self):
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, width=120)
        render(_report_with_tools(), console=console)
        output = buf.getvalue()
        assert "Tools" in output
        assert "5 discovered" in output

    def test_tool_names_visible(self):
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        render(_report_with_tools(), console=console)
        output = buf.getvalue()
        assert "delete_file" in output
        assert "send_email" in output
        assert "write_file" in output
        assert "read_file" in output
        assert "magic_tool" in output

    def test_risk_tiers_visible(self):
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        render(_report_with_tools(), console=console)
        output = buf.getvalue()
        assert "write_sensitive" in output
        assert "write_external" in output
        assert "read" in output

    def test_no_tools_no_section(self):
        r = SuiteReport(server_target="test")
        r.results = [CheckResult("COMP-001", Outcome.PASS, "OK")]
        r.count()
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        render(r, console=console)
        output = buf.getvalue()
        assert "discovered" not in output


# ── Tools in JSON output ─────────────────────────────────────────────


class TestToolsJson:
    def test_tools_in_json(self):
        d = to_dict(_report_with_tools())
        assert "tools" in d
        assert len(d["tools"]) == 5

    def test_tool_fields(self):
        d = to_dict(_report_with_tools())
        tool = d["tools"][0]
        assert "name" in tool
        assert "description" in tool
        assert "risk_tier" in tool

    def test_tool_order_by_risk(self):
        d = to_dict(_report_with_tools())
        tiers = [t["risk_tier"] for t in d["tools"]]
        assert tiers[0] == "write_sensitive"
        assert tiers[-1] in ("read", "unknown")

    def test_empty_tools(self):
        r = SuiteReport(server_target="test")
        r.count()
        d = to_dict(r)
        assert d["tools"] == []
