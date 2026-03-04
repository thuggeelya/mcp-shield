"""Tests for mcp_shield.reporting.recommendations."""

from __future__ import annotations

import pytest
from rich.console import Console

from mcp_shield.reporting.recommendations import (
    Recommendation,
    RecommendationReport,
    _format_tools_line,
    _parse_comp_field,
    _parse_injection,
    _parse_sec_tool,
    generate_recommendations,
    recommendations_to_dict,
    render_recommendations,
)
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport


# ── Parsing tests ─────────────────────────────────────────────────────


class TestParseSecTool:
    """Parse tool names from SEC-004/005/006/007 detail lines."""

    def test_high_destructive(self):
        assert _parse_sec_tool("  [high] Destructive operation: delete_file") == "delete_file"

    def test_medium_write(self):
        assert _parse_sec_tool("  [medium] Dangerous write operation: git_push") == "git_push"

    def test_medium_exec(self):
        assert _parse_sec_tool("  [medium] Execution operation: run_command") == "run_command"

    def test_medium_desc_destructive(self):
        assert _parse_sec_tool("  [medium] Description indicates destructive operation: cleanup") == "cleanup"

    def test_medium_user_facing_write(self):
        assert _parse_sec_tool("  [medium] User-facing write: send_email") == "send_email"

    def test_medium_cloud_write(self):
        assert _parse_sec_tool("  [medium] Cloud write: deploy_lambda") == "deploy_lambda"

    def test_medium_remote_write(self):
        assert _parse_sec_tool("  [medium] Remote write: db_insert") == "db_insert"

    def test_medium_non_idempotent(self):
        assert _parse_sec_tool("  [medium] Non-idempotent operation: create_order") == "create_order"

    def test_low_cloud_resource(self):
        assert _parse_sec_tool("  [low] Cloud resource creation: provision_vm") == "provision_vm"

    def test_low_paid_api(self):
        assert _parse_sec_tool("  [low] Paid API usage: translate") == "translate"

    def test_low_expensive_query(self):
        assert _parse_sec_tool("  [low] Expensive query backend: bigquery_run") == "bigquery_run"

    def test_no_match_empty(self):
        assert _parse_sec_tool("") is None

    def test_no_match_no_colon(self):
        assert _parse_sec_tool("  [high] Some finding without colon") is None


class TestParseInjection:
    """Parse tool.field or tool name from SEC-002 detail lines."""

    def test_dotted_field(self):
        assert _parse_injection("  [high] Potential injection vector: sql_runner.query") == "sql_runner.query"

    def test_unconstrained_path(self):
        assert _parse_injection("  [medium] Unconstrained path field: file_tool.path") == "file_tool.path"

    def test_tool_name_quoted(self):
        assert _parse_injection("  [medium] Tool 'raw_executor' has no input schema constraints") == "raw_executor"

    def test_no_match(self):
        assert _parse_injection("  random text") is None


class TestParseCompField:
    """Parse tool.field from COMP-008/009 detail lines."""

    def test_comp008_simple(self):
        assert _parse_comp_field("  mongodb.collection_name") == "mongodb.collection_name"

    def test_comp009_with_reason(self):
        assert _parse_comp_field("  github.path: path-like field without pattern") == "github.path"

    def test_no_match_no_dot(self):
        assert _parse_comp_field("  just_a_word") is None

    def test_no_match_empty(self):
        assert _parse_comp_field("") is None


# ── Generation tests ──────────────────────────────────────────────────


def _make_report(*results: CheckResult, target: str = "npx server") -> SuiteReport:
    """Helper to build a SuiteReport."""
    r = SuiteReport(server_target=target, results=list(results))
    r.count()
    return r


class TestGenerateRecommendations:
    """Test recommendation generation from SuiteReport."""

    def test_empty_report(self):
        report = _make_report()
        recs = generate_recommendations(report)
        assert recs.items == []
        assert recs.proxy_command == ""

    def test_all_pass_no_recs(self):
        report = _make_report(
            CheckResult("SEC-004", Outcome.PASS, "No dangerous ops"),
            CheckResult("SEC-002", Outcome.PASS, "No injection"),
        )
        recs = generate_recommendations(report)
        assert recs.items == []

    def test_sec004_fail(self):
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "Found 2 dangerous ops",
                details=[
                    "  [high] Destructive operation: delete_all",
                    "  [medium] Execution operation: run_shell",
                ],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 1
        rec = recs.items[0]
        assert rec.category == "block"
        assert rec.priority == "high"
        assert rec.tools == ["delete_all", "run_shell"]
        assert rec.check_id == "SEC-004"
        assert "2 found" in rec.title

    def test_sec002_warn(self):
        report = _make_report(
            CheckResult(
                "SEC-002", Outcome.WARN, "Found 1 injection vector",
                details=["  [high] Potential injection vector: exec.command"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 1
        assert recs.items[0].category == "injection"
        assert recs.items[0].tools == ["exec.command"]

    def test_sec005_warn(self):
        report = _make_report(
            CheckResult(
                "SEC-005", Outcome.WARN, "Found 1 write scope concern",
                details=["  [medium] User-facing write: send_message"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 1
        assert recs.items[0].category == "write_scope"
        assert recs.items[0].tools == ["send_message"]

    def test_sec006_warn(self):
        report = _make_report(
            CheckResult(
                "SEC-006", Outcome.WARN, "Found 1 non-idempotent op",
                details=["  [medium] Non-idempotent operation: create_payment"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 1
        assert recs.items[0].category == "idempotency"

    def test_sec007_warn(self):
        report = _make_report(
            CheckResult(
                "SEC-007", Outcome.WARN, "Found 1 cost risk",
                details=["  [low] Cloud resource creation: create_instance"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 1
        assert recs.items[0].category == "cost"
        assert recs.items[0].priority == "low"

    def test_comp_merged(self):
        report = _make_report(
            CheckResult(
                "COMP-008", Outcome.WARN, "5 fields missing",
                severity="warning",
                details=["  tool.a", "  tool.b"],
            ),
            CheckResult(
                "COMP-009", Outcome.WARN, "3 fields missing",
                severity="warning",
                details=["  tool.c: string without maxLength"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 1
        rec = recs.items[0]
        assert rec.category == "schema"
        assert rec.tools == ["tool.a", "tool.b", "tool.c"]
        assert "COMP-008" in rec.check_id
        assert "COMP-009" in rec.check_id

    def test_advisory_skipped(self):
        report = _make_report(
            CheckResult(
                "ADV-001", Outcome.WARN, "Auth hints found",
                details=["  some hint"],
            ),
        )
        recs = generate_recommendations(report)
        assert recs.items == []

    def test_skip_outcome_ignored(self):
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.SKIP, "No tools to scan",
                details=["  [high] Destructive operation: fake"],
            ),
        )
        recs = generate_recommendations(report)
        assert recs.items == []

    def test_deduplication(self):
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "Found ops",
                details=[
                    "  [high] Destructive operation: delete",
                    "  [medium] Description indicates destructive operation: delete",
                ],
            ),
        )
        recs = generate_recommendations(report)
        assert recs.items[0].tools == ["delete"]

    def test_ordering_sec004_before_sec002(self):
        report = _make_report(
            CheckResult(
                "SEC-002", Outcome.WARN, "injections",
                details=["  [high] Potential injection vector: t.cmd"],
            ),
            CheckResult(
                "SEC-004", Outcome.FAIL, "dangerous",
                details=["  [high] Destructive operation: rm"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) == 2
        assert recs.items[0].check_id == "SEC-004"
        assert recs.items[1].check_id == "SEC-002"

    def test_no_details_skipped(self):
        report = _make_report(
            CheckResult("SEC-004", Outcome.FAIL, "Found ops", details=[]),
        )
        recs = generate_recommendations(report)
        # SEC-003 not present, so no overall rec; SEC-004 has no parseable details
        assert not any(r.check_id == "SEC-004" for r in recs.items)

    def test_sec001_poisoning(self):
        report = _make_report(
            CheckResult(
                "SEC-001", Outcome.FAIL, "Found 1 poisoning indicator",
                severity="critical",
                details=["  [critical] Hidden instruction block in description: evil_tool"],
            ),
        )
        recs = generate_recommendations(report)
        poisoning_recs = [r for r in recs.items if r.category == "poisoning"]
        assert len(poisoning_recs) == 1
        assert poisoning_recs[0].priority == "high"
        assert "evil_tool" in poisoning_recs[0].tools

    def test_sec003_fail_generates_overall(self):
        report = _make_report(
            CheckResult(
                "SEC-003", Outcome.FAIL, "Security score: 30/100",
                severity="medium",
                metadata={"score": 30.0, "findings_count": 10},
            ),
        )
        recs = generate_recommendations(report)
        overall = [r for r in recs.items if r.category == "overall"]
        assert len(overall) == 1
        assert overall[0].check_id == "SEC-003"
        assert "30" in overall[0].title

    def test_sec003_warn_no_overall(self):
        report = _make_report(
            CheckResult(
                "SEC-003", Outcome.WARN, "Security score: 60/100",
                severity="medium",
                metadata={"score": 60.0},
            ),
        )
        recs = generate_recommendations(report)
        overall = [r for r in recs.items if r.category == "overall"]
        assert len(overall) == 0

    def test_sec003_first_then_sec004(self):
        """SEC-003 overall recommendation should come before specific ones."""
        report = _make_report(
            CheckResult(
                "SEC-003", Outcome.FAIL, "Security score: 20/100",
                metadata={"score": 20.0},
            ),
            CheckResult(
                "SEC-004", Outcome.FAIL, "dangerous",
                details=["  [high] Destructive operation: rm"],
            ),
        )
        recs = generate_recommendations(report)
        assert len(recs.items) >= 2
        assert recs.items[0].check_id == "SEC-003"
        assert recs.items[1].check_id == "SEC-004"

    def test_sec001_before_sec004(self):
        """SEC-001 poisoning should come before SEC-004 dangerous ops."""
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "dangerous",
                details=["  [high] Destructive operation: rm"],
            ),
            CheckResult(
                "SEC-001", Outcome.FAIL, "poisoning",
                severity="critical",
                details=["  [critical] Hidden instruction: evil"],
            ),
        )
        recs = generate_recommendations(report)
        check_ids = [r.check_id for r in recs.items]
        assert check_ids.index("SEC-001") < check_ids.index("SEC-004")


# ── Proxy command tests ───────────────────────────────────────────────


class TestProxyCommand:
    """Test proxy command generation."""

    def test_basic_command(self):
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "Found 1 dangerous op",
                details=["  [high] Destructive operation: delete_file"],
            ),
            target="npx -y @server/name",
        )
        recs = generate_recommendations(report)
        assert "mcp-shield proxy" in recs.proxy_command
        assert "--deny delete_file" in recs.proxy_command
        assert "@server/name" in recs.proxy_command

    def test_full_command_with_args(self):
        """Proxy command should include full server target, not just first word."""
        target = "npx -y @modelcontextprotocol/server-filesystem /tmp"
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "ops",
                details=["  [high] Destructive operation: rm"],
            ),
            target=target,
        )
        recs = generate_recommendations(report)
        # The full target should appear in the proxy command (quoted)
        assert "server-filesystem" in recs.proxy_command
        assert "/tmp" in recs.proxy_command

    def test_multiple_deny(self):
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "Found ops",
                details=[
                    "  [high] Destructive operation: rm_file",
                    "  [medium] Execution operation: exec_cmd",
                ],
            ),
        )
        recs = generate_recommendations(report)
        assert "--deny rm_file" in recs.proxy_command
        assert "--deny exec_cmd" in recs.proxy_command

    def test_no_sec004_no_proxy(self):
        report = _make_report(
            CheckResult(
                "SEC-002", Outcome.WARN, "injections",
                details=["  [high] Potential injection vector: t.f"],
            ),
        )
        recs = generate_recommendations(report)
        assert recs.proxy_command == ""

    def test_empty_target(self):
        report = _make_report(
            CheckResult(
                "SEC-004", Outcome.FAIL, "ops",
                details=["  [high] Destructive operation: rm"],
            ),
            target="",
        )
        recs = generate_recommendations(report)
        assert '"server"' in recs.proxy_command


# ── Serialisation tests ──────────────────────────────────────────────


class TestRecommendationsToDict:
    """Test JSON serialisation."""

    def test_empty(self):
        recs = RecommendationReport()
        d = recommendations_to_dict(recs)
        assert d == {"items": [], "proxy_command": ""}

    def test_full(self):
        recs = RecommendationReport(
            items=[
                Recommendation(
                    category="block",
                    priority="high",
                    title="Block dangerous tools (2 found)",
                    action="Add --deny rules",
                    tools=["rm", "exec"],
                    check_id="SEC-004",
                ),
            ],
            proxy_command="mcp-shield proxy server --deny rm",
        )
        d = recommendations_to_dict(recs)
        assert len(d["items"]) == 1
        assert d["items"][0]["category"] == "block"
        assert d["items"][0]["tools"] == ["rm", "exec"]
        assert d["proxy_command"] == "mcp-shield proxy server --deny rm"

    def test_roundtrip_fields(self):
        rec = Recommendation(
            category="injection",
            priority="high",
            title="Review injection risks (1 found)",
            action="Add constraints",
            tools=["t.f"],
            check_id="SEC-002",
        )
        recs = RecommendationReport(items=[rec])
        d = recommendations_to_dict(recs)
        item = d["items"][0]
        assert item["category"] == rec.category
        assert item["priority"] == rec.priority
        assert item["title"] == rec.title
        assert item["action"] == rec.action
        assert item["check_id"] == rec.check_id


# ── Format tools line tests ──────────────────────────────────────────


class TestFormatToolsLine:
    """Test tool name display truncation."""

    def test_under_limit(self):
        assert _format_tools_line(["a", "b", "c"]) == "a, b, c"

    def test_at_limit(self):
        tools = ["a", "b", "c", "d", "e"]
        assert _format_tools_line(tools) == "a, b, c, d, e"

    def test_over_limit(self):
        tools = ["a", "b", "c", "d", "e", "f", "g"]
        result = _format_tools_line(tools)
        assert result == "a, b, c, d, e (and 2 more)"

    def test_single(self):
        assert _format_tools_line(["only"]) == "only"


# ── Render tests ─────────────────────────────────────────────────────


class TestRenderRecommendations:
    """Test Rich terminal rendering (captures output)."""

    def test_empty_no_output(self):
        console = Console(file=None, force_terminal=True, width=80)
        with console.capture() as cap:
            render_recommendations(RecommendationReport(), console)
        assert cap.get() == ""

    def test_renders_title_and_action(self):
        recs = RecommendationReport(
            items=[
                Recommendation(
                    category="block",
                    priority="high",
                    title="Block dangerous tools (1 found)",
                    action="Add --deny rules",
                    tools=["rm"],
                    check_id="SEC-004",
                ),
            ],
        )
        console = Console(file=None, force_terminal=True, width=100)
        with console.capture() as cap:
            render_recommendations(recs, console)
        output = cap.get()
        assert "Recommendations" in output
        assert "Block dangerous tools" in output
        assert "SEC-004" in output
        assert "rm" in output
        assert "--deny rules" in output

    def test_renders_overall_recommendation(self):
        recs = RecommendationReport(
            items=[
                Recommendation(
                    category="overall",
                    priority="high",
                    title="Low security score (score 30/100)",
                    action="Address the specific findings below",
                    check_id="SEC-003",
                ),
            ],
        )
        console = Console(file=None, force_terminal=True, width=100)
        with console.capture() as cap:
            render_recommendations(recs, console)
        output = cap.get()
        assert "Low security score" in output
        assert "SEC-003" in output

    def test_renders_proxy_panel(self):
        recs = RecommendationReport(
            items=[
                Recommendation(
                    category="block", priority="high",
                    title="Block (1 found)", action="deny",
                    tools=["rm"], check_id="SEC-004",
                ),
            ],
            proxy_command="mcp-shield proxy server --deny rm",
        )
        console = Console(file=None, force_terminal=True, width=100)
        with console.capture() as cap:
            render_recommendations(recs, console)
        output = cap.get()
        assert "proxy command" in output.lower()
        assert "--deny rm" in output
