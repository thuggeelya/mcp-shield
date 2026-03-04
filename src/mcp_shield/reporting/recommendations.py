"""Actionable recommendations generated from check results.

Parses CheckResult.details strings to extract tool/field names and
groups them into prioritised recommendations with concrete actions.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport

# ── Detail parsers ────────────────────────────────────────────────────

# SEC-004/005/006/007 details look like:
#   "  [high] Destructive operation: tool_name"
#   "  [medium] User-facing write: tool_name"
# We want the tool_name after the last ": "
_RE_SEC_TOOL = re.compile(r"^\s*\[\w+\]\s+.+:\s+(\S+)\s*$")

# SEC-002 details — two patterns:
#   "  [high] Potential injection vector: tool.field"
#   "  [medium] Tool 'name' has no input schema constraints"
#   "  [medium] Unconstrained path field: tool.field"
_RE_INJECTION_DOTTED = re.compile(r"^\s*\[\w+\]\s+.+:\s+(\S+\.\S+)\s*$")
_RE_INJECTION_TOOL = re.compile(r"^\s*\[\w+\]\s+Tool\s+'([^']+)'")

# COMP-008 details: "  tool.field"
# COMP-009 details: "  tool.field: reason text"
_RE_COMP_FIELD = re.compile(r"^\s+(\S+\.\S+?)(?::|$|\s)")


def _parse_sec_tool(detail: str) -> str | None:
    """Extract tool name from SEC-004/005/006/007 detail lines."""
    m = _RE_SEC_TOOL.match(detail)
    return m.group(1) if m else None


def _parse_injection(detail: str) -> str | None:
    """Extract tool.field or tool name from SEC-002 detail lines."""
    m = _RE_INJECTION_DOTTED.match(detail)
    if m:
        return m.group(1)
    m = _RE_INJECTION_TOOL.match(detail)
    if m:
        return m.group(1)
    return None


def _parse_comp_field(detail: str) -> str | None:
    """Extract tool.field from COMP-008/009 detail lines."""
    m = _RE_COMP_FIELD.match(detail)
    return m.group(1) if m else None


# ── Data classes ──────────────────────────────────────────────────────


@dataclass
class Recommendation:
    """A single actionable recommendation."""

    category: str  # "block", "injection", "write_scope", "idempotency", "cost", "schema"
    priority: str  # "high", "medium", "low"
    title: str  # "Block dangerous tools (3 found)"
    action: str  # "Add --deny rules in the proxy"
    tools: list[str] = field(default_factory=list)
    check_id: str = ""


@dataclass
class RecommendationReport:
    """Collection of recommendations for a scan."""

    items: list[Recommendation] = field(default_factory=list)
    proxy_command: str = ""
    server_target: str = ""


# ── Category configs ──────────────────────────────────────────────────

_CATEGORY_CONFIG = {
    "SEC-001": {
        "category": "poisoning",
        "priority": "high",
        "title_tpl": "Investigate poisoning indicators",
        "action": "Review tool descriptions for hidden instructions; consider --deny suspect tools",
        "parser": _parse_sec_tool,
    },
    "SEC-004": {
        "category": "block",
        "priority": "high",
        "title_tpl": "Block dangerous tools",
        "action": "Add --deny rules in the proxy or require user confirmation",
        "parser": _parse_sec_tool,
    },
    "SEC-002": {
        "category": "injection",
        "priority": "high",
        "title_tpl": "Review injection risks",
        "action": "Add maxLength/pattern to schemas, or --deny high-risk tools",
        "parser": _parse_injection,
    },
    "SEC-005": {
        "category": "write_scope",
        "priority": "medium",
        "title_tpl": "Confirm write scope",
        "action": "Require user confirmation for write operations",
        "parser": _parse_sec_tool,
    },
    "SEC-006": {
        "category": "idempotency",
        "priority": "medium",
        "title_tpl": "Add idempotency keys",
        "action": "Add idempotency_key parameter to non-idempotent tools",
        "parser": _parse_sec_tool,
    },
    "SEC-007": {
        "category": "cost",
        "priority": "low",
        "title_tpl": "Monitor cost risks",
        "action": "Set budget alerts and rate limits",
        "parser": _parse_sec_tool,
    },
}

_COMP_CHECKS = {"COMP-008", "COMP-009"}

_MAX_TOOLS_DISPLAY = 5

# ── Generation ────────────────────────────────────────────────────────


def generate_recommendations(report: SuiteReport) -> RecommendationReport:
    """Generate actionable recommendations from check results."""
    sec_tools: dict[str, list[str]] = {}  # check_id -> [tool_names]
    comp_fields: list[str] = []
    comp_check_ids: set[str] = set()

    sec003_failed = False

    for r in report.results:
        if r.outcome not in (Outcome.FAIL, Outcome.WARN):
            continue
        if r.check_id.startswith("ADV-"):
            continue

        # SEC-003 has no details — track separately
        if r.check_id == "SEC-003" and r.outcome == Outcome.FAIL:
            sec003_failed = True
            continue

        if not r.details:
            continue

        if r.check_id in _CATEGORY_CONFIG:
            cfg = _CATEGORY_CONFIG[r.check_id]
            parser = cfg["parser"]
            tools = []
            for d in r.details:
                name = parser(d)
                if name and name not in tools:
                    tools.append(name)
            if tools:
                sec_tools[r.check_id] = tools

        elif r.check_id in _COMP_CHECKS:
            comp_check_ids.add(r.check_id)
            for d in r.details:
                name = _parse_comp_field(d)
                if name and name not in comp_fields:
                    comp_fields.append(name)

    items: list[Recommendation] = []

    # SEC-003 overall score failure — generic recommendation
    if sec003_failed:
        score_val = ""
        for r in report.results:
            if r.check_id == "SEC-003" and r.metadata.get("score") is not None:
                score_val = f" (score {r.metadata['score']:.0f}/100)"
                break
        items.append(Recommendation(
            category="overall",
            priority="high",
            title=f"Low security score{score_val}",
            action="Address the specific findings below to improve the score",
            check_id="SEC-003",
        ))

    # Security recommendations in priority order
    for check_id in ("SEC-001", "SEC-004", "SEC-002", "SEC-005", "SEC-006", "SEC-007"):
        if check_id not in sec_tools:
            continue
        cfg = _CATEGORY_CONFIG[check_id]
        tools = sec_tools[check_id]
        items.append(Recommendation(
            category=cfg["category"],
            priority=cfg["priority"],
            title=f"{cfg['title_tpl']} ({len(tools)} found)",
            action=cfg["action"],
            tools=tools,
            check_id=check_id,
        ))

    # Schema recommendation (merge COMP-008 + COMP-009)
    if comp_fields:
        ids = sorted(comp_check_ids)
        items.append(Recommendation(
            category="schema",
            priority="low",
            title=f"Improve schemas ({len(comp_fields)} fields)",
            action="Add descriptions, maxLength, and pattern constraints to inputSchema fields",
            tools=comp_fields,
            check_id=", ".join(ids),
        ))

    # Proxy command from SEC-004 dangerous tools (base tool names only)
    proxy_cmd = ""
    if "SEC-004" in sec_tools:
        deny_tools = sec_tools["SEC-004"]
        deny_args = " ".join(f"--deny {shlex.quote(t)}" for t in deny_tools)
        target = shlex.quote(report.server_target) if report.server_target else '"server"'
        proxy_cmd = f"mcp-shield proxy {target} {deny_args}"

    return RecommendationReport(
        items=items,
        proxy_command=proxy_cmd,
        server_target=report.server_target,
    )


# ── Serialisation ─────────────────────────────────────────────────────


def recommendations_to_dict(recs: RecommendationReport) -> Dict[str, Any]:
    """Convert RecommendationReport to a plain dict for JSON."""
    return {
        "items": [
            {
                "category": r.category,
                "priority": r.priority,
                "title": r.title,
                "action": r.action,
                "tools": r.tools,
                "check_id": r.check_id,
            }
            for r in recs.items
        ],
        "proxy_command": recs.proxy_command,
    }


# ── Rich rendering ───────────────────────────────────────────────────

_PRIORITY_STYLE = {
    "high": "red bold",
    "medium": "yellow bold",
    "low": "dim bold",
}


def _format_tools_line(tools: list[str]) -> str:
    """Format tool names with truncation at _MAX_TOOLS_DISPLAY."""
    if len(tools) <= _MAX_TOOLS_DISPLAY:
        return ", ".join(tools)
    shown = ", ".join(tools[:_MAX_TOOLS_DISPLAY])
    return f"{shown} (and {len(tools) - _MAX_TOOLS_DISPLAY} more)"


def render_recommendations(recs: RecommendationReport, console: Console) -> None:
    """Render recommendations as Rich output after the score panel."""
    if not recs.items:
        return

    console.rule("Recommendations")
    console.print()

    for idx, rec in enumerate(recs.items, 1):
        style = _PRIORITY_STYLE.get(rec.priority, "")

        # Title line
        title_text = Text(f"  [{idx}] {rec.title} ({rec.check_id})", style=style)
        console.print(title_text)

        # Tools line
        if rec.tools:
            tools_str = _format_tools_line(rec.tools)
            console.print(f"      Tools: {tools_str}", style="dim")

        # Action line
        console.print(f"      Action: {rec.action}")
        console.print()

    # Proxy command panel
    if recs.proxy_command:
        console.print(Panel(
            recs.proxy_command,
            title="Ready-to-use proxy command",
            border_style="green",
        ))
        console.print()
