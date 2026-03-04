"""SARIF 2.1.0 reporter — converts SuiteReport to SARIF for GitHub Code Scanning.

Generates a Static Analysis Results Interchange Format (SARIF) log file
that can be uploaded to GitHub's Security tab via ``codeql-action/upload-sarif``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_shield import __version__
from mcp_shield.reporting.score import compute_score, grade_label
from mcp_shield.security.cwe import cwe_for_check
from mcp_shield.testing.result import Outcome, SuiteReport

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# ── Mappings ─────────────────────────────────────────────────────────

# Human-readable check names for SARIF rules
_CHECK_NAMES: dict[str, str] = {
    "SEC-001": "ToolPoisoning",
    "SEC-002": "InjectionRisk",
    "SEC-003": "OverallSecurityScore",
    "SEC-004": "DangerousOperation",
    "SEC-005": "WriteScope",
    "SEC-006": "IdempotencyRisk",
    "SEC-007": "CostQuotaRisk",
    "COMP-001": "ProtocolHandshake",
    "COMP-002": "ToolDiscovery",
    "COMP-003": "ToolSchema",
    "COMP-004": "ToolNaming",
    "COMP-005": "ToolDescription",
    "COMP-006": "ErrorHandling",
    "COMP-007": "ResponseFormat",
    "COMP-008": "FieldDescriptions",
    "COMP-009": "SchemaConstraints",
    "COMP-010": "ResourcesPrompts",
    "ADV-001": "AuthHints",
    "ADV-002": "ExternalDependencies",
    "ADV-003": "BulkOperations",
    "ADV-004": "SensitiveData",
    "ADV-005": "NetworkAccess",
}


def _outcome_to_level(outcome: Outcome) -> str:
    """Map check outcome to SARIF level."""
    if outcome in (Outcome.FAIL, Outcome.ERROR):
        return "error"
    if outcome is Outcome.WARN:
        return "warning"
    return "note"


def _severity_to_cvss(severity: str) -> str:
    """Map severity string to a CVSS-like numeric score for SARIF."""
    mapping = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "2.0",
        "info": "1.0",
    }
    return mapping.get(severity, "1.0")


# Regex to extract tool name from detail lines like "  [high] Title: tool_name"
_RE_TOOL_FROM_DETAIL = re.compile(r"^\s*\[\w+\]\s+.+:\s+(\S+)\s*$")


def _extract_tool_names(result: Any) -> list[str]:
    """Extract tool names from check result details."""
    tools: list[str] = []
    for d in getattr(result, "details", []) or []:
        m = _RE_TOOL_FROM_DETAIL.match(d)
        if m:
            name = m.group(1)
            # Strip dotted field suffix (e.g. "tool.field" → "tool")
            base = name.split(".")[0] if "." in name else name
            if base and base not in tools:
                tools.append(base)
    return tools


# ── SARIF generation ─────────────────────────────────────────────────


def to_sarif(report: SuiteReport) -> dict[str, Any]:
    """Convert SuiteReport to SARIF 2.1.0 LogFile dict."""
    compute_score(report)  # ensure score is computed

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    server_name = report.server_name or report.server_target or "unknown"

    for r in report.results:
        # Only emit results for FAIL/WARN/ERROR
        if r.outcome not in (Outcome.FAIL, Outcome.WARN, Outcome.ERROR):
            continue

        check_id = r.check_id

        # Build rule (once per check_id)
        if check_id not in seen_rules:
            seen_rules.add(check_id)
            cwe_ids = r.metadata.get("cwe_ids", []) if r.metadata else []
            if not cwe_ids:
                cwe_ids = cwe_for_check(check_id)

            rule: dict[str, Any] = {
                "id": check_id,
                "name": _CHECK_NAMES.get(check_id, check_id),
                "shortDescription": {"text": r.message},
                "defaultConfiguration": {"level": _outcome_to_level(r.outcome)},
                "helpUri": f"https://github.com/thuggeelya/mcp-shield/blob/main/docs/checks.md#{check_id.lower()}",
                "properties": {
                    "security-severity": _severity_to_cvss(r.severity),
                },
            }

            # CWE relationships
            if cwe_ids:
                relationships = []
                for cwe_id in cwe_ids:
                    cwe_num = cwe_id.replace("CWE-", "")
                    relationships.append({
                        "target": {
                            "id": cwe_num,
                            "guid": f"CWE-{cwe_num}",
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["superset"],
                    })
                rule["relationships"] = relationships

            rules.append(rule)

        # Build result
        tool_names = _extract_tool_names(r)

        locations: list[dict[str, Any]] = []
        if tool_names:
            for tool_name in tool_names:
                locations.append({
                    "logicalLocations": [{
                        "name": tool_name,
                        "fullyQualifiedName": f"mcp://{server_name}/{tool_name}",
                        "kind": "function",
                    }],
                })
        else:
            # No specific tool — use server as location
            locations.append({
                "logicalLocations": [{
                    "name": server_name,
                    "fullyQualifiedName": f"mcp://{server_name}",
                    "kind": "module",
                }],
            })

        sarif_result: dict[str, Any] = {
            "ruleId": check_id,
            "level": _outcome_to_level(r.outcome),
            "message": {"text": r.message},
            "locations": locations,
        }
        results.append(sarif_result)

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-shield",
                    "version": __version__,
                    "informationUri": "https://github.com/thuggeelya/mcp-shield",
                    "rules": rules,
                    "supportedTaxonomies": [{"name": "CWE", "version": "4.14"}],
                },
            },
            "results": results,
            "taxonomies": [{
                "name": "CWE",
                "version": "4.14",
                "organization": "MITRE",
                "informationUri": "https://cwe.mitre.org/",
                "comprehensive": False,
            }],
        }],
    }


def render_sarif(report: SuiteReport) -> str:
    """Return SARIF as pretty-printed JSON string."""
    return json.dumps(to_sarif(report), indent=2, ensure_ascii=False)


def write_sarif(report: SuiteReport, path: str | Path) -> None:
    """Write SARIF report to file.

    Same path validation as write_json — blocks traversal and
    requires existing parent directory.
    """
    p = Path(path)
    resolved = p.resolve()

    if ".." in p.parts:
        raise ValueError(
            f"Output path contains '..': {path}. "
            f"Use an absolute path or a path without traversal sequences."
        )

    if not resolved.parent.exists():
        raise ValueError(
            f"Parent directory does not exist: {resolved.parent}. "
            f"Create it first or choose a different output path."
        )

    if resolved.is_dir():
        raise ValueError(
            f"Output path is a directory: {resolved}. "
            f"Provide a file path, e.g. {resolved / 'report.sarif'}"
        )

    resolved.write_text(render_sarif(report), encoding="utf-8")
