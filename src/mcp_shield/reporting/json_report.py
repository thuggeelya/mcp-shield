"""JSON reporter — serialises SuiteReport to a machine-readable dict."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from mcp_shield import __version__
from mcp_shield.reporting.recommendations import generate_recommendations, recommendations_to_dict
from mcp_shield.reporting.score import compute_score, grade_label
from mcp_shield.testing.result import SuiteReport, sort_results


def to_dict(report: SuiteReport) -> Dict[str, Any]:
    """Convert a SuiteReport into a plain dict suitable for json.dumps."""
    score = compute_score(report)
    grade = grade_label(score)

    return {
        "version": "1",
        "meta": {
            "mcp_shield_version": __version__,
            "scan_timestamp": report.timestamp,
        },
        "server": {
            "target": report.server_target,
            "name": report.server_name,
            "version": report.server_version,
        },
        "summary": {
            "score": round(score, 1),
            "grade": grade,
            "total": report.total_checks,
            "passed": report.passed,
            "failed": report.failed,
            "warnings": report.warnings,
            "skipped": report.skipped,
            "errors": report.errors,
            "duration_ms": report.duration_ms,
        },
        "timestamp": report.timestamp,
        "results": [
            {
                "check_id": r.check_id,
                "outcome": r.outcome.value,
                "severity": r.severity,
                "message": r.message,
                "duration_ms": r.duration_ms,
                "details": r.details,
                "metadata": r.metadata,
            }
            for r in sort_results(report.results)
        ],
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "risk_tier": t.risk_tier,
            }
            for t in report.tools
        ],
        "recommendations": recommendations_to_dict(generate_recommendations(report)),
    }


def render_json(report: SuiteReport) -> str:
    """Return the report as a pretty-printed JSON string."""
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False)


def write_json(report: SuiteReport, path: str | Path) -> None:
    """Write the JSON report to a file.

    DH-03: Validates output path before writing:
    - Parent directory must exist
    - Path must not contain traversal sequences
    - Resolves symlinks to prevent writes outside intended directory
    """
    p = Path(path)
    resolved = p.resolve()

    # Block obvious traversal attempts
    if ".." in p.parts:
        raise ValueError(
            f"Output path contains '..': {path}. "
            f"Use an absolute path or a path without traversal sequences."
        )

    # Parent directory must exist
    if not resolved.parent.exists():
        raise ValueError(
            f"Parent directory does not exist: {resolved.parent}. "
            f"Create it first or choose a different output path."
        )

    if resolved.is_dir():
        raise ValueError(
            f"Output path is a directory: {resolved}. "
            f"Provide a file path, e.g. {resolved / 'report.json'}"
        )

    resolved.write_text(render_json(report), encoding="utf-8")
