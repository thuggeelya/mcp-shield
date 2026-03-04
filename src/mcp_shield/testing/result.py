"""Test result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Outcome(str, Enum):
    """Possible outcomes for a single check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"  # the check itself crashed (not a server failure)


_OUTCOME_ORDER = {Outcome.FAIL: 0, Outcome.ERROR: 1, Outcome.WARN: 2, Outcome.PASS: 3, Outcome.SKIP: 4}
_SEVERITY_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3}


def sort_results(results: List[CheckResult]) -> List[CheckResult]:
    """Sort results by descending importance: outcome first, then severity."""
    return sorted(results, key=lambda r: (
        _OUTCOME_ORDER.get(r.outcome, 9),
        _SEVERITY_ORDER.get(r.severity, 9),
    ))


@dataclass
class CheckResult:
    """Result of a single compliance or security check."""

    check_id: str
    outcome: Outcome
    message: str
    severity: str = "error"  # critical | error | warning | info
    duration_ms: int = 0
    details: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolSummary:
    """Summary of a single MCP tool discovered on the server."""

    name: str
    description: str = ""
    risk_tier: str = "unknown"  # read | write_reversible | write_external | write_sensitive | unknown


@dataclass
class SuiteReport:
    """Aggregated results from all check suites."""

    server_target: str
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    results: List[CheckResult] = field(default_factory=list)
    tools: List[ToolSummary] = field(default_factory=list)
    score: float = 0.0
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    skipped: int = 0
    errors: int = 0
    duration_ms: int = 0
    timestamp: str = ""

    def count(self) -> None:
        """Recompute counters from *results*."""
        self.total_checks = len(self.results)
        self.passed = sum(1 for r in self.results if r.outcome is Outcome.PASS)
        self.failed = sum(1 for r in self.results if r.outcome is Outcome.FAIL)
        self.warnings = sum(1 for r in self.results if r.outcome is Outcome.WARN)
        self.skipped = sum(1 for r in self.results if r.outcome is Outcome.SKIP)
        self.errors = sum(1 for r in self.results if r.outcome is Outcome.ERROR)
