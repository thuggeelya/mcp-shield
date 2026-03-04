"""Security scan checks (SEC-001 .. SEC-007).

All checks read a pre-computed ``SecurityReport`` from the
``ScanConfig`` ContextVar.  The Runner populates it once before
executing check functions — no global cache needed.
"""

from __future__ import annotations

from typing import Callable

from mcp import ClientSession

from mcp_shield.security.cwe import cwe_for_check
from mcp_shield.security.scanner import scan_config
from mcp_shield.testing.registry import check
from mcp_shield.testing.result import CheckResult, Outcome


def _sev(severity: str) -> str:
    """Return the string value of a severity (handles both Enum and str)."""
    return severity.value if hasattr(severity, "value") else severity


def _get_report():
    """Read the SecurityReport from the current ScanConfig.

    Returns ``None`` if the Runner has not yet populated it.
    """
    return scan_config.get().report


# ── Category check factory ────────────────────────────────────────────


def _category_check(
    check_id: str,
    category: str,
    *,
    found_label: str,
    pass_label: str,
    fail_on_high: bool = False,
) -> Callable:
    """Create a check function that filters findings by category.

    Eliminates boilerplate for SEC-002, SEC-004..007 which share
    identical structure: filter → WARN/FAIL → PASS.

    Parameters
    ----------
    check_id:
        The check identifier (e.g. "SEC-004").
    category:
        Finding category to filter on (e.g. "dangerous_op").
    found_label:
        Label for the "found N" message (e.g. "dangerous operation").
    pass_label:
        Label for the "no X across N tools" message.
    fail_on_high:
        If True, escalate to FAIL when any finding has severity "high".
    """

    async def _check(session: ClientSession) -> CheckResult:
        report = _get_report()

        if report is None or report.tools_scanned == 0:
            return CheckResult(
                check_id=check_id,
                outcome=Outcome.SKIP,
                message="No tools to scan",
                severity=_check._severity,  # type: ignore[attr-defined]
            )

        matches = [f for f in report.findings if f.category == category]

        if matches:
            outcome = Outcome.WARN
            if fail_on_high and any(f.severity == "high" for f in matches):
                outcome = Outcome.FAIL
            return CheckResult(
                check_id=check_id,
                outcome=outcome,
                message=f"Found {len(matches)} {found_label}(s)",
                severity=_check._severity,  # type: ignore[attr-defined]
                details=[f"  [{_sev(f.severity)}] {f.title}" for f in matches],
                metadata={"cwe_ids": cwe_for_check(check_id)},
            )

        return CheckResult(
            check_id=check_id,
            outcome=Outcome.PASS,
            message=f"No {pass_label} across {report.tools_scanned} tools",
            severity=_check._severity,  # type: ignore[attr-defined]
        )

    _check.__name__ = f"check_{category}"
    _check.__doc__ = f"Check for {found_label} findings."
    return _check


# ── SEC-001 ───────────────────────────────────────────────────────────

@check("security", "SEC-001", severity="critical")
async def check_tool_poisoning(session: ClientSession) -> CheckResult:
    """Scan all tool descriptions for hidden malicious instructions."""
    report = _get_report()

    if report is None or report.tools_scanned == 0:
        return CheckResult(
            check_id="SEC-001",
            outcome=Outcome.SKIP,
            message="No tools to scan",
            severity="critical",
        )

    poisoning = [f for f in report.findings if f.category == "poisoning"]

    if poisoning:
        # Length-only findings (LOW severity) are informational — they
        # indicate "check with ML" rather than confirmed poisoning.
        # FAIL only when there are pattern-match findings (MEDIUM+).
        has_pattern_match = any(f.severity != "low" for f in poisoning)
        outcome = Outcome.FAIL if has_pattern_match else Outcome.WARN
        return CheckResult(
            check_id="SEC-001",
            outcome=outcome,
            message=f"Found {len(poisoning)} poisoning indicator(s)",
            severity="critical",
            details=[
                f"  [{_sev(f.severity)}] {f.title}"
                + (f': "{f.evidence[:80]}"' if f.evidence else "")
                for f in poisoning
            ],
            metadata={"cwe_ids": cwe_for_check("SEC-001")},
        )

    return CheckResult(
        check_id="SEC-001",
        outcome=Outcome.PASS,
        message=f"No poisoning detected across {report.tools_scanned} tools",
        severity="critical",
    )


# ── SEC-002 ───────────────────────────────────────────────────────────

check_injection_vectors = check("security", "SEC-002", severity="high")(
    _category_check(
        "SEC-002", "injection",
        found_label="potential injection vector",
        pass_label="injection risks found",
    )
)

# ── SEC-003 ───────────────────────────────────────────────────────────

@check("security", "SEC-003", severity="medium")
async def check_security_score(session: ClientSession) -> CheckResult:
    """Compute an overall security score for the server."""
    report = _get_report()

    if report is None:
        return CheckResult(
            check_id="SEC-003",
            outcome=Outcome.SKIP,
            message="No security report available",
            severity="medium",
        )

    outcome = Outcome.PASS
    if report.score < 50:
        outcome = Outcome.FAIL
    elif report.score < 80:
        outcome = Outcome.WARN

    return CheckResult(
        check_id="SEC-003",
        outcome=outcome,
        message=f"Security score: {report.score:.0f}/100 ({len(report.findings)} finding(s))",
        severity="medium",
        metadata={"score": report.score, "findings_count": len(report.findings), "cwe_ids": cwe_for_check("SEC-003")},
    )


# ── SEC-004 ───────────────────────────────────────────────────────────

check_dangerous_operations = check("security", "SEC-004", severity="medium")(
    _category_check(
        "SEC-004", "dangerous_op",
        found_label="dangerous operation",
        pass_label="dangerous operations detected",
        fail_on_high=True,
    )
)

# ── SEC-005 ───────────────────────────────────────────────────────────

check_write_scope = check("security", "SEC-005", severity="medium")(
    _category_check(
        "SEC-005", "write_scope",
        found_label="write scope concern",
        pass_label="write scope concerns",
    )
)

# ── SEC-006 ───────────────────────────────────────────────────────────

check_idempotency_risk = check("security", "SEC-006", severity="medium")(
    _category_check(
        "SEC-006", "idempotency",
        found_label="non-idempotent operation",
        pass_label="idempotency risks",
    )
)

# ── SEC-007 ───────────────────────────────────────────────────────────

check_cost_risk = check("security", "SEC-007", severity="medium")(
    _category_check(
        "SEC-007", "cost_risk",
        found_label="cost/quota risk",
        pass_label="cost risks",
    )
)
