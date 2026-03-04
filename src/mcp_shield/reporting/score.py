"""Scoring algorithm — converts check results into a 0-100 grade.

The composite score blends compliance checks (COMP-*) with the
security sub-score produced by SEC-003.  This prevents a server
with 33 injection vectors from getting an A just because there is
only one SEC-002 WARN check result.
"""

from __future__ import annotations

from mcp_shield.testing.result import Outcome, SuiteReport


# Letter grades
_GRADES = [
    (95, "A+"),
    (90, "A"),
    (85, "A-"),
    (80, "B+"),
    (75, "B"),
    (70, "B-"),
    (65, "C+"),
    (60, "C"),
    (50, "D"),
    (0, "F"),
]

# Points deducted per failure severity (for compliance checks)
_SEVERITY_PENALTY = {
    "critical": 20.0,
    "error": 10.0,
    "warning": 3.0,
    "info": 0.0,
}

# Compliance contributes 40%, security 60%
_COMPLIANCE_WEIGHT = 0.4
_SECURITY_WEIGHT = 0.6


def compute_score(report: SuiteReport) -> float:
    """Compute a weighted composite score (0-100).

    Blends compliance sub-score (COMP-* checks) with the security
    sub-score from SEC-003 metadata.  If SEC-003 is absent, falls
    back to the old penalty-only algorithm.
    """
    # Separate compliance and security results
    compliance_results = [r for r in report.results if r.check_id.startswith("COMP-")]
    sec003 = next((r for r in report.results if r.check_id == "SEC-003"), None)

    # Compliance sub-score (penalty-based on COMP checks only)
    comp_penalty = 0.0
    for r in compliance_results:
        if r.outcome in (Outcome.FAIL, Outcome.ERROR):
            comp_penalty += _SEVERITY_PENALTY.get(r.severity, 5.0)
        elif r.outcome is Outcome.WARN:
            comp_penalty += _SEVERITY_PENALTY.get(r.severity, 3.0) * 0.5
    compliance_score = max(0.0, 100.0 - comp_penalty)

    # Security sub-score from SEC-003 metadata
    if sec003 and sec003.metadata and "score" in sec003.metadata:
        security_score = float(sec003.metadata["score"])
    else:
        # Fallback: use SEC-* check outcomes
        sec_penalty = 0.0
        for r in report.results:
            if not r.check_id.startswith("SEC-"):
                continue
            if r.outcome in (Outcome.FAIL, Outcome.ERROR):
                sec_penalty += _SEVERITY_PENALTY.get(r.severity, 5.0)
            elif r.outcome is Outcome.WARN:
                sec_penalty += _SEVERITY_PENALTY.get(r.severity, 3.0) * 0.5
        security_score = max(0.0, 100.0 - sec_penalty)

    composite = compliance_score * _COMPLIANCE_WEIGHT + security_score * _SECURITY_WEIGHT
    report.score = round(max(0.0, composite), 1)
    return report.score


def grade_label(score: float) -> str:
    """Return a letter grade for the given score."""
    for threshold, label in _GRADES:
        if score >= threshold:
            return label
    return "F"
