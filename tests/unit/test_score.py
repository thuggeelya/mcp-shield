"""Tests for mcp_shield.reporting.score — compute_score & grade_label.

The composite score blends compliance (COMP-*) at 40% and security
(SEC-003 metadata) at 60%.
"""

from mcp_shield.reporting.score import compute_score, grade_label
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport


def _report(*results: CheckResult) -> SuiteReport:
    r = SuiteReport(server_target="test")
    r.results = list(results)
    r.count()
    return r


def _comp(outcome: Outcome, severity: str = "error") -> CheckResult:
    return CheckResult(
        check_id="COMP-001", outcome=outcome, message="test", severity=severity,
    )


def _sec003(score: float) -> CheckResult:
    return CheckResult(
        check_id="SEC-003", outcome=Outcome.PASS, message="test",
        severity="medium", metadata={"score": score},
    )


class TestComputeScore:
    def test_all_pass_score_100(self):
        report = _report(
            _comp(Outcome.PASS, "critical"),
            _comp(Outcome.PASS, "error"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 100.0
        assert report.score == 100.0

    def test_critical_comp_fail_deducts(self):
        """COMP critical FAIL: comp_score = 80, sec = 100 → 80*0.4 + 100*0.6 = 92"""
        report = _report(
            _comp(Outcome.PASS),
            _comp(Outcome.FAIL, "critical"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 92.0

    def test_error_comp_fail(self):
        """COMP error FAIL: comp_score = 90, sec = 100 → 90*0.4 + 100*0.6 = 96"""
        report = _report(
            _comp(Outcome.FAIL, "error"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 96.0

    def test_warning_comp_fail(self):
        """COMP warning FAIL: comp_score = 97, sec = 100 → 97*0.4 + 100*0.6 = 98.8"""
        report = _report(
            _comp(Outcome.FAIL, "warning"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 98.8

    def test_warn_outcome_half_penalty(self):
        """COMP WARN error: comp_score = 95, sec = 100 → 95*0.4 + 100*0.6 = 98"""
        report = _report(
            _comp(Outcome.WARN, "error"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 98.0

    def test_skip_no_penalty(self):
        report = _report(
            _comp(Outcome.SKIP, "critical"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 100.0

    def test_error_outcome_penalised(self):
        """ERROR outcome treated same as FAIL."""
        report = _report(
            _comp(Outcome.ERROR, "critical"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 92.0  # same as critical FAIL

    def test_score_floors_at_zero(self):
        report = _report(
            *[_comp(Outcome.FAIL, "critical") for _ in range(10)],
            _sec003(0.0),
        )
        score = compute_score(report)
        assert score == 0.0

    def test_info_severity_no_penalty(self):
        report = _report(
            _comp(Outcome.FAIL, "info"),
            _sec003(100.0),
        )
        score = compute_score(report)
        assert score == 100.0

    def test_security_score_dominates(self):
        """Security score 0/100 with perfect compliance → low composite."""
        report = _report(
            _comp(Outcome.PASS, "critical"),
            _sec003(0.0),
        )
        score = compute_score(report)
        # 100*0.4 + 0*0.6 = 40
        assert score == 40.0

    def test_security_score_mid(self):
        """Security 50/100, compliance 100 → 40 + 30 = 70."""
        report = _report(
            _comp(Outcome.PASS),
            _sec003(50.0),
        )
        score = compute_score(report)
        assert score == 70.0

    def test_both_bad(self):
        """Both compliance and security poor."""
        report = _report(
            _comp(Outcome.FAIL, "critical"),
            _comp(Outcome.FAIL, "critical"),
            _sec003(20.0),
        )
        score = compute_score(report)
        # comp = max(0, 100-40) = 60, sec = 20
        # 60*0.4 + 20*0.6 = 24+12 = 36
        assert score == 36.0

    def test_no_sec003_fallback(self):
        """Without SEC-003, fallback to SEC check penalties for security score."""
        sec_warn = CheckResult(
            check_id="SEC-002", outcome=Outcome.WARN, message="test",
            severity="high",
        )
        report = _report(
            _comp(Outcome.PASS),
            sec_warn,
        )
        score = compute_score(report)
        # comp = 100, sec_fallback: high=3.0 penalty, warn *0.5 = 1.5 → sec=98.5
        # 100*0.4 + 98.5*0.6 = 40+59.1 = 99.1
        assert score == 99.1

    def test_no_checks_at_all(self):
        """Empty report → 100."""
        report = _report()
        score = compute_score(report)
        assert score == 100.0


class TestGradeLabel:
    def test_a_plus(self):
        assert grade_label(95) == "A+"
        assert grade_label(100) == "A+"

    def test_a(self):
        assert grade_label(90) == "A"
        assert grade_label(94.9) == "A"

    def test_a_minus(self):
        assert grade_label(85) == "A-"

    def test_b_plus(self):
        assert grade_label(80) == "B+"

    def test_b(self):
        assert grade_label(75) == "B"

    def test_b_minus(self):
        assert grade_label(70) == "B-"

    def test_c_plus(self):
        assert grade_label(65) == "C+"

    def test_c(self):
        assert grade_label(60) == "C"

    def test_d(self):
        assert grade_label(50) == "D"

    def test_f(self):
        assert grade_label(0) == "F"
        assert grade_label(49.9) == "F"

    def test_boundary_exact(self):
        assert grade_label(95.0) == "A+"
        assert grade_label(94.99) == "A"
