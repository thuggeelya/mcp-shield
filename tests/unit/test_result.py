"""Tests for mcp_shield.testing.result — CheckResult & SuiteReport."""

from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport, sort_results


class TestOutcome:
    def test_values(self):
        assert Outcome.PASS.value == "pass"
        assert Outcome.FAIL.value == "fail"
        assert Outcome.WARN.value == "warn"
        assert Outcome.SKIP.value == "skip"
        assert Outcome.ERROR.value == "error"

    def test_is_string_enum(self):
        assert isinstance(Outcome.PASS, str)
        assert Outcome.PASS == "pass"


class TestCheckResult:
    def test_defaults(self):
        r = CheckResult(check_id="T-001", outcome=Outcome.PASS, message="ok")
        assert r.severity == "error"
        assert r.duration_ms == 0
        assert r.details == []
        assert r.metadata == {}

    def test_all_fields(self):
        r = CheckResult(
            check_id="T-002",
            outcome=Outcome.FAIL,
            message="broken",
            severity="critical",
            duration_ms=42,
            details=["line 1", "line 2"],
            metadata={"key": "value"},
        )
        assert r.check_id == "T-002"
        assert r.outcome is Outcome.FAIL
        assert r.duration_ms == 42
        assert len(r.details) == 2


class TestSuiteReport:
    def test_count_all_pass(self):
        r = SuiteReport(server_target="test")
        r.results = [
            CheckResult("A", Outcome.PASS, "ok"),
            CheckResult("B", Outcome.PASS, "ok"),
        ]
        r.count()
        assert r.total_checks == 2
        assert r.passed == 2
        assert r.failed == 0
        assert r.warnings == 0
        assert r.skipped == 0
        assert r.errors == 0

    def test_count_mixed(self):
        r = SuiteReport(server_target="test")
        r.results = [
            CheckResult("A", Outcome.PASS, "ok"),
            CheckResult("B", Outcome.FAIL, "bad"),
            CheckResult("C", Outcome.WARN, "meh"),
            CheckResult("D", Outcome.SKIP, "skip"),
            CheckResult("E", Outcome.ERROR, "crash"),
        ]
        r.count()
        assert r.total_checks == 5
        assert r.passed == 1
        assert r.failed == 1
        assert r.warnings == 1
        assert r.skipped == 1
        assert r.errors == 1

    def test_empty_report(self):
        r = SuiteReport(server_target="test")
        r.count()
        assert r.total_checks == 0
        assert r.passed == 0

    def test_server_fields(self):
        r = SuiteReport(
            server_target="http://localhost:8080",
            server_name="MyServer",
            server_version="1.2.3",
        )
        assert r.server_name == "MyServer"
        assert r.server_version == "1.2.3"


class TestSortResults:
    def test_empty_list(self):
        assert sort_results([]) == []

    def test_single_result(self):
        r = CheckResult("A", Outcome.PASS, "ok")
        assert sort_results([r]) == [r]

    def test_outcome_order(self):
        """FAIL < ERROR < WARN < PASS < SKIP."""
        skip = CheckResult("S", Outcome.SKIP, "skip", severity="info")
        pass_ = CheckResult("P", Outcome.PASS, "ok", severity="info")
        warn = CheckResult("W", Outcome.WARN, "warn", severity="warning")
        error = CheckResult("E", Outcome.ERROR, "err", severity="error")
        fail = CheckResult("F", Outcome.FAIL, "fail", severity="critical")

        shuffled = [pass_, skip, warn, fail, error]
        result = sort_results(shuffled)
        assert [r.check_id for r in result] == ["F", "E", "W", "P", "S"]

    def test_severity_within_same_outcome(self):
        """Within WARN: critical < error < warning < info."""
        w_info = CheckResult("W4", Outcome.WARN, "i", severity="info")
        w_warn = CheckResult("W3", Outcome.WARN, "w", severity="warning")
        w_err = CheckResult("W2", Outcome.WARN, "e", severity="error")
        w_crit = CheckResult("W1", Outcome.WARN, "c", severity="critical")

        result = sort_results([w_info, w_warn, w_err, w_crit])
        assert [r.check_id for r in result] == ["W1", "W2", "W3", "W4"]

    def test_fail_severities_before_warn(self):
        """All FAILs come before all WARNs regardless of severity."""
        fail_info = CheckResult("F-i", Outcome.FAIL, "f", severity="info")
        warn_crit = CheckResult("W-c", Outcome.WARN, "w", severity="critical")

        result = sort_results([warn_crit, fail_info])
        assert [r.check_id for r in result] == ["F-i", "W-c"]

    def test_mixed_realistic(self):
        """Realistic mix: FAIL/critical first, PASS/SKIP last."""
        results = [
            CheckResult("COMP-001", Outcome.PASS, "ok", severity="error"),
            CheckResult("SEC-004", Outcome.FAIL, "danger", severity="critical"),
            CheckResult("ADV-001", Outcome.PASS, "ok", severity="info"),
            CheckResult("SEC-005", Outcome.WARN, "scope", severity="warning"),
            CheckResult("COMP-002", Outcome.SKIP, "n/a", severity="info"),
            CheckResult("SEC-001", Outcome.FAIL, "inject", severity="error"),
        ]
        sorted_ = sort_results(results)
        ids = [r.check_id for r in sorted_]
        assert ids == [
            "SEC-004",   # FAIL/critical
            "SEC-001",   # FAIL/error
            "SEC-005",   # WARN/warning
            "COMP-001",  # PASS/error
            "ADV-001",   # PASS/info
            "COMP-002",  # SKIP/info
        ]

    def test_does_not_mutate_original(self):
        """sort_results returns a new list, does not modify the input."""
        original = [
            CheckResult("B", Outcome.PASS, "ok"),
            CheckResult("A", Outcome.FAIL, "bad"),
        ]
        original_ids = [r.check_id for r in original]
        sort_results(original)
        assert [r.check_id for r in original] == original_ids

    def test_unknown_severity_sorts_last(self):
        """Unknown severity values sort after known ones within same outcome."""
        known = CheckResult("K", Outcome.WARN, "w", severity="info")
        unknown = CheckResult("U", Outcome.WARN, "w", severity="custom")
        result = sort_results([unknown, known])
        assert [r.check_id for r in result] == ["K", "U"]
