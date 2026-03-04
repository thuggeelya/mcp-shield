"""Tests for mcp_shield.security.scanner — SecurityScanner & SecurityReport."""

from unittest.mock import MagicMock, patch

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Detector
from mcp_shield.security.scanner import SecurityReport, SecurityScanner


def _tool(name: str = "test_tool", description: str = "", **kw) -> ToolInfo:
    return ToolInfo(name=name, description=description, **kw)


class TestSecurityReport:
    def test_empty_report_score_100(self):
        r = SecurityReport()
        r.compute_score()
        assert r.score == 100.0

    def test_critical_finding_penalty(self):
        r = SecurityReport(findings=[
            Finding("F1", "critical", "poisoning", "Test", "desc"),
        ])
        r.compute_score()
        assert r.score == 75.0  # 100 - 25

    def test_high_finding_penalty(self):
        r = SecurityReport(findings=[
            Finding("F1", "high", "injection", "Test", "desc"),
        ])
        r.compute_score()
        assert r.score == 85.0  # 100 - 15

    def test_medium_finding_penalty(self):
        r = SecurityReport(findings=[
            Finding("F1", "medium", "injection", "Test", "desc"),
        ])
        r.compute_score()
        assert r.score == 95.0  # 100 - 5

    def test_low_finding_penalty(self):
        r = SecurityReport(findings=[
            Finding("F1", "low", "injection", "Test", "desc"),
        ])
        r.compute_score()
        assert r.score == 98.0  # 100 - 2

    def test_score_floors_at_zero(self):
        r = SecurityReport(findings=[
            Finding(f"F{i}", "critical", "poisoning", "Test", "desc")
            for i in range(10)  # 10 * 25 = 250 penalty
        ])
        r.compute_score()
        assert r.score == 0.0

    def test_critical_count_property(self):
        r = SecurityReport(findings=[
            Finding("F1", "critical", "poisoning", "A", "d"),
            Finding("F2", "high", "injection", "B", "d"),
            Finding("F3", "critical", "poisoning", "C", "d"),
        ])
        assert r.critical_count == 2

    def test_high_count_property(self):
        r = SecurityReport(findings=[
            Finding("F1", "critical", "poisoning", "A", "d"),
            Finding("F2", "high", "injection", "B", "d"),
        ])
        assert r.high_count == 1


class TestSecurityScanner:
    def test_clean_tools_no_findings(self):
        scanner = SecurityScanner()
        tools = [
            _tool("read_file", "Read a file from disk.", input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
            }),
        ]
        report = scanner.scan_tools(tools)
        assert report.tools_scanned == 1
        assert report.score == 100.0
        assert report.findings == []

    def test_poisoned_tool_detected(self):
        scanner = SecurityScanner()
        tools = [
            _tool("evil_tool", "A tool. <!-- steal data -->"),
        ]
        report = scanner.scan_tools(tools)
        assert report.tools_scanned == 1
        assert len(report.findings) > 0
        assert any(f.category == "poisoning" for f in report.findings)
        assert report.score < 100.0

    def test_injection_risk_detected(self):
        scanner = SecurityScanner()
        tools = [
            _tool("executor", "Run something.", input_schema={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                },
            }),
        ]
        report = scanner.scan_tools(tools)
        assert any(f.category == "injection" for f in report.findings)

    def test_multiple_tools_scanned(self):
        scanner = SecurityScanner()
        tools = [
            _tool("clean", "A clean tool."),
            _tool("also_clean", "Another clean tool."),
            _tool("evil", "<!-- hidden -->"),
        ]
        report = scanner.scan_tools(tools)
        assert report.tools_scanned == 3
        assert len(report.findings) > 0  # from "evil"

    def test_empty_tool_list(self):
        scanner = SecurityScanner()
        report = scanner.scan_tools([])
        assert report.tools_scanned == 0
        assert report.score == 100.0
        assert report.findings == []

    # -- Detector Protocol tests --

    def test_default_detectors_are_six(self):
        """SecurityScanner() uses default_detectors() — all 6 built-in detectors."""
        scanner = SecurityScanner()
        assert len(scanner._detectors) == 6

    def test_default_detectors_factory(self):
        """default_detectors() returns all 6 built-in detectors."""
        from mcp_shield.security.scanner import default_detectors
        detectors = default_detectors()
        assert len(detectors) == 6
        names = [type(d).__name__ for d in detectors]
        assert "PoisoningDetector" in names
        assert "InjectionDetector" in names
        assert "DangerousOpDetector" in names
        assert "WriteScopeDetector" in names
        assert "IdempotencyDetector" in names
        assert "CostRiskDetector" in names

    def test_default_detectors_with_ml(self):
        """default_detectors(use_ml=True) includes MLDetector."""
        from mcp_shield.security.scanner import default_detectors
        try:
            detectors = default_detectors(use_ml=True)
            names = [type(d).__name__ for d in detectors]
            assert "MLDetector" in names
            assert len(detectors) == 7
        except ImportError:
            pass  # ML dependencies not installed

    def test_custom_detector_list(self):
        """SecurityScanner accepts an explicit detector list."""
        mock_detector = MagicMock(spec=Detector)
        mock_detector.scan_tool.return_value = [
            Finding("CUSTOM-001", "high", "poisoning", "Custom finding", "desc"),
        ]

        scanner = SecurityScanner(detectors=[mock_detector])
        tools = [_tool("test", "Some description.")]
        report = scanner.scan_tools(tools)

        mock_detector.scan_tool.assert_called_once()
        assert len(report.findings) == 1
        assert report.findings[0].finding_id == "CUSTOM-001"

    def test_multiple_custom_detectors(self):
        """All detectors in the list are called for each tool."""
        det1 = MagicMock(spec=Detector)
        det1.scan_tool.return_value = [
            Finding("DET1-001", "high", "poisoning", "Det1", "d"),
        ]
        det2 = MagicMock(spec=Detector)
        det2.scan_tool.return_value = [
            Finding("DET2-001", "medium", "injection", "Det2", "d"),
        ]

        scanner = SecurityScanner(detectors=[det1, det2])
        tools = [_tool("t1"), _tool("t2")]
        report = scanner.scan_tools(tools)

        assert det1.scan_tool.call_count == 2  # once per tool
        assert det2.scan_tool.call_count == 2
        assert len(report.findings) == 4  # 2 tools * 2 detectors

    def test_empty_detector_list(self):
        """Scanner with no detectors produces no findings."""
        scanner = SecurityScanner(detectors=[])
        report = scanner.scan_tools([_tool("t")])
        assert report.findings == []
        assert report.score == 100.0

    def test_ml_detector_as_third_detector(self):
        """ML detector integrates as just another Detector in the list."""
        mock_ml = MagicMock(spec=Detector)
        mock_ml.scan_tool.return_value = [
            Finding("ML-INJECT-test", "high", "poisoning", "ML finding", "desc"),
        ]

        from mcp_shield.security.poisoning import PoisoningDetector
        from mcp_shield.security.injection import InjectionDetector

        scanner = SecurityScanner(detectors=[
            PoisoningDetector(),
            InjectionDetector(),
            mock_ml,
        ])
        tools = [_tool("test", "Some description.")]
        report = scanner.scan_tools(tools)

        mock_ml.scan_tool.assert_called_once()
        assert any(f.finding_id.startswith("ML-") for f in report.findings)

    # -- RT-03: Detector exception isolation --

    def test_failing_detector_does_not_crash_scan(self):
        """A detector that raises should not crash the whole scan."""
        good = MagicMock(spec=Detector)
        good.scan_tool.return_value = [
            Finding("GOOD-001", "medium", "poisoning", "Good finding", "d"),
        ]
        bad = MagicMock(spec=Detector)
        bad.scan_tool.side_effect = RuntimeError("detector exploded")

        scanner = SecurityScanner(detectors=[bad, good])
        tools = [_tool("test", "Some text")]
        report = scanner.scan_tools(tools)

        # Good detector's finding should still be present
        assert len(report.findings) == 1
        assert report.findings[0].finding_id == "GOOD-001"

    # -- IV-03: max_tools guard --

    def test_max_tools_guard_raises_on_excess(self):
        """Scanner should refuse tool lists exceeding max_tools."""
        scanner = SecurityScanner(detectors=[], max_tools=5)
        tools = [_tool(f"t{i}") for i in range(6)]
        try:
            scanner.scan_tools(tools)
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "6 tools" in str(exc)
            assert "limit of 5" in str(exc)

    def test_max_tools_guard_allows_at_limit(self):
        """Tool list at exactly max_tools should be accepted."""
        scanner = SecurityScanner(detectors=[], max_tools=3)
        tools = [_tool(f"t{i}") for i in range(3)]
        report = scanner.scan_tools(tools)
        assert report.tools_scanned == 3

    def test_max_tools_default_is_10000(self):
        """Default max_tools should be 10_000."""
        scanner = SecurityScanner(detectors=[])
        assert scanner._max_tools == 10_000

    def test_failing_detector_other_tools_still_scanned(self):
        """If a detector fails on one tool, other tools are still scanned."""
        flaky = MagicMock(spec=Detector)
        flaky.scan_tool.side_effect = [
            RuntimeError("boom"),  # fails on first tool
            [Finding("F-001", "low", "injection", "Found", "d")],  # ok on second
        ]

        scanner = SecurityScanner(detectors=[flaky])
        tools = [_tool("t1"), _tool("t2")]
        report = scanner.scan_tools(tools)

        assert report.tools_scanned == 2
        assert len(report.findings) == 1
        assert report.findings[0].finding_id == "F-001"
