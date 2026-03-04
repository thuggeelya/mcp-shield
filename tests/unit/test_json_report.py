"""Tests for mcp_shield.reporting.json_report — JSON serialisation."""

import json
import tempfile
from pathlib import Path

from mcp_shield.reporting.json_report import render_json, to_dict, write_json
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport


def _sample_report() -> SuiteReport:
    r = SuiteReport(
        server_target="python -m test_server",
        server_name="TestServer",
        server_version="0.1.0",
        timestamp="2026-01-01T00:00:00Z",
    )
    r.results = [
        CheckResult("COMP-001", Outcome.PASS, "Handshake OK", severity="critical", duration_ms=10),
        CheckResult("SEC-001", Outcome.FAIL, "Poisoning found", severity="critical", duration_ms=50,
                     details=["hidden block"]),
        CheckResult("SEC-003", Outcome.WARN, "Score low", severity="medium", duration_ms=5,
                     metadata={"score": 60.0}),
    ]
    r.count()
    return r


class TestToDict:
    def test_has_required_keys(self):
        d = to_dict(_sample_report())
        assert "version" in d
        assert "server" in d
        assert "summary" in d
        assert "results" in d
        assert "timestamp" in d
        assert "meta" in d

    def test_version_is_string(self):
        d = to_dict(_sample_report())
        assert d["version"] == "1"

    def test_server_info(self):
        d = to_dict(_sample_report())
        assert d["server"]["name"] == "TestServer"
        assert d["server"]["version"] == "0.1.0"
        assert d["server"]["target"] == "python -m test_server"

    def test_summary_counts(self):
        d = to_dict(_sample_report())
        s = d["summary"]
        assert s["total"] == 3
        assert s["passed"] == 1
        assert s["failed"] == 1
        assert s["warnings"] == 1
        assert s["skipped"] == 0

    def test_summary_score_and_grade(self):
        d = to_dict(_sample_report())
        s = d["summary"]
        assert isinstance(s["score"], float)
        assert 0 <= s["score"] <= 100
        assert isinstance(s["grade"], str)

    def test_results_list(self):
        d = to_dict(_sample_report())
        assert len(d["results"]) == 3

    def test_result_fields(self):
        d = to_dict(_sample_report())
        by_id = {r["check_id"]: r for r in d["results"]}
        comp = by_id["COMP-001"]
        assert comp["outcome"] == "pass"
        assert comp["severity"] == "critical"
        assert comp["duration_ms"] == 10

    def test_result_details_preserved(self):
        d = to_dict(_sample_report())
        by_id = {r["check_id"]: r for r in d["results"]}
        assert by_id["SEC-001"]["details"] == ["hidden block"]

    def test_result_metadata_preserved(self):
        d = to_dict(_sample_report())
        by_id = {r["check_id"]: r for r in d["results"]}
        assert by_id["SEC-003"]["metadata"]["score"] == 60.0

    def test_results_sorted_by_importance(self):
        """Results are sorted: FAIL first, then WARN, then PASS."""
        d = to_dict(_sample_report())
        outcomes = [r["outcome"] for r in d["results"]]
        assert outcomes == ["fail", "warn", "pass"]

    def test_serialisable_to_json(self):
        d = to_dict(_sample_report())
        text = json.dumps(d)
        parsed = json.loads(text)
        assert parsed["version"] == "1"


class TestRenderJson:
    def test_valid_json(self):
        text = render_json(_sample_report())
        parsed = json.loads(text)
        assert parsed["version"] == "1"

    def test_pretty_printed(self):
        text = render_json(_sample_report())
        assert "\n" in text  # indented


class TestToDict_Meta:
    """AO-03: Scan metadata in JSON report."""

    def test_meta_has_version(self):
        d = to_dict(_sample_report())
        from mcp_shield import __version__
        assert d["meta"]["mcp_shield_version"] == __version__

    def test_meta_has_scan_timestamp(self):
        d = to_dict(_sample_report())
        assert d["meta"]["scan_timestamp"] == "2026-01-01T00:00:00Z"


class TestWriteJson:
    def test_writes_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            write_json(_sample_report(), path)
            assert path.exists()
            parsed = json.loads(path.read_text())
            assert parsed["version"] == "1"
            assert len(parsed["results"]) == 3

    def test_traversal_path_rejected(self):
        """DH-03: Paths containing '..' should be rejected."""
        import pytest
        with pytest.raises(ValueError, match="\\.\\."):
            write_json(_sample_report(), "/tmp/../etc/report.json")

    def test_nonexistent_parent_rejected(self):
        """DH-03: Parent directory must exist."""
        import pytest
        with pytest.raises(ValueError, match="does not exist"):
            write_json(_sample_report(), "/nonexistent/dir/report.json")

    def test_directory_path_rejected(self):
        """Output path that is a directory must be rejected."""
        import pytest
        with pytest.raises(ValueError, match="is a directory"):
            write_json(_sample_report(), "/tmp")
