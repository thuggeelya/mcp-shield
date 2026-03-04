"""Tests for mcp_shield.testing.registry — @check decorator & registry."""

from mcp_shield.testing.registry import get_suite, get_suites, _suites


class TestRegistry:
    def test_suites_loaded(self):
        """The compliance, security, and advisory suites should be registered."""
        # runner.py imports trigger registration, but we import registry
        # which may not have triggered them yet — import runner to be safe.
        import mcp_shield.testing.runner  # noqa: F401

        suites = get_suites()
        assert "compliance" in suites
        assert "security" in suites
        assert "advisory" in suites

    def test_compliance_has_checks(self):
        import mcp_shield.testing.runner  # noqa: F401

        checks = get_suite("compliance")
        assert len(checks) >= 10  # COMP-001 through COMP-010

    def test_security_has_checks(self):
        import mcp_shield.testing.runner  # noqa: F401

        checks = get_suite("security")
        assert len(checks) >= 7  # SEC-001 through SEC-007

    def test_advisory_has_checks(self):
        import mcp_shield.testing.runner  # noqa: F401

        checks = get_suite("advisory")
        assert len(checks) >= 5  # ADV-001 through ADV-005

    def test_check_functions_have_metadata(self):
        import mcp_shield.testing.runner  # noqa: F401

        for fn in get_suite("compliance"):
            assert hasattr(fn, "_check_id"), f"{fn.__name__} missing _check_id"
            assert hasattr(fn, "_severity"), f"{fn.__name__} missing _severity"
            assert hasattr(fn, "_suite"), f"{fn.__name__} missing _suite"

    def test_unknown_suite_returns_empty(self):
        checks = get_suite("nonexistent")
        assert checks == []

    def test_check_ids_unique(self):
        import mcp_shield.testing.runner  # noqa: F401

        all_ids = []
        for suite_checks in get_suites().values():
            for fn in suite_checks:
                all_ids.append(getattr(fn, "_check_id", fn.__name__))
        assert len(all_ids) == len(set(all_ids)), f"Duplicate check IDs: {all_ids}"
