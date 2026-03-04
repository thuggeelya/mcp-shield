"""Test runner — connects to an MCP server and executes registered checks."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from mcp import ClientSession

from mcp_shield.client.connection import MCPConnection, ServerTarget
from mcp_shield.testing.context import cached_list_tools, init_result_var
from mcp_shield.testing.result import CheckResult, Outcome, SuiteReport, ToolSummary

# Importing suites triggers their @check decorators so they appear in the
# registry.  Keep these imports even though they look unused.
import mcp_shield.testing.suites.compliance as _compliance_mod  # noqa: F401
import mcp_shield.testing.suites.security as _security_mod  # noqa: F401
import mcp_shield.testing.suites.advisory as _advisory_mod  # noqa: F401

from mcp_shield.testing.registry import get_suite, get_suites, CheckFunc

logger = logging.getLogger(__name__)


class Runner:
    """Execute registered check suites against an MCP server."""

    def __init__(
        self,
        target: ServerTarget,
        *,
        suites: Optional[Sequence[str]] = None,
        timeout: float = 30.0,
        use_ml: bool = False,
    ) -> None:
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        self._target = target
        self._requested = suites
        self._timeout = timeout
        self._use_ml = use_ml

    async def run(self) -> SuiteReport:
        """Connect to the server, run matching suites, return a report."""
        from mcp_shield.security.scanner import (
            ScanConfig, SecurityScanner, scan_config,
        )
        from mcp_shield.security.base import Detector
        from mcp_shield.security.poisoning import PoisoningDetector
        from mcp_shield.security.injection import InjectionDetector
        from mcp_shield.models.mcp_types import ToolInfo

        config = ScanConfig(use_ml=self._use_ml)
        token = scan_config.set(config)

        try:
            report = SuiteReport(
                server_target=self._target.full_command
            )
            report.timestamp = datetime.now(timezone.utc).isoformat()

            t0 = time.monotonic()

            conn = MCPConnection(self._target)
            async with asyncio.timeout(self._timeout):
                async with conn as session:
                    init_result_var.set(conn.init_result)
                    self._fill_server_info(conn, report)

                    # Run security scan once and store in ScanConfig
                    suite_names = self._resolve_suites()
                    if "security" in suite_names:
                        sec_report, tool_infos = await self._run_security_scan(session, config)
                        config.report = sec_report
                        report.tools = self._build_tool_summaries(tool_infos)

                    for name in suite_names:
                        checks = get_suite(name)
                        for fn in checks:
                            result = await self._execute_check(session, fn)
                            report.results.append(result)

            report.duration_ms = int((time.monotonic() - t0) * 1000)
            report.count()
            return report
        finally:
            scan_config.reset(token)

    @staticmethod
    async def _run_security_scan(session: ClientSession, config: object) -> tuple:
        """Fetch tools and run all security detectors once.

        Returns (SecurityReport, list[ToolInfo]).
        """
        from mcp_shield.security.scanner import SecurityScanner, default_detectors
        from mcp_shield.models.mcp_types import ToolInfo

        result = await cached_list_tools(session)
        tools = result.tools if result else []

        infos = [
            ToolInfo(
                name=getattr(t, "name", "") or f"unnamed_{i}",
                description=getattr(t, "description", "") or "",
                input_schema=getattr(t, "inputSchema", {}) or {},
            )
            for i, t in enumerate(tools)
        ]

        use_ml = getattr(config, "use_ml", False)
        scanner = SecurityScanner(detectors=default_detectors(use_ml=use_ml))
        return scanner.scan_tools(infos), infos

    @staticmethod
    def _build_tool_summaries(tool_infos: list) -> list[ToolSummary]:
        """Classify each tool by risk tier and return summaries."""
        from mcp_shield.classification.risk import classify_tool_risk

        # Risk tier ordering for sorting (most dangerous first)
        _TIER_ORDER = {
            "write_sensitive": 0,
            "write_external": 1,
            "write_reversible": 2,
            "unknown": 3,
            "read": 4,
        }

        summaries = [
            ToolSummary(
                name=t.name,
                description=t.description,
                risk_tier=classify_tool_risk(t.name, t.description, t.input_schema).value,
            )
            for t in tool_infos
        ]
        summaries.sort(key=lambda s: (_TIER_ORDER.get(s.risk_tier, 9), s.name))
        return summaries

    # ------------------------------------------------------------------

    def _resolve_suites(self) -> List[str]:
        """Determine which suites to run."""
        available = get_suites()
        if not self._requested or "all" in self._requested:
            return sorted(available.keys())
        missing = set(self._requested) - set(available.keys())
        if missing:
            raise ValueError(f"Unknown suites: {', '.join(sorted(missing))}")
        return list(self._requested)

    async def _execute_check(self, session: ClientSession, fn: CheckFunc) -> CheckResult:
        """Run a single check with a timeout guard."""
        check_id: str = getattr(fn, "_check_id", fn.__name__)
        severity: str = getattr(fn, "_severity", "error")
        t0 = time.monotonic()

        try:
            result = await asyncio.wait_for(fn(session), timeout=self._timeout)
            result.duration_ms = int((time.monotonic() - t0) * 1000)
            return result
        except asyncio.TimeoutError:
            return CheckResult(
                check_id=check_id,
                outcome=Outcome.ERROR,
                message=f"Timed out after {self._timeout:.0f}s",
                severity=severity,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as exc:
            return CheckResult(
                check_id=check_id,
                outcome=Outcome.ERROR,
                message=f"Check crashed: {exc}",
                severity=severity,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    @staticmethod
    def _fill_server_info(conn: MCPConnection, report: SuiteReport) -> None:
        """Extract server metadata from the initialised connection."""
        try:
            init = conn.init_result
            if init and hasattr(init, "serverInfo"):
                info = init.serverInfo
                report.server_name = getattr(info, "name", "") or ""
                report.server_version = getattr(info, "version", "") or ""
        except Exception as exc:
            logger.debug("Failed to extract server info: %s", exc)
