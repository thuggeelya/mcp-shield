"""Security scanner — orchestrates all security detectors.

The ``SecurityScanner`` accepts a list of ``Detector`` instances and runs
them against tool definitions.  This replaces the previous hard-coded
detector list and ``use_ml`` flag with a composable, Protocol-based design.

``ScanConfig`` / ``scan_config`` provide an async-safe ContextVar for
passing configuration (e.g. ``use_ml``) from the CLI/Runner layer down
to security check functions without module-level mutable state.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import List, Sequence

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Detector, Finding

logger = logging.getLogger(__name__)


def default_detectors(*, use_ml: bool = False) -> list[Detector]:
    """Create the standard set of security detectors.

    Single source of truth — used by Runner, SecurityScanner defaults,
    and ShieldProxy.  Keeps detector lists in sync across the codebase.
    """
    from mcp_shield.security.poisoning import PoisoningDetector
    from mcp_shield.security.injection import InjectionDetector
    from mcp_shield.security.dangerous_ops import DangerousOpDetector
    from mcp_shield.security.write_scope import WriteScopeDetector
    from mcp_shield.security.idempotency import IdempotencyDetector
    from mcp_shield.security.cost_risk import CostRiskDetector

    detectors: list[Detector] = [
        PoisoningDetector(),
        InjectionDetector(),
        DangerousOpDetector(),
        WriteScopeDetector(),
        IdempotencyDetector(),
        CostRiskDetector(),
    ]
    if use_ml:
        from mcp_shield.security.ml_detector import MLDetector
        detectors.append(MLDetector())
    return detectors


# ── ScanConfig — async-safe configuration via ContextVar ──────────────

@dataclass
class ScanConfig:
    """Configuration for the current scan run.

    Stored in a ``ContextVar`` so it's safe for concurrent async tasks
    and doesn't require module-level mutable state.

    The ``report`` field is populated by the Runner after the first
    security scan, so that SEC-001/002/003 check functions can read
    it without re-scanning.
    """

    use_ml: bool = False
    report: SecurityReport | None = None


#: ContextVar holding the active scan configuration.
#: Set by ``Runner.run()`` before executing checks;
#: read by security suite check functions.
scan_config: ContextVar[ScanConfig] = ContextVar(
    "scan_config",
    default=ScanConfig(),
)


# ── SecurityReport ────────────────────────────────────────────────────

@dataclass
class SecurityReport:
    """Aggregated results from all security scans."""

    findings: List[Finding] = field(default_factory=list)
    tools_scanned: int = 0
    score: float = 100.0  # 0-100, deducted per finding

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def compute_score(self) -> None:
        """Recompute the score based on findings."""
        penalty = 0.0
        for f in self.findings:
            if f.severity == "critical":
                penalty += 25.0
            elif f.severity == "high":
                penalty += 15.0
            elif f.severity == "medium":
                penalty += 5.0
            elif f.severity == "low":
                penalty += 2.0
        self.score = max(0.0, 100.0 - penalty)


# ── SecurityScanner ───────────────────────────────────────────────────

_MAX_TOOLS = 10_000


class SecurityScanner:
    """Run all security checks against tool definitions.

    Parameters
    ----------
    detectors:
        Explicit list of ``Detector`` instances to use.  If ``None``,
        defaults to ``default_detectors()``.
    max_tools:
        Upper bound on the number of tools to scan.  Raises
        ``ValueError`` if exceeded.  Prevents DoS from servers
        declaring an unreasonable number of tools.
    """

    def __init__(
        self,
        *,
        detectors: Sequence[Detector] | None = None,
        max_tools: int = _MAX_TOOLS,
    ) -> None:
        if detectors is not None:
            self._detectors: list[Detector] = list(detectors)
        else:
            self._detectors = default_detectors()
        self._max_tools = max_tools

    def scan_tools(self, tools: Sequence[ToolInfo]) -> SecurityReport:
        """Scan a list of tool definitions and return a security report.

        IV-03: Raises ``ValueError`` if tools exceed *max_tools*.
        RT-03: Individual detector failures are caught and logged.
        """
        if len(tools) > self._max_tools:
            raise ValueError(
                f"Server declared {len(tools)} tools, exceeding the "
                f"limit of {self._max_tools}. This may indicate a DoS "
                f"attempt. Use max_tools= to raise the limit if needed."
            )

        report = SecurityReport(tools_scanned=len(tools))

        for tool in tools:
            for detector in self._detectors:
                try:
                    report.findings.extend(detector.scan_tool(tool))
                except Exception as exc:
                    detector_name = type(detector).__name__
                    logger.warning(
                        "Detector %s failed on tool '%s': %s",
                        detector_name,
                        tool.name,
                        str(exc)[:500],
                    )

        report.compute_score()

        # AO-01: Structured scan logging
        logger.info(
            "scan_complete",
            extra={
                "tools_scanned": report.tools_scanned,
                "finding_count": len(report.findings),
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "score": report.score,
                "detector_count": len(self._detectors),
            },
        )

        return report
