"""Security scanning layer.

Public API:
    - ``Finding`` — unified result type for all detectors
    - ``Detector`` — Protocol that every detector implements
    - ``Severity`` / ``FindingCategory`` — typed enums
    - ``SecurityScanner`` — orchestrator that runs detectors
    - ``SecurityReport`` — aggregated scan results
"""

from mcp_shield.security.base import (  # noqa: F401
    Detector,
    Finding,
    FindingCategory,
    Severity,
)
from mcp_shield.security.scanner import SecurityReport, SecurityScanner  # noqa: F401
