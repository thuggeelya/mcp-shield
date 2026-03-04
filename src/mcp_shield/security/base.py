"""Base types for all security detectors.

This module defines the shared abstractions used across the security layer:

- ``Detector`` — Protocol that every detector implements
- ``Finding`` — Unified result type for all detectors
- ``Severity`` / ``FindingCategory`` — String enums for type-safe values
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Protocol, runtime_checkable

from mcp_shield.models.mcp_types import ToolInfo


# ── Evidence Sanitization ─────────────────────────────────────────────────

# Patterns that match common secret formats — used to redact evidence fields
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # API keys: sk-live-..., pk-test-...
    (re.compile(r"((?:sk|pk)[-_](?:live|test|prod)[-_])[A-Za-z0-9]{4,}"), r"\g<1>****"),
    # GitHub PAT: ghp_...
    (re.compile(r"((?:ghp|gho|ghu|ghs|ghr)_)[A-Za-z0-9]{4,}"), r"\g<1>****"),
    # Slack tokens: xoxb-...
    (re.compile(r"(xox[bporas]-)[A-Za-z0-9-]{4,}"), r"\g<1>****"),
    # Generic key=value assignments with quoted values
    (re.compile(
        r"((?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)"
        r"\s*[=:]\s*['\"])[A-Za-z0-9+/=_-]{4,}(['\"])",
        re.IGNORECASE,
    ), r"\g<1>****\g<2>"),
    # JWT-like tokens (eyJ...)
    (re.compile(r"(eyJ)[A-Za-z0-9_-]{20,}"), r"\g<1>****"),
]


def sanitize_evidence(text: str) -> str:
    """Redact potential secrets from evidence text.

    Applied automatically when a ``Finding`` is created, so that secrets
    found during scanning are never persisted in reports or logs.
    """
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ── Enums ─────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Finding severity levels.

    Extends ``str`` so that ``Severity.CRITICAL == "critical"`` is True,
    preserving backward compatibility with string comparisons.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Finding category — which detector family produced the finding."""

    POISONING = "poisoning"
    INJECTION = "injection"
    RUG_PULL = "rug_pull"
    SHADOWING = "shadowing"
    NETWORK = "network"
    DANGEROUS_OP = "dangerous_op"
    WRITE_SCOPE = "write_scope"
    IDEMPOTENCY = "idempotency"
    COST_RISK = "cost_risk"
    AUTH_HINT = "auth_hint"
    DEPENDENCY = "dependency"
    BULK_OP = "bulk_op"
    SENSITIVE_DATA = "sensitive_data"
    NETWORK_ACCESS = "network_access"


# ── Finding ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding produced by any detector."""

    finding_id: str
    severity: str  # Severity enum value (str subclass, so plain strings still work)
    category: str  # FindingCategory enum value
    title: str
    description: str
    tool_name: str = ""
    evidence: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        """Sanitize evidence field to redact potential secrets."""
        if self.evidence:
            self.evidence = sanitize_evidence(self.evidence)


# ── Detector Protocol ─────────────────────────────────────────────────────

@runtime_checkable
class Detector(Protocol):
    """Interface that every security detector must implement.

    Detectors receive a ``ToolInfo`` and return zero or more ``Finding``
    objects.  The ``SecurityScanner`` iterates over a list of detectors,
    so adding a new one is just appending to the list.
    """

    def scan_tool(self, tool: ToolInfo) -> List[Finding]: ...
