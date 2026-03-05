"""Detect non-idempotent operations that are dangerous to retry.

LLMs may retry failed tool calls automatically.  Retrying a payment,
message send, or deployment can cause real damage.  This detector
flags tools whose names or descriptions indicate non-idempotent
(create/send/pay/deploy) semantics.
"""

from __future__ import annotations

import re
from typing import List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory

# Non-idempotent verbs — executing twice produces different results
_NON_IDEMPOTENT_NAME = re.compile(
    r"(?x)(?:^|_)"
    r"(create|send|post|submit|pay|charge|transfer|trigger|emit|"
    r"dispatch|broadcast|invoice|order|book|reserve|enqueue|publish)"
    r"(?:$|_)",
    re.IGNORECASE,
)

_NON_IDEMPOTENT_DESC = re.compile(
    r"(?i)\b(creat(?:es?|ing)|sends?|posts?|submits?|"
    r"pay(?:s|ing|ment)?|charg(?:es?|ing)|transfers?|"
    r"trigger(?:s|ing)?|dispatch(?:es|ing)?|"
    r"broadcasts?|invoic(?:es?|ing)|orders?|"
    r"book(?:s|ing)?|reserv(?:es?|ing)|enqueue(?:s|d)?|"
    r"publish(?:es|ing)?)\b"
)

# Read-only name prefixes — these tools are safe to retry regardless of
# what their description says (e.g. "creates a summary" in a read tool).
_READ_ONLY_NAME = re.compile(
    r"(?x)(?:^|_)"
    r"(get|list|search|find|fetch|read|query|lookup|describe|show|view|browse|"
    r"inspect|count|exists|has|is|check|verify|validate|resolve|discover|"
    r"explore|scan|analyze|detect|match|filter|select|retrieve|load|"
    r"export|extract|parse|convert|format|render|display|print|dump|"
    r"compare|diff|stat|info|help|status|health|ping|test|probe|"
    r"measure|calculate|compute|estimate|preview|sample|suggest|"
    r"recommend|summarize|aggregate|classify|categorize|sort|rank)"
    r"(?:$|_)",
    re.IGNORECASE,
)

# Idempotency key in schema suggests awareness
_IDEMPOTENCY_KEY = re.compile(
    r"(?i)(idempoten|request_id|client_id|dedup|nonce)"
)


class IdempotencyDetector:
    """Flag tools with non-idempotent operations that are risky to retry."""

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        findings: List[Finding] = []
        name = tool.name
        desc = tool.description or ""
        schema = tool.input_schema or {}

        # Skip tools whose names indicate read-only operations
        if _READ_ONLY_NAME.search(name):
            return findings

        m = _NON_IDEMPOTENT_NAME.search(name)
        if not m:
            m = _NON_IDEMPOTENT_DESC.search(desc)

        if not m:
            return findings

        verb = m.group(1).lower()

        # Check if schema has idempotency key (mitigating factor)
        schema_text = str(schema)
        has_idempotency_key = bool(_IDEMPOTENCY_KEY.search(schema_text))

        if has_idempotency_key:
            return findings  # Risk mitigated

        findings.append(Finding(
            finding_id=f"IDEMP-{name}",
            severity=Severity.MEDIUM,
            category=FindingCategory.IDEMPOTENCY,
            title=f"Non-idempotent operation: {name}",
            description=(
                f"Tool '{name}' performs a non-idempotent operation ('{verb}'). "
                f"If the LLM retries a failed call, it could produce duplicate "
                f"side effects (e.g. double payment, duplicate message)."
            ),
            tool_name=name,
            evidence=f"verb: {verb}",
            remediation=(
                "Add an idempotency key parameter to the tool schema, "
                "or document that retries are not safe."
            ),
        ))

        return findings
