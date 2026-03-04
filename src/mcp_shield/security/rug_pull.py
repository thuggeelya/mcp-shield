"""Rug Pull detector — detects tool description changes between sessions.

A "rug pull" attack occurs when an MCP server presents benign tool
descriptions during initial review, then silently changes them to
malicious versions in a later session.

This detector compares current tool ``description_hash`` values against
previously stored snapshots in the audit database.  Any change in
description triggers a finding.

Unlike stateless detectors (PoisoningDetector, InjectionDetector),
the RugPullDetector requires access to the ``AuditDB`` for historical
comparison.  It still follows the ``Detector`` protocol via a factory
pattern: call ``create_rug_pull_detector(db)`` to get an instance.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, FindingCategory, Severity


class RugPullDetector:
    """Detects tool description changes (rug pull attacks).

    Parameters
    ----------
    previous_snapshots:
        Dict of tool_name → {"description_hash": str, "input_schema_json": str}
        from the audit database.  Empty dict on first run (no history).
    """

    def __init__(self, previous_snapshots: Dict[str, Dict[str, Any]]) -> None:
        self._snapshots = previous_snapshots

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        """Compare tool's current state against stored snapshot."""
        findings: List[Finding] = []

        prev = self._snapshots.get(tool.name)
        if prev is None:
            # First time seeing this tool — no comparison possible
            return findings

        prev_desc_hash = prev.get("description_hash", "")
        if not prev_desc_hash or not tool.description_hash:
            return findings

        # Check description change
        if tool.description_hash != prev_desc_hash:
            findings.append(Finding(
                finding_id=f"RUGPULL-DESC-{tool.name}",
                severity=Severity.CRITICAL,
                category=FindingCategory.RUG_PULL,
                title=f"Tool description changed: {tool.name}",
                description=(
                    f"Tool '{tool.name}' description hash changed from "
                    f"{prev_desc_hash[:8]}... to {tool.description_hash[:8]}... "
                    f"This may indicate a rug pull attack where the server "
                    f"changed tool behavior after initial approval."
                ),
                tool_name=tool.name,
                evidence=f"Previous hash: {prev_desc_hash}, Current hash: {tool.description_hash}",
                remediation=(
                    "Review the tool's current description carefully. "
                    "Compare against the previously approved version. "
                    "If the change is unexpected, consider blocking this tool."
                ),
            ))

        # Check schema change
        prev_schema_json = prev.get("input_schema_json", "{}")
        current_schema_json = json.dumps(tool.input_schema, sort_keys=True, default=str)
        prev_schema_normalized = json.dumps(
            json.loads(prev_schema_json), sort_keys=True, default=str
        ) if prev_schema_json else "{}"

        if current_schema_json != prev_schema_normalized:
            findings.append(Finding(
                finding_id=f"RUGPULL-SCHEMA-{tool.name}",
                severity=Severity.HIGH,
                category=FindingCategory.RUG_PULL,
                title=f"Tool input schema changed: {tool.name}",
                description=(
                    f"Tool '{tool.name}' input schema differs from the "
                    f"previously stored version. Schema changes can alter "
                    f"tool behavior and introduce new attack surfaces."
                ),
                tool_name=tool.name,
                evidence=f"Schema changed since last snapshot at {prev.get('timestamp', 'unknown')}",
                remediation=(
                    "Review the tool's current input schema. "
                    "Verify that new or changed fields are safe."
                ),
            ))

        return findings
