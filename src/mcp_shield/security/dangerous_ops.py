"""Detect tools that perform dangerous or destructive operations.

Flags tools whose names indicate they can delete, overwrite, execute,
deploy, or otherwise make hard-to-reverse changes.  This is distinct
from injection detection — a tool like ``git_push`` is dangerous even
with perfectly validated input because the *operation itself* is risky.

Also analyzes tool *descriptions* for dangerous verbs that may not
appear in the tool name (e.g. ``manage_data`` → "permanently deletes").
"""

from __future__ import annotations

import re
from typing import List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory

# ── Name-based patterns (snake_case boundaries) ──────────────────────

# Destructive verbs — the tool *deletes* or *destroys* data
_DESTRUCTIVE_VERBS = re.compile(
    r"""(?x)(?:^|_)
      (delete|remove|drop|destroy|purge|erase|truncate|wipe|clean|uninstall)
    (?:$|_)""",
    re.IGNORECASE,
)

# Dangerous write verbs — the tool *pushes*, *deploys*, or *force-writes*
_DANGEROUS_WRITE_VERBS = re.compile(
    r"""(?x)(?:^|_)
      (push|deploy|publish|force|reset|overwrite|revert|rollback|rebase|merge)
    (?:$|_)""",
    re.IGNORECASE,
)

# Execution verbs — the tool *runs* arbitrary code/commands
_EXEC_VERBS = re.compile(
    r"""(?x)(?:^|_)
      (exec|execute|run|eval|spawn|start|kill|stop|restart|terminate|shutdown)
    (?:$|_)""",
    re.IGNORECASE,
)

# ── Description-based patterns (word boundaries for prose) ───────────

_DESC_DESTRUCTIVE = re.compile(
    r"""\b(delet(?:es?|ing)|remov(?:es?|ing)|drops?|destroy(?:s|ing)?|purg(?:es?|ing)|eras(?:es?|ing)|truncat(?:es?|ing)|wip(?:es?|ing))\b""",
    re.IGNORECASE,
)

_DESC_WRITE = re.compile(
    r"""\b(deploy(?:s|ing)?|publish(?:es|ing)?|(?:force[- ])?overwrite?s?|push(?:es|ing)?|(?:force[- ])?reset(?:s|ting)?)\b""",
    re.IGNORECASE,
)

_DESC_EXEC = re.compile(
    r"""\b(execut(?:es?|ing)|runs?|spawn(?:s|ing)?|kill(?:s|ing)?|terminat(?:es?|ing)|shutdown(?:s)?)\b""",
    re.IGNORECASE,
)


# ── Negation detection ────────────────────────────────────────────────
# Before flagging a verb from a description, check whether it's preceded
# by negation words within a small window.

_NEGATION_WINDOW = 30  # characters before the match to check

_NEGATION = re.compile(
    r"\b(?:not?|don'?t|doesn'?t|cannot|can'?t|won'?t|never|without|"
    r"no longer|unable to|prevent|avoid|instead of|rather than)\b",
    re.IGNORECASE,
)


def _is_negated(text: str, match_start: int) -> bool:
    """Check whether a match position is preceded by a negation word."""
    window_start = max(0, match_start - _NEGATION_WINDOW)
    window = text[window_start:match_start]
    return bool(_NEGATION.search(window))


class DangerousOpDetector:
    """Flag tools that perform inherently dangerous operations."""

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        findings: List[Finding] = []
        name = tool.name

        # Check destructive verbs (HIGH)
        m = _DESTRUCTIVE_VERBS.search(name)
        if m:
            verb = m.group(1).lower()
            findings.append(
                Finding(
                    finding_id=f"DANGER-DESTRUCT-{name}",
                    severity=Severity.HIGH,
                    category=FindingCategory.DANGEROUS_OP,
                    title=f"Destructive operation: {name}",
                    description=(
                        f"Tool '{name}' appears to perform a destructive "
                        f"operation ('{verb}'). Such tools can permanently "
                        f"delete data or resources."
                    ),
                    tool_name=name,
                    evidence=f"tool name contains destructive verb: {verb}",
                    remediation=(
                        "Require user confirmation before executing destructive "
                        "operations. Consider adding --dry-run support."
                    ),
                )
            )

        # Check dangerous write verbs (MEDIUM)
        m = _DANGEROUS_WRITE_VERBS.search(name)
        if m:
            verb = m.group(1).lower()
            findings.append(
                Finding(
                    finding_id=f"DANGER-WRITE-{name}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.DANGEROUS_OP,
                    title=f"Dangerous write operation: {name}",
                    description=(
                        f"Tool '{name}' appears to perform an operation "
                        f"('{verb}') that modifies shared/remote state and "
                        f"may be hard to reverse."
                    ),
                    tool_name=name,
                    evidence=f"tool name contains write verb: {verb}",
                    remediation=(
                        "Ensure the LLM client requires explicit user approval "
                        "before invoking this tool."
                    ),
                )
            )

        # Check execution verbs (MEDIUM)
        m = _EXEC_VERBS.search(name)
        if m:
            verb = m.group(1).lower()
            findings.append(
                Finding(
                    finding_id=f"DANGER-EXEC-{name}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.DANGEROUS_OP,
                    title=f"Execution operation: {name}",
                    description=(
                        f"Tool '{name}' appears to execute processes or code "
                        f"('{verb}'). Uncontrolled execution can lead to "
                        f"privilege escalation or data exfiltration."
                    ),
                    tool_name=name,
                    evidence=f"tool name contains execution verb: {verb}",
                    remediation=(
                        "Restrict allowed commands/scripts via allowlists. "
                        "Run in a sandboxed environment."
                    ),
                )
            )

        # ── Description-based detection ─────────────────────────────
        # Only fire if the name-based check for the same category
        # did NOT already produce a finding (avoid duplicates).

        desc = tool.description or ""
        if not desc:
            return findings

        name_categories = {f.finding_id.split("-")[1] for f in findings}

        if "DESTRUCT" not in name_categories:
            m = _DESC_DESTRUCTIVE.search(desc)
            if m and not _is_negated(desc, m.start()):
                verb = m.group(1).lower()
                findings.append(
                    Finding(
                        finding_id=f"DANGER-DESC-DESTRUCT-{name}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DANGEROUS_OP,
                        title=f"Description indicates destructive operation: {name}",
                        description=(
                            f"Tool '{name}' description mentions a destructive "
                            f"action ('{verb}'): \"{desc[:120]}\"."
                        ),
                        tool_name=name,
                        evidence=f"description contains destructive verb: {verb}",
                        remediation=(
                            "Review whether this tool permanently modifies data. "
                            "Consider requiring user confirmation."
                        ),
                    )
                )

        if "WRITE" not in name_categories:
            m = _DESC_WRITE.search(desc)
            if m and not _is_negated(desc, m.start()):
                verb = m.group(1).lower()
                findings.append(
                    Finding(
                        finding_id=f"DANGER-DESC-WRITE-{name}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DANGEROUS_OP,
                        title=f"Description indicates dangerous write: {name}",
                        description=(
                            f"Tool '{name}' description mentions a dangerous "
                            f"write operation ('{verb}'): \"{desc[:120]}\"."
                        ),
                        tool_name=name,
                        evidence=f"description contains write verb: {verb}",
                        remediation=(
                            "Ensure the LLM client requires explicit user approval "
                            "before invoking this tool."
                        ),
                    )
                )

        if "EXEC" not in name_categories:
            m = _DESC_EXEC.search(desc)
            if m and not _is_negated(desc, m.start()):
                verb = m.group(1).lower()
                findings.append(
                    Finding(
                        finding_id=f"DANGER-DESC-EXEC-{name}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DANGEROUS_OP,
                        title=f"Description indicates execution: {name}",
                        description=(
                            f"Tool '{name}' description mentions code/process "
                            f"execution ('{verb}'): \"{desc[:120]}\"."
                        ),
                        tool_name=name,
                        evidence=f"description contains execution verb: {verb}",
                        remediation=(
                            "Restrict allowed commands/scripts via allowlists. "
                            "Run in a sandboxed environment."
                        ),
                    )
                )

        return findings
