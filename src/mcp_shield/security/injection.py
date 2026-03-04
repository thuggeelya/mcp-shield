"""Detect tool input schemas that are susceptible to injection attacks.

Checks for:
  - Free-form string fields without validation (potential shell/SQL injection)
  - Fields whose names suggest they accept raw commands or queries
  - Schemas with no type constraints
"""

from __future__ import annotations

import re
from typing import List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory

# Field names that strongly suggest raw command / query injection risk.
# Uses ([_-]|^|$) boundaries instead of \b because field names use
# underscores or hyphens (e.g., "search_query", "sql-query").
# \b treats _ as a word char, so "description" would match "script".
_RISKY_FIELD_NAMES = re.compile(
    r"""(?x)                               # verbose mode
      (?:^|[_-])(command|cmd)(?:$|[_-])    # shell commands
    | (?:^|[_-])(sql|stmt)(?:$|[_-])       # SQL statements
    | (?:^|[_-])(query)(?:$|[_-])          # query (SQL or search)
    | (?:^|[_-])(script)(?:$|[_-])         # script (not "description")
    | (?:^|[_-])(code)(?:$|[_-])           # code execution
    | (?:^|[_-])(shell)(?:$|[_-])          # shell access
    | (?:^|[_-])(exec|eval)(?:$|[_-])      # eval / exec
    | (?:^|[_-])(expression)(?:$|[_-])     # expression evaluation
    """,
    re.IGNORECASE,
)

# Tool names that indicate search/lookup semantics — "query" in these
# tools is a search term, not SQL.  Downgrade severity from HIGH to MEDIUM.
_SEARCH_TOOL_NAMES = re.compile(
    r"(?i)(search|find|lookup|resolve|discover|browse|list|get|fetch|query.docs)",
)

# Matched keyword → risk tier.  "query" alone is ambiguous; context
# from the tool name decides whether it is SQL or search.
_HIGH_RISK_KEYWORDS = frozenset({
    "command", "cmd", "sql", "stmt", "script", "shell", "exec", "eval",
})
_CODE_KEYWORDS = frozenset({"code", "expression"})

# Field description patterns that indicate search (not SQL) semantics.
# Used to downgrade "query" fields when the field's own JSON Schema
# description hints at search/filter usage.
_SEARCH_FIELD_DESC = re.compile(
    r"(?i)\b(search|keyword|filter|look\s*up|find|term|phrase|text\s+to\s+search)\b",
)

# Field description patterns that indicate SQL/command semantics.
# These override search hints and keep severity HIGH.
_SQL_FIELD_DESC = re.compile(
    r"(?i)\b(sql|statement|query\s+to\s+execute|shell|command\s+to\s+run)\b",
)

# Field names that look like paths (file traversal risk)
_PATH_FIELD_NAMES = re.compile(
    r"(path|file|filename|filepath|dir|directory|folder|uri|url)",
    re.IGNORECASE,
)


def _is_string_type(field_schema: dict) -> bool:
    """Check if a field's type includes 'string', handling union types.

    JSON Schema allows ``"type": "string"`` or ``"type": ["string", "null"]``.
    Both mean the field accepts string input and should be checked for injection.
    """
    t = field_schema.get("type", "")
    if t == "string":
        return True
    if isinstance(t, list) and "string" in t:
        return True
    return False


class InjectionDetector:
    """Analyse input schemas for injection-prone patterns."""

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        findings: List[Finding] = []
        seen_ids: set[str] = set()
        schema = tool.input_schema
        if not isinstance(schema, dict):
            return findings

        self._scan_schema(tool.name, schema, findings, seen_ids)

        return findings

    def _scan_schema(
        self, tool_name: str, schema: dict, findings: List[Finding],
        seen_ids: set[str],
    ) -> None:
        """Recursively scan a schema, including oneOf/anyOf/allOf branches."""
        if not isinstance(schema, dict):
            return

        props = schema.get("properties", {})
        if isinstance(props, dict):
            for field_name, field_schema in props.items():
                findings.extend(self._check_field(tool_name, field_name, field_schema))

        # DC-10: Recurse into oneOf/anyOf/allOf branches
        for keyword in ("oneOf", "anyOf", "allOf"):
            variants = schema.get(keyword)
            if isinstance(variants, list):
                for variant in variants:
                    self._scan_schema(tool_name, variant, findings, seen_ids)

        # Flag tools with completely empty schema (accepts anything)
        empty_id = f"INJECT-EMPTY-{tool_name}"
        if not props and schema.get("type") != "object":
            if not any(schema.get(k) for k in ("oneOf", "anyOf", "allOf")):
                if empty_id not in seen_ids:
                    seen_ids.add(empty_id)
                    findings.append(
                        Finding(
                            finding_id=empty_id,
                            severity=Severity.MEDIUM,
                            category=FindingCategory.INJECTION,
                            title=f"Tool '{tool_name}' has no input schema constraints",
                            description=(
                                f"Tool '{tool_name}' does not define input properties, "
                                f"meaning it may accept arbitrary unvalidated input."
                            ),
                            tool_name=tool_name,
                            remediation="Add explicit properties and type constraints to inputSchema.",
                        )
                    )

    def _check_field(
        self, tool_name: str, field_name: str, field_schema: dict
    ) -> List[Finding]:
        if not isinstance(field_schema, dict):
            return []

        findings: List[Finding] = []
        is_string = _is_string_type(field_schema)

        # Risky field name + string type = possible injection vector
        match = _RISKY_FIELD_NAMES.search(field_name) if is_string else None
        if match:
            # Determine which keyword matched
            matched_keyword = next(
                (g.lower() for g in match.groups() if g is not None), ""
            )

            # Context-aware severity for "query" fields:
            # 1. Check field description first (most specific signal)
            # 2. Fall back to tool name heuristic
            field_desc = field_schema.get("description", "") or ""

            if matched_keyword == "query" and field_desc and _SQL_FIELD_DESC.search(field_desc):
                # Field description says SQL → HIGH
                severity = Severity.HIGH
                desc_suffix = (
                    "The field description indicates SQL/command execution."
                )
            elif matched_keyword == "query" and field_desc and _SEARCH_FIELD_DESC.search(field_desc):
                # Field description says search → MEDIUM
                severity = Severity.MEDIUM
                desc_suffix = (
                    "The field description suggests this is a search term rather "
                    "than SQL, but the field still accepts arbitrary user input."
                )
            elif matched_keyword == "query" and _SEARCH_TOOL_NAMES.search(tool_name):
                severity = Severity.MEDIUM
                desc_suffix = (
                    "The tool name suggests this is a search query rather than "
                    "SQL, but the field still accepts arbitrary user input."
                )
            elif matched_keyword in _HIGH_RISK_KEYWORDS:
                severity = Severity.HIGH
                desc_suffix = (
                    "Its name suggests it may be used in command/query "
                    "execution without sanitisation."
                )
            else:
                # code, expression, query (non-search context)
                severity = Severity.HIGH
                desc_suffix = (
                    "Its name suggests it may accept executable content."
                )

            findings.append(
                Finding(
                    finding_id=f"INJECT-CMD-{tool_name}.{field_name}",
                    severity=severity,
                    category=FindingCategory.INJECTION,
                    title=f"Potential injection vector: {tool_name}.{field_name}",
                    description=(
                        f"Field '{field_name}' in tool '{tool_name}' accepts a "
                        f"free-form string. {desc_suffix}"
                    ),
                    tool_name=tool_name,
                    evidence=f"type=string, name matches: {field_name}",
                    remediation=(
                        "Add input validation (pattern, enum, maxLength) or use "
                        "parameterised queries instead of raw string interpolation."
                    ),
                )
            )

        # Path field without pattern constraint = traversal risk
        if is_string and _PATH_FIELD_NAMES.search(field_name):
            has_pattern = "pattern" in field_schema
            has_enum = "enum" in field_schema
            if not has_pattern and not has_enum:
                findings.append(
                    Finding(
                        finding_id=f"INJECT-PATH-{tool_name}.{field_name}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.INJECTION,
                        title=f"Unconstrained path field: {tool_name}.{field_name}",
                        description=(
                            f"Field '{field_name}' in tool '{tool_name}' accepts any "
                            f"string as a path with no pattern validation, which may "
                            f"allow directory traversal (../../etc/passwd)."
                        ),
                        tool_name=tool_name,
                        remediation="Add a 'pattern' constraint or validate paths server-side.",
                    )
                )

        return findings
