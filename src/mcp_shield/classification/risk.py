"""Risk classification for MCP tools.

Assigns a ``RiskTier`` to each tool based on its name, description, and
input schema.  The classifier uses a priority-ordered rule set:

1. **WRITE_SENSITIVE** — destructive, execution, or admin operations
2. **WRITE_EXTERNAL** — actions that affect external systems (email, API, deploy)
3. **WRITE_REVERSIBLE** — local modifications (file write, config update)
4. **READ** — read-only operations (get, list, search, fetch)
5. **UNKNOWN** — no signals matched

Higher-risk tiers take precedence: if both "delete" and "send" signals
are found, the tool is classified as WRITE_SENSITIVE.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from mcp_shield.models.enums import RiskTier

# ── Pattern definitions ──────────────────────────────────────────────

# Each tier has patterns checked against (name, description, schema fields).
# Order within a tier doesn't matter; tier priority is enforced in code.

_SENSITIVE_NAME = re.compile(
    r"(?:^|_)"
    r"(?:delete|remove|drop|truncate|destroy|purge|kill|format|wipe|erase|"
    r"exec(?:ute)?|eval|run_code|shell|bash|admin_reset)"
    r"(?:_|$)",
    re.IGNORECASE,
)

_SENSITIVE_DESC = re.compile(
    r"\b(?:delet(?:e|ing)|remov(?:e|ing)|drop(?:ping)?|truncat(?:e|ing)|"
    r"destroy(?:ing)?|purg(?:e|ing)|kill(?:ing)?|format(?:ting)?|"
    r"wip(?:e|ing)|eras(?:e|ing)|permanently|"
    r"execut(?:e|ing)\s+(?:a\s+)?(?:shell|command|sql|code|script)|"
    r"run\s+(?:arbitrary|shell|command)|"
    r"eval(?:uat(?:e|ing))?(?:\s+(?:expression|code))?)\b",
    re.IGNORECASE,
)

_SENSITIVE_SCHEMA_FIELDS = re.compile(
    r"^(?:command|cmd|shell|bash|exec|eval|expression|stmt|sql|sql_query|script|code)$",
    re.IGNORECASE,
)

_EXTERNAL_NAME = re.compile(
    r"(?:^|_)"
    r"(?:send|post|publish|deploy|push|notify|webhook|upload|submit|broadcast|tweet|slack)"
    r"(?:_|$)",
    re.IGNORECASE,
)

_EXTERNAL_DESC = re.compile(
    r"\b(?:send(?:ing)?|post(?:ing)?|publish(?:ing)?|deploy(?:ing)?|"
    r"push(?:ing)?|notif(?:y|ying|ication)|webhook|upload(?:ing)?|"
    r"submit(?:ting)?|broadcast(?:ing)?|external\s+(?:api|service|endpoint)|"
    r"(?:to|via)\s+(?:slack|email|api|cloud|remote|webhook))\b",
    re.IGNORECASE,
)

_EXTERNAL_SCHEMA_FIELDS = re.compile(
    r"^(?:url|endpoint|webhook_url|recipient|to|cc|bcc|email)$",
    re.IGNORECASE,
)

_WRITE_NAME = re.compile(
    r"(?:^|_)"
    r"(?:write|edit|create|update|set|put|patch|modify|rename|move|copy|"
    r"mkdir|save|insert|add|append|replace|overwrite|install|configure)"
    r"(?:_|$)",
    re.IGNORECASE,
)

_WRITE_DESC = re.compile(
    r"\b(?:writ(?:e|ing)|edit(?:ing)?|creat(?:e|ing)|updat(?:e|ing)|"
    r"modif(?:y|ying)|renam(?:e|ing)|mov(?:e|ing)|copy(?:ing)?|"
    r"sav(?:e|ing)|insert(?:ing)?|append(?:ing)?|replac(?:e|ing)|"
    r"overwrite(?:ing)?|install(?:ing)?|configur(?:e|ing)|"
    r"set(?:ting)?(?:\s+(?:a\s+)?(?:value|config|option)))\b",
    re.IGNORECASE,
)

_READ_NAME = re.compile(
    r"(?:^|_)"
    r"(?:read|get|list|search|find|fetch|query|show|describe|view|inspect|"
    r"count|check|lookup|browse|scan|stat|info|status|head|tail|cat|less|"
    r"peek|preview|retrieve|load|open|display|summarize|analyze)"
    r"(?:_|$)",
    re.IGNORECASE,
)

_READ_DESC = re.compile(
    r"\b(?:read(?:ing)?|retriev(?:e|ing)|fetch(?:ing)?|get(?:ting)?|"
    r"list(?:ing)?|search(?:ing)?|find(?:ing)?|query(?:ing)?|"
    r"show(?:ing)?|describ(?:e|ing)|view(?:ing)?|inspect(?:ing)?|"
    r"count(?:ing)?|check(?:ing)?|look(?:ing)?\s*up|brows(?:e|ing)|"
    r"scan(?:ning)?|display(?:ing)?|preview(?:ing)?)\b",
    re.IGNORECASE,
)


# ── Public API ────────────────────────────────────────────────────────


def classify_tool_risk(
    name: str,
    description: str,
    input_schema: Optional[Dict[str, Any]] = None,
) -> RiskTier:
    """Classify a tool's risk tier based on its name, description, and schema.

    Parameters
    ----------
    name:
        Tool name (e.g. ``"read_file"``, ``"delete_user"``).
    description:
        Tool description text.
    input_schema:
        JSON Schema for the tool's input (optional).

    Returns
    -------
    RiskTier
        The classified risk level.
    """
    schema_fields = _extract_schema_fields(input_schema) if input_schema else []

    # Priority 1: WRITE_SENSITIVE
    if _matches_sensitive(name, description, schema_fields):
        return RiskTier.WRITE_SENSITIVE

    # Priority 2: WRITE_EXTERNAL
    if _matches_external(name, description, schema_fields):
        return RiskTier.WRITE_EXTERNAL

    # Priority 3: WRITE_REVERSIBLE
    if _matches_write(name, description):
        return RiskTier.WRITE_REVERSIBLE

    # Priority 4: READ
    if _matches_read(name, description):
        return RiskTier.READ

    return RiskTier.UNKNOWN


# ── Internal helpers ──────────────────────────────────────────────────


def _extract_schema_fields(schema: Dict[str, Any], *, _depth: int = 0) -> list[str]:
    """Extract property names from a JSON Schema, recursing into nested objects."""
    if _depth > 5:  # prevent infinite recursion
        return []
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return []
    fields = list(props.keys())
    for field_def in props.values():
        if isinstance(field_def, dict) and field_def.get("type") == "object":
            fields.extend(_extract_schema_fields(field_def, _depth=_depth + 1))
    return fields


def _matches_sensitive(name: str, desc: str, schema_fields: list[str]) -> bool:
    if _SENSITIVE_NAME.search(name):
        return True
    if desc and _SENSITIVE_DESC.search(desc):
        return True
    return any(_SENSITIVE_SCHEMA_FIELDS.match(f) for f in schema_fields)


def _matches_external(name: str, desc: str, schema_fields: list[str]) -> bool:
    if _EXTERNAL_NAME.search(name):
        return True
    if desc and _EXTERNAL_DESC.search(desc):
        return True
    # Schema with URL+body fields suggests external API call
    has_url = any(_EXTERNAL_SCHEMA_FIELDS.match(f) for f in schema_fields)
    has_body = any(f.lower() in ("body", "payload", "data", "content") for f in schema_fields)
    return has_url and has_body


def _matches_write(name: str, desc: str) -> bool:
    if _WRITE_NAME.search(name):
        return True
    return bool(desc and _WRITE_DESC.search(desc))


def _matches_read(name: str, desc: str) -> bool:
    if _READ_NAME.search(name):
        return True
    return bool(desc and _READ_DESC.search(desc))
