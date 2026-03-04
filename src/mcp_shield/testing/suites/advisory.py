"""Advisory checks (ADV-001 .. ADV-005).

Advisories are informational recommendations.  They do NOT affect the
security score or cause FAIL outcomes — they only produce WARN (with
severity="info") or PASS.  Think of them as "good to know" hints.
"""

from __future__ import annotations

import re

from mcp import ClientSession

from mcp_shield.security.scanner import scan_config
from mcp_shield.testing.context import cached_list_tools
from mcp_shield.testing.registry import check
from mcp_shield.testing.result import CheckResult, Outcome


# ── Helpers ───────────────────────────────────────────────────────────

def _get_report():
    return scan_config.get().report


# ── Patterns ──────────────────────────────────────────────────────────

_AUTH_HINTS = re.compile(
    r"(?i)\b(api[_\s]?key|token|secret|password|credential|auth|"
    r"bearer|oauth|api[_\s]?secret|access[_\s]?key|"
    r"connection[_\s]?string|private[_\s]?key)\b"
)

_EXTERNAL_SERVICE = re.compile(
    r"(?i)\b(api\.|\brest\b|graphql|endpoint|webhook|"
    r"third[_\s]?party|external[_\s]?service|"
    r"stripe|twilio|slack|discord|github|gitlab|"
    r"aws|gcp|azure|openai|anthropic|google|"
    r"firebase|supabase|cloudflare|datadog|sentry)\b"
)

_BULK_HINTS_NAME = re.compile(
    r"(?i)(?:^|_)(bulk|batch|all|mass|multi|many|list_delete|"
    r"purge|clear|truncate|flush)(?:$|_)"
)

_BULK_HINTS_DESC = re.compile(
    r"(?i)\b(all\s+(?:records?|items?|rows?|entries|documents?|messages?)|"
    r"bulk\s+(?:delete|update|insert|create|remove)|"
    r"batch\s+(?:process|operation|delete|update)|"
    r"truncat(?:es?|ing)|purg(?:es?|ing)\s+all|"
    r"clear\s+(?:all|entire|whole))\b"
)

_SENSITIVE_DATA = re.compile(
    r"(?i)\b(password|secret|credential|ssn|social[_\s]?security|"
    r"credit[_\s]?card|cvv|bank[_\s]?account|"
    r"private[_\s]?key|pii|phi|hipaa|gdpr|"
    r"medical|health[_\s]?record|diagnosis|"
    r"personal[_\s]?(?:data|information)|"
    r"date[_\s]?of[_\s]?birth|passport|"
    r"driver[_\s]?license|tax[_\s]?id)\b"
)

_NETWORK_VERBS = re.compile(
    r"(?i)\b(fetch|request|download|upload|connect|"
    r"call|invoke|post|get|put|patch|"
    r"browse|navigate|scrape|crawl)\b"
)

_URL_FIELDS = re.compile(
    r"(?i)(url|uri|endpoint|href|link|webhook|callback)"
)


# ── ADV-001: Auth requirement hints ──────────────────────────────────

@check("advisory", "ADV-001", severity="info")
async def check_auth_hints(session: ClientSession) -> CheckResult:
    """Detect if server likely requires authentication credentials."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="ADV-001",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="info",
        )

    hints: list[str] = []
    for tool in tools:
        desc = getattr(tool, "description", "") or ""
        schema_str = str(getattr(tool, "inputSchema", {}) or {})
        combined = f"{desc} {schema_str}"

        matches = _AUTH_HINTS.findall(combined)
        if matches:
            unique = sorted(set(m.lower() for m in matches))
            hints.append(f"{tool.name}: {', '.join(unique)}")

    if hints:
        return CheckResult(
            check_id="ADV-001",
            outcome=Outcome.WARN,
            message=f"{len(hints)} tool(s) reference authentication credentials",
            severity="info",
            details=[f"  {h}" for h in hints[:15]],
        )

    return CheckResult(
        check_id="ADV-001",
        outcome=Outcome.PASS,
        message="No auth requirement hints detected",
        severity="info",
    )


# ── ADV-002: External service dependency ─────────────────────────────

@check("advisory", "ADV-002", severity="info")
async def check_external_dependencies(session: ClientSession) -> CheckResult:
    """Flag tools that depend on external third-party services."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="ADV-002",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="info",
        )

    deps: list[str] = []
    for tool in tools:
        desc = getattr(tool, "description", "") or ""
        name = getattr(tool, "name", "") or ""
        combined = f"{name} {desc}"

        matches = _EXTERNAL_SERVICE.findall(combined)
        if matches:
            unique = sorted(set(m.lower().rstrip(".") for m in matches))
            deps.append(f"{name}: {', '.join(unique)}")

    if deps:
        return CheckResult(
            check_id="ADV-002",
            outcome=Outcome.WARN,
            message=f"{len(deps)} tool(s) depend on external services",
            severity="info",
            details=[f"  {d}" for d in deps[:15]],
        )

    return CheckResult(
        check_id="ADV-002",
        outcome=Outcome.PASS,
        message="No external service dependencies detected",
        severity="info",
    )


# ── ADV-003: Bulk operation warning ──────────────────────────────────

@check("advisory", "ADV-003", severity="info")
async def check_bulk_operations(session: ClientSession) -> CheckResult:
    """Flag tools that can operate on multiple records at once."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="ADV-003",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="info",
        )

    bulk: list[str] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", "") or ""

        if _BULK_HINTS_NAME.search(name) or _BULK_HINTS_DESC.search(desc):
            bulk.append(name)
            continue

        # Array input fields suggest batch operations
        schema = getattr(tool, "inputSchema", {}) or {}
        props = schema.get("properties", {})
        for field_name, field_def in props.items():
            if field_def.get("type") == "array":
                items = field_def.get("items", {})
                if not field_def.get("maxItems"):
                    bulk.append(f"{name} (unbounded array: {field_name})")
                    break

    if bulk:
        return CheckResult(
            check_id="ADV-003",
            outcome=Outcome.WARN,
            message=f"{len(bulk)} tool(s) may perform bulk operations",
            severity="info",
            details=[f"  {b}" for b in bulk[:15]],
        )

    return CheckResult(
        check_id="ADV-003",
        outcome=Outcome.PASS,
        message="No bulk operation risks detected",
        severity="info",
    )


# ── ADV-004: Sensitive data exposure hints ───────────────────────────

@check("advisory", "ADV-004", severity="info")
async def check_sensitive_data_hints(session: ClientSession) -> CheckResult:
    """Flag tools that may expose or process sensitive data."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="ADV-004",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="info",
        )

    sensitive: list[str] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", "") or ""
        schema_str = str(getattr(tool, "inputSchema", {}) or {})
        combined = f"{name} {desc} {schema_str}"

        matches = _SENSITIVE_DATA.findall(combined)
        if matches:
            unique = sorted(set(m.lower() for m in matches))
            sensitive.append(f"{name}: {', '.join(unique)}")

    if sensitive:
        return CheckResult(
            check_id="ADV-004",
            outcome=Outcome.WARN,
            message=f"{len(sensitive)} tool(s) may handle sensitive data",
            severity="info",
            details=[f"  {s}" for s in sensitive[:15]],
        )

    return CheckResult(
        check_id="ADV-004",
        outcome=Outcome.PASS,
        message="No sensitive data exposure hints detected",
        severity="info",
    )


# ── ADV-005: External network access ────────────────────────────────

@check("advisory", "ADV-005", severity="info")
async def check_network_access(session: ClientSession) -> CheckResult:
    """Flag tools that send or receive data over the network."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="ADV-005",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="info",
        )

    network: list[str] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", "") or ""

        has_verb = bool(_NETWORK_VERBS.search(f"{name} {desc}"))

        # Check for URL input fields
        schema = getattr(tool, "inputSchema", {}) or {}
        props = schema.get("properties", {})
        has_url_field = any(
            _URL_FIELDS.search(field_name)
            for field_name in props
        )

        if has_verb or has_url_field:
            reasons = []
            if has_verb:
                reasons.append("network verb")
            if has_url_field:
                reasons.append("URL input field")
            network.append(f"{name} ({', '.join(reasons)})")

    if network:
        return CheckResult(
            check_id="ADV-005",
            outcome=Outcome.WARN,
            message=f"{len(network)} tool(s) access external network",
            severity="info",
            details=[f"  {n}" for n in network[:15]],
        )

    return CheckResult(
        check_id="ADV-005",
        outcome=Outcome.PASS,
        message="No external network access detected",
        severity="info",
    )
