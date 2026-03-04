"""MCP spec compliance checks (COMP-001 .. COMP-010)."""

from __future__ import annotations

import re

from mcp import ClientSession

from mcp_shield.testing.registry import check
from mcp_shield.testing.result import CheckResult, Outcome
from mcp_shield.testing.context import cached_list_tools, init_result_var

# MCP spec: tool names must be 1-64 chars, [a-zA-Z0-9_.-]
_TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,64}$")


def _get_server_info(session: ClientSession) -> object | None:
    """Extract serverInfo from the InitializeResult stored by the runner."""
    init_result = init_result_var.get()
    if init_result is not None:
        return getattr(init_result, "serverInfo", None)
    return None


@check("compliance", "COMP-001", severity="critical")
async def verify_handshake(session: ClientSession) -> CheckResult:
    """Verify server completed the initialize handshake."""
    info = _get_server_info(session)
    if info is None:
        return CheckResult(
            check_id="COMP-001",
            outcome=Outcome.FAIL,
            message="Server did not return server_info in initialize response",
            severity="critical",
        )
    return CheckResult(
        check_id="COMP-001",
        outcome=Outcome.PASS,
        message=f"Handshake OK — server: {getattr(info, 'name', '?')}",
        severity="critical",
    )


@check("compliance", "COMP-002", severity="error")
async def verify_server_identity(session: ClientSession) -> CheckResult:
    """Verify server provides name and version."""
    info = _get_server_info(session)
    name = getattr(info, "name", "") if info else ""
    version = getattr(info, "version", "") if info else ""
    missing: list[str] = []
    if not name:
        missing.append("name")
    if not version:
        missing.append("version")
    if missing:
        return CheckResult(
            check_id="COMP-002",
            outcome=Outcome.WARN,
            message=f"Server missing: {', '.join(missing)}",
            severity="warning",
        )
    return CheckResult(
        check_id="COMP-002",
        outcome=Outcome.PASS,
        message=f"Server identity: {name} v{version}",
    )


@check("compliance", "COMP-003", severity="error")
async def verify_tools_list_schema(session: ClientSession) -> CheckResult:
    """Verify tools/list returns valid tool definitions with inputSchema."""
    try:
        result = await cached_list_tools(session)
    except Exception as exc:
        return CheckResult(
            check_id="COMP-003",
            outcome=Outcome.FAIL,
            message=f"tools/list failed: {exc}",
            severity="error",
        )

    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="COMP-003",
            outcome=Outcome.WARN,
            message="Server has zero tools registered",
            severity="warning",
        )

    broken: list[str] = []
    for tool in tools:
        schema = getattr(tool, "inputSchema", None)
        if not schema:
            broken.append(tool.name)

    if broken:
        return CheckResult(
            check_id="COMP-003",
            outcome=Outcome.FAIL,
            message=f"{len(broken)} tool(s) missing inputSchema",
            severity="error",
            details=[f"  {name}" for name in broken],
        )

    return CheckResult(
        check_id="COMP-003",
        outcome=Outcome.PASS,
        message=f"All {len(tools)} tools have valid inputSchema",
    )


@check("compliance", "COMP-004", severity="warning")
async def verify_tool_name_format(session: ClientSession) -> CheckResult:
    """Verify tool names follow spec: [a-zA-Z0-9_.-], 1-64 chars."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="COMP-004",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="warning",
        )

    bad: list[str] = []
    for tool in tools:
        if not _TOOL_NAME_RE.match(tool.name):
            bad.append(tool.name)

    if bad:
        return CheckResult(
            check_id="COMP-004",
            outcome=Outcome.WARN,
            message=f"{len(bad)} tool name(s) violate naming spec",
            severity="warning",
            details=[f"  {name!r}" for name in bad],
        )

    return CheckResult(
        check_id="COMP-004",
        outcome=Outcome.PASS,
        message=f"All {len(tools)} tool names conform to spec",
    )


@check("compliance", "COMP-005", severity="error")
async def verify_ping(session: ClientSession) -> CheckResult:
    """Verify server responds to ping."""
    try:
        await session.send_ping()
    except Exception as exc:
        return CheckResult(
            check_id="COMP-005",
            outcome=Outcome.FAIL,
            message=f"Ping failed: {exc}",
            severity="error",
        )
    return CheckResult(
        check_id="COMP-005",
        outcome=Outcome.PASS,
        message="Ping OK",
    )


@check("compliance", "COMP-006", severity="warning")
async def verify_tool_descriptions(session: ClientSession) -> CheckResult:
    """Verify all tools have a non-empty description."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="COMP-006",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="warning",
        )

    undocumented: list[str] = []
    for tool in tools:
        desc = getattr(tool, "description", "") or ""
        if not desc.strip():
            undocumented.append(tool.name)

    if undocumented:
        return CheckResult(
            check_id="COMP-006",
            outcome=Outcome.WARN,
            message=f"{len(undocumented)} tool(s) missing description",
            severity="warning",
            details=[f"  {name}" for name in undocumented],
        )

    return CheckResult(
        check_id="COMP-006",
        outcome=Outcome.PASS,
        message=f"All {len(tools)} tools have descriptions",
    )


@check("compliance", "COMP-007", severity="error")
async def verify_capabilities_consistency(session: ClientSession) -> CheckResult:
    """Verify server declared capabilities match actual behaviour.

    If the server declares tools capability, tools/list must succeed.
    """
    caps = session.get_server_capabilities()
    if caps is None:
        return CheckResult(
            check_id="COMP-007",
            outcome=Outcome.WARN,
            message="Server did not declare capabilities",
            severity="warning",
        )

    issues: list[str] = []

    # If tools capability declared, tools/list must work
    has_tools_cap = getattr(caps, "tools", None) is not None
    if has_tools_cap:
        try:
            await cached_list_tools(session)
        except Exception as exc:
            issues.append(f"Declared tools capability but tools/list failed: {exc}")

    # If resources capability declared, resources/list must work
    has_resources_cap = getattr(caps, "resources", None) is not None
    if has_resources_cap:
        try:
            await session.list_resources()
        except Exception as exc:
            issues.append(f"Declared resources capability but resources/list failed: {exc}")

    # If prompts capability declared, prompts/list must work
    has_prompts_cap = getattr(caps, "prompts", None) is not None
    if has_prompts_cap:
        try:
            await session.list_prompts()
        except Exception as exc:
            issues.append(f"Declared prompts capability but prompts/list failed: {exc}")

    if issues:
        return CheckResult(
            check_id="COMP-007",
            outcome=Outcome.FAIL,
            message=f"{len(issues)} capability mismatch(es)",
            severity="error",
            details=issues,
        )

    return CheckResult(
        check_id="COMP-007",
        outcome=Outcome.PASS,
        message="Declared capabilities are consistent",
    )


# ── COMP-008 ──────────────────────────────────────────────────────────

@check("compliance", "COMP-008", severity="warning")
async def verify_schema_field_descriptions(session: ClientSession) -> CheckResult:
    """Verify that input schema fields have descriptions."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="COMP-008",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="warning",
        )

    total_fields = 0
    undescribed: list[str] = []

    for tool in tools:
        schema = getattr(tool, "inputSchema", {}) or {}
        props = schema.get("properties", {})
        for field_name, field_def in props.items():
            total_fields += 1
            desc = field_def.get("description", "")
            if not desc or not desc.strip():
                undescribed.append(f"{tool.name}.{field_name}")

    if not total_fields:
        return CheckResult(
            check_id="COMP-008",
            outcome=Outcome.SKIP,
            message="No schema fields to check",
            severity="warning",
        )

    if undescribed:
        pct = len(undescribed) / total_fields * 100
        return CheckResult(
            check_id="COMP-008",
            outcome=Outcome.WARN,
            message=(
                f"{len(undescribed)}/{total_fields} field(s) "
                f"({pct:.0f}%) missing description"
            ),
            severity="warning",
            details=[f"  {f}" for f in undescribed[:20]],
        )

    return CheckResult(
        check_id="COMP-008",
        outcome=Outcome.PASS,
        message=f"All {total_fields} fields have descriptions",
    )


# ── COMP-009 ──────────────────────────────────────────────────────────

_PATH_LIKE = re.compile(r"(?i)(path|file|dir|folder|uri|url)")
_EMAIL_LIKE = re.compile(r"(?i)(email|e[-_]?mail)")
_ID_LIKE = re.compile(r"(?i)(^id$|_id$|_uuid$|_key$)")


@check("compliance", "COMP-009", severity="warning")
async def verify_schema_constraints(session: ClientSession) -> CheckResult:
    """Verify string fields have appropriate constraints (maxLength, pattern)."""
    result = await cached_list_tools(session)
    tools = result.tools if result else []
    if not tools:
        return CheckResult(
            check_id="COMP-009",
            outcome=Outcome.SKIP,
            message="No tools to check",
            severity="warning",
        )

    issues: list[str] = []

    for tool in tools:
        schema = getattr(tool, "inputSchema", {}) or {}
        props = schema.get("properties", {})
        for field_name, field_def in props.items():
            ftype = field_def.get("type", "")
            if ftype != "string":
                continue

            has_max = "maxLength" in field_def
            has_pattern = "pattern" in field_def
            has_enum = "enum" in field_def

            if has_enum:
                continue  # enum is self-constraining

            # Path-like fields should have pattern
            if _PATH_LIKE.search(field_name) and not has_pattern:
                issues.append(
                    f"{tool.name}.{field_name}: path-like field without pattern"
                )
            # No maxLength on any string
            elif not has_max:
                issues.append(
                    f"{tool.name}.{field_name}: string without maxLength"
                )

    if not issues:
        return CheckResult(
            check_id="COMP-009",
            outcome=Outcome.PASS,
            message="String fields have adequate constraints",
        )

    return CheckResult(
        check_id="COMP-009",
        outcome=Outcome.WARN,
        message=f"{len(issues)} field(s) missing constraints",
        severity="warning",
        details=[f"  {i}" for i in issues[:20]],
    )


# ── COMP-010 ──────────────────────────────────────────────────────────

@check("compliance", "COMP-010", severity="warning")
async def verify_resources_and_prompts(session: ClientSession) -> CheckResult:
    """Validate resources and prompts have descriptions and proper schemas."""
    caps = session.get_server_capabilities()
    if caps is None:
        return CheckResult(
            check_id="COMP-010",
            outcome=Outcome.SKIP,
            message="No capabilities declared",
            severity="warning",
        )

    issues: list[str] = []

    # Check resources
    has_resources = getattr(caps, "resources", None) is not None
    if has_resources:
        try:
            res_result = await session.list_resources()
            resources = res_result.resources if res_result else []
            for r in resources:
                name = getattr(r, "name", "") or ""
                desc = getattr(r, "description", "") or ""
                uri = getattr(r, "uri", "") or ""
                if not desc.strip():
                    issues.append(f"Resource '{name or uri}': missing description")
                if not uri:
                    issues.append(f"Resource '{name}': missing URI")
        except Exception:
            pass  # COMP-007 already covers this

    # Check prompts
    has_prompts = getattr(caps, "prompts", None) is not None
    if has_prompts:
        try:
            pr_result = await session.list_prompts()
            prompts = pr_result.prompts if pr_result else []
            for p in prompts:
                name = getattr(p, "name", "") or ""
                desc = getattr(p, "description", "") or ""
                if not desc.strip():
                    issues.append(f"Prompt '{name}': missing description")
                args = getattr(p, "arguments", []) or []
                for arg in args:
                    arg_name = getattr(arg, "name", "") or ""
                    arg_desc = getattr(arg, "description", "") or ""
                    if not arg_desc.strip():
                        issues.append(
                            f"Prompt '{name}' arg '{arg_name}': missing description"
                        )
        except Exception:
            pass

    if not has_resources and not has_prompts:
        return CheckResult(
            check_id="COMP-010",
            outcome=Outcome.SKIP,
            message="Server has no resources or prompts",
            severity="warning",
        )

    if issues:
        return CheckResult(
            check_id="COMP-010",
            outcome=Outcome.WARN,
            message=f"{len(issues)} resource/prompt issue(s)",
            severity="warning",
            details=[f"  {i}" for i in issues[:20]],
        )

    return CheckResult(
        check_id="COMP-010",
        outcome=Outcome.PASS,
        message="Resources and prompts are well-described",
    )
