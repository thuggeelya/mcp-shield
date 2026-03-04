"""E2E test against the real @modelcontextprotocol/server-everything.

Tests MCP capabilities that server-filesystem lacks:
- Resources (list, read, templates)
- Prompts (list, get with/without args)
- Tools with diverse profiles (echo, math, image, env)
- Audit logging across all capability types
- Security scan on a server with many tools

Requires: npx (Node.js) and network access for first npm install.

Run:
    uv run pytest tests/e2e/test_real_everything_server.py -v -m real_server --timeout=120
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcp_shield.storage.audit_db import AuditDB

from .conftest import UV_BIN, NPX_BIN

pytestmark = [
    pytest.mark.skipif(NPX_BIN is None, reason="npx not found (Node.js required)"),
    pytest.mark.real_server,
]


@pytest.fixture
def everything_proxy_params(audit_db_path: Path) -> StdioServerParameters:
    """Launch proxy wrapping @modelcontextprotocol/server-everything."""
    server_cmd = "npx -y @modelcontextprotocol/server-everything"
    return StdioServerParameters(
        command=UV_BIN,
        args=[
            "run", "mcp-shield", "proxy",
            server_cmd,
            "--deny", "toggle-*",
            "--rate-limit", "60",
            "--audit-db", str(audit_db_path),
        ],
        env={**os.environ},
    )


# ── Tools ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_handshake(everything_proxy_params: StdioServerParameters):
    """Proxy completes MCP handshake with server-everything."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_list_tools(everything_proxy_params: StdioServerParameters):
    """Lists tools with deny filter applied."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]

            # Core tools present
            assert "echo" in names
            assert "get-sum" in names
            assert "get-tiny-image" in names

            # toggle_* denied
            assert "toggle-simulated-logging" not in names
            assert "toggle-subscriber-updates" not in names


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_call_echo(everything_proxy_params: StdioServerParameters):
    """echo tool returns message through proxy."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("echo", {"message": "shield-test"})
            assert "shield-test" in result.content[0].text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_call_get_sum(everything_proxy_params: StdioServerParameters):
    """get-sum returns correct arithmetic result."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-sum", {"a": 17, "b": 25})
            assert "42" in result.content[0].text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_call_get_env(everything_proxy_params: StdioServerParameters):
    """get-env returns environment variables."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-env", {})
            text = result.content[0].text
            # Should contain some env vars as JSON
            assert "PATH" in text or "{" in text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_call_denied_tool(everything_proxy_params: StdioServerParameters):
    """toggle-simulated-logging is blocked by deny filter."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("toggle-simulated-logging", {})
            assert "denied" in result.content[0].text.lower()


# ── Resources ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_list_resources(everything_proxy_params: StdioServerParameters):
    """list_resources returns static documents from server-everything."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_resources()
            names = [r.name for r in result.resources]

            assert len(names) >= 5
            assert "features.md" in names


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_read_resource_static(everything_proxy_params: StdioServerParameters):
    """read_resource returns content of a static document."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.read_resource(
                "demo://resource/static/document/features.md"
            )
            # Should return markdown content
            assert len(result.contents) > 0
            text = result.contents[0].text
            assert len(text) > 50  # non-trivial content


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_read_resource_dynamic(everything_proxy_params: StdioServerParameters):
    """read_resource returns dynamically generated content."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.read_resource(
                "demo://resource/dynamic/text/1"
            )
            assert len(result.contents) > 0
            text = result.contents[0].text
            assert "Resource 1" in text


# ── Prompts ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_list_prompts(everything_proxy_params: StdioServerParameters):
    """list_prompts returns all 4 prompts."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_prompts()
            names = [p.name for p in result.prompts]

            assert len(names) >= 4
            assert "simple-prompt" in names
            assert "args-prompt" in names


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_get_prompt_simple(everything_proxy_params: StdioServerParameters):
    """get_prompt returns simple prompt without arguments."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.get_prompt("simple-prompt")
            assert len(result.messages) > 0
            assert "simple prompt" in result.messages[0].content.text.lower()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_get_prompt_with_args(everything_proxy_params: StdioServerParameters):
    """get_prompt with arguments returns parameterized content."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.get_prompt("args-prompt", {"city": "Tokyo"})
            assert len(result.messages) > 0
            assert "Tokyo" in result.messages[0].content.text


# ── Audit ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(90)
async def test_audit_all_capabilities(
    everything_proxy_params: StdioServerParameters,
    audit_db_path: Path,
):
    """Full session exercises all MCP capabilities and verifies audit trail."""
    async with stdio_client(everything_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Tools
            await session.list_tools()
            await session.call_tool("echo", {"message": "audit-test"})
            await session.call_tool("get-sum", {"a": 1, "b": 2})
            await session.call_tool("toggle-simulated-logging", {})  # denied

            # Resources
            await session.list_resources()
            await session.read_resource("demo://resource/dynamic/text/1")

            # Prompts
            await session.list_prompts()
            await session.get_prompt("simple-prompt")
            await session.get_prompt("args-prompt", {"city": "Berlin"})

    db = AuditDB(audit_db_path)
    db.open()

    events = db.get_events(limit=100)
    actions = {e.action for e in events}

    # All 6 action types should be present
    assert "list_tools" in actions
    assert "call_tool" in actions
    assert "list_resources" in actions
    assert "read_resource" in actions
    assert "list_prompts" in actions
    assert "get_prompt" in actions

    # Blocked event (denied tool)
    blocked = [e for e in events if e.blocked]
    assert len(blocked) >= 1

    # Risk classification active
    call_events = [e for e in events if e.action == "call_tool" and e.tool_name]
    risk_tiers = {e.risk_tier for e in call_events}
    assert len(risk_tiers) >= 1

    # Tool snapshots stored
    snapshots = db.get_latest_snapshots()
    assert len(snapshots) >= 10  # server-everything has 13+ tools

    # Security findings
    findings = db._db.execute("SELECT * FROM security_findings").fetchall()
    # server-everything may or may not trigger findings — just verify query works
    assert isinstance(findings, list)

    # Stats
    stats = db.get_stats()
    assert stats["total"] >= 9  # at least 9 operations
    assert stats["tool_calls"] >= 3
    assert stats["blocked"] >= 1

    db.close()
