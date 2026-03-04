"""End-to-end test: MCP client → ShieldProxy → test MCP server.

Tests all 6 MCP operations through the proxy, verifies tool filtering,
risk classification, security scanning, and audit logging.

Run:
    uv run pytest tests/e2e/test_proxy_e2e.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcp_shield.storage.audit_db import AuditDB

from .conftest import UV_BIN


@pytest.fixture
def proxy_params(basic_server_script: str, audit_db_path: Path) -> StdioServerParameters:
    """StdioServerParameters to launch proxy wrapping the basic test server."""
    return StdioServerParameters(
        command=UV_BIN,
        args=[
            "run", "mcp-shield", "proxy",
            f"{UV_BIN} run python {basic_server_script}",
            "--deny", "delete_*",
            "--rate-limit", "30",
            "--audit-db", str(audit_db_path),
        ],
        env={**os.environ},
    )


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_proxy_handshake(proxy_params: StdioServerParameters):
    """Proxy completes MCP handshake."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # If we get here, handshake succeeded


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_list_tools_deny_filter(proxy_params: StdioServerParameters):
    """--deny delete_* hides delete_file from tool list."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]

            assert "delete_file" not in names
            assert "read_file" in names
            assert "write_file" in names
            assert "exec_command" in names
            assert "send_email" in names
            assert "safe_tool" in names


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_call_tool_allowed(proxy_params: StdioServerParameters):
    """Allowed tool calls are forwarded to upstream."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "/etc/hostname"})
            assert result.content
            assert "Contents of" in result.content[0].text


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_call_tool_denied(proxy_params: StdioServerParameters):
    """Denied tool calls are blocked by the proxy."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("delete_file", {"path": "/tmp/x"})
            assert "denied" in result.content[0].text.lower()


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_call_multiple_tools(proxy_params: StdioServerParameters):
    """Various tool calls succeed through the proxy."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            calls = [
                ("write_file", {"path": "/tmp/x", "content": "hello"}),
                ("exec_command", {"command": "ls"}),
                ("send_email", {"to": "test@test.com", "subject": "Hi", "body": "Test"}),
                ("safe_tool", {"input": "test"}),
            ]
            for tool_name, args in calls:
                result = await session.call_tool(tool_name, args)
                text = result.content[0].text
                assert text and "Error" not in text, f"{tool_name} failed: {text}"


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_list_resources(proxy_params: StdioServerParameters):
    """list_resources is forwarded."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_resources()
            assert len(result.resources) > 0


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_list_prompts(proxy_params: StdioServerParameters):
    """list_prompts is forwarded."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_prompts()
            assert len(result.prompts) > 0


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_get_prompt(proxy_params: StdioServerParameters):
    """get_prompt is forwarded."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.get_prompt("greet")
            assert result.messages
            assert result.messages[0].content.text


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_audit_events_logged(proxy_params: StdioServerParameters, audit_db_path: Path):
    """Proxy logs audit events to SQLite."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()
            await session.call_tool("read_file", {"path": "/tmp/x"})
            await session.call_tool("delete_file", {"path": "/tmp/x"})  # denied

    db = AuditDB(audit_db_path)
    db.open()
    events = db.get_events(limit=100)
    assert len(events) > 0

    # Check risk classification is active
    risk_tiers = {e.risk_tier for e in events if e.tool_name}
    assert len(risk_tiers) > 1, f"Expected multiple risk tiers, got: {risk_tiers}"

    # Check blocked event
    blocked = [e for e in events if e.blocked]
    assert len(blocked) > 0
    db.close()


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_security_findings_saved(proxy_params: StdioServerParameters, audit_db_path: Path):
    """Security scan findings are persisted to audit DB."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()

    db = AuditDB(audit_db_path)
    db.open()
    rows = db._db.execute("SELECT * FROM security_findings").fetchall()
    assert len(rows) > 0, "Expected security findings (poisoned exec_command)"

    severities = {r["severity"] for r in rows}
    assert "critical" in severities or "high" in severities
    db.close()


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_tool_snapshots_saved(proxy_params: StdioServerParameters, audit_db_path: Path):
    """Tool snapshots are stored for rug pull detection."""
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()

    db = AuditDB(audit_db_path)
    db.open()
    snapshots = db.get_latest_snapshots()
    assert len(snapshots) > 0
    assert "read_file" in snapshots
    assert snapshots["read_file"]["description_hash"]
    db.close()
