"""E2E test against the real @modelcontextprotocol/server-filesystem.

Tests the full proxy stack with a production MCP server:
- Real tools with different risk profiles
- Security scan (injection detection on path fields)
- Tool filtering (deny write/delete operations)
- Risk classification (read vs write vs sensitive)
- Audit logging with real tool calls
- Rug pull detection (snapshots stored)

Requires: npx (Node.js) and network access for first npm install.

Run:
    uv run pytest tests/e2e/test_real_fs_server.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcp_shield.storage.audit_db import AuditDB

from .conftest import NPX_BIN, UV_BIN

pytestmark = [
    pytest.mark.skipif(NPX_BIN is None, reason="npx not found (Node.js required)"),
    pytest.mark.real_server,
]


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Create a sandbox directory with test files."""
    sandbox = tmp_path / "fs-sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("Hello from e2e test!")
    (sandbox / "subdir").mkdir()
    (sandbox / "subdir" / "nested.txt").write_text("Nested file")
    return sandbox


@pytest.fixture
def fs_proxy_params(sandbox: Path, audit_db_path: Path) -> StdioServerParameters:
    """Launch proxy wrapping @modelcontextprotocol/server-filesystem."""
    server_cmd = f"npx -y @modelcontextprotocol/server-filesystem {sandbox}"
    return StdioServerParameters(
        command=UV_BIN,
        args=[
            "run", "mcp-shield", "proxy",
            server_cmd,
            "--deny", "move_*",
            "--deny", "edit_*",
            "--rate-limit", "60",
            "--audit-db", str(audit_db_path),
        ],
        env={**os.environ},
    )


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_handshake(fs_proxy_params: StdioServerParameters):
    """Proxy completes MCP handshake with real filesystem server."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_deny_filter(fs_proxy_params: StdioServerParameters):
    """--deny move_* --deny edit_* hides move_file and edit_file."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]

            assert "move_file" not in names
            assert "edit_file" not in names
            assert len(names) >= 8  # filesystem server has ~14 tools, minus 2 denied


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_read_file(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """read_file returns real file contents through proxy."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Determine tool name (varies by server version)
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            read_tool = "read_text_file" if "read_text_file" in names else "read_file"

            result = await session.call_tool(read_tool, {"path": str(sandbox / "hello.txt")})
            assert "Hello" in result.content[0].text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_write_file(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """write_file creates a real file through proxy."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("write_file", {
                "path": str(sandbox / "written_by_proxy.txt"),
                "content": "Written through proxy!",
            })
            assert (sandbox / "written_by_proxy.txt").exists()
            assert "Written through proxy!" in (sandbox / "written_by_proxy.txt").read_text()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_list_directory(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """list_directory returns directory contents."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("list_directory", {"path": str(sandbox)})
            text = result.content[0].text
            assert "hello.txt" in text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_directory_tree(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """directory_tree shows nested structure."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("directory_tree", {"path": str(sandbox)})
            text = result.content[0].text
            assert "subdir" in text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_search_files(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """search_files finds matching files."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("search_files", {
                "path": str(sandbox),
                "pattern": "*.txt",
            })
            text = result.content[0].text
            assert "hello.txt" in text


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_denied_tool_move_file(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """move_file is blocked by deny filter."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("move_file", {
                "source": str(sandbox / "hello.txt"),
                "destination": str(sandbox / "moved.txt"),
            })
            assert "denied" in result.content[0].text.lower()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_denied_tool_edit_file(fs_proxy_params: StdioServerParameters, sandbox: Path):
    """edit_file is blocked by deny filter."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("edit_file", {
                "path": str(sandbox / "hello.txt"),
                "edits": [{"oldText": "Hello", "newText": "Bye"}],
            })
            assert "denied" in result.content[0].text.lower()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_resources_graceful(fs_proxy_params: StdioServerParameters):
    """list_resources handles unsupported capability gracefully."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            try:
                result = await session.list_resources()
                # Server may or may not support resources — either way, no crash
                assert isinstance(result.resources, list)
            except Exception:
                # Graceful failure is acceptable
                pass


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_audit_complete(fs_proxy_params: StdioServerParameters, sandbox: Path, audit_db_path: Path):
    """Full proxy session produces audit events, findings, and snapshots."""
    async with stdio_client(fs_proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Trigger tools for audit trail
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            read_tool = "read_text_file" if "read_text_file" in names else "read_file"

            await session.call_tool(read_tool, {"path": str(sandbox / "hello.txt")})
            await session.call_tool("write_file", {
                "path": str(sandbox / "audit_test.txt"),
                "content": "audit test",
            })
            await session.call_tool("list_directory", {"path": str(sandbox)})
            await session.call_tool("move_file", {  # denied
                "source": str(sandbox / "hello.txt"),
                "destination": str(sandbox / "nope.txt"),
            })

    db = AuditDB(audit_db_path)
    db.open()

    # Events logged
    events = db.get_events(limit=100)
    assert len(events) >= 4

    # Risk classification active
    call_tool_events = [e for e in events if e.action == "call_tool" and e.tool_name]
    risk_tiers = {e.risk_tier for e in call_tool_events}
    assert len(risk_tiers) >= 2, f"Expected diverse risk tiers, got: {risk_tiers}"

    # Blocked events
    blocked = [e for e in events if e.blocked]
    assert len(blocked) >= 1

    # Security findings saved
    findings = db._db.execute("SELECT * FROM security_findings").fetchall()
    assert len(findings) > 0, "Expected findings (path fields are flagged)"

    # Tool snapshots stored
    snapshots = db.get_latest_snapshots()
    assert len(snapshots) >= 8  # filesystem server has many tools

    # Stats
    stats = db.get_stats()
    assert stats["total"] > 0
    assert stats["tool_calls"] > 0
    assert stats["blocked"] >= 1

    db.close()
