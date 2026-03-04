"""Tests for advisory suite checks (ADV-001 .. ADV-005).

Advisory checks analyse tool metadata without connecting to a real
server.  We mock the ClientSession to provide tool definitions.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_shield.testing.result import Outcome
from mcp_shield.testing.suites.advisory import (
    check_auth_hints,
    check_external_dependencies,
    check_bulk_operations,
    check_sensitive_data_hints,
    check_network_access,
)


def _make_session(tools):
    """Create a mock ClientSession returning the given tools."""
    session = AsyncMock()
    result = MagicMock()
    result.tools = tools
    session.list_tools = AsyncMock(return_value=result)
    return session


def _tool(name, description="", input_schema=None):
    t = MagicMock()
    t.name = name
    t.description = description
    t.inputSchema = input_schema or {}
    return t


# ── ADV-001: Auth hints ──────────────────────────────────────────────

class TestAdvAuthHints:
    @pytest.mark.asyncio
    async def test_api_key_in_description(self):
        session = _make_session([_tool("search", "Requires API key for Brave")])
        result = await check_auth_hints(session)
        assert result.outcome is Outcome.WARN
        assert "1" in result.message

    @pytest.mark.asyncio
    async def test_no_auth_hints(self):
        session = _make_session([_tool("add", "Add two numbers")])
        result = await check_auth_hints(session)
        assert result.outcome is Outcome.PASS

    @pytest.mark.asyncio
    async def test_oauth_hint(self):
        session = _make_session([_tool("login", "Uses OAuth to authenticate")])
        result = await check_auth_hints(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_no_tools_skip(self):
        session = _make_session([])
        result = await check_auth_hints(session)
        assert result.outcome is Outcome.SKIP


# ── ADV-002: External dependencies ───────────────────────────────────

class TestAdvExternalDeps:
    @pytest.mark.asyncio
    async def test_stripe_detected(self):
        session = _make_session([_tool("charge", "Charge via Stripe API")])
        result = await check_external_dependencies(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_no_external_deps(self):
        session = _make_session([_tool("add", "Add two numbers")])
        result = await check_external_dependencies(session)
        assert result.outcome is Outcome.PASS

    @pytest.mark.asyncio
    async def test_github_detected(self):
        session = _make_session([_tool("pr", "Create GitHub pull request")])
        result = await check_external_dependencies(session)
        assert result.outcome is Outcome.WARN


# ── ADV-003: Bulk operations ─────────────────────────────────────────

class TestAdvBulkOps:
    @pytest.mark.asyncio
    async def test_bulk_delete_by_name(self):
        session = _make_session([_tool("bulk_delete", "Delete records in batch")])
        result = await check_bulk_operations(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_truncate_by_description(self):
        session = _make_session([_tool("clean", "Truncates all records from the table")])
        result = await check_bulk_operations(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_unbounded_array_input(self):
        tool = _tool("process", "Process items", input_schema={
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}},
            },
        })
        session = _make_session([tool])
        result = await check_bulk_operations(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_bounded_array_not_flagged(self):
        tool = _tool("process", "Process items", input_schema={
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}, "maxItems": 10},
            },
        })
        session = _make_session([tool])
        result = await check_bulk_operations(session)
        assert result.outcome is Outcome.PASS

    @pytest.mark.asyncio
    async def test_single_record_not_flagged(self):
        session = _make_session([_tool("get_user", "Get a single user")])
        result = await check_bulk_operations(session)
        assert result.outcome is Outcome.PASS


# ── ADV-004: Sensitive data hints ────────────────────────────────────

class TestAdvSensitiveData:
    @pytest.mark.asyncio
    async def test_password_field_flagged(self):
        tool = _tool("login", "Authenticate user", input_schema={
            "type": "object",
            "properties": {"password": {"type": "string"}},
        })
        session = _make_session([tool])
        result = await check_sensitive_data_hints(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_medical_record_flagged(self):
        session = _make_session([_tool("get_record", "Fetch patient health record")])
        result = await check_sensitive_data_hints(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_no_sensitive_data(self):
        session = _make_session([_tool("add", "Add two numbers")])
        result = await check_sensitive_data_hints(session)
        assert result.outcome is Outcome.PASS


# ── ADV-005: Network access ──────────────────────────────────────────

class TestAdvNetworkAccess:
    @pytest.mark.asyncio
    async def test_fetch_url_flagged(self):
        tool = _tool("fetch_page", "Fetch a web page", input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
        })
        session = _make_session([tool])
        result = await check_network_access(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_download_flagged(self):
        session = _make_session([_tool("download", "Download file from URL")])
        result = await check_network_access(session)
        assert result.outcome is Outcome.WARN

    @pytest.mark.asyncio
    async def test_local_read_not_flagged(self):
        session = _make_session([_tool("read_file", "Read a file from disk")])
        result = await check_network_access(session)
        assert result.outcome is Outcome.PASS

    @pytest.mark.asyncio
    async def test_calculator_not_flagged(self):
        session = _make_session([_tool("add", "Add two numbers")])
        result = await check_network_access(session)
        assert result.outcome is Outcome.PASS
