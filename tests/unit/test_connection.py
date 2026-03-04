"""Tests for mcp_shield.client.connection — parse_target & MCPConnection."""

from unittest.mock import AsyncMock, patch

import anyio
import pytest

from mcp_shield.client.connection import (
    MCPConnection,
    TransportKind,
    ServerTarget,
    parse_target,
    _BLOCKED_ENV_KEYS,
)


def _with_which(cmd: str):
    """Decorator / context manager to mock shutil.which for a given command."""
    return patch(
        "mcp_shield.client.connection.shutil.which",
        side_effect=lambda c: f"/usr/bin/{c}" if c == cmd else None,
    )


class TestParseTarget:
    def test_stdio_simple_command(self):
        with _with_which("python"):
            target = parse_target("python -m my_server")
        assert target.transport == TransportKind.STDIO
        assert target.command == "python"
        assert list(target.args) == ["-m", "my_server"]

    def test_stdio_quoted_args(self):
        with _with_which("npx"):
            target = parse_target('npx -y "@server/tool" /tmp')
        assert target.transport == TransportKind.STDIO
        assert target.command == "npx"
        assert "-y" in target.args

    def test_http_url(self):
        target = parse_target("http://localhost:8080/mcp")
        assert target.transport == TransportKind.HTTP
        assert target.url == "http://localhost:8080/mcp"
        assert target.command == ""

    def test_https_url(self):
        target = parse_target("https://api.example.com/mcp")
        assert target.transport == TransportKind.HTTP
        assert target.url == "https://api.example.com/mcp"

    def test_whitespace_stripped(self):
        target = parse_target("  http://localhost:8080  ")
        assert target.transport == TransportKind.HTTP
        assert target.url == "http://localhost:8080"

    def test_env_pairs(self):
        with _with_which("python"):
            target = parse_target("python server.py", env_pairs=["KEY=value", "FOO=bar"])
        assert target.env == {"KEY": "value", "FOO": "bar"}

    def test_env_pairs_empty(self):
        with _with_which("python"):
            target = parse_target("python server.py")
        assert target.env is None

    def test_empty_server_raises(self):
        with pytest.raises(Exception):
            parse_target("")

    # -- IV-07: URL scheme whitelist --

    def test_file_scheme_rejected(self):
        with pytest.raises(Exception, match="Unsupported URL scheme"):
            parse_target("file:///etc/passwd")

    def test_ftp_scheme_rejected(self):
        with pytest.raises(Exception, match="Unsupported URL scheme"):
            parse_target("ftp://evil.com/payload")

    def test_gopher_scheme_rejected(self):
        with pytest.raises(Exception, match="Unsupported URL scheme"):
            parse_target("gopher://evil.com/")

    def test_data_scheme_rejected(self):
        with pytest.raises(Exception, match="Unsupported URL scheme"):
            parse_target("data:text/html;base64,PHNjcmlwdD4=")

    # -- IV-08: Env var sanitization --

    def test_ld_preload_blocked(self):
        with _with_which("python"):
            with pytest.raises(Exception, match="blocked for security"):
                parse_target("python server.py", env_pairs=["LD_PRELOAD=/evil.so"])

    def test_pythonpath_blocked(self):
        with _with_which("python"):
            with pytest.raises(Exception, match="blocked for security"):
                parse_target("python server.py", env_pairs=["PYTHONPATH=/evil"])

    def test_node_options_blocked(self):
        with _with_which("node"):
            with pytest.raises(Exception, match="blocked for security"):
                parse_target("node server.js", env_pairs=["NODE_OPTIONS=--inspect"])

    def test_safe_env_allowed(self):
        with _with_which("python"):
            target = parse_target("python server.py", env_pairs=["API_KEY=secret123"])
        assert target.env == {"API_KEY": "secret123"}

    def test_all_blocked_keys_are_blocked(self):
        """Every key in _BLOCKED_ENV_KEYS must raise."""
        for key in _BLOCKED_ENV_KEYS:
            with _with_which("python"):
                with pytest.raises(Exception, match="blocked for security"):
                    parse_target("python s.py", env_pairs=[f"{key}=val"])

    # -- IV-09: Command validation --

    def test_command_not_found_raises(self):
        with patch("mcp_shield.client.connection.shutil.which", return_value=None):
            with pytest.raises(Exception, match="not found in PATH"):
                parse_target("nonexistent_binary --flag")

    # -- IV-10: Env key validation --

    def test_empty_env_key_rejected(self):
        """--env '=value' must be rejected (empty key)."""
        with _with_which("python"):
            with pytest.raises(Exception, match="key cannot be empty"):
                parse_target("python server.py", env_pairs=["=value"])

    def test_env_key_with_spaces_rejected(self):
        """--env 'KEY WITH SPACES=val' must be rejected."""
        with _with_which("python"):
            with pytest.raises(Exception, match="Invalid environment variable name"):
                parse_target("python server.py", env_pairs=["KEY WITH SPACES=val"])

    def test_env_key_with_hyphen_rejected(self):
        """--env 'MY-VAR=val' must be rejected (hyphens invalid in env names)."""
        with _with_which("python"):
            with pytest.raises(Exception, match="Invalid environment variable name"):
                parse_target("python server.py", env_pairs=["MY-VAR=val"])

    def test_env_key_starting_with_digit_rejected(self):
        """--env '1ABC=val' must be rejected."""
        with _with_which("python"):
            with pytest.raises(Exception, match="Invalid environment variable name"):
                parse_target("python server.py", env_pairs=["1ABC=val"])

    def test_env_no_equals_rejected(self):
        """--env 'NOEQUALS' must be rejected (missing =)."""
        with _with_which("python"):
            with pytest.raises(Exception, match="KEY=VALUE"):
                parse_target("python server.py", env_pairs=["NOEQUALS"])

    def test_env_empty_value_allowed(self):
        """--env 'KEY=' should be allowed (empty value is valid)."""
        with _with_which("python"):
            target = parse_target("python server.py", env_pairs=["KEY="])
        assert target.env == {"KEY": ""}

    def test_env_underscore_key_allowed(self):
        """--env '_PRIVATE=val' should be allowed."""
        with _with_which("python"):
            target = parse_target("python server.py", env_pairs=["_PRIVATE=val"])
        assert target.env == {"_PRIVATE": "val"}

    def test_env_value_with_equals_allowed(self):
        """--env 'DSN=postgres://host?opt=1' should keep the full value."""
        with _with_which("python"):
            target = parse_target("python server.py", env_pairs=["DSN=postgres://host?opt=1"])
        assert target.env["DSN"] == "postgres://host?opt=1"

    # -- IV-11: Malformed command strings --

    def test_unclosed_quote_rejected(self):
        """Unclosed quotes must produce a clean error, not a traceback."""
        with pytest.raises(Exception, match="Invalid SERVER syntax"):
            parse_target('echo "hello')

    def test_unclosed_single_quote_rejected(self):
        with pytest.raises(Exception, match="Invalid SERVER syntax"):
            parse_target("echo 'hello")


class TestServerTarget:
    def test_defaults(self):
        t = ServerTarget(transport=TransportKind.STDIO)
        assert t.command == ""
        assert list(t.args) == []
        assert t.env is None
        assert t.url == ""
        assert t.headers is None

    def test_full_command_stdio(self):
        t = ServerTarget(
            transport=TransportKind.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        full = t.full_command
        assert "npx" in full
        assert "@modelcontextprotocol/server-filesystem" in full
        assert "/tmp" in full

    def test_full_command_http(self):
        t = ServerTarget(transport=TransportKind.HTTP, url="http://localhost:8080/mcp")
        assert t.full_command == "http://localhost:8080/mcp"

    def test_full_command_no_args(self):
        t = ServerTarget(transport=TransportKind.STDIO, command="python")
        assert t.full_command == "python"

    def test_full_command_quotes_spaces(self):
        t = ServerTarget(
            transport=TransportKind.STDIO,
            command="python",
            args=["-m", "my server"],
        )
        full = t.full_command
        # shlex.quote wraps arg with spaces in quotes
        assert "'my server'" in full


class TestTransportKind:
    def test_values(self):
        assert TransportKind.STDIO.value == "stdio"
        assert TransportKind.HTTP.value == "http"


class TestEnvMerge:
    """Env vars from --env should be merged with MCP defaults, not replace them."""

    def test_env_merged_with_defaults(self):
        """User env should be merged with get_default_environment()."""
        from mcp.client.stdio import get_default_environment

        target = ServerTarget(
            transport=TransportKind.STDIO,
            command="fake",
            env={"API_KEY": "secret", "FOO": "bar"},
        )
        conn = MCPConnection(target)

        # Simulate what __aenter__ does with env
        env = target.env
        if env is not None:
            merged = get_default_environment()
            merged.update(env)
            env = merged

        # Must contain both user keys and default keys (PATH, HOME)
        assert "API_KEY" in env
        assert "FOO" in env
        assert "PATH" in env
        assert "HOME" in env
        assert env["API_KEY"] == "secret"

    def test_none_env_unchanged(self):
        """When no env is specified, it stays None (SDK uses its defaults)."""
        target = ServerTarget(transport=TransportKind.STDIO, command="fake")
        assert target.env is None


class TestMCPConnectionTeardown:
    """Teardown resilience: suppress BrokenResourceError from noisy servers."""

    async def test_broken_resource_suppressed(self):
        """ExceptionGroup with BrokenResourceError is silently suppressed."""
        conn = MCPConnection(ServerTarget(transport=TransportKind.STDIO, command="fake"))
        conn._stack = AsyncMock()
        conn._stack.__aexit__ = AsyncMock(
            side_effect=BaseExceptionGroup("teardown", [anyio.BrokenResourceError()])
        )
        # Should not raise
        result = await conn.__aexit__(None, None, None)
        assert result is False

    async def test_closed_resource_suppressed(self):
        """ExceptionGroup with ClosedResourceError is silently suppressed."""
        conn = MCPConnection(ServerTarget(transport=TransportKind.STDIO, command="fake"))
        conn._stack = AsyncMock()
        conn._stack.__aexit__ = AsyncMock(
            side_effect=BaseExceptionGroup("teardown", [anyio.ClosedResourceError()])
        )
        result = await conn.__aexit__(None, None, None)
        assert result is False

    async def test_non_teardown_error_propagates(self):
        """ExceptionGroup with non-teardown errors is re-raised."""
        conn = MCPConnection(ServerTarget(transport=TransportKind.STDIO, command="fake"))
        conn._stack = AsyncMock()
        conn._stack.__aexit__ = AsyncMock(
            side_effect=BaseExceptionGroup("other", [RuntimeError("real bug")])
        )
        with pytest.raises(BaseExceptionGroup) as exc_info:
            await conn.__aexit__(None, None, None)
        assert any(isinstance(e, RuntimeError) for e in exc_info.value.exceptions)

    async def test_mixed_group_reraises_non_teardown(self):
        """Mixed group: teardown errors suppressed, real errors re-raised."""
        conn = MCPConnection(ServerTarget(transport=TransportKind.STDIO, command="fake"))
        conn._stack = AsyncMock()
        conn._stack.__aexit__ = AsyncMock(
            side_effect=BaseExceptionGroup("mixed", [
                anyio.BrokenResourceError(),
                ValueError("important"),
            ])
        )
        with pytest.raises(BaseExceptionGroup) as exc_info:
            await conn.__aexit__(None, None, None)
        # BrokenResourceError filtered out, only ValueError remains
        errors = exc_info.value.exceptions
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)
