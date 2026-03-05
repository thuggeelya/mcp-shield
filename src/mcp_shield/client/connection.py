"""Unified MCP client connection — works with stdio and HTTP transports."""

from __future__ import annotations

import re
import shlex
import shutil
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlparse

import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

# Environment variables safe to propagate to MCP subprocesses.
_SAFE_ENV_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "USER", "SHELL",
    "TERM", "TZ", "LOGNAME", "XDG_RUNTIME_DIR",
})

# Environment variables that must never be propagated.
_BLOCKED_ENV_KEYS = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP",
    "NODE_OPTIONS", "PERL5OPT", "RUBYOPT",
})


class TransportKind(str, Enum):
    """Supported MCP transport types."""

    STDIO = "stdio"
    HTTP = "http"


@dataclass
class ServerTarget:
    """Parsed server connection target."""

    transport: TransportKind
    # stdio fields
    command: str = ""
    args: Sequence[str] = field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    # HTTP fields
    url: str = ""
    headers: Optional[Dict[str, str]] = None

    @property
    def full_command(self) -> str:
        """Return the full shell command string (command + args)."""
        if self.url:
            return self.url
        parts = [self.command, *self.args]
        return " ".join(shlex.quote(p) for p in parts if p)


def parse_target(target: str, *, env_pairs: Sequence[str] = ()) -> ServerTarget:
    """Parse a CLI target string into a ServerTarget.

    Recognises two formats:
      - HTTP URL: starts with ``http://`` or ``https://``
      - Shell command (stdio): everything else is split with ``shlex``

    Optional *env_pairs* like ``["KEY=VALUE", ...]`` are attached to stdio
    targets.

    Raises ``click.BadParameter`` for invalid URL schemes or
    dangerous environment variables.
    """
    stripped = target.strip()

    # IV-07: Validate URL scheme — only http/https allowed
    parsed = urlparse(stripped)
    if parsed.scheme:
        if parsed.scheme in ("http", "https"):
            return ServerTarget(transport=TransportKind.HTTP, url=stripped)
        # Any other scheme (file://, ftp://, gopher://, data:, etc.) is blocked
        raise click_bad(
            f"Unsupported URL scheme '{parsed.scheme}'. "
            "Only http:// and https:// are allowed."
        )

    try:
        parts = shlex.split(stripped)
    except ValueError as exc:
        raise click_bad(f"Invalid SERVER syntax: {exc}")
    if not parts:
        raise click_bad("SERVER cannot be empty")

    # IV-09: Validate command exists
    cmd = parts[0]
    if not shutil.which(cmd):
        display_cmd = cmd if len(cmd) <= 80 else cmd[:77] + "..."
        raise click_bad(
            f"Command '{display_cmd}' not found in PATH. "
            "Provide a valid command or an absolute path to the server binary."
        )

    env_dict: Dict[str, str] | None = None
    if env_pairs:
        env_dict = {}
        for pair in env_pairs:
            if "=" not in pair:
                raise click_bad(
                    f"Environment variable must be KEY=VALUE, got '{pair}'"
                )
            key, _, value = pair.partition("=")
            if not key:
                raise click_bad("Environment variable key cannot be empty")
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                raise click_bad(
                    f"Invalid environment variable name '{key}'. "
                    "Must match [A-Za-z_][A-Za-z0-9_]*."
                )
            if key in _BLOCKED_ENV_KEYS:
                raise click_bad(
                    f"Environment variable '{key}' is blocked for security reasons. "
                    f"Blocked variables: {', '.join(sorted(_BLOCKED_ENV_KEYS))}"
                )
            env_dict[key] = value

    return ServerTarget(
        transport=TransportKind.STDIO,
        command=cmd,
        args=parts[1:],
        env=env_dict,
    )


def click_bad(msg: str) -> Exception:
    """Return a click-friendly exception for bad input."""
    import click

    return click.BadParameter(msg)


class MCPConnection:
    """Async context manager for connecting to an MCP server.

    Usage::

        target = parse_target("npx -y @server/tool /tmp")
        async with MCPConnection(target) as session:
            tools = await session.list_tools()
    """

    def __init__(self, target: ServerTarget) -> None:
        self._target = target
        self._stack = AsyncExitStack()
        self._session: Optional[ClientSession] = None
        self._init_result: Optional[types.InitializeResult] = None

    @property
    def init_result(self) -> Optional[types.InitializeResult]:
        """The InitializeResult from the MCP handshake (available after connect)."""
        return self._init_result

    async def __aenter__(self) -> ClientSession:
        await self._stack.__aenter__()

        if self._target.transport == TransportKind.STDIO:
            # Merge user env with MCP SDK defaults (PATH, HOME, etc.)
            # so the subprocess can actually find executables.
            env = self._target.env
            if env is not None:
                from mcp.client.stdio import get_default_environment
                merged = get_default_environment()
                merged.update(env)
                env = merged
            params = StdioServerParameters(
                command=self._target.command,
                args=list(self._target.args),
                env=env,
            )
            read_stream, write_stream = await self._stack.enter_async_context(
                stdio_client(params)
            )
        elif self._target.transport == TransportKind.HTTP:
            from mcp_shield.client.transport import resolve_transport

            provider = await resolve_transport(
                self._target.url, self._target.headers,
            )
            read_stream, write_stream = await self._stack.enter_async_context(
                provider.connect(self._target.url, self._target.headers)
            )
        else:
            raise ValueError(f"Unsupported transport: {self._target.transport}")

        self._session = await self._stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        self._init_result = await self._session.initialize()
        return self._session

    async def __aexit__(self, *exc: Any) -> bool | None:
        try:
            return await self._stack.__aexit__(*exc)
        except BaseExceptionGroup as eg:
            # Some MCP servers (e.g. mongodb-mcp-server) send notifications
            # after the session starts closing, causing BrokenResourceError
            # in the MCP SDK's stdout_reader task.  Suppress these teardown
            # errors so the scan results are not lost.
            import anyio

            _teardown_types = (anyio.BrokenResourceError, anyio.ClosedResourceError)
            _, rest = eg.split(lambda e: isinstance(e, _teardown_types))
            if rest:
                raise rest
            return False

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("Not connected — use `async with MCPConnection(...) as session`")
        return self._session
