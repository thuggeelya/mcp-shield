"""ContextVars shared between the Runner and check suites."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from mcp import ClientSession

#: ContextVar holding the InitializeResult from the MCP handshake.
#: Set by Runner.run() after connecting; read by compliance checks.
init_result_var: ContextVar[object | None] = ContextVar(
    "init_result", default=None,
)

#: Cached list_tools() result — avoids redundant RPC calls.
_tools_cache_var: ContextVar[object | None] = ContextVar(
    "tools_cache", default=None,
)


async def cached_list_tools(session: ClientSession) -> Any:
    """Return (and cache) the result of ``session.list_tools()``.

    All compliance/advisory checks call ``list_tools()`` independently.
    Caching the result in a ContextVar avoids ~10 redundant RPC calls
    per scan while keeping the API transparent to check functions.
    """
    cached = _tools_cache_var.get()
    if cached is not None:
        return cached
    result = await session.list_tools()
    _tools_cache_var.set(result)
    return result
