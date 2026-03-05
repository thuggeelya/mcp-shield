"""Transport auto-detection for HTTP-based MCP servers.

Probes a URL to determine whether it speaks Streamable HTTP or legacy SSE,
then returns the appropriate transport provider.  No CLI flags needed.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Protocol, Tuple, runtime_checkable

import anyio
import httpx
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)

# (read_stream, write_stream) — the universal interface all MCP transports yield.
Streams = Tuple[
    MemoryObjectReceiveStream[SessionMessage | Exception],
    MemoryObjectSendStream[SessionMessage],
]


# ---------------------------------------------------------------------------
# Abstract layer
# ---------------------------------------------------------------------------

@runtime_checkable
class TransportProvider(Protocol):
    """Wraps a concrete MCP transport client behind a uniform interface."""

    @property
    def name(self) -> str: ...

    def connect(
        self, url: str, headers: dict[str, str] | None,
    ) -> Any:
        """Return an async context manager that yields *Streams*."""
        ...


@runtime_checkable
class TransportProber(Protocol):
    """Lightweight probe — checks whether *url* speaks a given transport."""

    @property
    def name(self) -> str: ...

    async def probe(self, url: str, headers: dict[str, str] | None) -> bool: ...

    def provider(self) -> TransportProvider: ...


# ---------------------------------------------------------------------------
# Streamable HTTP (MCP 2025-03-26+)
# ---------------------------------------------------------------------------

class StreamableHttpProvider:
    name = "streamable_http"

    @asynccontextmanager
    async def connect(
        self, url: str, headers: dict[str, str] | None,
    ) -> AsyncGenerator[Streams, None]:
        from mcp.client.streamable_http import streamable_http_client

        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["http_client"] = httpx.AsyncClient(headers=headers)

        async with streamable_http_client(url, **kwargs) as (read, write, _):
            yield read, write


class StreamableHttpProber:
    name = "streamable_http"

    async def probe(self, url: str, headers: dict[str, str] | None) -> bool:
        """POST a JSON-RPC initialize and expect a JSON or SSE response."""
        try:
            async with httpx.AsyncClient(
                headers=headers or {}, timeout=httpx.Timeout(8.0),
            ) as client:
                resp = await client.post(
                    url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "id": 1,
                        "params": {
                            "protocolVersion": "2025-03-26",
                            "clientInfo": {"name": "mcp-shield-probe", "version": "0.1"},
                            "capabilities": {},
                        },
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                )
                ct = resp.headers.get("content-type", "")
                ok = resp.status_code == 200 and (
                    "application/json" in ct or "text/event-stream" in ct
                )
                logger.debug(
                    "streamable_http probe: status=%s ct=%s ok=%s", resp.status_code, ct, ok,
                )
                return ok
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("streamable_http probe failed: %s", exc)
            return False

    def provider(self) -> TransportProvider:
        return StreamableHttpProvider()


# ---------------------------------------------------------------------------
# Legacy SSE
# ---------------------------------------------------------------------------

class SseProvider:
    name = "sse"

    @asynccontextmanager
    async def connect(
        self, url: str, headers: dict[str, str] | None,
    ) -> AsyncGenerator[Streams, None]:
        from mcp.client.sse import sse_client

        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["headers"] = headers

        async with sse_client(url, **kwargs) as (read, write):
            yield read, write


class SseProber:
    name = "sse"

    async def probe(self, url: str, headers: dict[str, str] | None) -> bool:
        """GET the URL and check for text/event-stream content-type."""
        try:
            async with httpx.AsyncClient(
                headers=headers or {}, timeout=httpx.Timeout(8.0),
            ) as client:
                async with client.stream("GET", url) as resp:
                    ct = resp.headers.get("content-type", "")
                    ok = "text/event-stream" in ct
                    logger.debug(
                        "sse probe: status=%s ct=%s ok=%s", resp.status_code, ct, ok,
                    )
                    return ok
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("sse probe failed: %s", exc)
            return False

    def provider(self) -> TransportProvider:
        return SseProvider()


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

DEFAULT_PROBERS: list[TransportProber] = [  # type: ignore[list-item]
    StreamableHttpProber(),
    SseProber(),
]


class TransportResolver:
    """Ordered chain of probers — returns the first matching provider."""

    def __init__(self, probers: list[TransportProber] | None = None) -> None:
        self._probers = probers or DEFAULT_PROBERS

    async def resolve(
        self, url: str, headers: dict[str, str] | None = None,
    ) -> TransportProvider:
        for prober in self._probers:
            logger.debug("probing %s with %s …", url, prober.name)
            try:
                if await prober.probe(url, headers):
                    logger.info("resolved transport: %s for %s", prober.name, url)
                    return prober.provider()
            except Exception as exc:
                logger.debug("prober %s raised: %s", prober.name, exc)

        tried = ", ".join(p.name for p in self._probers)
        raise ConnectionError(
            f"Could not detect MCP transport at {url}. "
            f"Tried: {tried}. "
            "Ensure the server is running and the URL is correct."
        )


async def resolve_transport(
    url: str,
    headers: dict[str, str] | None = None,
) -> TransportProvider:
    """Convenience wrapper — resolve using the default prober chain."""
    return await TransportResolver().resolve(url, headers)
