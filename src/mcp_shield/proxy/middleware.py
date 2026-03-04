"""Proxy middleware — auth, rate limiting, and tool filtering.

These components are applied at the handler level in ShieldProxy
before forwarding requests to the upstream MCP server.
"""

from __future__ import annotations

import fnmatch
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class ProxyConfig:
    """Configuration for the Shield proxy."""

    auth_mode: str = "none"  # none | bearer | api_key
    tokens: Dict[str, str] = field(default_factory=dict)  # client_id → token
    allow_tools: List[str] = field(default_factory=list)  # glob patterns
    deny_tools: List[str] = field(default_factory=list)  # glob patterns
    rate_limit: int = 60  # requests per minute per client (0 = unlimited)


class AuthChecker:
    """Validates client authentication based on ProxyConfig."""

    def __init__(self, config: ProxyConfig) -> None:
        self._mode = config.auth_mode
        self._tokens = config.tokens
        # Build reverse lookup: token → client_id
        self._token_to_client: Dict[str, str] = {v: k for k, v in config.tokens.items()}

    def check(self, token: str | None) -> Tuple[bool, str]:
        """Check authentication, return (allowed, client_id).

        In ``none`` mode, always returns ``(True, "stdio")``.
        In ``bearer`` / ``api_key`` mode, validates the token and returns
        the associated client ID.
        """
        if self._mode == "none":
            return True, "stdio"

        if token is None:
            return False, ""

        client_id = self._token_to_client.get(token)
        if client_id is None:
            return False, ""

        return True, client_id


class RateLimiter:
    """Sliding-window rate limiter (per client, 60-second window)."""

    def __init__(self, max_requests: int) -> None:
        self._max = max_requests
        self._windows: Dict[str, deque[float]] = defaultdict(deque)

    def check(self, client_id: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        if self._max == 0:
            return True

        now = time.monotonic()
        window = self._windows[client_id]

        # Evict expired entries (older than 60s)
        while window and window[0] <= now - 60.0:
            window.popleft()

        if len(window) >= self._max:
            return False

        window.append(now)
        return True


class ToolFilter:
    """Glob-based tool allow/deny filter.

    Evaluation order: deny first, then allow. If both lists are empty,
    all tools are allowed.
    """

    def __init__(self, allow: List[str], deny: List[str]) -> None:
        self._allow = allow
        self._deny = deny

    def is_allowed(self, tool_name: str) -> bool:
        """Return True if the tool is allowed by the filter rules."""
        # Deny patterns take precedence
        for pattern in self._deny:
            if fnmatch.fnmatch(tool_name, pattern):
                return False

        # If allow list is set, tool must match at least one
        if self._allow:
            return any(fnmatch.fnmatch(tool_name, p) for p in self._allow)

        return True
