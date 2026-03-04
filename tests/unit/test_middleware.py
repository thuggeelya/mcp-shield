"""Tests for mcp_shield.proxy.middleware — Auth, RateLimit, ToolFilter."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from mcp_shield.proxy.middleware import (
    AuthChecker,
    ProxyConfig,
    RateLimiter,
    ToolFilter,
)


# ── AuthChecker ──────────────────────────────────────────────────────


class TestAuthCheckerNone:
    def test_none_mode_always_allows(self):
        config = ProxyConfig(auth_mode="none")
        checker = AuthChecker(config)
        allowed, client_id = checker.check(None)
        assert allowed is True
        assert client_id == "stdio"

    def test_none_mode_ignores_token(self):
        config = ProxyConfig(auth_mode="none")
        checker = AuthChecker(config)
        allowed, client_id = checker.check("some-random-token")
        assert allowed is True
        assert client_id == "stdio"


class TestAuthCheckerBearer:
    def test_valid_token(self):
        config = ProxyConfig(
            auth_mode="bearer",
            tokens={"admin": "secret123"},
        )
        checker = AuthChecker(config)
        allowed, client_id = checker.check("secret123")
        assert allowed is True
        assert client_id == "admin"

    def test_invalid_token(self):
        config = ProxyConfig(
            auth_mode="bearer",
            tokens={"admin": "secret123"},
        )
        checker = AuthChecker(config)
        allowed, client_id = checker.check("wrong-token")
        assert allowed is False
        assert client_id == ""

    def test_missing_token(self):
        config = ProxyConfig(
            auth_mode="bearer",
            tokens={"admin": "secret123"},
        )
        checker = AuthChecker(config)
        allowed, client_id = checker.check(None)
        assert allowed is False
        assert client_id == ""

    def test_multiple_tokens(self):
        config = ProxyConfig(
            auth_mode="bearer",
            tokens={"alice": "token-a", "bob": "token-b"},
        )
        checker = AuthChecker(config)

        allowed_a, cid_a = checker.check("token-a")
        assert allowed_a is True
        assert cid_a == "alice"

        allowed_b, cid_b = checker.check("token-b")
        assert allowed_b is True
        assert cid_b == "bob"

    def test_api_key_mode_same_behavior(self):
        config = ProxyConfig(
            auth_mode="api_key",
            tokens={"svc": "key123"},
        )
        checker = AuthChecker(config)
        allowed, client_id = checker.check("key123")
        assert allowed is True
        assert client_id == "svc"


# ── RateLimiter ──────────────────────────────────────────────────────


class TestRateLimiter:
    def test_under_limit_allowed(self):
        limiter = RateLimiter(max_requests=5)
        for _ in range(5):
            assert limiter.check("client1") is True

    def test_at_limit_blocked(self):
        limiter = RateLimiter(max_requests=3)
        for _ in range(3):
            assert limiter.check("client1") is True
        assert limiter.check("client1") is False

    def test_window_expiry(self):
        limiter = RateLimiter(max_requests=2)

        # Fill up the window
        assert limiter.check("client1") is True
        assert limiter.check("client1") is True
        assert limiter.check("client1") is False

        # Simulate time passing beyond 60s by manipulating deque
        limiter._windows["client1"].clear()
        assert limiter.check("client1") is True

    def test_independent_client_buckets(self):
        limiter = RateLimiter(max_requests=2)
        assert limiter.check("alice") is True
        assert limiter.check("alice") is True
        assert limiter.check("alice") is False

        # Bob has his own bucket
        assert limiter.check("bob") is True
        assert limiter.check("bob") is True

    def test_zero_means_unlimited(self):
        limiter = RateLimiter(max_requests=0)
        for _ in range(1000):
            assert limiter.check("client1") is True

    def test_max_one(self):
        limiter = RateLimiter(max_requests=1)
        assert limiter.check("client1") is True
        assert limiter.check("client1") is False


# ── ToolFilter ───────────────────────────────────────────────────────


class TestToolFilter:
    def test_empty_allows_all(self):
        f = ToolFilter(allow=[], deny=[])
        assert f.is_allowed("anything") is True
        assert f.is_allowed("delete_all") is True

    def test_allow_only(self):
        f = ToolFilter(allow=["read_*", "list_*"], deny=[])
        assert f.is_allowed("read_file") is True
        assert f.is_allowed("list_items") is True
        assert f.is_allowed("write_file") is False
        assert f.is_allowed("delete_db") is False

    def test_deny_only(self):
        f = ToolFilter(allow=[], deny=["delete_*", "drop_*"])
        assert f.is_allowed("read_file") is True
        assert f.is_allowed("delete_file") is False
        assert f.is_allowed("drop_table") is False

    def test_deny_precedence_over_allow(self):
        f = ToolFilter(allow=["*"], deny=["delete_*"])
        assert f.is_allowed("read_file") is True
        assert f.is_allowed("delete_file") is False

    def test_glob_pattern_matching(self):
        f = ToolFilter(allow=[], deny=["*_dangerous"])
        assert f.is_allowed("very_dangerous") is False
        assert f.is_allowed("safe_tool") is True

    def test_exact_name_in_deny(self):
        f = ToolFilter(allow=[], deny=["rm"])
        assert f.is_allowed("rm") is False
        assert f.is_allowed("rmdir") is True

    def test_allow_specific_deny_broad(self):
        f = ToolFilter(allow=["read_file"], deny=["*"])
        # deny ["*"] blocks everything, including read_file
        assert f.is_allowed("read_file") is False

    def test_multiple_allow_patterns(self):
        f = ToolFilter(allow=["get_*", "fetch_*", "list_*"], deny=[])
        assert f.is_allowed("get_user") is True
        assert f.is_allowed("fetch_data") is True
        assert f.is_allowed("list_items") is True
        assert f.is_allowed("set_user") is False


class TestToolFilterAdversarial:
    """Adversarial inputs to ToolFilter."""

    def test_empty_tool_name(self):
        f = ToolFilter(allow=["read_*"], deny=[])
        assert f.is_allowed("") is False  # empty doesn't match "read_*"

    def test_unicode_tool_name(self):
        f = ToolFilter(allow=[], deny=["delete_*"])
        # Unicode tool names should pass through if not matching deny
        assert f.is_allowed("\u0434\u0435\u043b\u0435\u0442\u0435") is True

    def test_glob_bracket_pattern(self):
        f = ToolFilter(allow=[], deny=["[abc]*"])
        assert f.is_allowed("a_tool") is False
        assert f.is_allowed("d_tool") is True

    def test_very_long_tool_name(self):
        f = ToolFilter(allow=["*"], deny=[])
        assert f.is_allowed("a" * 10_000) is True

    def test_null_byte_in_tool_name(self):
        f = ToolFilter(allow=[], deny=["evil*"])
        # fnmatch handles null bytes as regular characters
        assert f.is_allowed("safe\x00tool") is True


class TestProxyConfig:
    def test_defaults(self):
        config = ProxyConfig()
        assert config.auth_mode == "none"
        assert config.tokens == {}
        assert config.allow_tools == []
        assert config.deny_tools == []
        assert config.rate_limit == 60

    def test_custom_values(self):
        config = ProxyConfig(
            auth_mode="bearer",
            tokens={"admin": "tok"},
            allow_tools=["read_*"],
            deny_tools=["delete_*"],
            rate_limit=100,
        )
        assert config.auth_mode == "bearer"
        assert config.rate_limit == 100
