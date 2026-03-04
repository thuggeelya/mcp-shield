"""Decorator-based check registry.

Every check is an async function that receives a ``ClientSession`` and returns
a ``CheckResult``.  Use the ``@check`` decorator to register it::

    @check("compliance", "COMP-001", severity="critical")
    async def verify_handshake(session: ClientSession) -> CheckResult:
        ...
"""

from __future__ import annotations

from typing import Any, Callable, Coroutine, Dict, List

from mcp import ClientSession

from mcp_shield.testing.result import CheckResult

# Type alias for a check function.
CheckFunc = Callable[[ClientSession], Coroutine[Any, Any, CheckResult]]

# Global map: suite_name -> [check_func, ...]
_suites: Dict[str, List[CheckFunc]] = {}


def check(suite: str, check_id: str, *, severity: str = "error") -> Callable[[CheckFunc], CheckFunc]:
    """Register an async check function under *suite*."""

    def decorator(fn: CheckFunc) -> CheckFunc:
        fn._check_id = check_id  # type: ignore[attr-defined]
        fn._suite = suite  # type: ignore[attr-defined]
        fn._severity = severity  # type: ignore[attr-defined]
        _suites.setdefault(suite, []).append(fn)
        return fn

    return decorator


def get_suites() -> Dict[str, List[CheckFunc]]:
    """Return all registered suites (makes a shallow copy)."""
    return dict(_suites)


def get_suite(name: str) -> List[CheckFunc]:
    """Return checks for a single suite, or empty list."""
    return _suites.get(name, [])
