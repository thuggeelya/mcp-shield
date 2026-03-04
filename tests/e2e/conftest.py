"""Shared fixtures for e2e tests."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

# Resolve paths relative to this file — no hardcoding
E2E_DIR = Path(__file__).resolve().parent
SERVERS_DIR = E2E_DIR / "servers"
BASIC_SERVER = SERVERS_DIR / "basic_server.py"
RUGPULL_SERVER = SERVERS_DIR / "rugpull_server.py"

# Find npx binary dynamically (for real server tests)
NPX_BIN = shutil.which("npx")

# Find uv binary dynamically
UV_BIN = shutil.which("uv")
if UV_BIN is None:
    # Fallback: common install locations
    for candidate in [
        Path.home() / ".local" / "bin" / "uv",
        Path.home() / ".cargo" / "bin" / "uv",
        Path("/usr/local/bin/uv"),
    ]:
        if candidate.exists():
            UV_BIN = str(candidate)
            break

if UV_BIN is None:
    pytest.skip("uv binary not found", allow_module_level=True)


@pytest.fixture
def audit_db_path(tmp_path: Path) -> Path:
    """Temporary audit database path — auto-cleaned."""
    return tmp_path / "audit.db"


@pytest.fixture
def basic_server_script() -> str:
    """Path to the basic test MCP server."""
    return str(BASIC_SERVER)


@pytest.fixture
def rugpull_server_script() -> str:
    """Path to the rug-pulled test MCP server."""
    return str(RUGPULL_SERVER)
