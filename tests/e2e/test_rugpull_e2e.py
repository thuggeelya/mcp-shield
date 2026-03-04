"""End-to-end test: Rug Pull detection across two proxy sessions.

Session 1: connect to basic_server → snapshots stored
Session 2: connect to rugpull_server → description change detected

Run:
    uv run pytest tests/e2e/test_rugpull_e2e.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcp_shield.storage.audit_db import AuditDB

from .conftest import UV_BIN


def _make_params(server_script: str, audit_db_path: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=UV_BIN,
        args=[
            "run", "mcp-shield", "proxy",
            f"{UV_BIN} run python {server_script}",
            "--audit-db", str(audit_db_path),
        ],
        env={**os.environ},
    )


async def _run_session(params: StdioServerParameters) -> None:
    """Connect, list tools, call read_file, disconnect."""
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()
            await session.call_tool("read_file", {"path": "/tmp/x"})


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_rugpull_detected(
    basic_server_script: str,
    rugpull_server_script: str,
    audit_db_path: Path,
):
    """Rug pull: description change between sessions triggers critical finding."""
    # Session 1: original server → stores snapshots
    params1 = _make_params(basic_server_script, audit_db_path)
    await _run_session(params1)

    # Verify snapshots saved
    db = AuditDB(audit_db_path)
    db.open()
    snapshots = db.get_latest_snapshots()
    assert "read_file" in snapshots
    original_hash = snapshots["read_file"]["description_hash"]
    db.close()

    # Session 2: rug-pulled server → should detect change
    params2 = _make_params(rugpull_server_script, audit_db_path)
    await _run_session(params2)

    # Check rug pull findings
    db = AuditDB(audit_db_path)
    db.open()

    rows = db._db.execute(
        "SELECT * FROM security_findings WHERE category = 'rug_pull'"
    ).fetchall()

    assert len(rows) >= 1, "Expected rug pull finding for changed read_file description"

    finding = rows[0]
    assert finding["severity"] == "critical"
    assert "read_file" in finding["title"]

    # Verify the hash actually changed
    new_snapshots = db.get_latest_snapshots()
    assert new_snapshots["read_file"]["description_hash"] != original_hash

    db.close()


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_no_rugpull_on_first_run(
    basic_server_script: str,
    audit_db_path: Path,
):
    """First run: no rug pull findings (no history to compare)."""
    params = _make_params(basic_server_script, audit_db_path)
    await _run_session(params)

    db = AuditDB(audit_db_path)
    db.open()

    rows = db._db.execute(
        "SELECT * FROM security_findings WHERE category = 'rug_pull'"
    ).fetchall()

    assert len(rows) == 0, "No rug pull findings expected on first run"
    db.close()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_no_rugpull_on_same_server(
    basic_server_script: str,
    audit_db_path: Path,
):
    """Same server twice: no rug pull findings."""
    params = _make_params(basic_server_script, audit_db_path)
    await _run_session(params)
    await _run_session(params)

    db = AuditDB(audit_db_path)
    db.open()

    rows = db._db.execute(
        "SELECT * FROM security_findings WHERE category = 'rug_pull'"
    ).fetchall()

    assert len(rows) == 0, "No rug pull findings expected when server is unchanged"
    db.close()
