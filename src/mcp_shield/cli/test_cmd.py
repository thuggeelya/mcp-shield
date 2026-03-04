"""mcp-shield test — validate an MCP server."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading

import click

from mcp_shield.client.connection import parse_target
from mcp_shield.testing.runner import Runner
from mcp_shield.testing.result import Outcome, SuiteReport

# Severity ordering for --fail-on comparison
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "any": 0,
}


def _should_fail(report: SuiteReport, fail_on: str) -> bool:
    """Return True if any failed check meets the --fail-on threshold."""
    threshold = _SEVERITY_RANK.get(fail_on, 0)
    for r in report.results:
        if r.outcome in (Outcome.FAIL, Outcome.ERROR):
            rank = _SEVERITY_RANK.get(r.severity, 0)
            if rank >= threshold:
                return True
    return False


@click.command("test")
@click.argument("server")
@click.option(
    "--suite", "-s",
    multiple=True,
    help="Test suites to run (compliance, security, advisory, all). Can repeat.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["terminal", "json", "sarif", "both"]),
    default="terminal",
    help="Output format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write JSON report to file.",
)
@click.option(
    "--timeout", "-t",
    type=click.FloatRange(min=0.1),
    default=30.0,
    help="Per-test timeout in seconds (minimum 0.1).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "any"]),
    default="high",
    help="Minimum severity to cause non-zero exit code.",
)
@click.option(
    "--ml",
    is_flag=True,
    default=False,
    help="Enable ML-based prompt injection detection (DeBERTa-v3, slower but more accurate).",
)
@click.option(
    "--sarif-output",
    type=click.Path(),
    default=None,
    help="Write SARIF report to file (for GitHub Code Scanning).",
)
@click.option(
    "--env", "-e",
    multiple=True,
    help="Environment variables for stdio server as KEY=VALUE. Can repeat.",
)
def test_cmd(
    server: str,
    suite: tuple[str, ...],
    output_format: str,
    output: str | None,
    timeout: float,
    fail_on: str,
    ml: bool,
    sarif_output: str | None,
    env: tuple[str, ...],
) -> None:
    """Test an MCP server for compliance and security issues.

    SERVER can be a command (stdio) or an HTTP URL.

    \b
    Examples:
      mcp-shield test "npx -y @modelcontextprotocol/server-filesystem /tmp"
      mcp-shield test "http://localhost:8080/mcp"
      mcp-shield test "npx server" --env API_KEY=sk-123 --env DB_URL=postgres://...
      mcp-shield test "npx server" --suite security --suite advisory
      mcp-shield test "npx server" --format json --output report.json
      mcp-shield test "npx server" --fail-on high   # exit code 1 if high+ severity fails
      mcp-shield test "npx server" --ml              # enable ML injection detection
    """
    target = parse_target(server, env_pairs=list(env) if env else None)
    suites = list(suite) if suite else None

    # Validate suite names before connecting to the server
    if suites:
        from mcp_shield.testing.registry import get_suites
        valid = set(get_suites().keys()) | {"all"}
        bad = set(suites) - valid
        if bad:
            click.echo(
                f"Error: Unknown suite(s): {', '.join(sorted(bad))}. "
                f"Available: {', '.join(sorted(valid))}",
                err=True,
            )
            sys.exit(2)

    runner = Runner(target, suites=suites, timeout=timeout, use_ml=ml)

    # Suppress noisy MCP SDK tracebacks (e.g. "Failed to parse JSONRPC message")
    # that appear when connecting to non-MCP servers.
    logging.getLogger("mcp").setLevel(logging.CRITICAL)

    async def _run_bounded() -> SuiteReport:
        return await asyncio.wait_for(runner.run(), timeout=timeout + 5)

    # Redirect fd 2 to /dev/null to suppress subprocess stderr output
    # and MCP SDK tracebacks that bypass Python's sys.stderr.
    saved_stderr_fd = os.dup(2)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)

    # Run in a daemon thread so that if asyncio cleanup hangs (e.g. a server
    # floods stdout and the subprocess won't die), we can still exit cleanly.
    result_box: list[SuiteReport | None] = [None]
    error_box: list[BaseException | None] = [None]

    def _run_thread() -> None:
        try:
            result_box[0] = asyncio.run(_run_bounded())
        except BaseException as exc:
            error_box[0] = exc

    thread = threading.Thread(target=_run_thread, daemon=True)
    thread.start()

    hard_timeout = timeout + 10
    try:
        thread.join(timeout=hard_timeout)
    except KeyboardInterrupt:
        os.dup2(saved_stderr_fd, 2)
        os.close(saved_stderr_fd)
        click.echo("\nAborted.", err=True)
        sys.exit(130)

    # Restore stderr
    os.dup2(saved_stderr_fd, 2)
    os.close(saved_stderr_fd)

    if thread.is_alive():
        # Thread stuck in cleanup — force exit
        click.echo(
            f"Error: Timed out after {timeout:.0f}s — server did not respond",
            err=True,
        )
        os._exit(1)

    if error_box[0] is not None:
        exc = error_box[0]
        if isinstance(exc, KeyboardInterrupt):
            click.echo("\nAborted.", err=True)
            sys.exit(130)
        msg = str(exc)
        if isinstance(exc, TimeoutError) or any(s in msg for s in (
            "Connection closed", "BrokenResourceError", "CancelledError",
            "unhandled errors in a TaskGroup", "cancel scope",
        )):
            if isinstance(exc, TimeoutError):
                msg = f"Timed out after {timeout:.0f}s — server did not respond"
            else:
                msg = "Connection failed — server is not a valid MCP server or exited early"
        click.echo(f"Error: {msg}", err=True)
        sys.exit(1)

    report = result_box[0]
    assert report is not None

    # --- Output ---

    if output_format in ("terminal", "both"):
        from mcp_shield.reporting.terminal import render
        render(report)

    if output_format in ("json", "both"):
        from mcp_shield.reporting.json_report import render_json
        click.echo(render_json(report))

    if output_format == "sarif":
        from mcp_shield.reporting.sarif_report import render_sarif
        click.echo(render_sarif(report))

    if output:
        from mcp_shield.reporting.json_report import write_json
        try:
            write_json(report, output)
            click.echo(f"Report written to {output}")
        except (ValueError, OSError) as exc:
            click.echo(f"Error writing report: {exc}", err=True)
            sys.exit(1)

    if sarif_output:
        from mcp_shield.reporting.sarif_report import write_sarif
        try:
            write_sarif(report, sarif_output)
            click.echo(f"SARIF report written to {sarif_output}")
        except (ValueError, OSError) as exc:
            click.echo(f"Error writing SARIF report: {exc}", err=True)
            sys.exit(1)

    # --- Exit code ---

    if _should_fail(report, fail_on):
        sys.exit(1)
