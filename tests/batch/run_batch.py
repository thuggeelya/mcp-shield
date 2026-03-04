#!/usr/bin/env python3
"""Batch-test mcp-shield against many real MCP servers.

Usage:
    uv run python tests/batch/run_batch.py [--json results.json]

Produces a summary table and optional JSON report.
"""

from __future__ import annotations

import asyncio
import gc
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from mcp_shield.client.connection import parse_target
from mcp_shield.testing.runner import Runner
from mcp_shield.testing.result import SuiteReport, Outcome


# ── Server definitions ──────────────────────────────────────────────

@dataclass
class ServerDef:
    """An MCP server to test."""
    name: str
    command: str
    needs_api_key: bool = False
    notes: str = ""


SERVERS: list[ServerDef] = [
    # Official reference servers
    ServerDef("filesystem", "npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-batch-sandbox"),
    ServerDef("memory", "npx -y @modelcontextprotocol/server-memory"),
    ServerDef("everything", "npx -y @modelcontextprotocol/server-everything"),
    ServerDef("sequential-thinking", "npx -y @modelcontextprotocol/server-sequential-thinking"),

    # Community — no API keys
    ServerDef("sqlite", "npx -y mcp-server-sqlite-npx /tmp/mcp-batch-test.db"),
    ServerDef("calculator", "npx -y @wrtnlabs/calculator-mcp@latest"),
    ServerDef("code-runner", "npx -y mcp-server-code-runner"),
    ServerDef("git", "npx -y @cyanheads/git-mcp-server@latest"),
    ServerDef("fetch", "npx -y @tokenizin/mcp-npx-fetch"),
    ServerDef("context7", "npx -y @upstash/context7-mcp"),

    # Community — no API keys (new batch)
    ServerDef("playwright", "npx -y @playwright/mcp@latest"),
    ServerDef("socket-security", "npx -y @socketsecurity/mcp@latest", needs_api_key=True),
    ServerDef("weather", "npx -y @dangahagan/weather-mcp@latest"),
    ServerDef("mermaid", "npx -y @lepion/mcp-server-mermaid"),
    ServerDef("quickchart", "npx -y @gongrzhe/quickchart-mcp-server"),
    ServerDef("markitdown", "markitdown-mcp"),
    ServerDef("npm-search", "npx -y npm-search-mcp-server"),
    ServerDef("duckduckgo", "npx -y duckduckgo-mcp-server"),
    ServerDef("mermaid2", "npx -y mcp-mermaid"),
    ServerDef("pm", "npx -y pm-mcp"),

    # Community — batch 3 (new finds)
    ServerDef("datetime", "npx -y @pinkpixel/datetime-mcp"),
    ServerDef("commands", "npx -y mcp-server-commands"),
    ServerDef("docker", "npx -y mcp-server-docker"),
    ServerDef("markdown", "npx -y mcp-server-markdown /tmp/mcp-batch-sandbox"),
    ServerDef("puppeteer", "npx -y @modelcontextprotocol/server-puppeteer"),

    # Heavyweight servers — batch 4
    ServerDef("mongodb", "npx -y mongodb-mcp-server@latest"),
    ServerDef("kubernetes", "npx -y mcp-server-kubernetes"),
    ServerDef("github", "npx -y @modelcontextprotocol/server-github"),
    ServerDef("neon-postgres", "npx -y @neondatabase/mcp-server-neon", needs_api_key=True),
    ServerDef("notion", "npx -y @notionhq/notion-mcp-server", needs_api_key=True),
    ServerDef("firecrawl", "npx -y firecrawl-mcp", needs_api_key=True),
    ServerDef("brave-search", "npx -y @modelcontextprotocol/server-brave-search", needs_api_key=True),
    ServerDef("postgres-enhanced", "npx -y @henkey/postgres-mcp-server"),
    ServerDef("stripe", "npx -y @stripe/mcp --tools=all", needs_api_key=True),
    ServerDef("linear", "npx -y @tacticlaunch/mcp-linear", needs_api_key=True),

    # Batch 5 — new finds (2026-03)
    ServerDef("chrome-devtools", "npx -y chrome-devtools-mcp@latest"),
    ServerDef("antv-chart", "npx -y @antv/mcp-server-chart"),
    ServerDef("obsidian", "npx -y @mauricio.wolff/mcp-obsidian@latest /tmp/mcp-batch-sandbox"),
    ServerDef("drawio", "npx -y @drawio/mcp"),
    ServerDef("sovr-security", "npx -y sovr-mcp-server", needs_api_key=True),
    ServerDef("browsermcp", "npx -y @browsermcp/mcp@latest"),
    ServerDef("bytedance-browser", "npx -y @agent-infra/mcp-server-browser"),
    ServerDef("mysql", "npx -y @benborla29/mcp-server-mysql", needs_api_key=True),

    # Python servers (install via: uv tool install mcp-server-fetch, etc.)
    ServerDef("py-fetch", "mcp-server-fetch"),
    ServerDef("py-git", "mcp-server-git"),
    ServerDef("py-time", "mcp-server-time"),
    ServerDef("py-sqlite", "mcp-server-sqlite --db-path /tmp/mcp-batch-py.db"),
]


# ── Result model ────────────────────────────────────────────────────

@dataclass
class ServerResult:
    name: str
    command: str
    success: bool = False
    score: float = 0.0
    grade: str = ""
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    skipped: int = 0
    errors: int = 0
    tools_count: int = 0
    server_name: str = ""
    server_version: str = ""
    duration_ms: int = 0
    error_message: str = ""
    findings: list[str] = field(default_factory=list)
    check_details: list[dict] = field(default_factory=list)


# ── Runner ──────────────────────────────────────────────────────────

async def test_server(sdef: ServerDef, timeout: float = 120.0) -> ServerResult:
    """Run mcp-shield test against a single server."""
    result = ServerResult(name=sdef.name, command=sdef.command)

    try:
        target = parse_target(sdef.command)
        runner = Runner(target)

        # Shield from CancelledError leaking from child tasks
        async def _guarded_run():
            try:
                return await runner.run()
            except asyncio.CancelledError:
                raise asyncio.TimeoutError("cancelled")

        report: SuiteReport = await asyncio.wait_for(_guarded_run(), timeout=timeout)

        from mcp_shield.reporting.score import compute_score, grade_label
        score = compute_score(report)
        grade = grade_label(score)

        result.success = True
        result.score = round(score, 1)
        result.grade = grade
        result.total_checks = report.total_checks
        result.passed = report.passed
        result.failed = report.failed
        result.warnings = report.warnings
        result.skipped = report.skipped
        result.errors = report.errors
        result.server_name = report.server_name
        result.server_version = report.server_version
        result.duration_ms = report.duration_ms

        # Count tools from COMP-003 message
        for r in report.results:
            if r.check_id == "COMP-003" and r.outcome == Outcome.PASS:
                # "All 14 tools have valid inputSchema"
                parts = r.message.split()
                for i, p in enumerate(parts):
                    if p == "All" and i + 1 < len(parts):
                        try:
                            result.tools_count = int(parts[i + 1])
                        except ValueError:
                            pass

        # Collect findings from SEC checks
        for r in report.results:
            if r.details:
                result.findings.extend(r.details)
            result.check_details.append({
                "id": r.check_id,
                "outcome": r.outcome.value,
                "severity": r.severity,
                "message": r.message,
            })

    except asyncio.TimeoutError:
        result.error_message = f"Timeout after {timeout}s"
    except asyncio.CancelledError:
        result.error_message = "CancelledError (server may have crashed)"
    except KeyboardInterrupt:
        raise
    except BaseException as e:
        result.error_message = f"{type(e).__name__}: {str(e)[:200]}"

    return result


def _run_single_server(sdef: ServerDef) -> ServerResult:
    """Run a single server test in an isolated event loop."""
    return asyncio.run(test_server(sdef))


def run_batch_sync(servers: list[ServerDef]) -> list[ServerResult]:
    """Test all servers sequentially, each in its own event loop for isolation."""
    results = []
    total = len(servers)

    for i, sdef in enumerate(servers, 1):
        print(f"\n[{i}/{total}] Testing {sdef.name}...", flush=True)
        t0 = time.monotonic()
        try:
            r = _run_single_server(sdef)
        except BaseException as e:
            r = ServerResult(name=sdef.name, command=sdef.command,
                             error_message=f"Loop crash: {type(e).__name__}: {str(e)[:150]}")
        elapsed = time.monotonic() - t0

        if r.success:
            print(f"  {r.server_name} v{r.server_version} | "
                  f"{r.tools_count} tools | "
                  f"Score: {r.score} {r.grade} | "
                  f"{r.passed}P/{r.failed}F/{r.warnings}W | "
                  f"{elapsed:.1f}s")
        else:
            print(f"  FAILED: {r.error_message} | {elapsed:.1f}s")

        results.append(r)
        gc.collect()

    return results


def print_summary(results: list[ServerResult]) -> None:
    """Print a summary table."""
    print("\n" + "=" * 100)
    print("BATCH TEST SUMMARY")
    print("=" * 100)
    print(f"{'Server':<25} {'Identity':<35} {'Tools':>5} {'Score':>7} {'Grade':>5} "
          f"{'P':>3} {'F':>3} {'W':>3} {'E':>3} {'ms':>6}")
    print("-" * 100)

    ok = 0
    fail = 0
    for r in results:
        if r.success:
            ok += 1
            identity = f"{r.server_name} v{r.server_version}"
            if len(identity) > 33:
                identity = identity[:33] + ".."
            print(f"{r.name:<25} {identity:<35} {r.tools_count:>5} "
                  f"{r.score:>6.0f} {r.grade:>5} "
                  f"{r.passed:>3} {r.failed:>3} {r.warnings:>3} {r.errors:>3} "
                  f"{r.duration_ms:>6}")
        else:
            fail += 1
            err = r.error_message[:60]
            print(f"{r.name:<25} {'FAILED':<35} {'':>5} {'':>7} {'':>5} "
                  f"{'':>3} {'':>3} {'':>3} {'':>3} {'':>6}  {err}")

    print("-" * 100)
    print(f"Total: {len(results)} servers | {ok} OK | {fail} FAILED")

    # Findings summary — sort check_details by outcome/severity importance
    _outcome_order = {"fail": 0, "error": 1, "warn": 2, "pass": 3, "skip": 4}
    _severity_order = {"critical": 0, "error": 1, "warning": 2, "info": 3}
    for r in results:
        if r.success:
            r.check_details.sort(key=lambda d: (
                _outcome_order.get(d["outcome"], 9),
                _severity_order.get(d["severity"], 9),
            ))

    all_findings = []
    for r in results:
        if r.success:
            for f in r.findings:
                all_findings.append((r.name, f))

    if all_findings:
        print(f"\nTotal findings across all servers: {len(all_findings)}")
        print()
        for name, f in all_findings[:30]:
            print(f"  [{name}] {f.strip()}")
        if len(all_findings) > 30:
            print(f"  ... and {len(all_findings) - 30} more")


def main():
    os.makedirs("/tmp/mcp-batch-sandbox", exist_ok=True)

    json_path = None
    if "--json" in sys.argv:
        idx = sys.argv.index("--json")
        if idx + 1 < len(sys.argv):
            json_path = sys.argv[idx + 1]

    only_failed_names: set[str] = set()
    if "--only-failed" in sys.argv:
        idx = sys.argv.index("--only-failed")
        if idx + 1 < len(sys.argv):
            prev_json = Path(sys.argv[idx + 1])
            if prev_json.exists():
                prev = json.loads(prev_json.read_text())
                only_failed_names = {r["name"] for r in prev if not r["success"]}
                print(f"Re-running {len(only_failed_names)} previously failed: {', '.join(sorted(only_failed_names))}")

    only_names: set[str] = set()
    if "--only" in sys.argv:
        idx = sys.argv.index("--only")
        if idx + 1 < len(sys.argv):
            only_names = set(sys.argv[idx + 1].split(","))

    servers = [s for s in SERVERS if not s.needs_api_key]
    if only_failed_names:
        servers = [s for s in servers if s.name in only_failed_names]
    elif only_names:
        servers = [s for s in servers if s.name in only_names]

    print(f"Batch testing {len(servers)} MCP servers...")

    results = run_batch_sync(servers)
    print_summary(results)

    if json_path:
        data = [asdict(r) for r in results]
        Path(json_path).write_text(json.dumps(data, indent=2))
        print(f"\nJSON report saved to {json_path}")


if __name__ == "__main__":
    main()
