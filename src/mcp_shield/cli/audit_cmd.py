"""mcp-shield audit — query and export audit logs."""

from __future__ import annotations

import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_shield.storage.audit_db import AuditDB


_MAX_SINCE_HOURS = 365 * 10 * 24  # 10 years


def _parse_since(since: str) -> str:
    """Parse a human-friendly time range (e.g. '24h', '7d') to ISO timestamp."""
    match = re.match(r"^(\d+)([hdwm])$", since.strip())
    if not match:
        raise click.BadParameter(
            f"Invalid time range '{since}'. Use format like 1h, 24h, 7d, 4w.",
            param_hint="--since",
        )
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"h": 1, "d": 24, "w": 168, "m": 720}
    hours = value * multipliers[unit]
    if hours > _MAX_SINCE_HOURS:
        raise click.BadParameter(
            f"Time range '{since}' exceeds maximum (10 years). Use a shorter range.",
            param_hint="--since",
        )
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return cutoff.isoformat()


@click.group("audit")
@click.option(
    "--db",
    type=click.Path(),
    default="~/.mcp-shield/audit.db",
    help="Path to audit SQLite database.",
)
@click.pass_context
def audit_group(ctx: click.Context, db: str) -> None:
    """Query audit logs from proxy sessions.

    \b
    Examples:
      mcp-shield audit show --last 20
      mcp-shield audit show --blocked --risk write_sensitive
      mcp-shield audit stats --since 7d
      mcp-shield audit export -f json -o audit.json
    """
    ctx.ensure_object(dict)
    ctx.obj["audit_db"] = db


@audit_group.command("show")
@click.option("--last", "-n", type=click.IntRange(min=1), default=50, help="Number of recent events.")
@click.option("--tool", type=str, default=None, help="Filter by tool name.")
@click.option(
    "--risk",
    type=click.Choice(["read", "write_reversible", "write_external", "write_sensitive"]),
    default=None,
    help="Filter by risk tier.",
)
@click.option("--client", type=str, default=None, help="Filter by client ID.")
@click.option("--blocked", is_flag=True, default=False, help="Show only blocked events.")
@click.pass_context
def audit_show(
    ctx: click.Context,
    last: int,
    tool: str | None,
    risk: str | None,
    client: str | None,
    blocked: bool,
) -> None:
    """Show recent audit events.

    \b
    Examples:
      mcp-shield audit show                              # last 50 events
      mcp-shield audit show -n 100 --tool delete_file    # filter by tool
      mcp-shield audit show --risk write_sensitive       # high-risk only
      mcp-shield audit show --blocked                    # denied calls only
      mcp-shield audit show --client admin               # filter by client
    """
    db_path = ctx.obj["audit_db"]
    db = AuditDB(db_path)

    try:
        db.open()
    except Exception as exc:
        click.echo(f"Error opening database: {exc}", err=True)
        sys.exit(1)

    try:
        events = db.get_events(
            limit=last,
            tool_name=tool,
            risk_tier=risk,
            client_id=client,
            blocked=blocked if blocked else None,
        )

        if not events:
            click.echo("No audit events found.")
            return

        console = Console()
        wide = console.width >= 120
        table = Table(show_header=True, header_style="bold")
        table.add_column("Timestamp", no_wrap=True)
        if wide:
            table.add_column("Client")
        table.add_column("Action")
        table.add_column("Tool", overflow="ellipsis")
        table.add_column("Risk")
        table.add_column("Blk", width=3, justify="center")
        table.add_column("ms", justify="right")

        for ev in events:
            blocked_text = Text("Y", style="red bold") if ev.blocked else Text("", style="dim")
            ts = ev.timestamp[11:19] if len(ev.timestamp) >= 19 else ev.timestamp
            if wide:
                ts = ev.timestamp[:19]
            duration = str(ev.duration_ms) if ev.duration_ms else ""
            risk_style = ""
            if ev.risk_tier == "write_sensitive":
                risk_style = "red"
            elif ev.risk_tier == "write_external":
                risk_style = "yellow"
            elif ev.risk_tier == "write_reversible":
                risk_style = "cyan"
            elif ev.risk_tier == "read":
                risk_style = "green"
            risk_text = Text(ev.risk_tier, style=risk_style) if ev.risk_tier else Text("")

            row: list[Any] = [ts]
            if wide:
                row.append(ev.client_id)
            row.extend([ev.action, ev.tool_name or "", risk_text, blocked_text, duration])
            table.add_row(*row)

        console.print(table)
        console.print(f"\n[dim]{len(events)} events shown[/dim]")
    finally:
        db.close()


@audit_group.command("export")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Export format.",
)
@click.option("--output", "-o", type=click.Path(), required=True, help="Output file path.")
@click.pass_context
def audit_export(ctx: click.Context, fmt: str, output: str) -> None:
    """Export audit logs to JSON or CSV.

    \b
    Examples:
      mcp-shield audit export -f json -o audit.json
      mcp-shield audit export -f csv -o audit.csv
    """
    db_path = ctx.obj["audit_db"]
    db = AuditDB(db_path)

    try:
        db.open()
    except Exception as exc:
        click.echo(f"Error opening database: {exc}", err=True)
        sys.exit(1)

    try:
        events = db.export_events()

        if not events:
            click.echo("No events to export.")
            return

        out_path = Path(output).expanduser().resolve()
        if out_path.is_dir():
            click.echo(
                f"Error: Output path is a directory: {out_path}. "
                f"Provide a file path, e.g. {out_path / 'audit.json'}",
                err=True,
            )
            sys.exit(1)

        try:
            if fmt == "json":
                with open(out_path, "w") as f:
                    json.dump(events, f, indent=2, default=str)
            elif fmt == "csv":
                if not events:
                    return
                fieldnames = list(events[0].keys())
                with open(out_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(events)
        except OSError as exc:
            click.echo(f"Error writing file: {exc}", err=True)
            sys.exit(1)

        click.echo(f"Exported {len(events)} events to {out_path}")
    finally:
        db.close()


@audit_group.command("stats")
@click.option("--since", type=str, default="24h", help="Time range (e.g. 1h, 7d).")
@click.pass_context
def audit_stats(ctx: click.Context, since: str) -> None:
    """Show summary statistics of audit events.

    \b
    Examples:
      mcp-shield audit stats                  # last 24 hours (default)
      mcp-shield audit stats --since 1h       # last hour
      mcp-shield audit stats --since 7d       # last 7 days
      mcp-shield audit stats --since 4w       # last 4 weeks

    \b
    Time units: h (hours), d (days), w (weeks), m (months/30d).
    """
    db_path = ctx.obj["audit_db"]
    db = AuditDB(db_path)

    try:
        db.open()
    except Exception as exc:
        click.echo(f"Error opening database: {exc}", err=True)
        sys.exit(1)

    try:
        since_ts = _parse_since(since)
        stats = db.get_stats(since=since_ts)

        console = Console()

        # Summary panel
        summary_lines = [
            f"Period: last {since}",
            f"Total events: {stats['total']}",
            f"Tool calls: {stats['tool_calls']}",
            f"Blocked: {stats['blocked']}",
            f"Unique tools: {stats['unique_tools']}",
            f"Unique clients: {stats['unique_clients']}",
            f"Avg duration: {stats['avg_duration_ms']}ms",
        ]
        console.print(Panel("\n".join(summary_lines), title="Audit Statistics", border_style="blue"))

        # Action breakdown
        if stats["by_action"]:
            action_table = Table(title="By Action", show_header=True, header_style="bold")
            action_table.add_column("Action")
            action_table.add_column("Count", justify="right")
            for action, count in sorted(stats["by_action"].items()):
                action_table.add_row(action, str(count))
            console.print(action_table)

        # Risk breakdown
        if stats["by_risk"]:
            risk_table = Table(title="By Risk Tier", show_header=True, header_style="bold")
            risk_table.add_column("Risk Tier")
            risk_table.add_column("Count", justify="right")
            for risk, count in sorted(stats["by_risk"].items()):
                risk_table.add_row(risk, str(count))
            console.print(risk_table)

        if stats["total"] == 0:
            click.echo(f"\nNo events in the last {since}.")
    finally:
        db.close()
