"""mcp-shield proxy — runtime protection for an MCP server."""

from __future__ import annotations

import asyncio
import sys

import click

from mcp_shield.client.connection import parse_target
from mcp_shield.proxy.middleware import ProxyConfig
from mcp_shield.proxy.server import ShieldProxy
from mcp_shield.storage.audit_db import AuditDB


def _parse_tokens(token_pairs: tuple[str, ...]) -> dict[str, str]:
    """Parse CLIENT_ID:TOKEN pairs into a dict."""
    result: dict[str, str] = {}
    for pair in token_pairs:
        if ":" not in pair:
            raise click.BadParameter(
                f"Token must be CLIENT_ID:TOKEN, got '{pair}'",
                param_hint="--token",
            )
        client_id, _, token = pair.partition(":")
        if not client_id or not token:
            raise click.BadParameter(
                f"Both CLIENT_ID and TOKEN must be non-empty in '{pair}'",
                param_hint="--token",
            )
        result[client_id] = token
    return result


@click.command("proxy")
@click.argument("server")
@click.option("--port", "-p", type=int, default=8080, help="Listen port (reserved for future HTTP transport).")
@click.option("--host", type=str, default="127.0.0.1", help="Listen address (reserved for future HTTP transport).")
@click.option(
    "--auth",
    type=click.Choice(["none", "bearer", "api_key"]),
    default="none",
    help="Authentication mode.",
)
@click.option(
    "--token",
    multiple=True,
    help="Bearer tokens as CLIENT_ID:TOKEN. Can repeat.",
)
@click.option("--allow", multiple=True, help="Allow only these tools (glob, e.g. 'read_*'). Can repeat.")
@click.option("--deny", multiple=True, help="Block tools by name (glob, e.g. 'delete_*'). Can repeat.")
@click.option(
    "--rate-limit",
    type=click.IntRange(min=0),
    default=60,
    help="Max requests per minute per client (0 = unlimited).",
)
@click.option(
    "--audit-db",
    type=click.Path(),
    default="~/.mcp-shield/audit.db",
    help="Path to audit SQLite database.",
)
@click.option(
    "--env", "-e",
    multiple=True,
    help="Environment variables for stdio server as KEY=VALUE. Can repeat.",
)
def proxy_cmd(
    server: str,
    port: int,
    host: str,
    auth: str,
    token: tuple[str, ...],
    allow: tuple[str, ...],
    deny: tuple[str, ...],
    rate_limit: int,
    audit_db: str,
    env: tuple[str, ...],
) -> None:
    """Start a protective proxy in front of an MCP server.

    SERVER is the upstream MCP server to proxy. The proxy intercepts all
    MCP requests, applies security controls, and logs to an audit database.

    \b
    Examples:
      mcp-shield proxy "npx server" --deny "delete_*" --deny "exec_*"
      mcp-shield proxy "npx server" --allow "read_*" --allow "list_*"
      mcp-shield proxy "npx server" --rate-limit 30 --audit-db ./audit.db
      mcp-shield proxy "npx server" --auth bearer --token admin:secret123
      mcp-shield proxy "npx server" --env API_KEY=sk-123
      mcp-shield proxy "http://upstream:9090/mcp" --deny "drop_*"
    """
    # Validate auth + token consistency
    if auth != "none" and not token:
        raise click.UsageError(
            f"--auth={auth} requires at least one --token CLIENT_ID:TOKEN"
        )

    tokens = _parse_tokens(token)
    target = parse_target(server, env_pairs=list(env) if env else None)

    if auth != "none" and target.transport.value == "stdio":
        click.echo(
            "Warning: --auth has no effect in stdio mode (single client). "
            "Auth will be enforced when HTTP transport is added.",
            err=True,
        )

    config = ProxyConfig(
        auth_mode=auth,
        tokens=tokens,
        allow_tools=list(allow),
        deny_tools=list(deny),
        rate_limit=rate_limit,
    )

    db = AuditDB(audit_db)

    proxy = ShieldProxy(target, config, db)

    # Log to stderr — stdout is the MCP stdio transport
    click.echo(f"MCP Shield proxy → {server}", err=True)
    if deny:
        click.echo(f"  Denied tools: {', '.join(deny)}", err=True)
    if allow:
        click.echo(f"  Allowed tools: {', '.join(allow)}", err=True)
    click.echo(f"  Rate limit: {rate_limit} req/min", err=True)
    click.echo(f"  Audit DB: {audit_db}", err=True)

    try:
        asyncio.run(proxy.run_stdio())
    except KeyboardInterrupt:
        click.echo("\nShutting down proxy...", err=True)
    except ConnectionError as exc:
        click.echo(f"Connection error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
