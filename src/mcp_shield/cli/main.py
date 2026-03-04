"""MCP Shield CLI — root command group."""

from __future__ import annotations

import click

from mcp_shield import __version__


@click.group()
@click.version_option(__version__, prog_name="mcp-shield")
def cli() -> None:
    """MCP Shield — Test, protect, and audit MCP servers.

    \b
    Quick start:
      mcp-shield test "npx -y @modelcontextprotocol/server-filesystem /tmp"
      mcp-shield proxy "npx server" --deny "delete_*" --rate-limit 30
      mcp-shield audit show --last 20 --blocked

    \b
    Docs: https://github.com/thuggeelya/mcp-shield
    """


# Import subcommands so they register with the group.
from mcp_shield.cli.test_cmd import test_cmd  # noqa: E402
from mcp_shield.cli.proxy_cmd import proxy_cmd  # noqa: E402
from mcp_shield.cli.audit_cmd import audit_group  # noqa: E402

cli.add_command(test_cmd, "test")
cli.add_command(proxy_cmd, "proxy")
cli.add_command(audit_group, "audit")
