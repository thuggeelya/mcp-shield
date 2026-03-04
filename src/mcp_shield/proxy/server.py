"""ShieldProxy — runtime MCP proxy with security scanning, auth, rate limiting.

Sits between an MCP client (stdio) and an upstream MCP server,
intercepting all requests to apply security controls and audit logging.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import signal
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

import mcp.types as types
from mcp import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp_shield.client.connection import MCPConnection, ServerTarget
from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.proxy.middleware import (
    AuthChecker,
    ProxyConfig,
    RateLimiter,
    ToolFilter,
)
from mcp_shield.classification.risk import classify_tool_risk
from mcp_shield.security.base import sanitize_evidence
from mcp_shield.security.rug_pull import RugPullDetector
from mcp_shield.security.scanner import SecurityReport, SecurityScanner
from mcp_shield.storage.audit_db import AuditAction, AuditDB, AuditEvent, RiskTier

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _hash_args(arguments: Dict[str, Any] | None) -> str:
    if not arguments:
        return ""
    raw = json.dumps(arguments, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _sanitize_args(arguments: Dict[str, Any] | None) -> str:
    if not arguments:
        return ""
    raw = json.dumps(arguments, sort_keys=True, default=str)
    return sanitize_evidence(raw[:200])


def _tool_to_info(tool: types.Tool) -> ToolInfo:
    """Convert an MCP SDK Tool to our ToolInfo model."""
    desc_hash = hashlib.sha256((tool.description or "").encode()).hexdigest()[:16]
    return ToolInfo(
        name=tool.name,
        description=tool.description or "",
        title=tool.title or "",
        input_schema=tool.inputSchema or {},
        output_schema=dict(tool.outputSchema) if tool.outputSchema else None,
        annotations=dict(tool.annotations) if tool.annotations else None,
        description_hash=desc_hash,
    )


class ShieldProxy:
    """MCP proxy server with security scanning and audit logging.

    Presents itself as an MCP server to the client, forwarding all
    requests to the upstream server after applying middleware checks.
    """

    def __init__(
        self,
        target: ServerTarget,
        config: ProxyConfig,
        audit_db: AuditDB,
    ) -> None:
        self._target = target
        self._config = config
        self._audit_db = audit_db

        self._auth = AuthChecker(config)
        self._rate_limiter = RateLimiter(config.rate_limit)
        self._tool_filter = ToolFilter(config.allow_tools, config.deny_tools)

        self._server = Server("mcp-shield-proxy")
        self._upstream: ClientSession | None = None
        self._security_report: SecurityReport | None = None
        self._scanned = False
        self._tool_infos: Dict[str, ToolInfo] = {}

        self._register_handlers()

    @property
    def server(self) -> Server:
        return self._server

    def _register_handlers(self) -> None:
        """Register all 6 MCP handler decorators."""
        server = self._server

        @server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return await self._handle_list_tools()

        @server.call_tool(validate_input=False)
        async def handle_call_tool(
            name: str, arguments: dict[str, Any] | None
        ) -> list[types.TextContent]:
            return await self._handle_call_tool(name, arguments)

        @server.list_resources()
        async def handle_list_resources() -> list[types.Resource]:
            return await self._handle_list_resources()

        @server.read_resource()
        async def handle_read_resource(uri: Any) -> str:
            return await self._handle_read_resource(uri)

        @server.list_prompts()
        async def handle_list_prompts() -> list[types.Prompt]:
            return await self._handle_list_prompts()

        @server.get_prompt()
        async def handle_get_prompt(
            name: str, arguments: dict[str, str] | None
        ) -> types.GetPromptResult:
            return await self._handle_get_prompt(name, arguments)

    # ── Handler implementations ──────────────────────────────────────

    async def _handle_list_tools(self) -> list[types.Tool]:
        start = time.monotonic()
        allowed, client_id = self._check_auth()

        # list_tools is exempt from rate limiting: it's a discovery
        # request, and the SDK server calls it internally on every
        # call_tool for input schema validation.

        upstream = self._get_upstream()
        result = await upstream.list_tools()
        tools = result.tools

        # Security scan on first list_tools
        if not self._scanned:
            await self._run_security_scan(tools)

        # Cache tool infos for risk classification
        for t in tools:
            info = _tool_to_info(t)
            self._tool_infos[t.name] = info

        # Strip outputSchema: the proxy forwards raw content from upstream,
        # not structured output.  If outputSchema is present, the SDK's
        # internal call_tool handler will reject the raw TextContent with
        # "outputSchema defined but no structured output returned".
        for t in tools:
            if t.outputSchema is not None:
                t.outputSchema = None

        # Filter tools
        filtered = [t for t in tools if self._tool_filter.is_allowed(t.name)]

        self._log_event(
            AuditAction.LIST_TOOLS,
            client_id,
            "",
            _elapsed_ms(start),
        )

        return filtered

    async def _handle_call_tool(
        self, name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent]:
        start = time.monotonic()
        allowed, client_id = self._check_auth()

        if not allowed:
            self._log_blocked(AuditAction.CALL_TOOL, client_id, name, "auth_failed", start)
            return [types.TextContent(type="text", text="Error: authentication failed")]

        if not self._rate_limiter.check(client_id):
            self._log_blocked(AuditAction.CALL_TOOL, client_id, name, "rate_limit", start)
            return [types.TextContent(type="text", text="Error: rate limit exceeded")]

        if not self._tool_filter.is_allowed(name):
            self._log_blocked(AuditAction.CALL_TOOL, client_id, name, "tool_denied", start)
            return [types.TextContent(type="text", text=f"Error: tool '{name}' is denied")]

        upstream = self._get_upstream()
        try:
            result = await upstream.call_tool(name, arguments)
        except Exception as exc:
            self._log_event(
                AuditAction.CALL_TOOL, client_id, name, _elapsed_ms(start),
                arguments=arguments, blocked=True, block_reason=f"upstream_error: {exc}",
            )
            return [types.TextContent(type="text", text=f"Error: upstream call failed: {exc}")]

        self._log_event(
            AuditAction.CALL_TOOL, client_id, name, _elapsed_ms(start),
            arguments=arguments,
        )

        return result.content  # type: ignore[return-value]

    async def _handle_list_resources(self) -> list[types.Resource]:
        start = time.monotonic()
        allowed, client_id = self._check_auth()

        # Discovery request — exempt from rate limiting.

        upstream = self._get_upstream()
        try:
            result = await upstream.list_resources()
        except Exception as exc:
            logger.debug("list_resources not supported by upstream: %s", exc)
            self._log_event(AuditAction.LIST_RESOURCES, client_id, "", _elapsed_ms(start))
            return []

        self._log_event(AuditAction.LIST_RESOURCES, client_id, "", _elapsed_ms(start))

        return result.resources

    async def _handle_read_resource(self, uri: Any) -> str:
        start = time.monotonic()
        allowed, client_id = self._check_auth()
        uri_str = str(uri)

        if not allowed:
            self._log_blocked(AuditAction.READ_RESOURCE, client_id, uri_str, "auth_failed", start)
            return ""

        if not self._rate_limiter.check(client_id):
            self._log_blocked(AuditAction.READ_RESOURCE, client_id, uri_str, "rate_limit", start)
            return ""

        upstream = self._get_upstream()
        result = await upstream.read_resource(uri)

        self._log_event(AuditAction.READ_RESOURCE, client_id, uri_str, _elapsed_ms(start))

        # Return first text content
        for content in result.contents:
            if hasattr(content, "text"):
                return content.text
        return ""

    async def _handle_list_prompts(self) -> list[types.Prompt]:
        start = time.monotonic()
        allowed, client_id = self._check_auth()

        # Discovery request — exempt from rate limiting.

        upstream = self._get_upstream()
        try:
            result = await upstream.list_prompts()
        except Exception as exc:
            logger.debug("list_prompts not supported by upstream: %s", exc)
            self._log_event(AuditAction.LIST_PROMPTS, client_id, "", _elapsed_ms(start))
            return []

        self._log_event(AuditAction.LIST_PROMPTS, client_id, "", _elapsed_ms(start))

        return result.prompts

    async def _handle_get_prompt(
        self, name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        start = time.monotonic()
        allowed, client_id = self._check_auth()

        if not allowed:
            self._log_blocked(AuditAction.GET_PROMPT, client_id, name, "auth_failed", start)
            return types.GetPromptResult(messages=[])

        if not self._rate_limiter.check(client_id):
            self._log_blocked(AuditAction.GET_PROMPT, client_id, name, "rate_limit", start)
            return types.GetPromptResult(messages=[])

        upstream = self._get_upstream()
        result = await upstream.get_prompt(name, arguments)

        self._log_event(AuditAction.GET_PROMPT, client_id, name, _elapsed_ms(start))

        return result

    # ── Security scan ────────────────────────────────────────────────

    async def _run_security_scan(self, tools: Sequence[types.Tool]) -> None:
        """Run SecurityScanner + RugPullDetector on tools (first list_tools only)."""
        self._scanned = True

        tool_infos = [_tool_to_info(t) for t in tools]

        # Standard security scan (all detectors)
        from mcp_shield.security.scanner import default_detectors
        scanner = SecurityScanner(detectors=default_detectors())
        report = scanner.scan_tools(tool_infos)

        # Rug pull detection — compare against stored snapshots
        try:
            snapshots = self._audit_db.get_latest_snapshots()
            rug_pull = RugPullDetector(snapshots)
            for tool_info in tool_infos:
                try:
                    report.findings.extend(rug_pull.scan_tool(tool_info))
                except Exception as exc:
                    logger.warning(
                        "RugPullDetector failed on tool '%s': %s",
                        tool_info.name, str(exc)[:500],
                    )
            report.compute_score()
        except Exception as exc:
            logger.warning("Rug pull detection skipped: %s", str(exc)[:500])

        self._security_report = report

        # Save findings to audit DB
        for finding in report.findings:
            self._audit_db.save_finding(
                finding_id=finding.finding_id,
                severity=finding.severity,
                category=finding.category,
                title=finding.title,
                tool_name=finding.tool_name,
                description=finding.description,
            )

        # Save tool snapshots (after rug pull check, so we have current state)
        for tool_info in tool_infos:
            tool_findings = [
                {"finding_id": f.finding_id, "severity": f.severity, "title": f.title}
                for f in report.findings
                if f.tool_name == tool_info.name
            ]
            self._audit_db.save_tool_snapshot(
                tool_name=tool_info.name,
                description_hash=tool_info.description_hash,
                input_schema=tool_info.input_schema,
                security_findings=tool_findings,
            )

        if report.findings:
            logger.warning(
                "Security scan: %d findings (score %.0f/100)",
                len(report.findings),
                report.score,
            )
        else:
            logger.info("Security scan: clean (score 100/100)")

    # ── Audit helpers ────────────────────────────────────────────────

    def _log_event(
        self,
        action: str,
        client_id: str,
        tool_name: str,
        duration_ms: int,
        *,
        arguments: Dict[str, Any] | None = None,
        blocked: bool = False,
        block_reason: str = "",
    ) -> None:
        score = self._security_report.score if self._security_report else 100.0
        risk_tier = self._classify_risk(tool_name)
        event = AuditEvent(
            timestamp=_now_iso(),
            client_id=client_id,
            action=action,
            tool_name=tool_name,
            arguments_hash=_hash_args(arguments),
            arguments_summary=_sanitize_args(arguments),
            risk_tier=risk_tier,
            blocked=blocked,
            block_reason=block_reason,
            duration_ms=duration_ms,
            security_score=score,
        )
        try:
            self._audit_db.log_event(event)
        except Exception:
            logger.exception("Failed to log audit event")

    def _log_blocked(
        self, action: str, client_id: str, tool_name: str, reason: str, start: float
    ) -> None:
        self._log_event(
            action, client_id, tool_name, _elapsed_ms(start),
            blocked=True, block_reason=reason,
        )

    def _classify_risk(self, tool_name: str) -> str:
        """Classify a tool's risk tier using cached tool info."""
        if not tool_name:
            return RiskTier.UNKNOWN
        info = self._tool_infos.get(tool_name)
        if info:
            return classify_tool_risk(info.name, info.description, info.input_schema)
        return classify_tool_risk(tool_name, "")

    def _check_auth(self, token: str | None = None) -> tuple[bool, str]:
        """Check auth and return (allowed, client_id).

        In stdio mode, token is always None and AuthChecker in "none"
        mode returns (True, "stdio").  When HTTP transport is added,
        the token will come from request headers.
        """
        return self._auth.check(token)

    def _get_upstream(self) -> ClientSession:
        if self._upstream is None:
            raise RuntimeError("Upstream connection not established")
        return self._upstream

    # ── Run ──────────────────────────────────────────────────────────

    async def run_stdio(self) -> None:
        """Run the proxy: connect to upstream and serve via stdio."""
        self._audit_db.open()

        # SIGTERM → graceful shutdown (docker stop, systemd, etc.)
        loop = asyncio.get_running_loop()
        shutdown_event = asyncio.Event()

        def _sigterm_handler() -> None:
            logger.info("Received SIGTERM, shutting down...")
            shutdown_event.set()

        try:
            loop.add_signal_handler(signal.SIGTERM, _sigterm_handler)
        except NotImplementedError:
            pass  # Windows doesn't support add_signal_handler

        try:
            async with MCPConnection(self._target) as session:
                self._upstream = session
                async with stdio_server() as (read_stream, write_stream):
                    init_options = self._server.create_initialization_options()

                    server_task = asyncio.create_task(
                        self._server.run(read_stream, write_stream, init_options)
                    )
                    shutdown_task = asyncio.create_task(shutdown_event.wait())

                    done, pending = await asyncio.wait(
                        [server_task, shutdown_task],
                        return_when=asyncio.FIRST_COMPLETED,
                    )

                    for task in pending:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

                    # Propagate server errors
                    for task in done:
                        if task is server_task and task.exception():
                            raise task.exception()  # type: ignore[misc]
        except OSError as exc:
            raise ConnectionError(
                f"Failed to connect to upstream server: {exc}"
            ) from exc
        except FileNotFoundError as exc:
            raise ConnectionError(
                f"Upstream server command not found: {exc}"
            ) from exc
        finally:
            self._upstream = None
            self._audit_db.close()
