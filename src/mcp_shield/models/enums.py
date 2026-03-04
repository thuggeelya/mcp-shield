"""Shared enumerations used across mcp-shield subsystems."""

from __future__ import annotations

from enum import Enum


class AuditAction(str, Enum):
    """MCP operations tracked by the audit log."""

    LIST_TOOLS = "list_tools"
    CALL_TOOL = "call_tool"
    LIST_RESOURCES = "list_resources"
    READ_RESOURCE = "read_resource"
    LIST_PROMPTS = "list_prompts"
    GET_PROMPT = "get_prompt"


class RiskTier(str, Enum):
    """Risk classification for tool operations."""

    READ = "read"
    WRITE_REVERSIBLE = "write_reversible"
    WRITE_EXTERNAL = "write_external"
    WRITE_SENSITIVE = "write_sensitive"
    UNKNOWN = "unknown"
