"""MCP-specific data types used across the project."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolInfo:
    """Parsed MCP tool definition from tools/list."""

    name: str
    description: str = ""
    title: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Optional[Dict[str, Any]] = None
    annotations: Optional[Dict[str, Any]] = None
    # SHA-256 of description at first discovery (for change detection)
    description_hash: str = ""


@dataclass
class ResourceInfo:
    """Parsed MCP resource definition."""

    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


@dataclass
class PromptInfo:
    """Parsed MCP prompt definition."""

    name: str
    description: str = ""
    arguments: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ServerCapabilities:
    """Parsed server capabilities from the initialize response."""

    protocol_version: str = ""
    server_name: str = ""
    server_version: str = ""
    has_tools: bool = False
    has_resources: bool = False
    has_prompts: bool = False
    has_logging: bool = False
    has_list_changed: bool = False
