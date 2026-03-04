"""Shared text extraction from MCP tool definitions.

Every detector that analyses tool text (descriptions, titles, schema
descriptions) should use this module instead of implementing its own
tree walk.  Adding a new scannable field here automatically benefits
all detectors.
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from mcp_shield.models.mcp_types import ToolInfo

logger = logging.getLogger(__name__)


_MAX_SCHEMA_DEPTH = 50


def collect_tool_texts(tool: ToolInfo) -> List[Tuple[str, str]]:
    """Extract all scannable text fields from a tool definition.

    Returns a list of ``(text, field_name)`` pairs.
    """
    pairs: List[Tuple[str, str]] = []
    if tool.description:
        pairs.append((tool.description, "description"))
    if tool.title:
        pairs.append((tool.title, "title"))
    _walk_schema_descriptions(tool.input_schema, "inputSchema", pairs)
    return pairs


def _walk_schema_descriptions(
    schema: dict,
    path: str,
    out: List[Tuple[str, str]],
    _depth: int = 0,
    _root: dict | None = None,
) -> None:
    """Recursively collect ``description`` fields from a JSON Schema.

    IV-11: Resolves ``$ref`` pointers (local JSON Pointer only, e.g.
    ``#/definitions/Foo``).  External ``$ref`` (file/URL) are ignored.
    """
    if not isinstance(schema, dict):
        return
    if _depth > _MAX_SCHEMA_DEPTH:
        logger.warning("Schema depth limit (%d) exceeded at path '%s'", _MAX_SCHEMA_DEPTH, path)
        return

    root = _root if _root is not None else schema

    # IV-11: Resolve $ref if present
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        resolved = _resolve_ref(root, ref)
        if resolved is not None and resolved is not schema:
            _walk_schema_descriptions(resolved, path, out, _depth + 1, root)
        return  # $ref replaces the current schema node

    desc = schema.get("description")
    if isinstance(desc, str) and desc:
        out.append((desc, path))
    for key in ("properties", "items", "additionalProperties"):
        child = schema.get(key)
        if isinstance(child, dict):
            for k, v in (child.items() if key == "properties" else [(key, child)]):
                _walk_schema_descriptions(v, f"{path}.{k}", out, _depth + 1, root)

    # DC-10: Walk oneOf/anyOf/allOf branches for descriptions too
    for keyword in ("oneOf", "anyOf", "allOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list):
            for i, variant in enumerate(variants):
                _walk_schema_descriptions(
                    variant, f"{path}.{keyword}[{i}]", out, _depth + 1, root
                )


def _resolve_ref(root: dict, ref: str) -> dict | None:
    """Resolve a local JSON Pointer (``#/definitions/Foo``) against the root schema.

    Returns the resolved sub-schema dict, or None if resolution fails.
    """
    parts = ref.lstrip("#/").split("/")
    node: object = root
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, dict) else None
