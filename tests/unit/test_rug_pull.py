"""Tests for mcp_shield.security.rug_pull — Rug Pull detection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import FindingCategory, Severity
from mcp_shield.security.rug_pull import RugPullDetector
from mcp_shield.storage.audit_db import AuditDB


def _make_tool(
    name: str,
    description: str = "A tool.",
    input_schema: dict | None = None,
) -> ToolInfo:
    desc_hash = hashlib.sha256(description.encode()).hexdigest()[:16]
    return ToolInfo(
        name=name,
        description=description,
        description_hash=desc_hash,
        input_schema=input_schema or {"type": "object"},
    )


class TestNoHistory:
    """First run — no previous snapshots to compare against."""

    def test_no_snapshots_no_findings(self):
        detector = RugPullDetector({})
        tool = _make_tool("read_file")
        findings = detector.scan_tool(tool)
        assert findings == []

    def test_new_tool_no_findings(self):
        # Snapshot exists for a different tool
        detector = RugPullDetector({
            "other_tool": {"description_hash": "abc123", "input_schema_json": "{}"},
        })
        tool = _make_tool("read_file")
        findings = detector.scan_tool(tool)
        assert findings == []


class TestDescriptionChange:
    """Description hash mismatch → rug pull finding."""

    def test_description_changed(self):
        old_hash = hashlib.sha256(b"Original description").hexdigest()[:16]
        detector = RugPullDetector({
            "read_file": {
                "description_hash": old_hash,
                "input_schema_json": json.dumps({"type": "object"}),
            },
        })
        tool = _make_tool("read_file", "Modified description <!-- steal data -->")
        findings = detector.scan_tool(tool)

        assert len(findings) >= 1
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1
        assert desc_findings[0].severity == Severity.CRITICAL
        assert desc_findings[0].category == FindingCategory.RUG_PULL
        assert "read_file" in desc_findings[0].title
        assert desc_findings[0].tool_name == "read_file"

    def test_description_unchanged(self):
        desc = "Read a file from disk"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]
        detector = RugPullDetector({
            "read_file": {
                "description_hash": desc_hash,
                "input_schema_json": json.dumps({"type": "object"}),
            },
        })
        tool = _make_tool("read_file", desc)
        findings = detector.scan_tool(tool)

        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 0


class TestSchemaChange:
    """Input schema mismatch → schema change finding."""

    def test_schema_changed(self):
        desc = "Read a file"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]
        old_schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        new_schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "command": {"type": "string"},  # New field
            },
        }
        detector = RugPullDetector({
            "read_file": {
                "description_hash": desc_hash,
                "input_schema_json": json.dumps(old_schema),
            },
        })
        tool = _make_tool("read_file", desc, new_schema)
        findings = detector.scan_tool(tool)

        schema_findings = [f for f in findings if "SCHEMA" in f.finding_id]
        assert len(schema_findings) == 1
        assert schema_findings[0].severity == Severity.HIGH
        assert schema_findings[0].category == FindingCategory.RUG_PULL

    def test_schema_unchanged(self):
        desc = "Read a file"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]
        schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        detector = RugPullDetector({
            "read_file": {
                "description_hash": desc_hash,
                "input_schema_json": json.dumps(schema),
            },
        })
        tool = _make_tool("read_file", desc, schema)
        findings = detector.scan_tool(tool)

        schema_findings = [f for f in findings if "SCHEMA" in f.finding_id]
        assert len(schema_findings) == 0

    def test_schema_key_order_irrelevant(self):
        """JSON key order should not produce false positives."""
        desc = "A tool"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]
        schema = {"properties": {"a": {"type": "string"}}, "type": "object"}
        detector = RugPullDetector({
            "tool": {
                "description_hash": desc_hash,
                "input_schema_json": json.dumps({"type": "object", "properties": {"a": {"type": "string"}}}),
            },
        })
        tool = _make_tool("tool", desc, schema)
        findings = detector.scan_tool(tool)

        schema_findings = [f for f in findings if "SCHEMA" in f.finding_id]
        assert len(schema_findings) == 0


class TestBothChanged:
    """Both description and schema changed → two findings."""

    def test_both_changed(self):
        old_hash = hashlib.sha256(b"Old desc").hexdigest()[:16]
        old_schema = {"type": "object"}
        detector = RugPullDetector({
            "tool": {
                "description_hash": old_hash,
                "input_schema_json": json.dumps(old_schema),
            },
        })
        tool = _make_tool("tool", "New malicious desc", {"type": "object", "properties": {"cmd": {"type": "string"}}})
        findings = detector.scan_tool(tool)

        assert len(findings) == 2
        categories = {f.finding_id.split("-")[1] for f in findings}
        assert categories == {"DESC", "SCHEMA"}


class TestEmptyHashes:
    """Edge cases with empty description hashes."""

    def test_empty_prev_hash(self):
        detector = RugPullDetector({
            "tool": {"description_hash": "", "input_schema_json": "{}"},
        })
        tool = _make_tool("tool", "Some desc")
        findings = detector.scan_tool(tool)
        # No comparison possible when prev hash is empty
        assert len([f for f in findings if "DESC" in f.finding_id]) == 0

    def test_empty_current_hash(self):
        detector = RugPullDetector({
            "tool": {"description_hash": "abc123", "input_schema_json": "{}"},
        })
        tool = ToolInfo(name="tool", description="desc", description_hash="")
        findings = detector.scan_tool(tool)
        assert len([f for f in findings if "DESC" in f.finding_id]) == 0


class TestFindingContent:
    """Verify finding fields are populated correctly."""

    def test_finding_has_remediation(self):
        old_hash = hashlib.sha256(b"Old").hexdigest()[:16]
        detector = RugPullDetector({
            "tool": {"description_hash": old_hash, "input_schema_json": "{}"},
        })
        tool = _make_tool("tool", "New")
        findings = detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert desc_findings[0].remediation != ""

    def test_finding_has_evidence(self):
        old_hash = hashlib.sha256(b"Old").hexdigest()[:16]
        detector = RugPullDetector({
            "tool": {"description_hash": old_hash, "input_schema_json": "{}"},
        })
        tool = _make_tool("tool", "New")
        findings = detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert "Previous hash" in desc_findings[0].evidence


class TestDetectorProtocol:
    """RugPullDetector satisfies the Detector protocol."""

    def test_implements_protocol(self):
        from mcp_shield.security.base import Detector
        detector = RugPullDetector({})
        assert isinstance(detector, Detector)


class TestAuditDBIntegration:
    """Integration with AuditDB.get_latest_snapshots()."""

    def test_round_trip(self, tmp_path: Path):
        db = AuditDB(tmp_path / "test.db")
        db.open()

        # Save initial snapshot
        schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        db.save_tool_snapshot("read_file", "hash_v1", schema, [])

        # Get snapshots and create detector
        snapshots = db.get_latest_snapshots()
        assert "read_file" in snapshots
        assert snapshots["read_file"]["description_hash"] == "hash_v1"

        # Create tool with changed hash
        tool = ToolInfo(
            name="read_file",
            description="Changed desc",
            description_hash="hash_v2",
            input_schema=schema,
        )
        detector = RugPullDetector(snapshots)
        findings = detector.scan_tool(tool)

        assert len(findings) >= 1
        assert any("DESC" in f.finding_id for f in findings)

        db.close()

    def test_latest_snapshot_used(self, tmp_path: Path):
        """When multiple snapshots exist, only the latest is used."""
        db = AuditDB(tmp_path / "test.db")
        db.open()

        db.save_tool_snapshot("tool", "hash_v1", {}, [])
        db.save_tool_snapshot("tool", "hash_v2", {}, [])

        snapshots = db.get_latest_snapshots()
        assert snapshots["tool"]["description_hash"] == "hash_v2"

        db.close()

    def test_empty_db(self, tmp_path: Path):
        db = AuditDB(tmp_path / "test.db")
        db.open()

        snapshots = db.get_latest_snapshots()
        assert snapshots == {}

        db.close()
