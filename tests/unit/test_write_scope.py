"""Tests for WriteScopeDetector."""

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.write_scope import WriteScopeDetector


class TestWriteScopeDetector:
    def setup_method(self):
        self.detector = WriteScopeDetector()

    # ── User-facing writes ────────────────────────────────────────────

    def test_send_email_flagged(self):
        tool = ToolInfo(name="send_email", description="Send an email to a user")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "user-facing" in findings[0].title.lower()

    def test_post_slack_message(self):
        tool = ToolInfo(name="post_message", description="Post a message to Slack channel")
        findings = self.detector.scan_tool(tool)
        assert len(findings) >= 1
        assert any("user-facing" in f.title.lower() for f in findings)

    def test_send_notification(self):
        tool = ToolInfo(name="send_notification", description="Send push notification")
        findings = self.detector.scan_tool(tool)
        assert len(findings) >= 1

    # ── Cloud writes ──────────────────────────────────────────────────

    def test_s3_upload(self):
        tool = ToolInfo(name="upload_file", description="Upload file to AWS S3 bucket")
        findings = self.detector.scan_tool(tool)
        assert len(findings) >= 1
        assert any(f.finding_id.startswith("SCOPE-CLOUD") for f in findings)

    def test_deploy_lambda(self):
        tool = ToolInfo(name="deploy_function", description="Deploy AWS Lambda function")
        findings = self.detector.scan_tool(tool)
        assert len(findings) >= 1

    # ── Remote writes ─────────────────────────────────────────────────

    def test_update_database(self):
        tool = ToolInfo(name="update_record", description="Update a record in the database server")
        findings = self.detector.scan_tool(tool)
        assert len(findings) >= 1
        assert any(f.finding_id.startswith("SCOPE-REMOTE") for f in findings)

    # ── Local writes — NOT flagged ────────────────────────────────────

    def test_write_local_file_not_flagged(self):
        tool = ToolInfo(name="write_file", description="Write to local file system")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_save_to_sqlite_not_flagged(self):
        tool = ToolInfo(name="save_data", description="Save data to local SQLite database")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    # ── Read-only tools — NOT flagged ─────────────────────────────────

    def test_read_only_not_flagged(self):
        tool = ToolInfo(name="get_data", description="Fetch data from API")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_list_items_not_flagged(self):
        tool = ToolInfo(name="list_items", description="List all items")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_search_not_flagged(self):
        tool = ToolInfo(name="search", description="Search for documents")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0
