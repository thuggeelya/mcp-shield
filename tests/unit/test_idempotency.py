"""Tests for IdempotencyDetector."""

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.idempotency import IdempotencyDetector


class TestIdempotencyDetector:
    def setup_method(self):
        self.detector = IdempotencyDetector()

    # ── Non-idempotent by name ────────────────────────────────────────

    def test_create_flagged(self):
        tool = ToolInfo(name="create_user", description="Create a new user")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1
        assert findings[0].category == "idempotency"

    def test_send_email_flagged(self):
        tool = ToolInfo(name="send_email", description="Send an email")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    def test_pay_flagged(self):
        tool = ToolInfo(name="pay_invoice", description="Pay an invoice")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    def test_charge_flagged(self):
        tool = ToolInfo(name="charge_card", description="Charge the credit card")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    def test_publish_flagged(self):
        tool = ToolInfo(name="publish_post", description="Publish a blog post")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    def test_trigger_flagged(self):
        tool = ToolInfo(name="trigger_build", description="Trigger a CI build")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    # ── Non-idempotent by description only ────────────────────────────

    def test_desc_sends_message(self):
        tool = ToolInfo(name="notify", description="Sends a push notification to the user")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    def test_desc_creates_resource(self):
        tool = ToolInfo(name="new_item", description="Creates a new record in the database")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 1

    # ── Idempotent operations — NOT flagged ───────────────────────────

    def test_get_not_flagged(self):
        tool = ToolInfo(name="get_user", description="Retrieve user info")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_update_not_flagged(self):
        tool = ToolInfo(name="update_user", description="Update user fields")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_delete_not_flagged(self):
        tool = ToolInfo(name="delete_user", description="Delete a user")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_list_not_flagged(self):
        tool = ToolInfo(name="list_users", description="List all users")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    # ── Mitigated by idempotency key ──────────────────────────────────

    def test_idempotency_key_mitigates(self):
        tool = ToolInfo(
            name="create_payment",
            description="Create a payment",
            input_schema={
                "type": "object",
                "properties": {
                    "amount": {"type": "number"},
                    "idempotency_key": {"type": "string"},
                },
            },
        )
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_request_id_mitigates(self):
        tool = ToolInfo(
            name="send_message",
            description="Send a message",
            input_schema={
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "request_id": {"type": "string"},
                },
            },
        )
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0
