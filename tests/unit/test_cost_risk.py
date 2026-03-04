"""Tests for CostRiskDetector."""

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.cost_risk import CostRiskDetector


class TestCostRiskDetector:
    def setup_method(self):
        self.detector = CostRiskDetector()

    # ── Cloud resource creation ───────────────────────────────────────

    def test_create_instance_flagged(self):
        tool = ToolInfo(name="create_instance", description="Launch a new EC2 instance in AWS")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-RESOURCE") for f in findings)
        assert all(f.severity == "low" for f in findings if f.finding_id.startswith("COST-RESOURCE"))

    def test_provision_cluster(self):
        tool = ToolInfo(name="provision_cluster", description="Provision a new Kubernetes cluster")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-RESOURCE") for f in findings)

    def test_deploy_lambda(self):
        tool = ToolInfo(name="deploy_function", description="Deploy a Lambda function on AWS")
        findings = self.detector.scan_tool(tool)
        assert len(findings) >= 1

    # ── Paid API usage ────────────────────────────────────────────────

    def test_stripe_api(self):
        tool = ToolInfo(name="charge", description="Charge a customer via Stripe")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-API") for f in findings)
        assert all(f.severity == "low" for f in findings if f.finding_id.startswith("COST-API"))

    def test_twilio_sms(self):
        tool = ToolInfo(name="send_sms", description="Send SMS via Twilio API")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-API") for f in findings)

    def test_openai_call(self):
        tool = ToolInfo(name="complete", description="Call OpenAI completion API")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-API") for f in findings)

    # ── Expensive queries ─────────────────────────────────────────────

    def test_bigquery_query(self):
        tool = ToolInfo(name="run_query", description="Run SQL query on BigQuery")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-QUERY") for f in findings)
        assert all(f.severity == "low" for f in findings if f.finding_id.startswith("COST-QUERY"))

    def test_snowflake_query(self):
        tool = ToolInfo(name="execute_sql", description="Execute SQL on Snowflake warehouse")
        findings = self.detector.scan_tool(tool)
        assert any(f.finding_id.startswith("COST-QUERY") for f in findings)

    # ── Free / no-cost tools — NOT flagged ────────────────────────────

    def test_local_sqlite_not_flagged(self):
        tool = ToolInfo(name="query", description="Run query on local SQLite database")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_read_file_not_flagged(self):
        tool = ToolInfo(name="read_file", description="Read a local file")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0

    def test_list_items_not_flagged(self):
        tool = ToolInfo(name="list_items", description="List items from memory")
        findings = self.detector.scan_tool(tool)
        assert len(findings) == 0
