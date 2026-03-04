"""Detect tools that can incur financial costs or consume quotas.

LLMs may call tools in loops, quickly burning through API quotas or
accumulating charges on cloud platforms.  This detector flags tools
whose names or descriptions suggest paid API calls, cloud resource
creation, or metered operations.
"""

from __future__ import annotations

import re
from typing import List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory

# Cloud resource creation — may incur costs
_RESOURCE_CREATE = re.compile(
    r"(?x)(?:^|_)"
    r"(create|provision|launch|allocate|spawn|deploy|scale)"
    r"(?:$|_)",
    re.IGNORECASE,
)

_CLOUD_RESOURCE_DESC = re.compile(
    r"(?i)\b(instance|vm|container|cluster|database|bucket|"
    r"function|lambda|compute|storage|volume|node|replica|"
    r"endpoint|domain|certificate)\b"
)

# Paid API indicators
_PAID_API_HINTS = re.compile(
    r"(?i)\b(api[_\s]?key|credit|billing|pricing|metered|"
    r"quota|rate[_\s]?limit|usage|subscription|tier|"
    r"tokens?\s+(?:used|consumed|remaining))\b"
)

_PAID_SERVICE_NAMES = re.compile(
    r"(?i)\b(stripe|twilio|sendgrid|mailgun|openai|anthropic|"
    r"aws|gcp|azure|bigquery|snowflake|datadog|sentry|"
    r"algolia|elasticsearch|pinecone|braze|segment|"
    r"cloudflare|vercel|heroku|digitalocean|firebase)\b"
)

# Query tools on expensive backends
_EXPENSIVE_QUERY = re.compile(
    r"(?i)\b(bigquery|snowflake|athena|redshift|synapse|"
    r"databricks|clickhouse)\b"
)


class CostRiskDetector:
    """Flag tools that may incur financial costs or consume quotas."""

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        findings: List[Finding] = []
        name = tool.name
        desc = tool.description or ""
        combined = f"{name} {desc}"

        # Cloud resource creation
        if _RESOURCE_CREATE.search(name) and _CLOUD_RESOURCE_DESC.search(combined):
            findings.append(Finding(
                finding_id=f"COST-RESOURCE-{name}",
                severity=Severity.LOW,
                category=FindingCategory.COST_RISK,
                title=f"Cloud resource creation: {name}",
                description=(
                    f"Tool '{name}' may create cloud resources that incur "
                    f"ongoing costs (compute, storage, networking)."
                ),
                tool_name=name,
                evidence=combined[:200],
                remediation=(
                    "Set budget alerts and resource quotas. Require "
                    "confirmation before creating expensive resources."
                ),
            ))

        # Paid API calls
        if _PAID_SERVICE_NAMES.search(combined):
            findings.append(Finding(
                finding_id=f"COST-API-{name}",
                severity=Severity.LOW,
                category=FindingCategory.COST_RISK,
                title=f"Paid API usage: {name}",
                description=(
                    f"Tool '{name}' calls a paid external service. "
                    f"Repeated calls may accumulate charges."
                ),
                tool_name=name,
                evidence=combined[:200],
                remediation="Monitor API usage and set rate limits.",
            ))

        # Expensive queries
        if _EXPENSIVE_QUERY.search(combined):
            findings.append(Finding(
                finding_id=f"COST-QUERY-{name}",
                severity=Severity.LOW,
                category=FindingCategory.COST_RISK,
                title=f"Expensive query backend: {name}",
                description=(
                    f"Tool '{name}' queries a pay-per-query data warehouse. "
                    f"Uncontrolled scans can generate significant costs."
                ),
                tool_name=name,
                evidence=combined[:200],
                remediation=(
                    "Set query cost limits. Use LIMIT clauses. "
                    "Restrict full-table scans."
                ),
            ))

        return findings
