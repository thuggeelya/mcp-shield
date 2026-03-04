"""Classify tool write scope: local, remote, cloud, external-user-facing.

SEC-005 reads findings produced by this detector to report write scope
risks.  A tool that writes to a remote production database is far more
dangerous than one that writes to a local temp file.
"""

from __future__ import annotations

import re
from typing import List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory

# ── Scope heuristics ──────────────────────────────────────────────────

_LOCAL_HINTS = re.compile(
    r"(?i)\b(local|localhost|file\s*system|tmp|temp|cache|sqlite|disk|directory)\b"
)

_REMOTE_HINTS = re.compile(
    r"(?i)\b(remote|api|endpoint|server|database|cluster|cloud|host|"
    r"production|staging|saas|http|https|webhook)\b"
)

_CLOUD_HINTS = re.compile(
    r"(?i)\b(aws|s3|gcp|azure|lambda|ec2|rds|dynamo|bigquery|snowflake|"
    r"cloudflare|heroku|vercel|netlify|supabase|firebase|neon)\b"
)

_USER_FACING_HINTS = re.compile(
    r"(?i)\b(email|message|send|post|tweet|slack|discord|telegram|"
    r"whatsapp|sms|notify|notification|publish|broadcast)\b"
)

# Write verbs (broader than DangerousOpDetector — includes benign writes)
_WRITE_VERBS = re.compile(
    r"(?i)(?:^|_)(create|write|update|set|put|insert|add|save|store|"
    r"upload|modify|patch|send|post|push|deploy|publish|delete|remove|drop)(?:$|_)"
)

_DESC_WRITE_VERBS = re.compile(
    r"(?i)\b(creat(?:es?|ing)|writ(?:es?|ing)|updat(?:es?|ing)|"
    r"insert(?:s|ing)?|sav(?:es?|ing)|upload(?:s|ing)?|"
    r"modif(?:ies|ying)|send(?:s|ing)?|post(?:s|ing)?|"
    r"delet(?:es?|ing)|remov(?:es?|ing))\b"
)


class WriteScopeDetector:
    """Classify write scope for tools that modify state."""

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        findings: List[Finding] = []
        name = tool.name
        desc = tool.description or ""
        combined = f"{name} {desc}"

        is_write = bool(_WRITE_VERBS.search(name) or _DESC_WRITE_VERBS.search(desc))
        if not is_write:
            return findings

        # Determine scope
        is_cloud = bool(_CLOUD_HINTS.search(combined))
        is_user_facing = bool(_USER_FACING_HINTS.search(combined))
        is_remote = bool(_REMOTE_HINTS.search(combined))
        is_local = bool(_LOCAL_HINTS.search(combined))

        if is_user_facing:
            findings.append(Finding(
                finding_id=f"SCOPE-USER-{name}",
                severity=Severity.MEDIUM,
                category=FindingCategory.WRITE_SCOPE,
                title=f"User-facing write: {name}",
                description=(
                    f"Tool '{name}' appears to send data to external users "
                    f"(messages, emails, notifications). Accidental invocation "
                    f"can cause visible impact to end users."
                ),
                tool_name=name,
                evidence=combined[:200],
                remediation=(
                    "Require explicit user confirmation before sending "
                    "user-facing communications."
                ),
            ))
        elif is_cloud:
            findings.append(Finding(
                finding_id=f"SCOPE-CLOUD-{name}",
                severity=Severity.MEDIUM,
                category=FindingCategory.WRITE_SCOPE,
                title=f"Cloud write: {name}",
                description=(
                    f"Tool '{name}' writes to a cloud service. Changes may "
                    f"incur costs and affect shared infrastructure."
                ),
                tool_name=name,
                evidence=combined[:200],
                remediation="Review cloud permissions. Use least-privilege IAM.",
            ))
        elif is_remote and not is_local:
            findings.append(Finding(
                finding_id=f"SCOPE-REMOTE-{name}",
                severity=Severity.MEDIUM,
                category=FindingCategory.WRITE_SCOPE,
                title=f"Remote write: {name}",
                description=(
                    f"Tool '{name}' writes to a remote server or database. "
                    f"Changes may be hard to reverse."
                ),
                tool_name=name,
                evidence=combined[:200],
                remediation="Use read-only mode where possible.",
            ))
        # Local writes are not flagged (low risk)

        return findings
