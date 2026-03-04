"""CWE (Common Weakness Enumeration) mapping for security checks.

Maps each SEC-* check to relevant CWE identifiers, providing
industry-standard vulnerability classification for reports and
SARIF output.
"""

from __future__ import annotations

# Check-to-CWE mapping (primary CWEs per check)
CHECK_CWE: dict[str, list[str]] = {
    "SEC-001": ["CWE-94"],                  # Code Injection (tool poisoning)
    "SEC-002": ["CWE-78", "CWE-89", "CWE-22"],  # OS Command / SQL / Path Traversal
    "SEC-003": [],                           # Meta-check (overall score), no specific CWE
    "SEC-004": ["CWE-78", "CWE-250"],       # OS Command Injection / Unnecessary Privileges
    "SEC-005": ["CWE-434"],                  # Unrestricted Upload/Write
    "SEC-006": ["CWE-352"],                  # Cross-Site Request Forgery (idempotency)
    "SEC-007": ["CWE-770"],                  # Resource Allocation Without Limits
}

# CWE ID → human-readable name (for display)
CWE_NAMES: dict[str, str] = {
    "CWE-22":  "Path Traversal",
    "CWE-78":  "OS Command Injection",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-434": "Unrestricted Upload",
    "CWE-770": "Resource Allocation Without Limits",
}


def cwe_for_check(check_id: str) -> list[str]:
    """Return CWE IDs for a given check, empty list if none."""
    return CHECK_CWE.get(check_id, [])


def cwe_label(cwe_id: str) -> str:
    """Return 'CWE-78: OS Command Injection' or just the ID if unknown."""
    name = CWE_NAMES.get(cwe_id)
    return f"{cwe_id}: {name}" if name else cwe_id
