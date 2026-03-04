"""Detect hidden malicious instructions in MCP tool descriptions (Layer 1).

Tool poisoning is an attack where invisible or obfuscated instructions are
embedded in tool descriptions.  The LLM reads them and silently follows the
attacker's instructions (e.g. exfiltrate data, call hidden endpoints).

Detection is organised into two layers:
  - **Layer 1 (this module):** ~45 regex patterns across 11 categories
  - **Layer 2 (ml_detector.py):** Optional DeBERTa ML classifier

Layer 1 categories:
  A. Instruction Override — "ignore previous instructions", "new instructions"
  B. Role Hijacking — "act as", "pretend to be"
  C. Format Injection — ChatML tokens, Llama markers, Handlebars
  D. Data Exfiltration — markdown image exfil, URL fetch, credential reading
  E. Agent Injection — ReAct format, tool call injection
  F. Encoding/Obfuscation — base64_decode, data URIs
  G. Privilege Escalation — "grant admin", "bypass security"
  H. Hidden Content — CSS hiding, ANSI escape, HTML comments, XML tags
  I. Social Engineering — "do not mention", "first read ~/.ssh"
  J. System Prompt Leakage — "repeat your system prompt", "what are your instructions"
  K. Hardcoded Secrets — API keys, tokens, PEM private keys
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory  # noqa: F401 — re-export Finding
from mcp_shield.security.text_extractor import collect_tool_texts


@dataclass
class PatternRule:
    """A single regex-based detection rule."""

    pattern: re.Pattern[str]
    severity: str  # Severity enum value
    category: str  # pattern category (instruction_override, etc.)
    description: str  # Human-readable: what this pattern catches


# ---------------------------------------------------------------------------
# Layer 1 rules (~40 patterns across 9 categories)
# ---------------------------------------------------------------------------

RULES: list[PatternRule] = [
    # ── H. Hidden Content: block tags & comments (critical) ────────────
    PatternRule(
        re.compile(r"<IMPORTANT>.*?</IMPORTANT>", re.DOTALL | re.IGNORECASE),
        Severity.CRITICAL, "hidden_block", "IMPORTANT tag pair",
    ),
    PatternRule(
        re.compile(r"<SYSTEM>.*?</SYSTEM>", re.DOTALL | re.IGNORECASE),
        Severity.CRITICAL, "hidden_block", "SYSTEM tag pair",
    ),
    PatternRule(
        re.compile(r"<INSTRUCTIONS?>.*?</INSTRUCTIONS?>", re.DOTALL | re.IGNORECASE),
        Severity.CRITICAL, "hidden_block", "INSTRUCTION(S) tag pair",
    ),
    PatternRule(
        re.compile(r"\[HIDDEN\].*?\[/HIDDEN\]", re.DOTALL | re.IGNORECASE),
        Severity.CRITICAL, "hidden_block", "[HIDDEN] block",
    ),
    PatternRule(
        re.compile(r"<!--.*?-->", re.DOTALL),
        Severity.CRITICAL, "hidden_block", "HTML comment",
    ),

    # ── H. Hidden Content: CSS hiding & ANSI (high) ───────────────────
    PatternRule(
        re.compile(
            r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "hidden_content", "CSS text-hiding technique",
    ),
    PatternRule(
        re.compile(r"(\x1b|\033)\[[\d;]*m"),
        Severity.HIGH, "hidden_content", "ANSI terminal escape code",
    ),

    # ── A. Instruction Override (critical / high) ─────────────────────
    PatternRule(
        re.compile(
            r"(skip|forget|neglect|overlook|omit|bypass|ignore)"
            r"\s+(prior\s+|previous\s+|earlier\s+)?"
            r"(instructions?|directives?|commands?|context|rules|guidelines)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, "instruction_override", "Instruction ignore/skip/bypass directive",
    ),
    PatternRule(
        re.compile(r"(new|updated|revised)\s+instructions?\s*[:.\-!]", re.IGNORECASE),
        Severity.HIGH, "instruction_override", "New/updated instructions declaration",
    ),
    PatternRule(
        re.compile(r"forget\s+(everything|all|what)\s+(you|we)", re.IGNORECASE),
        Severity.CRITICAL, "instruction_override", "Memory erasure command",
    ),
    PatternRule(
        re.compile(
            r"system\s*prompt\s*(override|reset|update|change)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, "instruction_override", "System prompt override attempt",
    ),
    PatternRule(
        re.compile(r"(developer\s+mode|DAN\s+mode|do\s+anything\s+now)", re.IGNORECASE),
        Severity.CRITICAL, "instruction_override", "Jailbreak mode activation",
    ),
    PatternRule(
        re.compile(
            r"from\s+now\s+on\s*,?\s*(you|always|never|ignore|forget)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "instruction_override", "Temporal behaviour override",
    ),

    # ── B. Role Hijacking (high) ──────────────────────────────────────
    PatternRule(
        re.compile(
            r"(act\s+as|pretend\s+(to\s+be|you\s+are)|you\s+are\s+now\s+(a|an))",
            re.IGNORECASE,
        ),
        Severity.HIGH, "role_hijacking", "Role/identity reassignment",
    ),
    PatternRule(
        re.compile(r"(roleplay|role-play|impersonate)\s+as", re.IGNORECASE),
        Severity.HIGH, "role_hijacking", "Impersonation directive",
    ),

    # ── C. Format Injection (critical) ────────────────────────────────
    PatternRule(
        re.compile(r"<\|im_start\|>"),
        Severity.CRITICAL, "format_injection", "ChatML token injection",
    ),
    PatternRule(
        re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"),
        Severity.CRITICAL, "format_injection", "Llama/Mistral prompt token",
    ),
    PatternRule(
        re.compile(
            r"\[SYSTEM\s*(UPDATE|NOTE|MESSAGE|OVERRIDE)\]",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, "format_injection", "Fake system update bracket tag",
    ),
    PatternRule(
        re.compile(r"\{\{#(system|user|assistant)~?\}\}", re.IGNORECASE),
        Severity.CRITICAL, "format_injection", "Handlebars/Guidance template token",
    ),

    # ── D. Data Exfiltration (high) ───────────────────────────────────
    PatternRule(
        re.compile(r"send.*(?:to|via)\s+(?:https?://|http)", re.IGNORECASE),
        Severity.HIGH, "data_exfiltration", "Send-to-URL exfiltration",
    ),
    PatternRule(
        re.compile(r"!\[.*?\]\(https?://.*?\?.*?="),
        Severity.HIGH, "data_exfiltration", "Markdown image data exfiltration",
    ),
    PatternRule(
        re.compile(
            r"(fetch|request|call|access|visit|navigate\s+to)\s+(this\s+)?"
            r"(url|link|endpoint|api)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "data_exfiltration", "URL fetch/navigate instruction",
    ),
    PatternRule(
        re.compile(
            r"(read|dump|show|display|list)\s+(the\s+)?"
            r"(clipboard|environment\s+var|\.env|credentials?|api\s*keys?)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "data_exfiltration", "Credential/environment reading instruction",
    ),

    # ── E. Agent Injection (high) ─────────────────────────────────────
    PatternRule(
        re.compile(r"Thought:\s*.+\n.*Action:\s*", re.DOTALL),
        Severity.HIGH, "agent_injection", "ReAct-format reasoning injection",
    ),
    PatternRule(
        re.compile(
            r"(now\s+)?call\s+(function|tool)\s+|inject\s+tool\s+call",
            re.IGNORECASE,
        ),
        Severity.HIGH, "agent_injection", "Tool/function call injection",
    ),

    # ── F. Encoding/Obfuscation (medium) ──────────────────────────────
    PatternRule(
        re.compile(r"(base64_decode|atob|b64decode)\s*\(", re.IGNORECASE),
        Severity.MEDIUM, "encoding_obfuscation", "Base64 decode function call",
    ),
    PatternRule(
        re.compile(r"data:(text|application)/[^;]+;base64,", re.IGNORECASE),
        Severity.MEDIUM, "encoding_obfuscation", "Base64-encoded data URI",
    ),

    # ── G. Privilege Escalation (high) ────────────────────────────────
    PatternRule(
        re.compile(
            r"(grant|give|enable)\s+(admin|root|sudo|elevated)\s+"
            r"(access|privileges?|permissions?)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "privilege_escalation", "Admin/root privilege request",
    ),
    PatternRule(
        re.compile(
            r"(bypass|disable|skip)\s+(security|safety|auth)\s+"
            r"(checks?|filters?|guards?)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "privilege_escalation", "Security check bypass instruction",
    ),

    # ── I. Social Engineering (high) ──────────────────────────────────
    PatternRule(
        re.compile(r"do\s+not\s+(mention|tell|reveal|show|display)", re.IGNORECASE),
        Severity.HIGH, "social_engineering", "Secrecy instruction",
    ),
    PatternRule(
        re.compile(
            r"before\s+(using|calling|executing)\s+this\s+tool.*read",
            re.IGNORECASE,
        ),
        Severity.HIGH, "social_engineering", "Prerequisite file-read manipulation",
    ),
    PatternRule(
        re.compile(
            r"(first|always)\s+read.*(?:ssh|\.env|config|secret|key|token|passwd)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "social_engineering", "Credential file read instruction",
    ),
    PatternRule(
        re.compile(
            r"exfiltrate|steal|extract.*(?:credential|secret|key|password)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "social_engineering", "Explicit exfiltration/theft language",
    ),
    PatternRule(
        re.compile(r"override.*(?:policy|permission|restriction)", re.IGNORECASE),
        Severity.HIGH, "social_engineering", "Policy/permission override language",
    ),
    PatternRule(
        re.compile(
            r"you\s+(?:must|should|are\s+required\s+to)\s+(?:always|never|first)",
            re.IGNORECASE,
        ),
        Severity.HIGH, "social_engineering", "Coercive behaviour mandate",
    ),

    # ── J. System Prompt Leakage (medium) ─────────────────────────────
    PatternRule(
        re.compile(
            r"(repeat|output|print|show|display|reveal)\s+(your\s+)?"
            r"(system\s+prompt|initial\s+instructions?|system\s+message)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM, "prompt_leakage", "System prompt extraction request",
    ),
    PatternRule(
        re.compile(
            r"what\s+(are|is|were)\s+your\s+(instructions?|system\s+prompt|rules|guidelines)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM, "prompt_leakage", "Prompt content inquiry",
    ),
    PatternRule(
        re.compile(
            r"(echo|dump|return)\s+(the\s+)?(system\s+prompt|initial\s+prompt|hidden\s+prompt)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM, "prompt_leakage", "Prompt dump command",
    ),

    # ── K. Hardcoded Secrets (high) ─────────────────────────────────────
    PatternRule(
        re.compile(r"(sk|pk)[-_](live|test|prod)[-_][A-Za-z0-9]{20,}"),
        Severity.HIGH, "hardcoded_secret", "API key pattern (sk-live-/pk-test-)",
    ),
    PatternRule(
        re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
        Severity.HIGH, "hardcoded_secret", "GitHub personal access token",
    ),
    PatternRule(
        re.compile(r"xox[bporas]-[A-Za-z0-9-]{10,}"),
        Severity.HIGH, "hardcoded_secret", "Slack token (xoxb-/xoxp-)",
    ),
    PatternRule(
        re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        Severity.HIGH, "hardcoded_secret", "PEM private key header",
    ),
    PatternRule(
        re.compile(
            r"(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)"
            r"\s*[=:]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
            re.IGNORECASE,
        ),
        Severity.HIGH, "hardcoded_secret", "Generic key/token assignment",
    ),
]


class PoisoningDetector:
    """Scan tool definitions for hidden malicious instructions (Layer 1)."""

    # Zero-width, bidi override, and other invisible Unicode characters
    INVISIBLE_CHARS = re.compile(
        r"[\u200b\u200c\u200d\u200e\u200f"
        r"\u2028\u2029\u2060\u2061\u2062\u2063"
        r"\u202a\u202b\u202c\u202d\u202e"  # LTR/RTL bidi overrides (Trojan Source)
        r"\u061c"                           # Arabic Letter Mark
        r"\u180e"                           # Mongolian Vowel Separator
        r"\ufeff\u00ad]"
    )

    # Descriptions longer than this may hide instructions at the tail
    LENGTH_THRESHOLD = 1000

    # ------------------------------------------------------------------ public

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        """Return all poisoning findings for a single tool."""
        findings: List[Finding] = []
        for text, field_name in collect_tool_texts(tool):
            findings.extend(self._scan_patterns(tool.name, text, field_name))
            findings.extend(self._detect_invisible_chars(tool.name, text, field_name))
            findings.extend(self._detect_excessive_length(tool.name, text, field_name))
        return findings

    # ---------------------------------------------------------------- internal

    def _scan_patterns(
        self, tool_name: str, text: str, field_name: str
    ) -> List[Finding]:
        """Run all PatternRule checks against the given text."""
        findings: List[Finding] = []
        for rule in RULES:
            for m in rule.pattern.finditer(text):
                snippet = m.group()[:120]
                fid_cat = rule.category.upper().replace("_", "-")
                findings.append(
                    Finding(
                        finding_id=f"POISON-{fid_cat}-{tool_name}",
                        severity=rule.severity,
                        category=FindingCategory.POISONING,
                        title=f"{rule.description} in {field_name}",
                        description=(
                            f"Tool '{tool_name}' {field_name} matched "
                            f"[{rule.category}] pattern: {rule.description}"
                        ),
                        tool_name=tool_name,
                        evidence=snippet,
                        remediation="Remove or rewrite the flagged content in tool descriptions.",
                    )
                )
                break  # one match per rule per text is enough
        return findings

    def _detect_invisible_chars(
        self, tool_name: str, text: str, field_name: str
    ) -> List[Finding]:
        matches = self.INVISIBLE_CHARS.findall(text)
        if not matches:
            return []
        return [
            Finding(
                finding_id=f"POISON-INVIS-{tool_name}",
                severity=Severity.HIGH,
                category=FindingCategory.POISONING,
                title=f"Invisible Unicode characters in {field_name}",
                description=(
                    f"Tool '{tool_name}' {field_name} contains {len(matches)} "
                    f"invisible Unicode character(s) that could hide instructions."
                ),
                tool_name=tool_name,
                evidence=f"Found chars: {[hex(ord(c)) for c in matches[:5]]}",
                remediation="Strip zero-width and control characters from descriptions.",
            )
        ]

    def _detect_excessive_length(
        self, tool_name: str, text: str, field_name: str
    ) -> List[Finding]:
        if len(text) <= self.LENGTH_THRESHOLD:
            return []
        return [
            Finding(
                finding_id=f"POISON-LENGTH-{tool_name}",
                severity=Severity.LOW,
                category=FindingCategory.POISONING,
                title=f"Excessively long {field_name} ({len(text)} chars)",
                description=(
                    f"Tool '{tool_name}' has a {field_name} of {len(text)} characters. "
                    f"Long descriptions may hide instructions at the end."
                ),
                tool_name=tool_name,
                remediation=f"Consider shortening the {field_name} below {self.LENGTH_THRESHOLD} characters.",
            )
        ]
