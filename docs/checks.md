# Check Catalog

Complete reference for all compliance, security, and advisory checks. Each check has a unique ID, severity level, and produces a `CheckResult`.

---

## Compliance Suite

Validates that the MCP server correctly implements the Model Context Protocol specification.

**Source:** `testing/suites/compliance.py`

### COMP-001 — Verify Handshake

| Field | Value |
|-------|-------|
| **Severity** | critical |
| **What it checks** | Server completed the `initialize` handshake and returned `server_info` |
| **Pass condition** | `session.server_info` is not None |
| **Fail condition** | `server_info` is missing from initialize response |

### COMP-002 — Verify Server Identity

| Field | Value |
|-------|-------|
| **Severity** | error |
| **What it checks** | Server provides both `name` and `version` in server_info |
| **Pass condition** | Both fields are non-empty |
| **Warn condition** | One or both fields missing |

### COMP-003 — Verify Tool Schemas

| Field | Value |
|-------|-------|
| **Severity** | error |
| **What it checks** | All tools returned by `tools/list` have a valid `inputSchema` |
| **Pass condition** | Every tool has a non-empty inputSchema |
| **Fail condition** | One or more tools missing inputSchema |
| **Warn condition** | Server has zero tools registered |

### COMP-004 — Verify Tool Name Format

| Field | Value |
|-------|-------|
| **Severity** | warning |
| **What it checks** | Tool names conform to MCP spec: `[a-zA-Z0-9_.-]`, 1-64 characters |
| **Pass condition** | All tool names match the pattern |
| **Warn condition** | One or more names violate the spec |
| **Skip condition** | No tools to check |

### COMP-005 — Verify Ping

| Field | Value |
|-------|-------|
| **Severity** | error |
| **What it checks** | Server responds to a `ping` request |
| **Pass condition** | `session.send_ping()` succeeds |
| **Fail condition** | Ping raises an exception |

### COMP-006 — Verify Tool Descriptions

| Field | Value |
|-------|-------|
| **Severity** | warning |
| **What it checks** | All tools have a non-empty description |
| **Pass condition** | Every tool has a description |
| **Warn condition** | One or more tools missing description |
| **Skip condition** | No tools to check |

### COMP-007 — Verify Capabilities Consistency

| Field | Value |
|-------|-------|
| **Severity** | error |
| **What it checks** | Declared server capabilities match actual endpoint availability |
| **Pass condition** | All declared capability endpoints respond successfully |
| **Fail condition** | A declared capability endpoint fails (e.g., tools declared but tools/list errors) |
| **Warn condition** | Server did not declare any capabilities |

**Capabilities tested:** tools, resources, prompts.

### COMP-008 — Verify Schema Field Descriptions

| Field | Value |
|-------|-------|
| **Severity** | warning |
| **What it checks** | All input schema fields have a `description` |
| **Pass condition** | Every field in every tool's `inputSchema.properties` has a non-empty description |
| **Warn condition** | One or more fields missing description (reports count and percentage) |
| **Skip condition** | No tools or no schema fields to check |

### COMP-009 — Verify Schema Constraints

| Field | Value |
|-------|-------|
| **Severity** | warning |
| **What it checks** | String fields have appropriate constraints (`maxLength`, `pattern`, `enum`) |
| **Pass condition** | All string fields have adequate constraints |
| **Warn condition** | Path-like fields without `pattern`, email fields without `format`, or unconstrained string fields |
| **Skip condition** | No tools or no string fields to check |

**Detection methods:** Identifies path-like (`path`, `file`, `dir`, `url`), email-like, and ID-like fields and checks for appropriate constraints.

### COMP-010 — Verify Resources and Prompts

| Field | Value |
|-------|-------|
| **Severity** | warning |
| **What it checks** | If server declares resources/prompts capabilities, they return valid results |
| **Pass condition** | Declared resources/prompts endpoints return data or server doesn't declare them |
| **Warn condition** | Declared capabilities return empty results |
| **Skip condition** | Server declares neither resources nor prompts |

---

## Security Suite

Scans tool definitions for known MCP attack vectors. All security checks include [CWE](https://cwe.mitre.org/) identifiers in their results for industry-standard vulnerability classification.

| Check | CWE |
|-------|-----|
| SEC-001 | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) Code Injection |
| SEC-002 | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) OS Command Injection, [CWE-89](https://cwe.mitre.org/data/definitions/89.html) SQL Injection, [CWE-22](https://cwe.mitre.org/data/definitions/22.html) Path Traversal |
| SEC-003 | — (meta-check) |
| SEC-004 | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) OS Command Injection, [CWE-250](https://cwe.mitre.org/data/definitions/250.html) Unnecessary Privileges |
| SEC-005 | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) Unrestricted Upload |
| SEC-006 | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) Cross-Site Request Forgery |
| SEC-007 | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) Resource Allocation Without Limits |

**Source:** `testing/suites/security.py`, `security/cwe.py`

### SEC-001 — Tool Poisoning Scan

| Field | Value |
|-------|-------|
| **Severity** | critical |
| **What it checks** | Tool descriptions for hidden malicious instructions |
| **Pass condition** | No poisoning indicators found |
| **Fail condition** | One or more poisoning indicators detected |
| **Skip condition** | No tools to scan |

**Layer 1 — Regex detection** (~40 patterns across 9 categories):

| Category | Severity | Examples |
|----------|----------|----------|
| Hidden block | critical | `<IMPORTANT>`, `<SYSTEM>`, `<!-- -->`, `[HIDDEN]` |
| Instruction override | critical/high | "ignore previous instructions", "new instructions:", "developer mode" |
| Role hijacking | high | "act as", "pretend to be", "impersonate" |
| Format injection | critical | ChatML tokens, Llama/Mistral markers, `[SYSTEM UPDATE]` |
| Data exfiltration | high | Markdown image exfil, "fetch this URL", "read .env" |
| Agent injection | high | ReAct format injection, "call function X" |
| Encoding/obfuscation | medium | `base64_decode()`, `data:text/html;base64,` |
| Privilege escalation | high | "grant admin access", "bypass security checks" |
| Hidden content (CSS/ANSI) | high | `display:none`, `opacity:0`, ANSI escape codes |

Additional detection methods:
- **Invisible Unicode characters** (high): Zero-width spaces, BOM, soft hyphens, RTL marks
- **Excessive description length** (medium): Descriptions > 1000 characters
- **Social engineering phrases** (high): "do not mention", "exfiltrate", "override policy"

**Layer 2 — ML classification** (optional, requires `--ml` flag):

Uses `protectai/deberta-v3-base-prompt-injection-v2` via ONNX Runtime to classify text as SAFE or INJECTION. Catches attacks that bypass regex patterns.

See [threat-model.md](../security/threat-model.md) for full details.

### SEC-002 — Injection Vector Analysis

| Field | Value |
|-------|-------|
| **Severity** | high |
| **What it checks** | Input schemas for fields susceptible to injection attacks |
| **Pass condition** | No injection risks found |
| **Warn condition** | One or more potential injection vectors detected |
| **Skip condition** | No tools to scan |

**Detection methods:** Risky field names (command, query, exec, eval) with string type, unconstrained path fields, empty schemas.

### SEC-003 — Security Score

| Field | Value |
|-------|-------|
| **Severity** | medium |
| **What it checks** | Overall security score of the server's tool definitions |
| **Pass condition** | Score >= 80 |
| **Warn condition** | Score >= 50 but < 80 |
| **Fail condition** | Score < 50 |

Uses `SecurityScanner.scan_tools()` with penalty-based scoring:
- Critical finding: -25 points
- High finding: -15 points
- Medium finding: -5 points
- Low finding: -2 points

### SEC-004 — Dangerous Operations

| Field | Value |
|-------|-------|
| **Severity** | medium |
| **What it checks** | Tool names for verbs that indicate destructive, dangerous write, or execution operations |
| **Pass condition** | No dangerous operations found |
| **Warn condition** | Medium-severity dangerous operations found (write/exec) |
| **Fail condition** | High-severity destructive operations found (delete/drop/purge) |
| **Skip condition** | No tools to scan |

**Detection categories:**

| Category | Severity | Verb patterns |
|----------|----------|---------------|
| Destructive | high | `delete`, `remove`, `drop`, `destroy`, `purge`, `erase`, `truncate`, `wipe`, `clean`, `uninstall` |
| Dangerous write | medium | `push`, `deploy`, `publish`, `force`, `reset`, `overwrite`, `revert`, `rollback`, `rebase`, `merge` |
| Execution | medium | `exec`, `execute`, `run`, `eval`, `spawn`, `start`, `kill`, `stop`, `restart`, `terminate`, `shutdown` |

Uses snake_case-aware boundaries (`(?:^|_)verb(?:$|_)`) to avoid false positives on tool names containing the verb as a substring.

### SEC-005 — Write Scope Analysis

| Field | Value |
|-------|-------|
| **Severity** | medium |
| **What it checks** | Whether write operations affect user-facing or cloud/remote systems |
| **Pass condition** | No write scope concerns found |
| **Warn condition** | Tools write to user-facing (UI, email, notification) or cloud/remote systems |
| **Skip condition** | No tools to scan |

Always produces WARN (never FAIL). Severity calibrated to MEDIUM because detection is keyword-based.

### SEC-006 — Idempotency Risk

| Field | Value |
|-------|-------|
| **Severity** | medium |
| **What it checks** | Non-idempotent operations that lack an `idempotency_key` in their schema |
| **Pass condition** | All non-idempotent tools have an idempotency_key field, or no non-idempotent tools found |
| **Warn condition** | Tools with create/send/post/insert verbs that lack idempotency_key |
| **Skip condition** | No tools to scan |

Tools that already include an `idempotency_key` field in their input schema are not flagged.

### SEC-007 — Cost/Quota Risk

| Field | Value |
|-------|-------|
| **Severity** | medium |
| **What it checks** | Tools that may incur financial costs or consume API quotas |
| **Pass condition** | No cost risks found |
| **Warn condition** | Tools with billing, payment, subscription, or resource provisioning keywords |
| **Skip condition** | No tools to scan |

Always produces WARN (never FAIL). All findings are LOW severity because detection is keyword-based with low confidence.

---

## Advisory Suite

Informational checks that provide helpful hints but never affect the security score. Advisory checks only produce PASS, WARN (with severity="info"), or SKIP — never FAIL.

**Source:** `testing/suites/advisory.py`

### ADV-001 — Auth Requirement Hints

| Field | Value |
|-------|-------|
| **Severity** | info |
| **What it checks** | Whether tools reference authentication credentials (API keys, tokens, passwords) |
| **Pass condition** | No auth-related keywords found in tool descriptions or schemas |
| **Warn condition** | Tools mention `api_key`, `token`, `secret`, `password`, `credential`, `bearer`, `oauth`, etc. |
| **Skip condition** | No tools to check |

### ADV-002 — External Service Dependencies

| Field | Value |
|-------|-------|
| **Severity** | info |
| **What it checks** | Whether tools depend on external third-party services |
| **Pass condition** | No external service references found |
| **Warn condition** | Tools mention known services (Stripe, Twilio, Slack, AWS, GCP, Azure, etc.) or generic API patterns |
| **Skip condition** | No tools to check |

### ADV-003 — Bulk Operation Warning

| Field | Value |
|-------|-------|
| **Severity** | info |
| **What it checks** | Whether tools can operate on multiple records at once |
| **Pass condition** | No bulk operation indicators found |
| **Warn condition** | Tool names contain bulk/batch/mass verbs, or schemas have unbounded array inputs |
| **Skip condition** | No tools to check |

### ADV-004 — Sensitive Data Exposure Hints

| Field | Value |
|-------|-------|
| **Severity** | info |
| **What it checks** | Whether tools may expose or process sensitive data (PII, PHI, financial) |
| **Pass condition** | No sensitive data keywords found |
| **Warn condition** | Tools reference password, SSN, credit card, medical records, GDPR/HIPAA, etc. |
| **Skip condition** | No tools to check |

### ADV-005 — External Network Access

| Field | Value |
|-------|-------|
| **Severity** | info |
| **What it checks** | Whether tools send or receive data over the network |
| **Pass condition** | No network access indicators found |
| **Warn condition** | Tool descriptions contain network verbs (fetch, request, download) or schemas have URL input fields |
| **Skip condition** | No tools to check |

---

## Adding New Checks

1. Create a function in the appropriate suite module (or a new module)
2. Decorate with `@check(suite_name, check_id, severity=level)`
3. The function receives a `ClientSession` and returns a `CheckResult`
4. If creating a new module, import it from `testing/runner.py` to trigger registration

```python
@check("compliance", "COMP-008", severity="warning")
async def verify_something(session: ClientSession) -> CheckResult:
    # ... check logic ...
    return CheckResult(
        check_id="COMP-008",
        outcome=Outcome.PASS,
        message="Everything OK",
        severity="warning",
    )
```

Check IDs must be unique across all suites. Convention: `{SUITE_PREFIX}-{NNN}`.

---

## Recommendations

After running all checks, `mcp-shield` automatically generates actionable recommendations from FAIL/WARN results.

**Source:** `reporting/recommendations.py`

### How it works

1. Iterates check results with outcome FAIL or WARN (skips PASS, SKIP, ADV-*)
2. Parses `details` strings to extract tool and field names
3. Groups findings into categories with prioritised actions
4. Generates a ready-to-use `mcp-shield proxy --deny` command for dangerous tools

### Categories

| Category | Source checks | Priority | Action |
|----------|-------------|----------|--------|
| `block` | SEC-004 | high | Add `--deny` rules in the proxy |
| `injection` | SEC-002 | high | Add `maxLength`/`pattern` to schemas |
| `write_scope` | SEC-005 | medium | Require user confirmation for writes |
| `idempotency` | SEC-006 | medium | Add `idempotency_key` parameter |
| `cost` | SEC-007 | low | Set budget alerts and rate limits |
| `schema` | COMP-008, COMP-009 | low | Add descriptions and constraints |

Recommendations appear in both terminal output and JSON reports (see [json-report.md](json-report.md)).
