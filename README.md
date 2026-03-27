# MCP Shield

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Like [Bandit](https://github.com/PyCQA/bandit) for Python code, but for MCP servers.

Security scanner, runtime proxy, and audit logger for [Model Context Protocol](https://modelcontextprotocol.io/) servers.

## Install

```bash
pip install mcp-shield-cli
```

Requires Python 3.11+ and Node.js (for npx-based MCP servers).

## Usage

### `mcp-shield test` — scan a server

```bash
# Scan a local stdio server
mcp-shield test "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Scan a remote HTTP server
mcp-shield test "http://localhost:8080/mcp"

# Run only specific suites (compliance, security, advisory, or all)
mcp-shield test "npx server" --suite security
mcp-shield test "npx server" --suite security --suite advisory

# Pass environment variables to the server process
mcp-shield test "npx server" --env API_KEY=sk-123 --env DB_URL=postgres://host/db

# Save JSON report to file
mcp-shield test "npx server" --output report.json

# JSON to stdout (for piping)
mcp-shield test "npx server" --format json

# SARIF output (for GitHub Code Scanning)
mcp-shield test "npx server" --format sarif

# SARIF to file (can combine with any --format)
mcp-shield test "npx server" --sarif-output report.sarif

# Both terminal and JSON output
mcp-shield test "npx server" --format both --output report.json

# CI mode: exit code 1 if any high+ severity check fails
mcp-shield test "npx server" --fail-on high

# Enable ML-based poisoning detection (DeBERTa, slower but more accurate)
mcp-shield test "npx server" --ml

# Set connection/check timeout (default 30s)
mcp-shield test "npx server" --timeout 10
```

Example output:

```
 Check        | Result | Severity | Message
 COMP-001     |  PASS  | critical | Handshake OK
 COMP-002     |  PASS  | error    | Server identity: filesystem-server v0.2.0
 SEC-002      |  WARN  | high     | Found 11 potential injection vector(s) (CWE-78, CWE-89, CWE-22)
 SEC-004      |  FAIL  | high     | 2 dangerous tool(s): move_file, edit_file (CWE-78, CWE-250)
 SEC-005      |  WARN  | medium   | Write scope: local filesystem (CWE-434)
 ADV-002      |  WARN  | info     | External dependencies: filesystem access

 Score: 57/100  Grade: D

─────────────── Recommendations ───────────────

  [1] Block dangerous tools (SEC-004) (CWE-78, CWE-250)
      Tools: move_file, edit_file
      Action: Add --deny rules in proxy or require user confirmation

┌──── Ready-to-use proxy command ────┐
│ mcp-shield proxy "npx ..." \       │
│   --deny move_file --deny edit_file│
└────────────────────────────────────┘
```

### `mcp-shield proxy` — runtime firewall

```bash
# Block specific tools by name (glob patterns)
mcp-shield proxy "npx server" --deny "delete_*" --deny "exec_*"

# Allow only safe tools (everything else is blocked)
mcp-shield proxy "npx server" --allow "read_*" --allow "list_*"

# Rate-limit to 30 requests/minute per client
mcp-shield proxy "npx server" --rate-limit 30

# Custom audit database path
mcp-shield proxy "npx server" --audit-db ./my-audit.db

# Require authentication
mcp-shield proxy "npx server" --auth bearer --token admin:secret123
mcp-shield proxy "npx server" --auth bearer --token alice:tok-a --token bob:tok-b

# Combine everything: deny + rate limit + auth + env
mcp-shield proxy "npx server" \
    --deny "git_push" --deny "git_reset" \
    --rate-limit 30 \
    --auth bearer --token ci:token123 \
    --env GITHUB_TOKEN=ghp_xxx

# Proxy a remote HTTP server
mcp-shield proxy "http://upstream:9090/mcp" --deny "drop_*"
```

The proxy sits between the LLM client and the MCP server:

```
LLM Client  ──stdio──▶  mcp-shield proxy  ──stdio──▶  MCP Server
                           │
                     ┌─────┴─────┐
                     │ deny list │
                     │ rate limit│
                     │ auth check│
                     │ audit log │
                     └───────────┘
```

Blocked calls return an error to the client and are logged with the block reason.

### `mcp-shield audit` — query logs

```bash
# Show last 50 events (default)
mcp-shield audit show

# Show last 100 events
mcp-shield audit show --last 100

# Filter by tool name
mcp-shield audit show --tool delete_file

# Show only blocked calls
mcp-shield audit show --blocked

# Filter by risk tier (read, write_reversible, write_external, write_sensitive)
mcp-shield audit show --risk write_sensitive

# Filter by client ID (when using --auth)
mcp-shield audit show --client admin

# Combine filters
mcp-shield audit show --blocked --risk write_sensitive --last 20
```

```bash
# Summary statistics (default: last 24 hours)
mcp-shield audit stats

# Stats for a time range (h=hours, d=days, w=weeks, m=months)
mcp-shield audit stats --since 1h
mcp-shield audit stats --since 7d
mcp-shield audit stats --since 4w
```

```bash
# Export to JSON
mcp-shield audit export -f json -o audit.json

# Export to CSV
mcp-shield audit export -f csv -o audit.csv
```

```bash
# Use a custom database path (applies to all subcommands)
mcp-shield audit --db /path/to/audit.db show --last 20
mcp-shield audit --db /path/to/audit.db stats --since 7d
```

## What it checks

22 checks across 3 suites, ~2 seconds per scan.

### Compliance (COMP-001..010)

| Check | What it verifies |
|-------|-----------------|
| COMP-001 | MCP handshake (JSON-RPC initialize) |
| COMP-002 | Server identity (name + version) |
| COMP-003 | Valid `inputSchema` on all tools |
| COMP-004 | Tool naming conventions |
| COMP-005 | Ping/pong support |
| COMP-006 | Tool descriptions present |
| COMP-007 | Server capabilities declared |
| COMP-008 | Schema field descriptions |
| COMP-009 | Schema constraints (`maxLength`, `pattern`) |
| COMP-010 | Resource/prompt validation |

### Security (SEC-001..007)

| Check | What it detects | Severity | CWE |
|-------|----------------|----------|-----|
| SEC-001 | Tool poisoning (hidden instructions in descriptions) | critical | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) |
| SEC-002 | Injection vectors (path, URL, SQL, code fields) | high | [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| SEC-003 | Aggregated security score (0-100) | -- | -- |
| SEC-004 | Dangerous operations (`delete`, `exec`, `deploy`) | high | [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-250](https://cwe.mitre.org/data/definitions/250.html) |
| SEC-005 | Write scope (local vs cloud vs user-facing) | medium | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) |
| SEC-006 | Idempotency risk (non-retryable operations) | medium | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| SEC-007 | Cost risk (cloud provisioning, paid APIs) | low | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |

### Advisory (ADV-001..005)

Informational only — does not affect the score.

| Check | What it flags |
|-------|--------------|
| ADV-001 | Auth requirement hints (API key, OAuth) |
| ADV-002 | External service dependencies (AWS, Stripe, GitHub) |
| ADV-003 | Bulk operation warnings (unbounded arrays) |
| ADV-004 | Sensitive data exposure (PII, credentials) |
| ADV-005 | External network access (URL + fetch patterns) |

### Scoring

Composite score: **40% compliance + 60% security**. Deductions per finding:

| Severity | Deduction |
|----------|-----------|
| critical | -25 |
| high | -15 |
| medium | -5 |
| low | -2 |

Advisory checks are informational and do not affect the score.

### Poisoning detection

**Layer 1** — ~45 regex patterns across 11 categories:

| Category | Examples |
|----------|----------|
| Instruction override | "ignore previous instructions", "new instructions:" |
| Role hijacking | "act as", "pretend to be", "you are now" |
| Format injection | ChatML `<\|im_start\|>`, Llama `[INST]`, Handlebars `{{#system}}` |
| Data exfiltration | Markdown image exfil, "send to URL", credential reading |
| Hidden content | HTML comments, CSS `display:none`, ANSI escapes, zero-width Unicode |
| Hardcoded secrets | API keys (`sk-live-*`), GitHub PATs, Slack tokens |
| Agent injection | ReAct format injection, tool call injection |

**Layer 2** (opt-in, `--ml`) — DeBERTa-v3-base classifier for semantic detection.

ML dependencies (`onnxruntime`, `tokenizers`, `huggingface-hub`) are included in the default install. The `--ml` flag downloads the [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) ONNX model (~740 MB, cached in `~/.cache/mcp-shield/models/`) on first use.

**Why opt-in?** The ML classifier can produce false positives on directive-like tool descriptions (e.g., "DEPRECATED: Use X instead" may be flagged as an injection). Use `--ml` when you want maximum detection sensitivity and can tolerate reviewing flagged results.

### Risk classification

Every tool is classified into a risk tier:

| Tier | Examples |
|------|----------|
| `read` | read_file, list_directory, search |
| `write_reversible` | write_file, create_directory |
| `write_external` | send_email, deploy, webhook |
| `write_sensitive` | delete, exec, eval, drop |

## GitHub Actions

### Using the action (recommended)

[`thuggeelya/mcp-shield-action@v1`](https://github.com/thuggeelya/mcp-shield-action) runs the scan, posts a PR comment with findings, and uploads SARIF to GitHub Security — all automatically.

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: npm ci && npm run build
- uses: thuggeelya/mcp-shield-action@v1
  with:
    server: 'node dist/index.js'
```

### Manual setup

If you need more control, use `mcp-shield-cli` directly:

```yaml
- name: Scan MCP server
  run: |
    pip install mcp-shield-cli
    mcp-shield test "npx -y @modelcontextprotocol/server-filesystem /tmp" \
      --sarif-output results.sarif \
      --fail-on high

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### SARIF & GitHub Code Scanning

Both approaches produce [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) reports with CWE references, severity scores, and MCP tool names — visible in GitHub's Security tab.

```bash
# Generate SARIF on stdout
mcp-shield test "npx server" --format sarif

# Save SARIF to file (works alongside any --format)
mcp-shield test "npx server" --sarif-output results.sarif
```

## Contributing

Contributions are welcome. Open an issue or submit a pull request.

```bash
git clone https://github.com/thuggeelya/mcp-shield.git
cd mcp-shield
pip install -e ".[dev]"
pytest
```

## Author

**thuggeelya**

- LinkedIn: [thuggeelya](https://www.linkedin.com/in/thuggeelya/)
- Telegram: [@thuggeelya](https://t.me/thuggeelya)
- Email: [thuggeelya@gmail.com](mailto:thuggeelya@gmail.com)

## License

[Apache 2.0](LICENSE)
