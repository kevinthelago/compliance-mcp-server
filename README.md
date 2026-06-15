# Compliance MCP Server

An MCP server that surfaces compliance findings — GDPR, SOC2, ISO 27001, HIPAA, PCI DSS, and
custom rule sets — directly into AI coding assistants.

## Quickstart

```bash
uv run compliance-mcp
```

## Configuration

Edit `compliance.toml` or set `COMPLIANCE_*` environment variables:

| Key | Default | Description |
|-----|---------|-------------|
| `corpus_path` | `compliance_corpus` | Directory of policy documents |
| `enabled_lenses` | `["gdpr","soc2","iso27001"]` | Which lenses to run |
| `severity_threshold` | `medium` | Minimum severity to surface |
| `required_locales` | `["en"]` | Locales to validate |
| `concurrency_cap` | `8` | Max parallel lens workers |
| `lens_timeout_seconds` | `60` | Per-lens timeout |

## Available tools

| Tool | Description |
|------|-------------|
| `query_policy` | Retrieve specific policy text by id |
| `list_policies` | List all policies, optionally filtered by domain |
| `scan_project` | Run all enabled lenses against a project path |
| `scan_diff` | Run lenses against a git diff (pre-commit / CI gate) |
| `control_coverage` | Report which controls are met / missing for a project |
| `explain_control` | Return the full text + rationale for a control |
| `compliance_gate` | Assert all findings are within thresholds; fail otherwise |
| `generate_report` | Generate a compliance report in markdown or JSON |

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check src tests
```
