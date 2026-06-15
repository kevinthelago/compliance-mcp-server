# Compliance MCP Server

An MCP server that surfaces compliance findings — GDPR, SOC2, ISO 27001, HIPAA, PCI DSS, and
custom rule sets — directly into AI coding assistants.

## Quickstart

```bash
uv run compliance-mcp
```

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check src tests
```
