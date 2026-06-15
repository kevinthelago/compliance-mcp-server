# Docker Usage

Bundles semgrep, trivy, syft, and gitleaks with the server.

## Build

    docker build -t compliance-mcp-server:local .

## Run as MCP stdio server

    docker run --rm -i compliance-mcp-server:local
    docker run --rm -i -v $(pwd):/workspace:ro compliance-mcp-server:local

## Verify scanners

    docker run --rm compliance-mcp-server:local compliance-mcp --help

## Environment variables

COMPLIANCE_CORPUS_PATH, COMPLIANCE_SEVERITY_THRESHOLD, COMPLIANCE_REQUIRED_LOCALES,
COMPLIANCE_LENS_TIMEOUT_SECONDS

## Claude Code (.claude/mcp.json)

    {"mcpServers": {"compliance": {"command": "docker", "args": ["run", "--rm", "-i", "compliance-mcp-server:local"]}}}
