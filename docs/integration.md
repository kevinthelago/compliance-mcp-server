# Integration Guide

The Compliance MCP Server exposes compliance scanning and policy advisory via MCP stdio.

## Installation

    uv pip install compliance-mcp-server
    # or from source
    git clone https://github.com/kevinthelago/compliance-mcp-server
    cd compliance-mcp-server && uv sync

## Running

    uv run compliance-mcp

## Register with Claude Code (.claude/mcp.json)

    {"mcpServers": {"compliance": {"command": "compliance-mcp"}}}

## The two flows

Pull - worker queries before writing code:

    query_policy(domain="security", topic="credential-storage")

Push - director scans and gates a merge:

    result = scan_project(path="/workspace")
    gate = compliance_gate(scan_result=result)
    # gate["decision"]: "pass" | "block" | "inconclusive"

## Tool reference

- list_capabilities() -> lenses + scanner binary detection
- query_policy(domain?, topic?, query?, framework?) -> matching policies
- list_policies() -> all policies grouped by domain
- scan_project(path, lenses?) -> findings + run_summary + total
- scan_diff(path, base_ref?, changed_paths?) -> findings for changed files
- control_coverage(scan_result, framework) -> per-control addressed/at_risk/no_evidence
- explain_control(framework, control_id) -> description + mapped policies
- compliance_gate(scan_result | path) -> pass/block/inconclusive + blocking_findings
- generate_report(scan_result, format?, output_path?) -> markdown report

## Configuration (compliance.toml or COMPLIANCE_* env vars)

    corpus_path = "policies"
    severity_threshold = "high"
    required_locales = ["en"]
    lens_timeout_seconds = 60
