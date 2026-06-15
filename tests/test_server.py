"""Tests for server bootstrap and registry (SC-4)."""

from __future__ import annotations

from compliance_mcp.registry import discover_lenses, registered_lenses


class TestRegistry:
    def test_discover_lenses_runs_without_error(self):
        """discover_lenses() must succeed even when no lens modules are installed."""
        discover_lenses()
        # With no lens modules installed, the registry should be empty (not raise).
        assert isinstance(registered_lenses(), list)

    def test_lens_decorator_registers(self):
        from compliance_mcp.models.finding import Finding, Lens
        from compliance_mcp.registry import _REGISTRY, lens  # noqa: PLC0415

        @lens("gdpr")
        async def _fake_gdpr(project_path: str, config: object) -> list[Finding]:
            return []

        assert Lens.GDPR in _REGISTRY
        assert _REGISTRY[Lens.GDPR] is _fake_gdpr

        # Clean up
        del _REGISTRY[Lens.GDPR]

    def test_registered_lenses_returns_list(self):
        result = registered_lenses()
        assert isinstance(result, list)


class TestServerModule:
    def test_mcp_instance_exists(self):
        from compliance_mcp.server import mcp  # noqa: PLC0415

        assert mcp is not None

    def test_tool_stubs_are_registered(self):
        """All 8 tool stubs must be reachable on the mcp instance."""
        import asyncio  # noqa: PLC0415

        from compliance_mcp.server import mcp  # noqa: PLC0415

        tool_names = {t.name for t in asyncio.run(mcp.list_tools())}
        expected = {
            "query_policy",
            "list_policies",
            "scan_project",
            "scan_diff",
            "control_coverage",
            "explain_control",
            "compliance_gate",
            "generate_report",
        }
        assert expected.issubset(tool_names), f"Missing tools: {expected - tool_names}"
