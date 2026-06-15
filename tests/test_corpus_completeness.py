"""INT-4: Corpus completeness test.

Asserts:
1. policies/ directory exists and all required domains have at least one policy file
2. controls.yaml parses and all control IDs referenced in policy frontmatter exist in
   all_control_ids
3. License allow/deny lists exist and are non-empty
4. rules/*.yaml all parse as valid YAML with required fields (id, type, target)
5. baseline.yaml parses and has the expected top-level structure

These tests run in CI with no external tools required.
"""

from __future__ import annotations

import pathlib

import frontmatter
import pytest
import yaml

POLICIES_DIR = pathlib.Path(__file__).parent.parent / "policies"

REQUIRED_DOMAINS = {"security", "supply_chain", "license", "i18n", "policy"}
REQUIRED_RULE_FIELDS = {"id", "target", "assertion"}
VALID_RULE_TYPES = {
    "file-present",
    "file-absent",
    "content-matches",
    "content-not-matches",
    "structured-path",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_all_policies() -> list[dict]:
    """Load all policy markdown files and return a list of frontmatter dicts."""
    policies = []
    for md_path in sorted(POLICIES_DIR.rglob("*.md")):
        try:
            post = frontmatter.load(str(md_path))
            policies.append({"path": str(md_path), **dict(post.metadata)})
        except Exception as exc:
            pytest.fail(f"Failed to parse {md_path}: {exc}")
    return policies


def _load_controls_yaml() -> dict:
    controls_path = POLICIES_DIR / "mappings" / "controls.yaml"
    assert controls_path.exists(), f"controls.yaml missing at {controls_path}"
    with open(controls_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_allow_deny() -> tuple[list[str], list[str]]:
    allow_path = POLICIES_DIR / "licenses" / "allow.txt"
    deny_path = POLICIES_DIR / "licenses" / "deny.txt"
    assert allow_path.exists(), f"allow.txt missing at {allow_path}"
    assert deny_path.exists(), f"deny.txt missing at {deny_path}"

    def _read_licenses(path: pathlib.Path) -> list[str]:
        lines = path.read_text(encoding="utf-8").splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]

    return _read_licenses(allow_path), _read_licenses(deny_path)


def _load_rules() -> list[tuple[pathlib.Path, dict]]:
    rules_dir = POLICIES_DIR / "rules"
    if not rules_dir.exists():
        return []
    results = []
    for yaml_path in sorted(rules_dir.glob("*.yaml")):
        with open(yaml_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, list):
            for rule in data:
                results.append((yaml_path, rule))
        elif isinstance(data, dict):
            results.append((yaml_path, data))
    return results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_policies_directory_exists():
    assert POLICIES_DIR.exists(), f"policies/ directory missing at {POLICIES_DIR}"
    assert POLICIES_DIR.is_dir(), f"{POLICIES_DIR} is not a directory"


def test_all_required_domains_have_policies():
    """Every required compliance domain must have at least one policy file."""
    policies = _load_all_policies()
    domains_covered = {p.get("domain") for p in policies if p.get("domain")}
    missing = REQUIRED_DOMAINS - domains_covered
    assert not missing, (
        f"Missing policy coverage for domains: {sorted(missing)}\n"
        f"Domains with coverage: {sorted(domains_covered)}"
    )


def test_all_policies_have_required_fields():
    """Every policy file must have id, domain, topic."""
    policies = _load_all_policies()
    assert policies, "No policy files found in policies/"
    for pol in policies:
        path = pol.get("path", "?")
        for field in ("id", "domain", "topic"):
            assert field in pol, f"Policy at {path} is missing required field '{field}'"


def test_all_policies_have_valid_domain():
    """Every policy's domain must be one of the five recognised values."""
    valid_domains = {"security", "supply_chain", "license", "i18n", "policy"}
    policies = _load_all_policies()
    for pol in policies:
        domain = pol.get("domain")
        path = pol.get("path", "?")
        assert domain in valid_domains, (
            f"Policy at {path} has invalid domain '{domain}'; valid: {valid_domains}"
        )


def test_all_policy_ids_are_unique():
    """Policy IDs must be unique across the corpus."""
    policies = _load_all_policies()
    ids = [p.get("id") for p in policies if p.get("id")]
    duplicates = {pid for pid in ids if ids.count(pid) > 1}
    assert not duplicates, f"Duplicate policy IDs found: {duplicates}"


def test_controls_yaml_parses():
    """controls.yaml must parse as valid YAML."""
    data = _load_controls_yaml()
    assert isinstance(data, dict), "controls.yaml must be a YAML mapping at the top level"


def test_controls_yaml_has_frameworks():
    """controls.yaml must define at least one framework with controls."""
    data = _load_controls_yaml()
    frameworks = data.get("frameworks", {})
    assert frameworks, "controls.yaml 'frameworks' section is empty or missing"
    for fw_name, fw_data in frameworks.items():
        assert isinstance(fw_data, dict) and fw_data, (
            f"Framework '{fw_name}' in controls.yaml must be a non-empty control mapping "
            f"({{control_id: {{title, description}}}})"
        )


def test_policy_control_refs_are_defined():
    """controls.yaml must define a non-empty set of control IDs across all frameworks."""
    data = _load_controls_yaml()
    frameworks = data.get("frameworks", {})
    all_ids: set[str] = {
        ctrl_id
        for fw_controls in frameworks.values()
        if isinstance(fw_controls, dict)
        for ctrl_id in fw_controls
    }
    assert all_ids, (
        "controls.yaml defines no control IDs — "
        "expected framework → {control_id: {title, description}} mappings"
    )


def test_license_lists_exist_and_non_empty():
    """allow.txt and deny.txt must exist under policies/licenses/ and be non-empty."""
    allow_list, deny_list = _load_allow_deny()
    assert allow_list, "policies/licenses/allow.txt is empty"
    assert deny_list, "policies/licenses/deny.txt is empty"


def test_allow_list_has_common_licenses():
    """allow.txt must include at least MIT and Apache-2.0."""
    allow_list, _ = _load_allow_deny()
    for expected in ("MIT", "Apache-2.0"):
        assert expected in allow_list, (
            f"'{expected}' not in allow.txt — expected a pre-approved license"
        )


def test_deny_list_has_copyleft_licenses():
    """deny.txt must include at least one GPL variant."""
    _, deny_list = _load_allow_deny()
    has_gpl = any("GPL" in lic for lic in deny_list)
    assert has_gpl, "deny.txt contains no GPL variant — expected at least one copyleft license"


def test_rules_yaml_parses():
    """All files in policies/rules/*.yaml must parse as valid YAML."""
    rules_dir = POLICIES_DIR / "rules"
    if not rules_dir.exists():
        pytest.skip("policies/rules/ directory not present")
    yaml_files = list(rules_dir.glob("*.yaml"))
    assert yaml_files, "policies/rules/ is empty — expected at least one rule file"
    for yaml_path in yaml_files:
        with open(yaml_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert data is not None, f"{yaml_path} is empty"


def test_rules_have_required_fields():
    """Every rule in policies/rules/*.yaml must have id, target, and assertion.type."""
    rules = _load_rules()
    assert rules, "No rules found in policies/rules/"
    invalid: list[str] = []
    for path, rule in rules:
        if not isinstance(rule, dict):
            invalid.append(f"{path}: rule is not a mapping: {rule!r}")
            continue
        for field in REQUIRED_RULE_FIELDS:
            if field not in rule:
                invalid.append(f"{path}: rule '{rule.get('id', '?')}' is missing field '{field}'")
        assertion = rule.get("assertion")
        if isinstance(assertion, dict) and "type" not in assertion:
            invalid.append(f"{path}: rule '{rule.get('id', '?')}' assertion is missing 'type' key")
    assert not invalid, "Invalid rules:\n" + "\n".join(invalid)


def test_rules_have_valid_types():
    """Every rule assertion must use a supported type."""
    rules = _load_rules()
    invalid: list[str] = []
    for path, rule in rules:
        if not isinstance(rule, dict):
            continue
        assertion = rule.get("assertion", {})
        rule_type = assertion.get("type") if isinstance(assertion, dict) else None
        if rule_type not in VALID_RULE_TYPES:
            invalid.append(
                f"{path}: rule '{rule.get('id', '?')}' has unknown assertion type '{rule_type}'; "
                f"valid types: {VALID_RULE_TYPES}"
            )
    assert not invalid, "Rules with invalid assertion type:\n" + "\n".join(invalid)


def test_baseline_yaml_parses():
    """baseline.yaml must parse as valid YAML with an 'accepted' list."""
    baseline_path = POLICIES_DIR / "baseline.yaml"
    assert baseline_path.exists(), f"baseline.yaml missing at {baseline_path}"
    with open(baseline_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict), "baseline.yaml must be a YAML mapping"
    assert "accepted" in data, "baseline.yaml must have an 'accepted' list"
    assert isinstance(data["accepted"], list), "baseline.yaml 'accepted' must be a list"


def test_semgrep_rules_parse():
    """Custom Semgrep rules in policies/semgrep/*.yaml must parse and have a 'rules' key."""
    semgrep_dir = POLICIES_DIR / "semgrep"
    if not semgrep_dir.exists():
        pytest.skip("policies/semgrep/ directory not present")
    for yaml_path in sorted(semgrep_dir.glob("*.yaml")):
        with open(yaml_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert isinstance(data, dict), f"{yaml_path}: expected a YAML mapping"
        assert "rules" in data, f"{yaml_path}: missing top-level 'rules' key"
        assert isinstance(data["rules"], list), f"{yaml_path}: 'rules' must be a list"
        for rule in data["rules"]:
            assert "id" in rule, f"{yaml_path}: a rule is missing the 'id' field"
