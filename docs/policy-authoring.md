# Policy Corpus Authoring Guide

The corpus lives in the policies/ directory.

## Directory layout

policies/ contains domain folders (security, supply_chain, license, i18n, policy),
mappings/controls.yaml, licenses/allow.txt and deny.txt,
rules/*.yaml for policy-as-code, semgrep/*.yaml for custom rules, baseline.yaml.

## Policy markdown files

YAML frontmatter: id, domain, topic, severity, controls, keywords, locales.
Body is the policy text cited by agents.

Domains: security, supply_chain, license, i18n, policy

## controls.yaml

Maps framework controls to policy IDs and rule IDs.
Supported frameworks: soc2, iso27001, hipaa, pci-dss, gdpr.

## License lists

One SPDX license ID per line in licenses/allow.txt and licenses/deny.txt.
Unlisted licenses generate MEDIUM findings.

## Policy-as-code rules

YAML list in rules/*.yaml with id, description, severity, controls, type, target, remediation.
Types: file-present, file-absent, content-matches, content-not-matches.

## baseline.yaml

version: 1
suppressions: list of {fingerprint, reason} dicts to suppress known-accepted findings.
