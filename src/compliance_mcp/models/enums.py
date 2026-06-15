import enum


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Lens(enum.StrEnum):
    SECURITY = "security"
    SUPPLY_CHAIN = "supply-chain"
    I18N = "i18n"
    POLICY_AS_CODE = "policy-as-code"


class Domain(enum.StrEnum):
    SECURITY = "security"
    SUPPLY_CHAIN = "supply_chain"
    LICENSE = "license"
    I18N = "i18n"
    POLICY = "policy"
