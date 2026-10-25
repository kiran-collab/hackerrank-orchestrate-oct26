"""deletion_rules.csv -> required treatment per record, and the step catalogue."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

# Allowed operations, in the order the problem statement lists them. That order is
# also the required sort order within a phase.
OPERATIONS = [
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {op: i for i, (_, op, _) in enumerate(OPERATIONS)}
OP_STATE = {op: st for _, op, st in OPERATIONS}
OP_PHASE = {op: ph for ph, op, _ in OPERATIONS}

# Treatment -> (finding op, remediation op, verification op, compliant observed states)
TREATMENTS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", {"ABSENT"}),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", {"REDACTED", "ANONYMIZED"}),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", {"ANONYMIZED", "REDACTED"}),
    "DISABLE_FLOW": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", {"DISABLED"}),
    "BLOCK_RESTORE": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", {"BLOCKED"}),
    "RETAIN": (None, None, "VERIFY_RECORD_PRESENT", {"PRESENT", "REDACTED", "ANONYMIZED", "EXPOSED"}),
}

# Data category per resource family (refined per record by category hints).
DEFAULT_CATEGORY = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "cache": "CACHE_ENTRY",
    "support": "SUPPORT_MESSAGE",
    "analytics": "ANALYTICS_PROFILE",
    "export": "USER_EXPORT",
    "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "backup": "BACKUP_ARCHIVE",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "data_flow": "DATA_FLOW",
    "object": "SUPPORT_ATTACHMENT",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    condition: str
    action: str


class Policy:
    def __init__(self, dataset: Path):
        with open(dataset / "deletion_rules.csv", newline="", encoding="utf-8") as f:
            self.rules = {r["data_category"]: Rule(r["rule_id"], r["data_category"], r["condition"], r["required_action"])
                          for r in csv.DictReader(f)}

    def treatment(self, category: str) -> str | None:
        """Treatment for a category. Data flows are not a stored category: any enabled flow that can
        recreate subject data must be disabled. Backups are RETAIN-with-restore-blocked (rule 14)."""
        if category == "DATA_FLOW":
            return "DISABLE_FLOW"
        if category == "BACKUP_ARCHIVE":
            return "BLOCK_RESTORE"
        rule = self.rules.get(category)
        if rule is None:
            return None
        return rule.action  # DELETE / REDACT / ANONYMIZE / RETAIN
