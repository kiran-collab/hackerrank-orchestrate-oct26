"""Interpret a raw Record: which identifiers it carries and what state it shows.

States:
  PRESENT     record exists (and, for PII-bearing categories, still identifies the subject)
  ABSENT      record does not exist
  EXPOSED     record exists and still carries direct identifiers policy says must go
  ANONYMIZED  record exists, no direct identifiers (analytics/telemetry)
  REDACTED    record exists, prohibited identifiers removed (support, tombstone, email logs)
  ACTIVE      data flow enabled / backup restorable
  DISABLED    data flow disabled
  BLOCKED     backup restore blocked
  None        record says nothing decisive about state (e.g. a *_started log line)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ghost_audit.extract import Record
from ghost_audit.identity import tokens_in

DIRECT_ID_KEYS = re.compile(
    r"(^|\.)(email|phone|full_name|name|display_name|requester_email|requester_phone|requester_name|"
    r"owner_email|owner_phone|customer_email|email_hash|user_id|customer_reference|matched_value)$"
)
# Keys whose values identify who a record *is about*, but are lookup metadata rather than stored PII.
LOOKUP_KEYS = {"lookup_key", "subject_key", "match_key", "owner_key", "scan_key", "subject_ref", "query",
               "correlation_key"}
# Stable internal references a retained record is allowed to keep.
STABLE_REF_KEYS = {"subject_reference", "subject_selector", "customer_reference", "user_id"}


def _truthy(v) -> bool | None:
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "allow", "allowed", "active", "enabled"):
        return True
    if s in ("false", "0", "no", "deny", "denied", "blocked", "disabled", "stopped"):
        return False
    return None


@dataclass
class Observation:
    record: Record
    tokens: set[str]  # every identity token mentioned (stored PII + lookup keys + stable refs)
    pii_tokens: set[str]  # tokens from fields that store direct identifiers in the record itself
    state: str | None
    category_hint: str | None = None


def _status(f: dict) -> str | None:
    """Generic existence signal: FOUND / NOT_FOUND."""
    for k in ("result", "http_status", "status_code", "rows", "hits.total", "total_hits", "available",
              "download_available", "archive_present"):
        v = f.get(k)
        if v is None:
            continue
        s = str(v).strip().lower()
        if s in ("not_found", "404", "0", "miss", "false", "absent", "deleted"):
            return "ABSENT"
        if s in ("found", "200", "hit", "true", "present") or (s.isdigit() and int(s) > 0):
            return "PRESENT"
    return None


_DISABLED_WORDS = re.compile(r"\b(disabled|paused|stopped|inactive|revoked)\b", re.I)
_BLOCKED_WORDS = re.compile(r"\b(blocked|restore (disabled|denied)|legal hold only|deny)\b", re.I)
_GONE_WORDS = re.compile(r"\b(expired|deleted|purged|not found|removed)\b", re.I)


def _document_state(prefix: str, row: str, has_pii: bool) -> str | None:
    """State shown on a business screen or document line. A screen that displays a record shows
    that it exists; status words on the same row refine it."""
    if prefix == "data_flow":
        return "DISABLED" if _DISABLED_WORDS.search(row) else "ACTIVE"
    if prefix == "backup":
        return "BLOCKED" if _BLOCKED_WORDS.search(row) else "ACTIVE"
    if _GONE_WORDS.search(row) and prefix in ("export", "search", "account", "object", "marketing"):
        return "ABSENT"
    if prefix in ("analytics",):
        return "EXPOSED" if has_pii else "ANONYMIZED"
    if prefix in ("support", "tombstone"):
        return "EXPOSED" if has_pii else "REDACTED"
    return "PRESENT"


def interpret(rec: Record) -> Observation:
    f = rec.fields
    tokens: set[str] = set()
    pii: set[str] = set()
    for k, v in f.items():
        if k in ("_document_text", "_row_text"):
            continue
        t = tokens_in(v, k)
        tokens |= t
        base = k.split(".")[-1]
        if DIRECT_ID_KEYS.search(k) and base not in STABLE_REF_KEYS:
            pii |= t
        if base == "message_text" or base == "message_excerpt":
            pii |= {x for x in t if x.startswith(("email:", "phone:"))}
    row = f.get("_row_text")
    if isinstance(row, str):
        # Row scope: identifiers on the same screen row / document line as the resource.
        t = tokens_in(row)
        tokens |= t
        pii |= {x for x in t if not x.startswith("user:")}

    p = rec.prefix
    state: str | None = None
    result = str(f.get("result") or "").upper()
    event = str(f.get("event") or "")
    category = f.get("record_type")

    if rec.origin == "activity":
        state = None  # workflow claims are not proof of state
    elif rec.origin.startswith("doc:"):
        state = _document_state(p, str(f.get("_row_text") or ""), bool(pii))
    elif result in ("NOT_FOUND",):
        state = "ABSENT"
    elif p == "account":
        s = _status(f)
        if s:
            state = s
        elif str(f.get("account_status") or "").upper() == "DELETED":
            state = "ABSENT"
        elif rec.origin.startswith(("sql:", "json:")) and any(f.get(k) for k in ("email", "full_name", "account_status")):
            state = "PRESENT"
        elif rec.origin.startswith("doc:"):
            state = "PRESENT"
    elif p == "search":
        s = _status(f)
        if s:
            state = s
        elif rec.origin.startswith(("sql:", "json:")) and (f.get("email") or f.get("document.email") or f.get("display_name")):
            state = "PRESENT"
        elif result == "FOUND":
            state = "PRESENT"
    elif p == "export":
        s = _status(f)
        if s:
            state = s
        elif rec.origin.startswith(("sql:", "json:")) and (f.get("owner_email") or f.get("object_key")):
            state = "PRESENT"
    elif p in ("analytics", "support", "tombstone"):
        if result in ("ANONYMIZED",):
            state = "ANONYMIZED"
        elif result in ("REDACTED",):
            state = "REDACTED"
        elif result in ("IDENTIFIABLE", "FOUND", "EXPOSED"):
            state = "EXPOSED" if (pii or result == "IDENTIFIABLE") else "PRESENT"
        elif event.endswith(("_pii_scan", "identity_scan")):
            state = "EXPOSED" if str(f.get("direct_identifiers", "1")) != "0" else ("ANONYMIZED" if p == "analytics" else "REDACTED")
        elif event in ("contact_lookup_completed",):
            state = "EXPOSED"
            category = "MARKETING_PROFILE"  # contact/opt-in record keyed by a hashed email
        elif event in ("deletion_marker_check",) or (event == "contact_query_completed" and str(f.get("rows")) != "0"):
            state = "EXPOSED"
            category = category or "SUPPORT_ATTACHMENT"
        elif event.endswith("_started"):
            state = None
        elif rec.origin.startswith(("sql:", "json:", "log:", "doc:")):
            s = _status(f)
            if s == "ABSENT":
                state = "ABSENT"
            elif pii:
                state = "EXPOSED"
            elif str(f.get("message_text") or f.get("message_excerpt") or "").strip() == "[REDACTED]" or p != "analytics":
                state = "REDACTED"
            else:
                state = "ANONYMIZED"
    elif p == "data_flow":
        if result in ("ACTIVE", "ENABLED"):
            state = "ACTIVE"
        elif result in ("DISABLED", "STOPPED"):
            state = "DISABLED"
        else:
            en = _truthy(f.get("enabled"))
            if en is not None:
                state = "ACTIVE" if en else "DISABLED"
    elif p == "backup":
        if result in ("ACTIVE", "RESTORABLE"):
            state = "ACTIVE"
        elif result in ("BLOCKED",):
            state = "BLOCKED"
        elif f.get("restore_allowed") is not None:
            state = "ACTIVE" if _truthy(f["restore_allowed"]) else "BLOCKED"
        elif f.get("decision") is not None:
            state = "BLOCKED" if str(f["decision"]).lower() == "deny" else "ACTIVE"
        elif f.get("eligible") is not None:
            restorable = _truthy(f["eligible"]) and not _truthy(f.get("deletion_block"))
            state = "ACTIVE" if restorable else "BLOCKED"
    elif p in ("audit_record", "legal_hold"):
        s = _status(f)
        state = s or ("PRESENT" if not event.endswith("_started") else None)
    elif p in ("cache", "marketing", "email_delivery", "object"):
        s = _status(f)
        state = s or ("EXPOSED" if pii else "PRESENT")
    return Observation(rec, tokens, pii, state, category)
