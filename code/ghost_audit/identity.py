"""Identity resolution: current snapshot + audit-log history -> every identifier a subject ever had."""

from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
USER_RE = re.compile(r"\buser_\d+\b")
PHONE_RE = re.compile(r"\+\d[\d\s().-]{6,}\d")


def norm_email(v: str) -> str:
    return v.strip().lower()


def norm_phone(v: str) -> str:
    return re.sub(r"\D", "", v)


def norm_name(v: str) -> str:
    return " ".join(v.casefold().split())


def email_hash(email: str) -> str:
    return hashlib.sha256(norm_email(email).encode()).hexdigest()


@dataclass
class Subject:
    user_id: str
    names: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    audit_ids: list[str] = field(default_factory=list)  # identity-change audit rows

    def tokens(self, with_names: bool = True) -> set[str]:
        toks = {f"user:{self.user_id}"}
        toks |= {f"email:{e}" for e in self.emails}
        toks |= {f"phone:{p}" for p in self.phones}
        toks |= {f"hash:{h}" for h in self.hashes}
        if with_names:
            toks |= {f"name:{n}" for n in self.names}
        return toks


class IdentityIndex:
    def __init__(self, dataset: Path):
        self.subjects: dict[str, Subject] = {}
        with open(dataset / "user_identities.csv", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                s = Subject(row["user_id"])
                s.names.add(norm_name(row["name"]))
                s.emails.add(norm_email(row["email"]))
                s.phones.add(norm_phone(row["phone"]))
                s.hashes.add(row["email_hash"].lower())
                self.subjects[s.user_id] = s
        with open(dataset / "user_audit_log.csv", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                s = self.subjects.setdefault(row["user_id"], Subject(row["user_id"]))
                s.audit_ids.append(row["audit_id"])
                for value in (row["old_value"], row["new_value"]):
                    if not value:
                        continue
                    if row["field_name"] == "email":
                        s.emails.add(norm_email(value))
                    elif row["field_name"] == "phone":
                        s.phones.add(norm_phone(value))
                    elif row["field_name"] == "email_hash":
                        s.hashes.add(value.lower())
                    elif row["field_name"] in ("name", "full_name"):
                        s.names.add(norm_name(value))
        for s in self.subjects.values():
            s.hashes |= {email_hash(e) for e in s.emails}
        # Reverse index; names are only usable when unique across all subjects.
        self.owner: dict[str, set[str]] = {}
        for s in self.subjects.values():
            for t in s.tokens():
                self.owner.setdefault(t, set()).add(s.user_id)

    def resolve_email(self, email: str) -> Subject | None:
        owners = self.owner.get(f"email:{norm_email(email)}", set())
        return self.subjects[next(iter(owners))] if len(owners) == 1 else None

    def owners_of(self, tokens: set[str]) -> set[str]:
        out: set[str] = set()
        for t in tokens:
            owners = self.owner.get(t, set())
            if t.startswith("name:") and len(owners) != 1:
                continue  # ambiguous name: not a usable link
            out |= owners
        return out


def tokens_in(value: object, key: str = "") -> set[str]:
    """Identity tokens found in one field value."""
    if value is None:
        return set()
    if isinstance(value, (list, tuple)):
        return set().union(*(tokens_in(v, key) for v in value)) if value else set()
    text = str(value)
    toks = {f"email:{norm_email(e)}" for e in EMAIL_RE.findall(text)}
    toks |= {f"hash:{h}" for h in HASH_RE.findall(text.lower())}
    toks |= {f"user:{u}" for u in USER_RE.findall(text)}
    toks |= {f"phone:{norm_phone(p)}" for p in PHONE_RE.findall(text)}
    k = key.lower()
    if k.endswith(("name", "full_name", "display_name", "requester_name")) and text.strip():
        toks.add(f"name:{norm_name(text)}")
    if k.endswith("phone") and text.strip():
        toks.add(f"phone:{norm_phone(text)}")
    return toks
