"""Evidence extraction: every supplied artifact becomes a list of flat `Record`s.

A Record is one observation of one resource in one source, with the raw fields
that source exposed. Interpretation (who it belongs to, what state it is in)
happens later in `observe.py`; this module only parses faithfully.

Formats handled:
  * SQL snapshot exports (executed in an in-memory SQLite database)
  * JSON records and bundles (walked recursively; any object with resource_id)
  * logs in five syntaxes (k=v, JSON-lines, syslog, cloud-runtime, bracketed),
    grouped by trace so identity keys on *_started lines attach to the
    resource on the matching *_completed line
  * plain-text handover reports
  * PDFs (text layer via pdftotext / pypdf)
  * images (facts produced by the vision extractor, see media.py)
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RESOURCE_RE = re.compile(
    r"\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|legal_hold|"
    r"cache|email_delivery|marketing|object)_\d+\b"
)

SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "legal_hold": "legal_service",
    "cache": "cache_service",
    "email_delivery": "email_delivery_service",
    "marketing": "marketing_platform",
    "object": "object_storage",
}


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    v = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def prefix_of(resource_id: str) -> str:
    return re.sub(r"_\d+$", "", resource_id)


def system_for(resource_id: str) -> str | None:
    return SYSTEM_BY_PREFIX.get(prefix_of(resource_id))


@dataclass
class Record:
    source_id: str  # file_id or activity_id/audit_id
    source_time: datetime  # capture time of the source (citation cutoff)
    observed_at: datetime  # when this state was observed
    resource_id: str
    system: str | None
    fields: dict[str, object]
    origin: str  # parser + location, for debugging and replica logic
    complete_scope: bool = False  # True when the source is a full table dump for `system`

    @property
    def prefix(self) -> str:
        return prefix_of(self.resource_id)


@dataclass
class Manifest:
    file_id: str
    path: Path
    origin: str
    captured_at: datetime


@dataclass
class Corpus:
    records: list[Record] = field(default_factory=list)
    # Full-table SQL dumps: file_id -> (captured_at, {system: set(resource_ids)})
    full_tables: dict[str, tuple[datetime, dict[str, set[str]]]] = field(default_factory=dict)
    texts: dict[str, str] = field(default_factory=dict)  # file_id -> extracted text (pdf, txt, images)
    failures: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- helpers


def _flatten(obj: dict, out: dict | None = None, prefix: str = "") -> dict:
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            if "resource_id" in v:
                continue  # nested record: emitted separately
            _flatten(v, out, f"{key}.")
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                out[key] = v
            else:
                out[key] = [x for x in v if not (isinstance(x, dict) and "resource_id" in x)]
        else:
            out[key] = v
    return out


def _norm_null(v):
    if isinstance(v, str) and v.strip().lower() in ("null", "none", ""):
        return None
    return v


# ---------------------------------------------------------------- JSON


_TIME_KEYS = ("observed_at", "captured_at", "recorded_at", "updated_at", "exported_at")
_SYSTEM_KEYS = ("data_store", "system", "origin_system")


def _walk_json(node, ctx: dict, emit) -> None:
    if isinstance(node, dict):
        ctx = dict(ctx)
        for k in _TIME_KEYS:
            if isinstance(node.get(k), str) and parse_ts(node[k]):
                ctx["time"] = node[k]
        for k in _SYSTEM_KEYS:
            if isinstance(node.get(k), str) and node[k].endswith(("_service", "_platform", "_storage")):
                ctx["system"] = node[k]
        if isinstance(node.get("collection"), str):
            ctx["collection"] = node["collection"]
        if isinstance(node.get("resource_id"), str):
            emit(node, ctx)
        for k, v in node.items():
            child = dict(ctx)
            if k.endswith(("_service", "_platform")) and isinstance(v, dict):
                child["system"] = k
            if isinstance(v, (dict, list)):
                if isinstance(v, dict) and k not in ("profile", "document", "metrics"):
                    child["container"] = k
                elif isinstance(v, list):
                    child["container"] = k
                _walk_json(v, child, emit)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, ctx, emit)


def parse_json(m: Manifest, corpus: Corpus) -> None:
    data = json.loads(m.path.read_text(encoding="utf-8"))

    def emit(node: dict, ctx: dict) -> None:
        rid = node["resource_id"]
        if not RESOURCE_RE.fullmatch(rid):
            return
        fields = {k: _norm_null(v) for k, v in _flatten(node).items()}
        fields["_collection"] = ctx.get("collection") or ctx.get("container")
        observed = parse_ts(node.get("observed_at") or node.get("recorded_at") or ctx.get("time")) or m.captured_at
        corpus.records.append(
            Record(m.file_id, m.captured_at, observed, rid, node.get("system") or ctx.get("system") or system_for(rid),
                   fields, f"json:{ctx.get('collection') or ctx.get('container')}")
        )

    _walk_json(data, {}, emit)


# ---------------------------------------------------------------- SQL


def parse_sql(m: Manifest, corpus: Corpus) -> None:
    text = m.path.read_text(encoding="utf-8")
    header_ts = re.search(r"Captured at:\s*(\S+)", text)
    full_dump = "point-in-time database snapshot" in text
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(text)
        scope: dict[str, datetime] = {}
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "snapshot_scope" in tables:
            for sysid, ts in con.execute("SELECT origin_system, captured_at FROM snapshot_scope"):
                scope[sysid] = parse_ts(ts) or m.captured_at
        present: dict[str, set[str]] = {}
        for table in tables:
            if table == "snapshot_scope":
                continue
            cur = con.execute(f'SELECT * FROM "{table}"')
            cols = [c[0] for c in cur.description]
            for row in cur:
                rec = dict(zip(cols, row, strict=True))
                rid = rec.get("resource_id")
                if not isinstance(rid, str):
                    continue
                payload = {}
                if isinstance(rec.get("record_json"), str):
                    payload = json.loads(rec["record_json"])
                fields = {k: _norm_null(v) for k, v in {**rec, **_flatten(payload)}.items() if k != "record_json"}
                fields["_table"] = table
                fields["_collection"] = rec.get("collection_name") or table
                system = rec.get("origin_system") or system_for(rid)
                observed = parse_ts(rec.get("updated_at") or rec.get("indexed_at")) or scope.get(system) or m.captured_at
                corpus.records.append(
                    Record(m.file_id, m.captured_at, observed, rid, system, fields, f"sql:{table}", complete_scope=full_dump)
                )
                if full_dump and system:
                    present.setdefault(system, set()).add(rid)
        if full_dump:
            # Absence-by-omission is only sound for dedicated per-system tables (e.g. customer_profiles_*,
            # search_documents_*). Generic multi-system dumps hold samples, not whole tables.
            covered = set()
            for table in tables:
                if "profiles" in table:
                    covered.add("account_service")
                if "search_documents" in table:
                    covered.add("search_service")
            snap = parse_ts(header_ts.group(1)) if header_ts else m.captured_at
            corpus.full_tables[m.file_id] = (snap or m.captured_at, {s: present.get(s, set()) for s in covered})
    finally:
        con.close()


# ---------------------------------------------------------------- logs

_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_BRACKET_RE = re.compile(r"^(\S+) \[(\w+)\] \[([\w-]+)\] \[([\w-]+)\] (\w+): (.*)$")
_SYSLOG_RE = re.compile(r"^(\S+) <\d+>\d+ \S+ (\S+) (\S+) - - (.*)$")
_JSONLINE_RE = re.compile(r"^(\S+) (\{.*\})$")


def _kv(text: str) -> dict:
    out = {}
    for k, v in _KV_RE.findall(text):
        if v.startswith('"'):
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    if "message" in out and "=" in str(out["message"]):
        out.update(_kv(out["message"]))  # cloud-runtime nests the real fields in message="..."
    return out


def _parse_log_line(line: str) -> dict | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    if m := _JSONLINE_RE.match(line):
        d = {k: str(v) for k, v in json.loads(m.group(2)).items()}
        d["_ts"] = m.group(1)
        d.setdefault("service", d.get("logger"))
        return d
    if m := _BRACKET_RE.match(line):
        d = _kv(m.group(6))
        d.update({"_ts": m.group(1), "level": m.group(2), "service": m.group(3), "trace_id": m.group(4),
                  "event": m.group(5)})
        return d
    if m := _SYSLOG_RE.match(line):
        d = _kv(m.group(4))
        d.update({"_ts": m.group(1), "service": m.group(2), "trace_id": m.group(3)})
        return d
    ts, _, rest = line.partition(" ")
    d = _kv(rest)
    d["_ts"] = ts
    d.setdefault("service", d.get("function"))
    d.setdefault("trace_id", d.get("requestId"))
    return d


IDENTITY_KEYS = ("lookup_key", "subject_key", "match_key", "owner_key", "scan_key", "subject_ref",
                 "correlation_key", "matched_value", "subject_reference")


def parse_log(m: Manifest, corpus: Corpus) -> None:
    lines = [d for d in map(_parse_log_line, m.path.read_text(encoding="utf-8").splitlines()) if d]
    # Group by trace so identity on *_started attaches to the resource on *_completed.
    traces: dict[str, list[dict]] = {}
    for i, d in enumerate(lines):
        tid = d.get("trace_id") or f"line{i}"
        traces.setdefault(tid, []).append(d)
    for i, d in enumerate(lines):
        rid = _norm_null(d.get("resource_id"))
        if not rid or not RESOURCE_RE.fullmatch(rid):
            continue
        fields = {k: _norm_null(v) for k, v in d.items()}
        tid = d.get("trace_id")
        if tid:
            for other in traces.get(tid, []):
                if other is d:
                    continue
                orid = _norm_null(other.get("resource_id"))
                if orid and orid != rid:
                    continue  # another resource in the same trace
                for k in IDENTITY_KEYS:
                    if _norm_null(other.get(k)) and k not in fields:
                        fields[k] = other[k]
        system = d.get("system") or d.get("service")
        if not system or not str(system).endswith(("_service", "_platform")) or system_for(rid) != system:
            system = system_for(rid)
        observed = parse_ts(d.get("_ts")) or m.captured_at
        corpus.records.append(Record(m.file_id, m.captured_at, observed, rid, system, fields, "log:" + m.path.name))


# ---------------------------------------------------------------- text, pdf, images

_HANDOVER_RE = re.compile(r"^- (\S+) \| (\w+) \| (\w+) \| (\w+) \| (\w+) \| (.+)$")


def parse_text_report(m: Manifest, text: str, corpus: Corpus) -> None:
    corpus.texts[m.file_id] = text
    for line in text.splitlines():
        if mm := _HANDOVER_RE.match(line.strip()):
            ts, system, rid, category, result, subject = mm.groups()
            corpus.records.append(Record(
                m.file_id, m.captured_at, parse_ts(ts) or m.captured_at, rid, system,
                {"record_type": category, "result": result, "subject_reference": _norm_null(subject)},
                "text:handover"))


def pdf_text(path: Path) -> str:
    import shutil
    import subprocess

    if shutil.which("pdftotext"):
        out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=False)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout
    from pypdf import PdfReader

    return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)


DOC_RESOURCE_RE = re.compile(
    r"(?<![a-z_])(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|legal_hold|"
    r"cache|email_delivery|marketing|object)_\d+(?!\d)"
)


def parse_document(m: Manifest, text: str, corpus: Corpus, aliases: dict[str, str] | None = None) -> None:
    """PDFs and screenshot transcripts. Each resource ID (or catalog alias, e.g. an attachment file
    name) becomes a record carrying the text of its own row; the whole document text is kept too,
    and the solver widens linking to document scope only for single-subject documents."""
    corpus.texts[m.file_id] = text
    rows = text.splitlines()
    found: dict[str, list[str]] = {}
    named: set[str] = set()  # resources whose ID appears literally (not only via a catalog alias)
    for row in rows:
        for mm in DOC_RESOURCE_RE.finditer(row):
            found.setdefault(mm.group(0), []).append(row)
            named.add(mm.group(0))
        for alias, rid in (aliases or {}).items():
            if alias in row:
                found.setdefault(rid, []).append(row)
    for rid, own_rows in sorted(found.items()):
        corpus.records.append(Record(m.file_id, m.captured_at, m.captured_at, rid, system_for(rid),
                                     {"_row_text": "\n".join(own_rows), "_document_text": text,
                                      "_via": "id" if rid in named else "alias"},
                                     "doc:" + m.path.name))


# ---------------------------------------------------------------- activity stream


def activity_records(dataset: Path) -> list[Record]:
    out = []
    with open(dataset / "system_activity.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ts = parse_ts(row["event_time"])
            assert ts is not None
            out.append(Record(row["activity_id"], ts, ts, row["resource_id"], row["target_system"],
                              dict(row), "activity"))
    return out


# ---------------------------------------------------------------- entry point


def load_manifest(dataset: Path) -> list[Manifest]:
    out = []
    with open(dataset / "evidence_files.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ts = parse_ts(row["captured_at"])
            assert ts is not None
            out.append(Manifest(row["file_id"], dataset / row["file_path"], row["origin"], ts))
    return out


_ALIAS_RE = re.compile(r"linked (\w+_\d+) \(([^)]+)\)|confirmed (\w+_\d+) \(([^)]+)\)")


def catalog_aliases(dataset: Path) -> dict[str, str]:
    """Data-catalog activity names resources by business aliases (attachment file names, statement
    numbers). Map alias -> resource_id so documents that only show the alias are still linked."""
    out = {}
    with open(dataset / "system_activity.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            for mm in _ALIAS_RE.finditer(row["details"]):
                rid, alias = (mm.group(1), mm.group(2)) if mm.group(1) else (mm.group(3), mm.group(4))
                if alias != rid and not alias.startswith("user_"):
                    out[alias] = rid
    return out


def build_corpus(dataset: Path, image_texts: dict[str, str] | None = None) -> Corpus:
    corpus = Corpus()
    aliases = catalog_aliases(dataset)
    for m in load_manifest(dataset):
        try:
            suffix = m.path.suffix.lower()
            if suffix == ".sql":
                parse_sql(m, corpus)
            elif suffix == ".json":
                parse_json(m, corpus)
            elif suffix == ".log":
                parse_log(m, corpus)
            elif suffix == ".txt":
                parse_text_report(m, m.path.read_text(encoding="utf-8"), corpus)
            elif suffix == ".pdf":
                parse_document(m, pdf_text(m.path), corpus, aliases)
            elif suffix in (".png", ".jpg", ".jpeg"):
                text = (image_texts or {}).get(m.file_id)
                if text:
                    parse_document(m, text, corpus, aliases)
                else:
                    corpus.failures.append(f"{m.file_id}: no transcript for image {m.path.name}")
            else:
                corpus.failures.append(f"{m.file_id}: unsupported type {suffix}")
        except Exception as exc:  # one bad artifact must not sink the run
            corpus.failures.append(f"{m.file_id}: {type(exc).__name__}: {exc}")
    return corpus
