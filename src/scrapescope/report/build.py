"""Assemble report.json v1 from a meter snapshot, attribution and find results.

What the builder guarantees (tests enforce it):

- The result validates against report/schema.json.
- Every string is sanitised: hosts with ``clean_host`` (or redaction labels),
  paths with ``clean_path``, free text with ``scrub_text`` + ``safe_text``,
  generated code with ``safe_code``; lists are capped at the schema's limits.
- Paths appear only with ``keep_urls`` (and never with ``redact_hosts``); query
  strings never appear. The builder never receives the upstream URL, the command
  line or the environment, and terminal-only fields (full URLs, starter code) of
  find results are never serialised.

Accuracy labels travel with the report: totals are "tunnel-measured",
per-type bytes "allocated", hook sizes "hook-reported" and costs "estimated
billable transfer". In direct (sizing) mode the with-CONNECT figure is an
estimate and the report says so.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from .._version import __version__
from ..config import LOW_UNITS_THRESHOLD, format_size
from ..model import compute_cost, compute_what_if
from ..snippets import generate_fixes
from ..types import (
    COVERAGE_SKIP_LABELS,
    MAX_JS_SAFE_INT,
    REPORT_SCHEMA_VERSION,
    AttributionResult,
    BudgetEvent,
    Catalogs,
    Coverage,
    FindResult,
    HostAttribution,
    MeterSnapshot,
    ReportOptions,
    clean_path,
    is_catalog_id,
    safe_code,
    safe_text,
)
from ._fmt import GeneratedReport, find_load_label
from .redact import HostLabeler

LABELS: dict[str, str] = {
    "totals": "tunnel-measured",
    "allocated": "allocated",
    "hook": "hook-reported",
    "cost": "estimated billable transfer",
}
SIZING_WARNING = (
    "sizing mode: no upstream; the with-CONNECT figure is estimated; exit location, "
    "blocking and retries of a real upstream are not reproduced"
)

MAX_HOSTS = 10_000
MAX_WARNINGS = 200
MAX_FIND = 10
MAX_MATCHES = 20
MAX_TYPES = 64
MAX_NON_TARGET = 1000
MAX_BUDGET_EVENTS = 1000
MAX_BYPASS_HOSTS = 100
MAX_TEXT_LIST = 50
MAX_PATHS = 20
MAX_PORTS = 64
MAX_TOP_HOSTS = 10
MAX_WHAT_IF = 20
MAX_FIXES = 20

_TYPE_RE = re.compile(r"[a-z_]{1,32}")
_COUNT_KEY_RE = re.compile(r"[a-z_]{1,32}")
_STATUS_KEY_RE = re.compile(r"[0-9]{1,3}|failed")
_BUCKET_RE = re.compile(r"attributed|preconnect_idle|before_attach|unattributed|background:[a-z0-9][a-z0-9_-]{0,63}")
_METHOD_RE = re.compile(r"[A-Z]{1,16}")
_MIME_RE = re.compile(r"[a-z0-9!#$&^_.+-]{1,64}/[a-z0-9!#$&^_.+-]{1,64}")
_MATCH_KIND_RE = re.compile(r"exact|none|variant:[a-z0-9-]{1,32}")
_LOCATION_RE = re.compile(r"[a-z][a-z0-9+_-]{0,31}(:[A-Za-z0-9_.$@\[\]-]{1,128})?")
_ENCODING_RE = re.compile(r"[a-z0-9._+-]{1,32}(, ?[a-z0-9._+-]{1,32})*")
#: Locations kept per value of one match (report.json allows 10).
MAX_VALUE_LOCATIONS = 10
_SIGNAL_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}:(header|cookie|status|body):[\x21-\x7e]{1,128}")
_VENDOR_NAME_RE = re.compile(r"[\x20-\x7e]{1,64}")


# ---------------------------------------------------------------------------
# Small sanitisers
# ---------------------------------------------------------------------------


def rfc3339(ts: float) -> str:
    """``2026-09-23T10:00:00.123Z`` (UTC, milliseconds). Invalid input gives the epoch."""
    try:
        value = float(ts)
        if not math.isfinite(value) or value < 0:
            value = 0.0
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        dt = datetime.fromtimestamp(0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _count(value: Any) -> int:
    """A non-negative JSON-safe integer (bytes or counts)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        value = int(value)
    return max(0, min(int(value), MAX_JS_SAFE_INT))


def _opt_count(value: Any) -> int | None:
    return None if value is None else _count(value)


def _status(value: Any) -> int | None:
    if value is None or isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 999 else None


def _fraction(value: Any) -> float | None:
    if value is None or isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    f = float(value)
    if not math.isfinite(f):
        return None
    return round(min(1.0, max(0.0, f)), 6)


def _mime(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    base = value.split(";", 1)[0].strip().lower()
    return base if _MIME_RE.fullmatch(base) else None


def _counts_dict(mapping: dict[str, Any], key_re: re.Pattern[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for key, value in mapping.items():
        if isinstance(key, str) and key_re.fullmatch(key):
            out[key] = out.get(key, 0) + _count(value)
    return out


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _host_row(h: HostAttribution, labeler: HostLabeler, keep_paths: bool) -> dict[str, Any]:
    buckets: dict[str, dict[str, int]] = {}
    for name, tally in h.buckets.items():
        if isinstance(name, str) and _BUCKET_RE.fullmatch(name):
            buckets[name] = {"tunnels": _count(tally.tunnels), "bytes": _count(tally.bytes)}
    paths: list[dict[str, Any]] = []
    if keep_paths:
        for p in h.paths:
            cleaned = clean_path(p.path)
            if cleaned is not None:
                paths.append({"path": cleaned, "requests": _count(p.requests), "reported_bytes": _count(p.reported_bytes)})
        paths = paths[:MAX_PATHS]
    ports = sorted({p for p in h.ports if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536})
    return {
        "host": labeler.label(h.host),
        "ports": ports[:MAX_PORTS],
        "tunnels": _count(h.tunnels),
        "failed_tunnels": _count(h.failed_tunnels),
        "denied_tunnels": _count(h.denied_tunnels),
        "bytes_sent": _count(h.bytes_sent),
        "bytes_received": _count(h.bytes_received),
        "bytes_with_connect": _count(h.bytes_with_connect),
        "bytes_without_connect": _count(h.bytes_without_connect),
        "requests": _count(h.requests),
        "buckets": buckets,
        "allocated_by_type": _counts_dict(h.allocated_by_type, _TYPE_RE),
        "background_id": h.background_id if is_catalog_id(h.background_id) else None,
        "paths": paths,
    }


def _merge_host_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge rows that share a label (several hosts can map to one catalog id when redacting)."""
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        into = merged.get(row["host"])
        if into is None:
            merged[row["host"]] = row
            continue
        for key in ("tunnels", "failed_tunnels", "denied_tunnels", "bytes_sent", "bytes_received",
                    "bytes_with_connect", "bytes_without_connect", "requests"):
            into[key] = _count(into[key] + row[key])
        into["ports"] = sorted(set(into["ports"]) | set(row["ports"]))[:MAX_PORTS]
        for name, tally in row["buckets"].items():
            cur = into["buckets"].setdefault(name, {"tunnels": 0, "bytes": 0})
            cur["tunnels"] = _count(cur["tunnels"] + tally["tunnels"])
            cur["bytes"] = _count(cur["bytes"] + tally["bytes"])
        for rtype, n in row["allocated_by_type"].items():
            into["allocated_by_type"][rtype] = _count(into["allocated_by_type"].get(rtype, 0) + n)
        if into["background_id"] != row["background_id"]:
            into["background_id"] = None
        into["paths"] = []
    return list(merged.values())


def _hosts(attribution: AttributionResult, labeler: HostLabeler, keep_paths: bool) -> tuple[list[dict[str, Any]], list[str]]:
    rows = [_host_row(h, labeler, keep_paths) for h in attribution.hosts]
    if labeler.redact:
        rows = _merge_host_rows(rows)
    rows.sort(key=lambda r: (-r["bytes_with_connect"], r["host"]))
    notes: list[str] = []
    if len(rows) > MAX_HOSTS:
        notes.append(f"hosts list truncated to the {MAX_HOSTS:,} heaviest of {len(rows):,} hosts")
        rows = rows[:MAX_HOSTS]
    return rows, notes


def _types(attribution: AttributionResult) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for t in attribution.types:
        if not isinstance(t.type, str) or not _TYPE_RE.fullmatch(t.type):
            continue
        row = merged.setdefault(t.type, {"type": t.type, "requests": 0, "reported_bytes": 0, "allocated_bytes": 0})
        row["requests"] = _count(row["requests"] + _count(t.requests))
        row["reported_bytes"] = _count(row["reported_bytes"] + _count(t.reported_bytes))
        row["allocated_bytes"] = _count(row["allocated_bytes"] + _count(t.allocated_bytes))
    rows = sorted(merged.values(), key=lambda r: (-r["allocated_bytes"], r["type"]))
    return rows[:MAX_TYPES]


def _buckets(attribution: AttributionResult) -> dict[str, Any]:
    b = attribution.buckets
    return {
        "attributed": _count(b.attributed),
        "preconnect_idle": _count(b.preconnect_idle),
        "before_attach": _count(b.before_attach),
        "unattributed": _count(b.unattributed),
        "background": {k: _count(v) for k, v in b.background.items() if is_catalog_id(k)},
    }


def _non_target(attribution: AttributionResult, labeler: HostLabeler) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for nt in attribution.non_target:
        cid = nt.catalog_id if is_catalog_id(nt.catalog_id) else "unknown"
        label = labeler.label(nt.host)
        row = merged.setdefault(
            (label, cid), {"host": label, "catalog_id": cid, "tunnels": 0, "bytes_sent": 0, "bytes_received": 0}
        )
        row["tunnels"] = _count(row["tunnels"] + _count(nt.tunnels))
        row["bytes_sent"] = _count(row["bytes_sent"] + _count(nt.bytes_sent))
        row["bytes_received"] = _count(row["bytes_received"] + _count(nt.bytes_received))
    rows = sorted(merged.values(), key=lambda r: (-(r["bytes_sent"] + r["bytes_received"]), r["host"]))
    return rows[:MAX_NON_TARGET]


def _budget_event(ev: BudgetEvent, labeler: HostLabeler) -> dict[str, Any]:
    top: dict[str, int] = {}
    for hb in ev.top_hosts:
        label = labeler.label(hb.host)
        top[label] = _count(top.get(label, 0) + _count(hb.bytes))
    top_rows = sorted(({"host": h, "bytes": n} for h, n in top.items()), key=lambda r: (-r["bytes"], r["host"]))
    return {
        "ts": rfc3339(ev.ts),
        "kind": ev.kind if ev.kind in ("warn_80", "tripped", "tunnel_cap") else "warn_80",
        "counted_bytes": _count(ev.counted_bytes),
        "limit_bytes": _opt_count(ev.limit_bytes),
        "tunnel_id": _opt_count(ev.tunnel_id),
        "host": None if ev.host is None else labeler.label(ev.host),
        "top_hosts": top_rows[:MAX_TOP_HOSTS],
        "closed_tunnels": _count(ev.closed_tunnels),
    }


def _challenge(result: FindResult) -> dict[str, Any]:
    ch = result.challenge
    name: str | None = None
    if isinstance(ch.vendor_name, str) and ch.vendor_name:
        candidate = safe_text(ch.vendor_name, 64).encode("ascii", "replace").decode("ascii")
        name = candidate if _VENDOR_NAME_RE.fullmatch(candidate) else None
    signals = [s for s in ch.signals if isinstance(s, str) and _SIGNAL_RE.fullmatch(s)]
    return {
        "blocked": bool(ch.blocked),
        "vendor_id": ch.vendor_id if is_catalog_id(ch.vendor_id) else None,
        "vendor_name": name,
        "signals": signals[:MAX_TEXT_LIST],
        "status": _status(ch.status),
    }


def _find_match(m: Any, labeler: HostLabeler, keep_paths: bool) -> dict[str, Any]:
    scheme = m.scheme if m.scheme in ("http", "https") else "https"
    port = m.port if isinstance(m.port, int) and not isinstance(m.port, bool) and 0 < m.port < 65536 else (
        443 if scheme == "https" else 80
    )
    rank = m.rank if isinstance(m.rank, int) and not isinstance(m.rank, bool) else 1
    kinds = [k if isinstance(k, str) and _MATCH_KIND_RE.fullmatch(k) else "none" for k in m.match_kinds]
    locations = [loc for loc in m.locations if isinstance(loc, str) and _LOCATION_RE.fullmatch(loc)]
    by_value = [
        [loc for loc in locs if isinstance(loc, str) and _LOCATION_RE.fullmatch(loc)][:MAX_VALUE_LOCATIONS]
        for locs in (m.locations_by_value or [])
        if isinstance(locs, list)
    ][:MAX_TEXT_LIST]
    encoding = m.content_encoding if isinstance(m.content_encoding, str) and len(m.content_encoding) <= 32 and _ENCODING_RE.fullmatch(m.content_encoding) else None
    flags = m.flags
    return {
        "rank": min(1000, max(1, rank)),
        "host": labeler.label(m.host),
        "port": port,
        "scheme": scheme,
        "path": clean_path(m.path) if keep_paths and m.path else None,
        "method": m.method if isinstance(m.method, str) and _METHOD_RE.fullmatch(m.method) else "OTHER",
        "resource_type": m.resource_type if isinstance(m.resource_type, str) and _TYPE_RE.fullmatch(m.resource_type) else "other",
        "status": _status(m.status),
        "mime_type": _mime(m.mime_type),
        "all_values": bool(m.all_values),
        "values_matched": _count(m.values_matched),
        "match_kinds": kinds[:MAX_TEXT_LIST],
        "locations": locations[:MAX_MATCHES],
        "encoded_body_bytes": _count(m.encoded_body_bytes),
        "response_header_bytes": _count(m.response_header_bytes),
        "request_header_bytes": _count(m.request_header_bytes),
        "tls_handshake_estimate": _count(m.tls_handshake_estimate),
        "billed_basis_bytes": _count(m.billed_basis_bytes),
        "flags": {
            "sent_cookies": bool(flags.sent_cookies),
            "sent_authorization": bool(flags.sent_authorization),
            "random_query_token": bool(flags.random_query_token),
            "third_party": bool(flags.third_party),
            "non_get": bool(flags.non_get),
            "sent_token_header": bool(getattr(flags, "sent_token_header", False)),
        },
        "code_eligible": bool(m.code_eligible),
        "code_ineligible_reason": None if m.code_ineligible_reason is None else labeler.text(m.code_ineligible_reason),
        "content_encoding": encoding,
        "multiplexed": bool(m.multiplexed),
        "locations_by_value": by_value if len(by_value) == len(kinds[:MAX_TEXT_LIST]) else [],
    }


def coverage_line(status: str, coverage: Coverage, vendor_name: str | None) -> str:
    """The report's coverage line; never "not found" for a blocked page or a failed load."""
    if status == "blocked":
        return f"blocked; cannot search (challenge: {vendor_name or 'unrecognised vendor'})"
    if status == "error":
        return "page load failed; nothing was searched"
    return coverage.summary(status == "found")


def _find_entry(result: FindResult, labeler: HostLabeler, keep_paths: bool) -> dict[str, Any]:
    status = result.status if result.status in ("found", "not_found", "blocked", "error") else "error"
    challenge = _challenge(result)
    skipped = {
        k: _count(v) for k, v in result.coverage.skipped.items() if k in COVERAGE_SKIP_LABELS and _count(v) > 0
    }
    coverage = Coverage(inspected=_count(result.coverage.inspected), skipped=skipped)
    matches = sorted(result.matches, key=lambda m: m.rank if isinstance(m.rank, int) else 0)[:MAX_MATCHES]
    verify = result.verify
    return {
        "status": status,
        "target_host": labeler.label(result.target_host),
        "target_path": clean_path(result.target_path) if keep_paths and result.target_path else None,
        "values_count": min(50, max(1, _count(result.values_count))),
        "short_value_warning": bool(result.short_value_warning),
        "challenge": challenge,
        "matches": [_find_match(m, labeler, keep_paths) for m in matches],
        "coverage": {
            "inspected": coverage.inspected,
            "skipped": skipped,
            "line": safe_text(coverage_line(status, coverage, challenge["vendor_name"])),
        },
        "verify": {
            "replays": verify.replays if verify.replays in ("yes", "no", "not_tested") else "not_tested",
            "status": _status(verify.status),
            "received_bytes": _opt_count(verify.received_bytes),
            "reason": None if verify.reason is None else labeler.text(verify.reason),
            "replay_billed_basis_bytes": _opt_count(verify.replay_billed_basis_bytes),
        },
        "responses_total": _count(result.responses_total),
        "page_reported_bytes": _count(result.page_reported_bytes),
        "warnings": _dedupe(labeler.text(w) for w in result.warnings)[:MAX_TEXT_LIST],
    }


def _what_if(attribution: AttributionResult, snapshot: MeterSnapshot, catalogs: Catalogs, labeler: HostLabeler) -> list[dict[str, Any]]:
    rows = []
    for w in compute_what_if(attribution, snapshot.totals(), catalogs)[:MAX_WHAT_IF]:
        rows.append(
            {
                "id": w.id,
                "title": labeler.text(w.title),
                "bytes_saved": _count(w.bytes_saved),
                "share": _fraction(w.share) or 0.0,
                "basis": "allocated",
                "caveats": [labeler.text(c) for c in w.caveats][:MAX_TEXT_LIST],
            }
        )
    return rows


def _fixes(attribution: AttributionResult, snapshot: MeterSnapshot, catalogs: Catalogs, options: ReportOptions, labeler: HostLabeler) -> list[dict[str, Any]]:
    rows = []
    for f in generate_fixes(attribution, snapshot, catalogs, gb_unit=options.gb_unit)[:MAX_FIXES]:
        rows.append(
            {
                "id": f.id,
                "title": labeler.text(f.title),
                "detection": labeler.text(f.detection),
                "language": f.language,
                # Code carries only catalogued hosts and the meter port; never host-replaced.
                "code": safe_code(f.code),
                "caveats": [labeler.text(c) for c in f.caveats][:MAX_TEXT_LIST],
            }
        )
    return rows


def _standard_warnings(
    snapshot: MeterSnapshot,
    attribution: AttributionResult,
    options: ReportOptions,
    budget_events: list[dict[str, Any]],
) -> list[str]:
    unit = options.gb_unit
    out: list[str] = []
    if snapshot.mode == "direct":
        out.append(SIZING_WARNING)
    for ev in budget_events:
        if ev["kind"] != "tripped":
            continue
        heaviest = ", ".join(f"{h['host']} ({format_size(h['bytes'], unit)})" for h in ev["top_hosts"][:5])
        limit = format_size(ev["limit_bytes"], unit) if ev["limit_bytes"] is not None else "the"
        out.append(
            f"budget tripped: {format_size(ev['counted_bytes'], unit)} counted against {limit} budget; "
            f"the meter closed {ev['closed_tunnels']} tunnel(s) and refused new ones"
            + (f"; heaviest hosts in the final minute: {heaviest}" if heaviest else "")
            + ". The provider may bill bytes that were already in flight."
        )
    caps = [ev for ev in budget_events if ev["kind"] == "tunnel_cap"]
    if caps:
        out.append(
            f"{len(caps)} tunnel(s) closed by the per-tunnel cap "
            f"({format_size(caps[0]['limit_bytes'] or 0, unit)} per tunnel)"
        )
    # attribution.warnings may already cover bypass and units (contracts section 6,
    # step 14); add ours only when it does not, so the report does not say it twice.
    upstream = [w.lower() for w in attribution.warnings]
    has_bypass = any(w.startswith("incomplete") for w in upstream)
    has_units = any("unit" in w and "per-1,000" in w for w in upstream)
    bypass = attribution.bypass
    if bypass.incomplete and not has_bypass:
        out.append(
            f"incomplete: helpers saw {bypass.requests} network request(s) to {len(bypass.hosts)} host(s) "
            "that no tunnel carried, so those bytes are missing from the totals; clients that bypass "
            "the meter without helpers cannot be detected"
        )
    count = attribution.units.count
    if has_units:
        pass
    elif 0 < count < LOW_UNITS_THRESHOLD:
        out.append(
            f"only {count} unit(s) ({attribution.units.source}): per-1,000 figures from fewer than "
            f"{LOW_UNITS_THRESHOLD} units are unreliable"
        )
    elif count == 0 and options.command != "find":
        out.append(
            "no units counted: per-1,000 figures are unavailable; use the helpers or hooks, or pass --units N"
        )
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _register_hosts(
    labeler: HostLabeler,
    snapshot: MeterSnapshot,
    attribution: AttributionResult,
    find_results: Sequence[FindResult],
) -> None:
    labeler.register(t.host for t in snapshot.tunnels)
    labeler.register(h.host for h in attribution.hosts)
    labeler.register(nt.host for nt in attribution.non_target)
    labeler.register(attribution.bypass.hosts)
    for ev in snapshot.budget_events:
        if ev.host is not None:
            labeler.label(ev.host)
        labeler.register(hb.host for hb in ev.top_hosts)
    for result in find_results:
        labeler.label(result.target_host)
        labeler.register(m.host for m in result.matches)


_FAILURE_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")


def _tunnel_failures(snapshot: MeterSnapshot) -> dict[str, int]:
    """Failed target tunnels by reason ("upstream_unreachable", "upstream_status_407", "local_limit"...)."""
    out: dict[str, int] = {}
    for tunnel in snapshot.target_tunnels():
        if not tunnel.failed:
            continue
        reason = str(tunnel.status).split(":", 1)[-1]
        if reason == "upstream_status" and isinstance(tunnel.upstream_status, int):
            reason = f"upstream_status_{tunnel.upstream_status}"
        if _FAILURE_KEY_RE.fullmatch(reason):
            out[reason] = out.get(reason, 0) + 1
        else:
            out["other"] = out.get("other", 0) + 1
    return dict(sorted(out.items()))


def build_report(
    *,
    snapshot: MeterSnapshot,
    attribution: AttributionResult,
    catalogs: Catalogs,
    options: ReportOptions,
    find_results: Sequence[FindResult] = (),
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    """The report.json v1 dict (validates against report/schema.json).

    Returns a :class:`~scrapescope.report._fmt.GeneratedReport` (a ``dict``) so
    renderers know its fix code was generated in this process; a report read
    back from a file is a plain dict and its fixes are rebuilt from their ids.

    Calls ``snapshot.totals()``, ``model.compute_cost`` (only when
    ``options.rate`` is set), ``model.compute_what_if`` and
    ``snippets.generate_fixes``. Warnings: sizing mode, budget trip (with the
    heaviest hosts of the final minute), per-tunnel cap closures, incomplete
    run, low or missing unit counts, then ``attribution.warnings`` and the
    caller's ``warnings``, de-duplicated and capped at 200.
    """
    labeler = HostLabeler(catalogs, redact=options.redact_hosts)
    keep_paths = bool(options.keep_urls) and not options.redact_hosts
    _register_hosts(labeler, snapshot, attribution, find_results)

    totals = snapshot.totals()
    hosts, host_notes = _hosts(attribution, labeler, keep_paths)
    budget_events = [_budget_event(ev, labeler) for ev in snapshot.budget_events[:MAX_BUDGET_EVENTS]]
    finds = [_find_entry(r, labeler, keep_paths) for r in list(find_results)[:MAX_FIND]]

    cost = None
    if options.rate is not None:
        cost = compute_cost(
            totals, attribution.units, attribution.success, rate=options.rate, gb_unit=options.gb_unit
        ).to_dict()

    success = None
    if attribution.success is not None:
        s = attribution.success
        success = {
            "count": _count(s.count),
            "basis": s.basis if s.basis in ("navigations", "requests") else "requests",
            "rate": _fraction(s.rate),
        }

    per_unit = None
    if attribution.per_unit is not None:
        pu = attribution.per_unit
        resolution = pu.resolution_s if isinstance(pu.resolution_s, (int, float)) and math.isfinite(pu.resolution_s) else 0.0
        per_unit = {
            "first_unit_bytes": _count(pu.first_unit_bytes),
            "rest_units": _count(pu.rest_units),
            "rest_bytes": _count(pu.rest_bytes),
            "rest_mean_bytes": _opt_count(pu.rest_mean_bytes),
            "resolution_s": min(60.0, max(0.0, float(resolution))),
        }

    bypass_hosts = sorted({labeler.label(h) for h in attribution.bypass.hosts})[:MAX_BYPASS_HOSTS]
    units = attribution.units
    unit_count = _count(units.count)

    upstream_warnings = list(attribution.warnings)
    if options.command == "find":
        # find loads one page and has no units by design; unit warnings are noise there.
        upstream_warnings = [w for w in upstream_warnings if not ("unit" in w and "per-1,000" in w)]
    all_warnings = (
        _standard_warnings(snapshot, attribution, options, budget_events)
        + upstream_warnings
        + list(warnings)
        + host_notes
    )
    warning_texts = _dedupe(labeler.text(w) for w in all_warnings)
    if len(warning_texts) > MAX_WARNINGS:
        dropped = len(warning_texts) - (MAX_WARNINGS - 1)
        warning_texts = warning_texts[: MAX_WARNINGS - 1] + [f"{dropped} more warnings were omitted"]

    ended_at = options.ended_at if options.ended_at is not None else snapshot.taken_at
    launches = _count(attribution.browser_launches)
    labels = dict(LABELS)
    if options.command == "find":
        # find launches exactly one Chromium per page it loads; it writes no helper events.
        launches = max(launches, min(len(find_results), MAX_FIND))
        # Its unattributed bucket is its own page load (and --verify replay): say so in the JSON too.
        labels["unattributed"] = find_load_label({"find": finds})

    return GeneratedReport({
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool_version": __version__,
        "command": options.command,
        "catalog_versions": catalogs.versions(),
        "started_at": rfc3339(snapshot.started_at),
        "ended_at": rfc3339(ended_at),
        "mode": snapshot.mode,
        "gb_unit": options.gb_unit,
        "labels": labels,
        "totals": {
            "with_connect": _count(totals.with_connect),
            "without_connect": _count(totals.without_connect),
            "bytes_sent": _count(totals.bytes_sent),
            "bytes_received": _count(totals.bytes_received),
            "tunnels": _count(totals.tunnels),
            "failed_tunnels": _count(totals.failed_tunnels),
            "denied_tunnels": _count(totals.denied_tunnels),
            "with_connect_estimated": bool(totals.with_connect_estimated),
            # meas4-6: upstream connections opened for those records (fewer when a kept provider
            # connection carried several plain-HTTP records on the HTTP CONNECT route)
            "connections": _count(totals.connections),
        },
        "budget": {
            "limit_bytes": _opt_count(snapshot.budget_bytes),
            "max_tunnel_bytes": _opt_count(snapshot.max_tunnel_bytes),
            "counted_bytes": _count(snapshot.counted_bytes),
            "tripped": bool(snapshot.budget_tripped),
        },
        "units": {
            "count": unit_count,
            "source": units.source if units.source in ("navigations", "requests", "override", "none") else "none",
            # find loads one page and has no units or per-1,000 figures to warn about.
            "low_sample_warning": unit_count < LOW_UNITS_THRESHOLD and options.command != "find",
        },
        "browser_launches": launches,
        "bytes_before_first_navigation": _opt_count(attribution.bytes_before_first_navigation),
        "per_unit": per_unit,
        "hosts": hosts,
        "types": _types(attribution),
        "buckets": _buckets(attribution),
        "non_target": _non_target(attribution, labeler),
        "status_histogram": _counts_dict(attribution.status_histogram, _STATUS_KEY_RE),
        "success": success,
        "find": finds,
        "budget_events": budget_events,
        "warnings": warning_texts,
        "incomplete": bool(attribution.bypass.incomplete),
        "bypass": {"hosts": bypass_hosts, "requests": _count(attribution.bypass.requests)},
        "what_if": _what_if(attribution, snapshot, catalogs, labeler),
        "fixes": _fixes(attribution, snapshot, catalogs, options, labeler),
        "cost": cost,
        "refused": _counts_dict(snapshot.refused, _COUNT_KEY_RE),
        "tunnel_failures": _tunnel_failures(snapshot),
        "accept_limit_errors": _count(snapshot.accept_limit_errors),
        "helper_events": {
            "attach": _count(attribution.events.attach),
            "launch": _count(attribution.events.launch),
            "request": _count(attribution.events.request),
            "dropped": _count(attribution.events.dropped),
        },
    })


__all__ = ["LABELS", "SIZING_WARNING", "build_report", "coverage_line", "rfc3339"]
