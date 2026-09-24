"""Generated fix snippets, emitted only when their detection fired.

Order and detections (docs/dev/contracts.md section 10):

=========================== ===========================================================
id                          fires when
=========================== ===========================================================
playwright-cdp-block        Playwright events seen and image+media+font allocated bytes
                            are at least 10% of the run's with-CONNECT total
playwright-route-block      same (the route() alternative, with its cache warning)
chromium-background-flags   any bytes in a ``background:<catalog id>`` bucket; the
                            Playwright (Python) profile code only when Playwright
                            helper events were seen, else the stack-independent part
playwright-mcp-flags        same (titled "If you use Playwright MCP": an MCP-driven
                            browser writes no helper events, so it cannot be detected)
requests-session-reuse      Requests hook events, units counted from hook requests,
                            at least 10 units and at least 0.5 target tunnels per unit
httpx-client-reuse          same with HTTPX hook events
=========================== ===========================================================

What the background fixes recommend, and why: refuse the catalogued hosts at the
meter (``--deny-catalog background``) and keep one browser profile. Launch
switches are not offered as the fix, because Playwright already passes
``--disable-background-networking`` and ``--disable-component-update`` and
NodeMaven observed the optimization-guide download with both in force; Playwright
MCP's ``--blocked-origins`` is not offered either, because it is implemented with
Playwright routing, which only intercepts page and worker requests (and turns
the HTTP cache off). The MCP fix starts the MCP server under ``scrapescope run``
with ``--budget``: the credential-free local listener then exists only while the
server runs, on a random port, with a spending limit (never a standing
``serve``, which requires its token, on a fixed port). The id ``chromium-background-flags``
is kept for compatibility with existing reports.

Accuracy limits: the detections use allocated bytes and tunnel counts, so they
say where a fix is likely to pay off, not that it will. Allocated bytes of the
``unreported`` type never count. Every fix says to verify with a compared second
run; blocking fixes also carry the blocking caveat. Generated code contains no
user data except catalogued background hosts, never credentials, and passes
through ``types.safe_code``.

Report files are untrusted input: :func:`regenerate_fix` rebuilds a fix's title,
detection, code and caveats from its id, the catalogs and the report's own
figures (per-type allocated bytes, background buckets, totals, units), so a
report read from a file can never present its own code or text as
scrapescope's. Those figures are the file's and are not re-measured.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..config import format_size
from ..model.what_if import BLOCKABLE_TYPES, BLOCKING_CAVEAT, background_bytes, blockable_bytes
from ..types import AttributionResult, Catalogs, Fix, MeterSnapshot, clean_host, is_catalog_id, safe_code, safe_text
from . import templates

VERIFY_CAVEAT = "verify with a compared second run"
SECURITY_CAVEAT = (
    "security trade-off: component updates also deliver certificate-revocation and Safe Browsing data"
)
ROUTE_CACHE_CAVEAT = "routing disables the HTTP cache and misses service-worker requests"
ROUTE_MULTI_PAGE_CAVEAT = (
    "this run loaded several pages per context; without the HTTP cache, repeated stylesheets, "
    "scripts and fonts are downloaded again, which can cost more than blocking saves"
)
CDP_LIMITS_CAVEAT = (
    "URL patterns miss fonts and media served without a file extension; the CDP block covers "
    "the page it is attached to, not out-of-process iframes or workers"
)
PROFILE_CAVEAT = "a persistent profile keeps cookies and site data between runs"
TOKENLESS_CAVEAT = (
    "while the MCP server runs, any local process can use the meter's listener without a token and "
    "spend your provider balance; keep --budget set"
)
PIN_CAVEAT = "pin the Playwright MCP release you reviewed instead of @latest"
SWITCHES_CAVEAT = (
    "launch switches are not the fix: Playwright already passes --disable-background-networking and "
    "--disable-component-update, and the optimization-guide download was observed with both in force"
)
REUSE_CAVEAT = (
    "not where a new exit per request is the point: reusing a connection usually keeps the same exit"
)

#: Blocking fixes fire when image+media+font allocated bytes reach this share of the total.
BLOCKING_SHARE_THRESHOLD = 0.10
#: Session-reuse fixes need at least this many hook-counted units ...
REUSE_MIN_UNITS = 10
#: ... and at least this many target tunnels per unit.
REUSE_TUNNELS_PER_UNIT = 0.5
CDP_BLOCK_ID = "playwright-cdp-block"
ROUTE_BLOCK_ID = "playwright-route-block"
BACKGROUND_ID = "chromium-background-flags"
MCP_ID = "playwright-mcp-flags"
REQUESTS_REUSE_ID = "requests-session-reuse"
HTTPX_REUSE_ID = "httpx-client-reuse"

#: Every fix id this version generates, in the contract's order.
FIX_IDS: tuple[str, ...] = (CDP_BLOCK_ID, ROUTE_BLOCK_ID, BACKGROUND_ID, MCP_ID, REQUESTS_REUSE_ID, HTTPX_REUSE_ID)
FIX_TITLES: dict[str, str] = {
    CDP_BLOCK_ID: "Block fonts and media per page with CDP; disable images at launch (keeps the HTTP cache)",
    ROUTE_BLOCK_ID: "Alternative: block with route() (disables the HTTP cache)",
    BACKGROUND_ID: "Refuse catalogued background hosts at the meter and keep one browser profile",
    MCP_ID: "If you use Playwright MCP: run it under a budgeted meter that refuses background hosts, and keep a profile",
    REQUESTS_REUSE_ID: "Reuse one requests.Session (keep-alive)",
    HTTPX_REUSE_ID: "Reuse one httpx.Client (keep-alive)",
}
FIX_LANGUAGES: dict[str, str] = {
    CDP_BLOCK_ID: "python",
    ROUTE_BLOCK_ID: "python",
    BACKGROUND_ID: "python",
    MCP_ID: "shell",
    REQUESTS_REUSE_ID: "python",
    HTTPX_REUSE_ID: "python",
}
#: Caveats a fix carries only when the run showed the condition (every other caveat is unconditional).
CONDITIONAL_CAVEATS = frozenset({ROUTE_MULTI_PAGE_CAVEAT})
#: Every caveat a fix can carry (a report read from a file may show only these).
FIX_CAVEATS: dict[str, tuple[str, ...]] = {
    CDP_BLOCK_ID: (BLOCKING_CAVEAT, CDP_LIMITS_CAVEAT, VERIFY_CAVEAT),
    ROUTE_BLOCK_ID: (BLOCKING_CAVEAT, ROUTE_CACHE_CAVEAT, ROUTE_MULTI_PAGE_CAVEAT, VERIFY_CAVEAT),
    BACKGROUND_ID: (SECURITY_CAVEAT, SWITCHES_CAVEAT, PROFILE_CAVEAT, VERIFY_CAVEAT),
    MCP_ID: (TOKENLESS_CAVEAT, PIN_CAVEAT, SECURITY_CAVEAT, PROFILE_CAVEAT, VERIFY_CAVEAT),
    REQUESTS_REUSE_ID: (REUSE_CAVEAT, VERIFY_CAVEAT),
    HTTPX_REUSE_ID: (REUSE_CAVEAT, VERIFY_CAVEAT),
}


def _fix(id: str, detection: str, code: str, caveats: Sequence[str], language: str | None = None) -> Fix:
    return Fix(
        id=id,
        title=safe_text(FIX_TITLES[id]),
        detection=safe_text(detection),
        language=language or FIX_LANGUAGES[id],  # type: ignore[arg-type]
        code=safe_code(code),
        caveats=[safe_text(c) for c in caveats],
    )


# ---------------------------------------------------------------------------
# Code builders (shared by generate_fixes and regenerate_fix)
# ---------------------------------------------------------------------------


def _host_list(hosts: Sequence[str]) -> str:
    return ", ".join(hosts) or "see the hosts table"


def background_code(hosts: Sequence[str], playwright: bool = True) -> str:
    """The chromium-background-flags snippet for these catalogued hosts.

    With ``playwright`` (Playwright helper events were seen): the meter-side
    refusal plus a metered, instrumented persistent context in Playwright
    (Python). Otherwise only the stack-independent part, as shell.
    """
    template = templates.CHROMIUM_BACKGROUND_FLAGS if playwright else templates.CHROMIUM_BACKGROUND_REFUSE
    return template.replace("{hosts}", _host_list(hosts))


def background_language(playwright: bool) -> str:
    """Language of the chromium-background-flags snippet (see :func:`background_code`)."""
    return FIX_LANGUAGES[BACKGROUND_ID] if playwright else "shell"


def mcp_code(hosts: Sequence[str]) -> str:
    """The playwright-mcp-flags snippet: the MCP server under a budgeted ``scrapescope run``."""
    return templates.PLAYWRIGHT_MCP_FLAGS.replace("{hosts}", _host_list(hosts))


def blocking_detection(blocked: int, total: int, gb_unit: str = "GB") -> str:
    """Detection text of the blocking fixes (image+media+font allocated bytes of the run's total)."""
    share = blocked / total if total > 0 else 0.0
    return (
        f"images, media and fonts were {share * 100:.0f}% of the run's bytes "
        f"({format_size(blocked, gb_unit)} allocated of {format_size(total, gb_unit)})"  # type: ignore[arg-type]
    )


def background_detection(total_background: int, ids: Sequence[str], gb_unit: str = "GB") -> str:
    """Detection text of the background fixes (bytes in the background buckets, catalog ids heaviest first)."""
    return (
        f"{format_size(total_background, gb_unit)} went to catalogued background hosts "  # type: ignore[arg-type]
        f"({', '.join(ids)})"
    )


def reuse_detection(tunnels: int, units: int) -> str:
    return f"{tunnels} new tunnels for {units} hook-counted requests ({tunnels / units:.2f} per request)"


def reuse_code(fix_id: str, detection: str) -> str:
    template = templates.REQUESTS_SESSION_REUSE if fix_id == REQUESTS_REUSE_ID else templates.HTTPX_CLIENT_REUSE
    return template.replace("{detection}", detection)


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------


def _blocking_fixes(attribution: AttributionResult, total: int, gb_unit: str) -> list[Fix]:
    if "playwright" not in attribution.sources or total <= 0:
        return []
    blocked = blockable_bytes(attribution)
    share = blocked / total
    if share < BLOCKING_SHARE_THRESHOLD:
        return []
    detection = blocking_detection(blocked, total, gb_unit)
    route_caveats = [BLOCKING_CAVEAT, ROUTE_CACHE_CAVEAT]
    if attribution.multi_page_context:
        route_caveats.append(ROUTE_MULTI_PAGE_CAVEAT)
    route_caveats.append(VERIFY_CAVEAT)
    return [
        _fix(CDP_BLOCK_ID, detection, templates.PLAYWRIGHT_CDP_BLOCK, [BLOCKING_CAVEAT, CDP_LIMITS_CAVEAT, VERIFY_CAVEAT]),
        _fix(ROUTE_BLOCK_ID, detection, templates.PLAYWRIGHT_ROUTE_BLOCK, route_caveats),
    ]


def _background_hosts(attribution: AttributionResult, catalogs: Catalogs) -> list[str]:
    """Catalogued background hosts with bytes in a background bucket, heaviest first."""
    rows = []
    for host in attribution.hosts:
        if catalogs.background_entry_for(host.host) is None:
            continue
        bucket_bytes = sum(t.bytes for name, t in host.buckets.items() if name.startswith("background:"))
        if bucket_bytes > 0:
            rows.append((bucket_bytes, host.host))
    rows.sort(key=lambda r: (-r[0], r[1]))
    return [h for _, h in rows]


def _background_fixes(attribution: AttributionResult, catalogs: Catalogs, gb_unit: str) -> list[Fix]:
    total_background = background_bytes(attribution)
    if total_background <= 0:
        return []
    ids = sorted(
        (cid for cid, b in attribution.buckets.background.items() if b > 0),
        key=lambda cid: (-attribution.buckets.background[cid], cid),
    )
    detection = background_detection(total_background, ids, gb_unit)
    hosts = _background_hosts(attribution, catalogs)
    playwright = "playwright" in attribution.sources
    return [
        _fix(BACKGROUND_ID, detection, background_code(hosts, playwright), FIX_CAVEATS[BACKGROUND_ID],
             background_language(playwright)),
        _fix(MCP_ID, detection, mcp_code(hosts), FIX_CAVEATS[MCP_ID]),
    ]


def _reuse_fixes(attribution: AttributionResult, snapshot: MeterSnapshot) -> list[Fix]:
    units = attribution.units
    if units.source != "requests" or units.count < REUSE_MIN_UNITS:
        return []
    # meas3-3: count upstream connections, not tunnel records. On the http-connect route a keep-alive
    # plain-HTTP client that switches host keeps its provider connection and only starts a new record.
    tunnels = sum(1 for t in snapshot.target_tunnels() if t.opened_connection)
    if tunnels / units.count < REUSE_TUNNELS_PER_UNIT:
        return []
    detection = reuse_detection(tunnels, units.count)
    fixes = []
    for source, fix_id in (("requests", REQUESTS_REUSE_ID), ("httpx", HTTPX_REUSE_ID)):
        if source in attribution.sources:
            fixes.append(_fix(fix_id, detection, reuse_code(fix_id, detection), FIX_CAVEATS[fix_id]))
    return fixes


def generate_fixes(
    attribution: AttributionResult,
    snapshot: MeterSnapshot,
    catalogs: Catalogs,
    *,
    gb_unit: str = "GB",
) -> list[Fix]:
    """Fixes whose detection fired, in the contract's order (possibly empty).

    ``gb_unit`` only changes how sizes are written in ``detection`` texts.
    """
    total = snapshot.totals().with_connect
    fixes: list[Fix] = []
    fixes += _blocking_fixes(attribution, total, gb_unit)
    fixes += _background_fixes(attribution, catalogs, gb_unit)
    fixes += _reuse_fixes(attribution, snapshot)
    return fixes


# ---------------------------------------------------------------------------
# Report files: rebuild fixes from their id instead of trusting stored code
# ---------------------------------------------------------------------------


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def report_background_hosts(report: Mapping[str, Any], catalogs: Catalogs) -> list[str]:
    """Catalogued background hosts named by a report's host rows (heaviest first).

    Only hosts that match this scrapescope's background catalog are returned;
    redacted rows (``catalog:<id>``) give that entry's literal host names.
    """
    rows: list[tuple[int, str]] = []
    entries = {entry.id: entry for entry in catalogs.background}
    hosts = report.get("hosts")
    for row in hosts if isinstance(hosts, list) else []:
        if not isinstance(row, Mapping):
            continue
        buckets = row.get("buckets")
        if not isinstance(buckets, Mapping) or not any(
            isinstance(name, str) and name.startswith("background:") for name in buckets
        ):
            continue
        label = row.get("host")
        weight = _as_int(row.get("bytes_with_connect"))
        if isinstance(label, str) and label.startswith("catalog:") and label[8:] in entries:
            rows += [(weight, h) for h in entries[label[8:]].hosts if "*" not in h]
        elif isinstance(label, str) and clean_host(label) == label and catalogs.background_entry_for(label):
            rows.append((weight, label))
    rows.sort(key=lambda r: (-r[0], r[1]))
    out: list[str] = []
    for _, host in rows:
        if host not in out:
            out.append(host)
    return out


#: Resource types that only hooks (``http_client``) or attribution (``unreported``) write.
_NON_BROWSER_TYPES = frozenset({"http_client", "unreported"})


def report_saw_playwright(report: Mapping[str, Any]) -> bool:
    """Whether a report's per-type rows hold browser request types (Playwright helper events).

    Reports do not store their event sources; browser resource types come only
    from the Playwright helper.
    """
    rows = report.get("types")
    for row in rows if isinstance(rows, list) else []:
        if (
            isinstance(row, Mapping)
            and isinstance(row.get("type"), str)
            and row.get("type") not in _NON_BROWSER_TYPES
            and _as_int(row.get("requests")) > 0
        ):
            return True
    return False


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _report_gb_unit(report: Mapping[str, Any]) -> str:
    return "GiB" if report.get("gb_unit") == "GiB" else "GB"


def _report_blocking_detection(report: Mapping[str, Any]) -> str:
    """The blocking detection rebuilt from a report's per-type allocated bytes and with-CONNECT total."""
    total = _as_int(_mapping(report.get("totals")).get("with_connect"))
    rows = report.get("types")
    blocked = sum(
        _as_int(row.get("allocated_bytes"))
        for row in (rows if isinstance(rows, list) else [])
        if isinstance(row, Mapping) and row.get("type") in BLOCKABLE_TYPES
    )
    if total <= 0:
        return "see the report's per-type figures"
    return blocking_detection(min(blocked, total), total, _report_gb_unit(report))


def _report_background_detection(report: Mapping[str, Any]) -> str:
    """The background detection rebuilt from a report's background buckets (catalog ids only)."""
    background = _mapping(_mapping(report.get("buckets")).get("background"))
    rows = [(n, cid) for cid, value in background.items()
            if isinstance(cid, str) and is_catalog_id(cid) and (n := _as_int(value)) > 0]
    if not rows:
        return "see the report's buckets"
    rows.sort(key=lambda r: (-r[0], r[1]))
    return background_detection(sum(n for n, _ in rows), [cid for _, cid in rows], _report_gb_unit(report))


def _report_reuse_detection(report: Mapping[str, Any]) -> str:
    totals = report.get("totals") if isinstance(report.get("totals"), Mapping) else {}
    units = report.get("units") if isinstance(report.get("units"), Mapping) else {}
    tunnels = _as_int(totals.get("tunnels"))  # type: ignore[union-attr]
    count = _as_int(units.get("count"))  # type: ignore[union-attr]
    if units.get("source") != "requests" or count <= 0:  # type: ignore[union-attr]
        return "see the report's units and tunnels"
    return reuse_detection(tunnels, count)


def regenerate_fix(fix: Mapping[str, Any], report: Mapping[str, Any], catalogs: Catalogs) -> Fix | None:
    """Rebuild a fix of a report read from a file; None for an id this version does not generate.

    Title, language, detection, code and caveats come from this scrapescope
    (templates filled with catalogued hosts and the report's own figures), never
    from the file: the stored detection text is ignored, so a crafted file cannot
    put its own words under scrapescope's fix title. A fix carries every
    unconditional caveat of its id; a conditional one (see
    :data:`CONDITIONAL_CAVEATS`) only when the stored fix carried it.
    """
    fix_id = fix.get("id")
    if not isinstance(fix_id, str) or fix_id not in FIX_TITLES:
        return None
    language = None
    if fix_id in (CDP_BLOCK_ID, ROUTE_BLOCK_ID):
        detection = _report_blocking_detection(report)
        code = templates.PLAYWRIGHT_CDP_BLOCK if fix_id == CDP_BLOCK_ID else templates.PLAYWRIGHT_ROUTE_BLOCK
    elif fix_id == BACKGROUND_ID:
        detection = _report_background_detection(report)
        playwright = report_saw_playwright(report)
        code = background_code(report_background_hosts(report, catalogs), playwright)
        language = background_language(playwright)
    elif fix_id == MCP_ID:
        detection = _report_background_detection(report)
        code = mcp_code(report_background_hosts(report, catalogs))
    else:
        detection = _report_reuse_detection(report)
        code = reuse_code(fix_id, detection)
    stored = fix.get("caveats")
    stored_texts = {c for c in stored if isinstance(c, str)} if isinstance(stored, list) else set()
    caveats = [c for c in FIX_CAVEATS[fix_id] if c not in CONDITIONAL_CAVEATS or c in stored_texts]
    return _fix(fix_id, detection, code, caveats, language)


__all__ = [
    "BLOCKING_SHARE_THRESHOLD",
    "FIX_CAVEATS",
    "FIX_IDS",
    "FIX_LANGUAGES",
    "FIX_TITLES",
    "CONDITIONAL_CAVEATS",
    "PIN_CAVEAT",
    "TOKENLESS_CAVEAT",
    "REUSE_MIN_UNITS",
    "REUSE_TUNNELS_PER_UNIT",
    "SECURITY_CAVEAT",
    "VERIFY_CAVEAT",
    "background_code",
    "background_detection",
    "blocking_detection",
    "background_language",
    "generate_fixes",
    "mcp_code",
    "regenerate_fix",
    "report_background_hosts",
    "report_saw_playwright",
]
