"""Formatting helpers shared by the text and HTML renderers.

Renderers take a report dict that may come from disk, so every accessor here
tolerates missing or mistyped values instead of raising.
"""

from __future__ import annotations

import math
from typing import Any

from ..config import format_size
from ..types import safe_text


def get(obj: Any, *keys: str, default: Any = None) -> Any:
    """Nested ``dict.get`` that tolerates non-dicts on the way."""
    for key in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key, default)
    return obj


def as_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if isinstance(value, float) and not math.isfinite(value):
        return 0
    return int(value)


def as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def unit_of(report: dict[str, Any]) -> str:
    return "GiB" if report.get("gb_unit") == "GiB" else "GB"


def size(n: Any, unit: str) -> str:
    """Human-readable size (kB/MB/GB, or KiB/MiB/GiB with --gib)."""
    return format_size(as_int(n), unit)  # type: ignore[arg-type]


def size_exact(n: Any, unit: str) -> str:
    """``11.51 MB (11,507,680 B)``."""
    value = as_int(n)
    human = format_size(value, unit)  # type: ignore[arg-type]
    return human if value < 1000 else f"{human} ({value:,} B)"


def num(n: Any) -> str:
    return f"{as_int(n):,}"


def pct(x: Any) -> str:
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
        return "-"
    return f"{x * 100:.1f}%"


#: Significant digits of amounts below one dollar (ux-1): every cost line of a report reads alike.
MONEY_SIGNIFICANT_DIGITS = 3


def money(x: Any) -> str:
    """USD: cents from one dollar up ("$12.35"), else three significant digits ("$0.120", "$0.00235").

    At most 6 decimals, the precision costs are stored with ("$0.000045").
    """
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
        return "-"
    if abs(x) < 1 and x != 0:
        magnitude = math.floor(math.log10(abs(x)))
        decimals = min(6, max(2, MONEY_SIGNIFICANT_DIGITS - 1 - magnitude))
        if abs(round(x, decimals)) < 1:
            return f"${x:.{decimals}f}"
    return f"${x:,.2f}"


def yes_no(value: Any) -> str:
    return "yes" if value is True else "no"


def text(value: Any, max_len: int = 500) -> str:
    """One safe line (every untrusted string passes through here)."""
    if value is None:
        return "-"
    return safe_text(value, max_len)


def rate_unit(report: dict[str, Any]) -> str:
    return "USD per GiB" if unit_of(report) == "GiB" else "USD per GB"


def unit_note(unit: str) -> str:
    return "GiB = 2^30 bytes" if unit == "GiB" else "GB = 10^9 bytes"


def flags_text(flags: Any) -> str:
    names = {
        "sent_cookies": "sent cookies",
        "sent_authorization": "sent authorization",
        "random_query_token": "random-looking token",
        "third_party": "third-party",
        "sent_token_header": "sent a token header",
        "non_get": "not GET",
    }
    on = [label for key, label in names.items() if get(flags, key) is True]
    return ", ".join(on) if on else "-"


def _kind_name(kind: str) -> str:
    if kind == "variant:substring":
        return "substring (not counted)"
    return kind.split(":", 1)[1] if kind.startswith("variant:") else kind


def match_kind_text(kinds: Any) -> str:
    """The report's match column: the one kind every value shares, else ``mixed:`` with each value's kind.

    ``exact``, ``variant: <id>``, or ``mixed: 1 number-format, 2 exact`` (a
    weak hit reads ``substring (not counted)``, a value the response lacks
    ``none``), like the terminal's ``mixed`` with its per-value lines.
    """
    kinds = [k if isinstance(k, str) else "none" for k in as_list(kinds)]
    if not kinds:
        return "-"
    if len(set(kinds)) == 1:
        kind = kinds[0]
        return "variant: " + _kind_name(kind) if kind.startswith("variant:") else kind
    return "mixed: " + ", ".join(f"{i} {_kind_name(k)}" for i, k in enumerate(kinds, start=1))


def values_text(match: Any) -> str:
    """The report's values column, as the terminal's: ``all 2/2`` or ``some 1/2``."""
    head = "all" if get(match, "all_values") is True else "some"
    kinds = as_list(get(match, "match_kinds"))
    return f"{head} {as_int(get(match, 'values_matched'))}/{len(kinds)}" if kinds else head


def replays_text(verify: Any) -> str:
    """The --verify outcome as one safe line (the stored reason passes through ``safe_text``)."""
    replays = get(verify, "replays")
    label = {"yes": "yes", "no": "no", "not_tested": "not tested"}.get(replays, "not tested")
    reason = get(verify, "reason")
    return f"{label} ({text(reason, 200)})" if isinstance(reason, str) and reason else label


_VERIFY_PREFIX = "replays without a browser: "


def find_replay_text(find: Any) -> str:
    """A find entry's --verify outcome as the terminal prints it, without the ``replays without a browser:`` label.

    The entry is rebuilt with ``FindResult.from_dict`` and passed to
    :func:`scrapescope.find.render.verify_line`, so it names the replayed
    rank (and a value that response lacks) as the terminal does; an entry
    that cannot be rebuilt falls back to :func:`replays_text`.
    """
    fallback = replays_text(get(find, "verify"))
    result = _rebuilt_find(find)
    if result is None:
        return fallback
    from ..find.render import verify_line

    try:
        line = verify_line(result)
    except (ValueError, TypeError, KeyError, AttributeError):
        return fallback
    if line is None or not line.startswith(_VERIFY_PREFIX):
        return fallback
    return line[len(_VERIFY_PREFIX) :]


def host_path(host: Any, path: Any) -> str:
    h = host if isinstance(host, str) else "-"
    return f"{h}{path}" if isinstance(path, str) and path else h


# ---------------------------------------------------------------------------
# Provenance of a report: built here, or read from a file
# ---------------------------------------------------------------------------


class GeneratedReport(dict):  # type: ignore[type-arg]
    """A report dict that ``build_report`` assembled in this process.

    Renderers show the stored code of its fixes, which this process generated.
    Any other dict (a report read from a file, or assembled by hand) is
    untrusted: fix titles, detections, code and caveats are rebuilt from the
    fix id and the report's own figures by
    :func:`scrapescope.snippets.regenerate_fix`, never shown as stored.
    """


def is_generated(report: Any) -> bool:
    return isinstance(report, GeneratedReport)


#: Resource types that only hooks (``http_client``) or attribution (``unreported``) write.
_NON_BROWSER_TYPES = frozenset({"http_client", "unreported"})
UNREPORTED_TYPE = "unreported"
PER_UNIT_WITHHELD_PREFIX = "first unit vs the rest not shown"
LAUNCHES_NOT_RECORDED = (
    "not recorded (a browser ran, but no launch was recorded: use launch(), instrument() on a context "
    "made with browser.new_context(), or record_launch())"
)


def is_find(report: dict[str, Any]) -> bool:
    return report.get("command") == "find"


def browser_launches_text(report: dict[str, Any]) -> str:
    """Launch count, or "not recorded" when browser request types exist but no launch was recorded."""
    launches = as_int(report.get("browser_launches"))
    if launches == 0 and not is_find(report):
        browser_rows = [
            t for t in as_list(report.get("types"))
            if isinstance(get(t, "type"), str) and get(t, "type") not in _NON_BROWSER_TYPES and as_int(get(t, "requests")) > 0
        ]
        if browser_rows:
            return LAUNCHES_NOT_RECORDED
    return num(launches)


#: Label of the status histogram line: network requests only; "failed" means no response arrived.
STATUS_LABEL = "status (network requests; failed = no response)"
#: Diagnostics label for MeterSnapshot.accept_limit_errors (report.json "accept_limit_errors").
ACCEPT_LIMIT_LABEL = "accepting paused for lack of file descriptors (this machine's open-files limit)"
#: Label and explanation of the request events that are not network requests.
NOT_NETWORK_LABEL = "not network requests"
NOT_NETWORK_NOTE = (
    "HTTP-cache hits, service-worker answers, and requests answered or stopped before the network "
    "(route.fulfill, route.abort, browser blocks such as mixed content); not in the status line or "
    "per-type figures"
)


def connections_text(totals: Any) -> str | None:
    """The totals' upstream-connection count when it differs from the record count (meas4-6), else None.

    On the HTTP CONNECT route a keep-alive plain-HTTP client that switches host keeps its
    provider connection; each host gets a record of its own, so there are fewer connections
    than tunnel records. Reports from before round 4 have no ``connections`` and show nothing.
    """
    t = as_dict(totals)
    connections, tunnels = t.get("connections"), t.get("tunnels")
    if not isinstance(connections, int) or isinstance(connections, bool) or not isinstance(tunnels, int):
        return None
    if connections == tunnels:
        return None
    return (
        f"{num(connections)} (fewer than tunnels: a kept provider connection carried records for "
        "several hosts)"
    )


def served_without_network(report: dict[str, Any]) -> int:
    """Request events that are not network requests (events minus network requests).

    HTTP-cache hits, page requests a service worker answered, and requests the
    helpers marked as answered or stopped before the network (``route.fulfill``,
    ``route.abort``, browser blocks such as mixed content).
    """
    events = as_int(get(report, "helper_events", "request"))
    network = sum(as_int(v) for v in as_dict(report.get("status_histogram")).values())
    return max(0, events - network)


def per_unit_withheld(report: dict[str, Any]) -> bool:
    return report.get("per_unit") is None and any(
        isinstance(w, str) and w.startswith(PER_UNIT_WITHHELD_PREFIX) for w in as_list(report.get("warnings"))
    )


def verify_replayed(report: dict[str, Any]) -> bool:
    """True when a find entry's --verify replay said yes or no (its tunnel is then part of the run's totals).

    A known limit (docs/method.md section 8): a replay that was sent but came
    back ``not_tested`` (a gateway error, over the size cap, an unsupported
    encoding, past its deadline) also moved tunnel bytes, yet is not counted
    here, so the labels read "find page load" for it.
    """
    return any(get(f, "verify", "replays") in ("yes", "no") for f in as_list(report.get("find")))


def find_load_label(report: dict[str, Any]) -> str:
    """What a find report's unattributed tunnel bytes are: the page load, plus the --verify replay when sent."""
    return "find page load and --verify replay" if verify_replayed(report) else "find page load"


def host_requests_text(report: dict[str, Any], row: Any) -> str:
    """A hosts-table row's helper-reported request count; "-" in a find report.

    find writes no helper events, so every find host has 0 helper-reported
    requests although find saw its responses (counted in the find section).
    """
    return "-" if is_find(report) else num(get(row, "requests"))


def footer_text(report: dict[str, Any]) -> str:
    """The closing accuracy line, naming only the kinds of figures the report holds."""
    parts = ["Totals are tunnel-measured at the meter's upstream socket"]
    if as_list(report.get("types")):
        parts.append("per-type figures are allocated")
    if is_find(report):
        parts.append("find's response sizes are browser-reported and its billed-basis figures are estimates")
    if isinstance(report.get("cost"), dict):
        parts.append("costs are estimated billable transfer at your rate")
    return "; ".join(parts) + ". This is a measurement, not a bill."


def _rebuilt_find(find: Any) -> Any:
    """A report's find entry as a ``FindResult`` (``FindResult.from_dict``), or None when it does not rebuild."""
    if not isinstance(find, dict):
        return None
    from ..types import FindResult

    try:
        return FindResult.from_dict(find)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def verify_hosts(report: dict[str, Any]) -> set[str] | None:
    """Hosts the --verify replays went to (their tunnels hold replay bytes), or None when unknown.

    The replayed match is chosen as ``find`` chose it
    (:func:`scrapescope.find.render.replayed_match`, which applies
    ``heuristics.select_verify_target`` to the rebuilt entry): the top eligible
    match, or a higher-ranked one withheld only for the cookies or token header
    it sent, which stays ineligible when its replay said no. Hosts compare
    equal under ``--redact-hosts`` too (one key per report). None when a
    replay was sent but its match is not in the report. Like
    :func:`verify_replayed`, only replays that said yes or no count.
    """
    from ..find.render import replayed_match

    hosts: set[str] = set()
    for f in as_list(report.get("find")):
        if get(f, "verify", "replays") not in ("yes", "no"):
            continue
        result = _rebuilt_find(f)
        try:
            target = replayed_match(result) if result is not None else None
        except (ValueError, TypeError, KeyError, AttributeError):
            target = None
        if target is None or not isinstance(target.host, str):
            return None
        hosts.add(target.host)
    return hosts


def bucket_label(report: dict[str, Any], name: str, host: Any = None) -> str:
    """A bucket name for display; find reports call the unattributed page load what it is.

    With ``host`` (a hosts-table row), the --verify replay is named only for the
    host it went to; without it (run-level buckets), whenever a replay was sent.
    """
    if not (is_find(report) and name == "unattributed"):
        return name
    if host is None or not verify_replayed(report):
        return find_load_label(report)
    replayed = verify_hosts(report)
    if replayed is None or host in replayed:
        return "find page load and --verify replay"
    return "find page load"


def fix_views(report: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """(fixes to show, generated here). Fixes of untrusted reports are rebuilt from their id.

    Each view has ``id``, ``title``, ``detection``, ``language``, ``code`` and
    ``caveats``; a fix id this version does not generate gives a view with
    ``code`` None and ``unknown`` True.
    """
    fixes = [f for f in as_list(report.get("fixes")) if isinstance(f, dict)]
    if is_generated(report):
        return fixes, True
    from ..catalog import load_catalogs
    from ..snippets import regenerate_fix

    catalogs = load_catalogs()
    views: list[dict[str, Any]] = []
    for fix in fixes:
        rebuilt = regenerate_fix(fix, report, catalogs)
        if rebuilt is None:
            views.append({"id": fix.get("id"), "title": "not a fix this scrapescope generates; omitted",
                          "detection": None, "language": None, "code": None, "caveats": [], "unknown": True})
        else:
            views.append(rebuilt.to_dict())
    return views, False


def best_match_share_text(report: dict[str, Any], find: Any) -> str | None:
    """find's own page-load share line for a report's find entry (None when no share applies).

    The entry is rebuilt with ``FindResult.from_dict`` and passed to
    :func:`scrapescope.find.render.share_line`, so the report prints exactly
    the terminal's line (find3-1): the smallest response holding every value,
    network copies first; its body and headers against the page load's
    DevTools-reported bytes, TLS left out of both; shown only for a
    code-eligible network response and called a saving only when the
    ``--verify`` replay of that response said yes. An ineligible top match
    gets ``share of this page load: not shown for rank N (<why>)``. The line is
    already sanitised. The report's ``unit`` does not apply: the terminal
    prints bytes.
    """
    from ..find.render import share_line

    result = _rebuilt_find(find)
    if result is None:
        return None
    try:
        return share_line(result)
    except (ValueError, TypeError, KeyError, AttributeError, ZeroDivisionError):
        return None


__all__ = [
    "LAUNCHES_NOT_RECORDED",
    "NOT_NETWORK_LABEL",
    "NOT_NETWORK_NOTE",
    "STATUS_LABEL",
    "ACCEPT_LIMIT_LABEL",
    "MONEY_SIGNIFICANT_DIGITS",
    "PER_UNIT_WITHHELD_PREFIX",
    "UNREPORTED_TYPE",
    "GeneratedReport",
    "as_dict",
    "best_match_share_text",
    "browser_launches_text",
    "bucket_label",
    "find_load_label",
    "find_replay_text",
    "fix_views",
    "footer_text",
    "host_requests_text",
    "is_find",
    "is_generated",
    "per_unit_withheld",
    "served_without_network",
    "as_int",
    "as_list",
    "flags_text",
    "get",
    "host_path",
    "match_kind_text",
    "money",
    "num",
    "pct",
    "rate_unit",
    "replays_text",
    "size",
    "size_exact",
    "text",
    "unit_note",
    "unit_of",
    "values_text",
    "verify_hosts",
    "verify_replayed",
    "yes_no",
]
