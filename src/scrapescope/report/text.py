"""Terminal summary of a report: plain text, no colours, clearly labelled.

Every string from the report passes through ``safe_text`` (control, bidi and
BOM characters are shown as escapes), so a hostile host or path cannot move the
cursor or reorder the terminal line. Figures keep their accuracy labels:
totals are tunnel-measured, per-type bytes allocated, costs estimated billable
transfer; none of it is a bill.
"""

from __future__ import annotations

from typing import Any

from ._fmt import (
    ACCEPT_LIMIT_LABEL,
    NOT_NETWORK_LABEL,
    NOT_NETWORK_NOTE,
    STATUS_LABEL,
    UNREPORTED_TYPE,
    as_dict,
    as_int,
    as_list,
    best_match_share_text,
    browser_launches_text,
    connections_text,
    bucket_label,
    find_load_label,
    find_replay_text,
    fix_views,
    flags_text,
    footer_text,
    get,
    host_requests_text,
    host_path,
    is_find,
    match_kind_text,
    money,
    num,
    pct,
    per_unit_withheld,
    served_without_network,
    size,
    size_exact,
    text,
    unit_note,
    unit_of,
    values_text,
    yes_no,
)

RULE = "-" * 72
TYPES_HEADING = (
    "Resource types (allocated: each host's tunnel bytes shared in proportion to reported sizes, "
    "scaled down or up)"
)
UNREPORTED_NOTE = (
    "unreported: tunnel bytes beyond the reported sizes and an overhead allowance (requests in flight "
    "when a page navigated or closed, open WebSockets, clients without helpers); not in what-if or fixes"
)
#: The closing line of a report with per-type figures and costs; ``footer_text`` names only what a
#: report holds (a find report has no per-type figures, a report without --rate no costs).
NOT_A_BILL = (
    "Totals are tunnel-measured at the meter's upstream socket; per-type figures are allocated; "
    "costs are estimated billable transfer at your rate. This is a measurement, not a bill."
)


def _table(headers: list[str], rows: list[list[str]], right: set[int] | None = None, max_width: int = 48) -> list[str]:
    right = right or set()
    cells = [[text(c, max_width) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(values: list[str]) -> str:
        parts = [v.rjust(widths[i]) if i in right else v.ljust(widths[i]) for i, v in enumerate(values)]
        return ("  " + "  ".join(parts)).rstrip()

    return [line(headers), line(["-" * w for w in widths])] + [line(r) for r in cells]


def _section(title: str) -> list[str]:
    return ["", title, RULE]


def _header(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    lines = [
        f"scrapescope {text(report.get('tool_version'))} report: {text(report.get('command'))}",
        f"  mode: {text(report.get('mode'))}   unit: {unit} ({unit_note(unit)})",
        f"  started {text(report.get('started_at'))}   ended {text(report.get('ended_at'))}",
    ]
    versions = as_dict(report.get("catalog_versions"))
    if versions:
        lines.append(
            "  catalogs: " + ", ".join(f"{text(k)} {text(v)}" for k, v in sorted(versions.items()))
        )
    return lines


def _banners(report: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    if report.get("incomplete") is True:
        bypass = as_dict(report.get("bypass"))
        hosts = [text(h, 80) for h in as_list(bypass.get("hosts"))[:5]]
        requests = as_int(bypass.get("requests"))
        lines += [
            "",
            "!! INCOMPLETE: helpers or hooks reported traffic that the meter did not carry "
            f"(hosts: {', '.join(hosts) or '-'})"
            + (f"; {num(requests)} request(s) found no meter tunnel to their host" if requests > 0 else "")
            + ". Totals miss that traffic (see Warnings).",
        ]
    if get(report, "budget", "tripped") is True:
        lines += ["", "!! BUDGET TRIPPED: the meter closed every tunnel and refused new ones (see Budget)."]
    return lines


def _totals(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    t = as_dict(report.get("totals"))
    estimated = t.get("with_connect_estimated") is True
    label = "tunnel-measured" + ("; with-CONNECT estimated in sizing mode" if estimated else "")
    lines = _section(f"Totals ({label})") + [
        f"  with CONNECT      {size_exact(t.get('with_connect'), unit)}" + ("  [estimated]" if estimated else ""),
        f"  without CONNECT   {size_exact(t.get('without_connect'), unit)}",
        f"  sent / received   {size(t.get('bytes_sent'), unit)} / {size(t.get('bytes_received'), unit)}",
        f"  tunnels           {num(t.get('tunnels'))} ({num(t.get('failed_tunnels'))} failed, "
        f"{num(t.get('denied_tunnels'))} denied)",
    ]
    connections = connections_text(t)
    if connections:
        lines.append(f"  connections       {connections}")
    return lines


def _budget(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    b = as_dict(report.get("budget"))
    limit = b.get("limit_bytes")
    cap = b.get("max_tunnel_bytes")
    counted = as_int(b.get("counted_bytes"))
    lines = _section("Budget (upstream socket bytes, both directions, negotiation included)")
    if isinstance(limit, int) and limit > 0:
        lines.append(f"  limit {size(limit, unit)}; counted {size(counted, unit)} ({pct(counted / limit)})")
    else:
        lines.append(f"  no budget set; counted {size(counted, unit)}")
    lines.append(f"  per-tunnel cap: {size(cap, unit) if isinstance(cap, int) else 'none'}; tripped: {yes_no(b.get('tripped'))}")
    for ev in as_list(report.get("budget_events")):
        kind = get(ev, "kind")
        when = text(get(ev, "ts"))
        if kind == "warn_80":
            lines.append(f"  {when} warning: 80% of the budget reached ({size(get(ev, 'counted_bytes'), unit)})")
        elif kind == "tripped":
            top = ", ".join(
                f"{text(get(h, 'host'), 80)} ({size(get(h, 'bytes'), unit)})" for h in as_list(get(ev, "top_hosts"))
            )
            lines.append(
                f"  {when} TRIPPED at {size(get(ev, 'counted_bytes'), unit)}; closed {num(get(ev, 'closed_tunnels'))} tunnel(s)"
            )
            if top:
                lines.append(f"    heaviest hosts in the final minute: {top}")
        elif kind == "tunnel_cap":
            lines.append(
                f"  {when} tunnel #{num(get(ev, 'tunnel_id'))} to {text(get(ev, 'host'), 80)} closed at "
                f"{size(get(ev, 'counted_bytes'), unit)} (per-tunnel cap)"
            )
    if isinstance(limit, int) and limit > 0:
        lines.append(
            "  The meter stops at its own count; bytes already in flight at the provider may add a few MB per open tunnel."
        )
    return lines


def _units(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    u = as_dict(report.get("units"))
    count = as_int(u.get("count"))
    if is_find(report):
        return _section("Page load (find)") + [
            "  find loaded one page itself: units, per-unit and per-request attribution do not apply",
            f"  browser launches: {browser_launches_text(report)}",
        ]
    lines = _section("Units (denominator for per-1,000 figures)")
    lines.append(f"  units: {num(count)} ({text(u.get('source'))})")
    if u.get("low_sample_warning") is True and count > 0:
        lines.append("  warning: fewer than 20 units; per-1,000 figures are unreliable")
    lines.append(f"  browser launches: {browser_launches_text(report)}")
    before = report.get("bytes_before_first_navigation")
    if isinstance(before, int):
        lines.append(f"  bytes before the first navigation: {size(before, unit)} (approximate to the meter timeline)")
    pu = report.get("per_unit")
    if isinstance(pu, dict):
        mean = pu.get("rest_mean_bytes")
        lines.append(
            f"  first unit: {size(pu.get('first_unit_bytes'), unit)}; rest: {num(pu.get('rest_units'))} unit(s), "
            f"{size(pu.get('rest_bytes'), unit)}"
            + (f", mean {size(mean, unit)} per unit" if isinstance(mean, int) else "")
            + f" (timeline at {text(pu.get('resolution_s'), 16)} s; approximate)"
        )
    success = report.get("success")
    if isinstance(success, dict):
        rate = success.get("rate")
        lines.append(
            f"  success: {num(success.get('count'))} ({text(success.get('basis'))})"
            + (f", rate {pct(rate)}" if isinstance(rate, (int, float)) else "")
        )
    if per_unit_withheld(report):
        lines.append("  first unit vs the rest: not shown (units started closer together than the meter's "
                     "timeline step; see Warnings)")
    hist = as_dict(report.get("status_histogram"))
    if hist:
        lines.append(f"  {STATUS_LABEL}: " + ", ".join(f"{text(k, 8)} x{num(v)}" for k, v in sorted(hist.items())))
    cached = served_without_network(report)
    if cached:
        lines.append(f"  {NOT_NETWORK_LABEL}: {num(cached)} request event(s): {NOT_NETWORK_NOTE}")
    return lines


def _hosts(report: dict[str, Any], limit: int) -> list[str]:
    unit = unit_of(report)
    hosts = as_list(report.get("hosts"))
    if not hosts:
        return _section("Hosts") + ["  none"]
    rows = []
    for h in hosts[:limit]:
        buckets = ", ".join(sorted(text(bucket_label(report, k, get(h, "host")), 80) for k in as_dict(get(h, "buckets"))))
        rows.append(
            [
                get(h, "host", default="-"),
                num(get(h, "tunnels")),
                num(get(h, "failed_tunnels")),
                size(get(h, "bytes_with_connect"), unit),
                size(get(h, "bytes_without_connect"), unit),
                host_requests_text(report, h),
                buckets or "-",
            ]
        )
    shown = f"top {min(limit, len(hosts))} of {len(hosts)}"
    lines = _section(f"Hosts ({shown}; tunnel-measured)")
    lines += _table(
        ["host", "tunnels", "failed", "with CONNECT", "without", "requests", "buckets"],
        rows,
        right={1, 2, 3, 4, 5},
    )
    for h in hosts[:limit]:
        paths = as_list(get(h, "paths"))
        if paths:
            lines.append(f"  paths on {text(get(h, 'host'), 80)} (reported bytes):")
            for p in paths[:10]:
                lines.append(f"    {text(get(p, 'path'), 120)}  {num(get(p, 'requests'))} req  {size(get(p, 'reported_bytes'), unit)}")
    return lines


def _buckets(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    b = as_dict(report.get("buckets"))
    unattributed = (
        f"{find_load_label(report)} (see the find section)"
        if is_find(report)
        else "unattributed"
    )
    rows = [
        ["attributed (matched helper requests)", size(b.get("attributed"), unit)],
        ["preconnect_idle (no request, small)", size(b.get("preconnect_idle"), unit)],
        ["before_attach (before helpers attached)", size(b.get("before_attach"), unit)],
        [unattributed, size(b.get("unattributed"), unit)],
    ]
    for cid, n in sorted(as_dict(b.get("background")).items()):
        rows.append([f"background:{cid} (catalogued)", size(n, unit)])
    return _section("Buckets (with CONNECT; they add up to the total)") + _table(["bucket", "bytes"], rows, right={1}, max_width=72)


def _types(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    types = as_list(report.get("types"))
    if not types:
        return []
    rows = [
        [get(t, "type", default="-"), num(get(t, "requests")), size(get(t, "reported_bytes"), unit), size(get(t, "allocated_bytes"), unit)]
        for t in types
    ]
    lines = _section(TYPES_HEADING) + _table(["type", "requests", "reported", "allocated"], rows, right={1, 2, 3})
    if any(get(t, "type") == UNREPORTED_TYPE for t in types):
        lines.append(f"  {UNREPORTED_NOTE}")
    return lines


def _non_target(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    rows = [
        [get(n, "host", default="-"), get(n, "catalog_id", default="-"), num(get(n, "tunnels")),
         size(get(n, "bytes_sent"), unit), size(get(n, "bytes_received"), unit)]
        for n in as_list(report.get("non_target"))
    ]
    if not rows:
        return []
    return _section("Non-target hosts (carried direct, not sent to the upstream; excluded from totals)") + _table(
        ["host", "direct.json", "tunnels", "sent", "received"], rows, right={2, 3, 4}
    )


def _find(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    lines: list[str] = []
    for f in as_list(report.get("find")):
        lines += _section(f"find: {text(host_path(get(f, 'target_host'), get(f, 'target_path')), 200)}")
        status = get(f, "status")
        lines.append(f"  result: {text(status)}   values: {num(get(f, 'values_count'))}")
        if get(f, "challenge", "blocked") is True:
            lines.append(f"  challenge: {text(get(f, 'challenge', 'vendor_name') or 'unrecognised vendor')}")
        lines.append(f"  {text(get(f, 'coverage', 'line'))}")
        share = best_match_share_text(report, f)
        if share is not None:
            lines.append(f"  {share}")
        matches = as_list(get(f, "matches"))
        if matches:
            rows = []
            for m in matches:
                rows.append(
                    [
                        num(get(m, "rank")),
                        host_path(get(m, "host"), get(m, "path")),
                        get(m, "resource_type", default="-"),
                        get(m, "method", default="-"),
                        str(get(m, "status")) if isinstance(get(m, "status"), int) else "-",
                        size(get(m, "billed_basis_bytes"), unit),
                        values_text(m),
                        match_kind_text(get(m, "match_kinds")),
                        flags_text(get(m, "flags")),
                        "yes" if get(m, "code_eligible") is True else "no",
                    ]
                )
            lines += _table(
                ["#", "response", "type", "method", "status", "billed basis", "values", "match", "flags", "code"],
                rows,
                right={0, 5},
            )
        lines.append(f"  replays without a browser: {find_replay_text(f)}")
        find_warnings = as_list(get(f, "warnings"))
        if get(f, "short_value_warning") is True and not any("short" in str(w).lower() for w in find_warnings):
            lines.append("  warning: a value is short or numeric; the smallest match is often a beacon or an ID")
        for w in find_warnings:
            lines.append(f"  warning: {text(w)}")
    return lines


def _what_if(report: dict[str, Any]) -> list[str]:
    unit = unit_of(report)
    items = as_list(report.get("what_if"))
    if not items:
        return []
    lines = _section("What-if (allocated basis; modelled, not measured)")
    for w in items:
        lines.append(
            f"  {text(get(w, 'title'))}: would remove about {size(get(w, 'bytes_saved'), unit)} "
            f"({pct(get(w, 'share'))} of this run, modelled)"
        )
        for c in as_list(get(w, "caveats")):
            lines.append(f"    - {text(c)}")
    return lines


def _fixes(report: dict[str, Any], show_code: bool) -> list[str]:
    fixes, generated = fix_views(report)
    if not fixes:
        return []
    lines = _section("Suggested fixes (only for detections that fired)")
    if not generated:
        lines.append("  Read from a report file: titles, detections, code and caveats are rebuilt by this scrapescope")
        lines.append("  from each fix id and the file's own figures. Code and text stored in fixes are never shown.")
    for f in fixes:
        lines.append(f"  [{text(get(f, 'id'), 64)}] {text(get(f, 'title'))}")
        if get(f, "unknown") is True:
            continue
        lines.append(f"    detected: {text(get(f, 'detection'))}")
        for c in as_list(get(f, "caveats")):
            lines.append(f"    - {text(c)}")
        code = get(f, "code")
        if show_code and isinstance(code, str):
            origin = "" if generated else ", rebuilt from the fix id"
            lines.append(f"    code ({text(get(f, 'language'), 16)}{origin}):")
            for code_line in code.splitlines():
                lines.append("      " + text(code_line, 400))
    return lines


def _cost(report: dict[str, Any]) -> list[str]:
    c = report.get("cost")
    if not isinstance(c, dict):
        return []
    rate = c.get("rate")
    rate_text = f"{rate:g}" if isinstance(rate, (int, float)) and not isinstance(rate, bool) else "-"
    lines = _section(f"Cost (estimated billable transfer at your rate: {rate_text} {text(c.get('rate_unit'))}; not a bill)")
    lines.append(f"  with CONNECT          {money(c.get('with_connect'))}")
    lines.append(f"  without CONNECT       {money(c.get('without_connect'))}")
    if c.get("per_1000_units") is not None:
        lines.append(f"  per 1,000 units       {money(c.get('per_1000_units'))}")
    if c.get("per_1000_successes") is not None:
        lines.append(f"  per 1,000 successes   {money(c.get('per_1000_successes'))}")
    return lines


def _diagnostics(report: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    refused = {k: v for k, v in as_dict(report.get("refused")).items() if as_int(v) > 0}
    failures = {k: v for k, v in as_dict(report.get("tunnel_failures")).items() if as_int(v) > 0}
    accept_errors = as_int(report.get("accept_limit_errors"))
    events = as_dict(report.get("helper_events"))
    if refused or failures or accept_errors > 0 or any(as_int(v) for v in events.values()):
        lines += _section("Diagnostics")
        if refused:
            lines.append("  refused before a tunnel: " + ", ".join(f"{text(k, 32)} {num(v)}" for k, v in sorted(refused.items())))
        if failures:
            lines.append("  failed tunnels: " + ", ".join(f"{text(k, 40)} {num(v)}" for k, v in sorted(failures.items())))
        if accept_errors > 0:
            lines.append(f"  {ACCEPT_LIMIT_LABEL}: {num(accept_errors)} time(s)")
        if events:
            lines.append(
                "  helper events: "
                + ", ".join(f"{name} {num(events.get(name))}" for name in ("attach", "launch", "request", "dropped"))
            )
    return lines


def _warnings(report: dict[str, Any]) -> list[str]:
    warnings = as_list(report.get("warnings"))
    if not warnings:
        return []
    return _section("Warnings") + [f"  - {text(w)}" for w in warnings]


def render_text(report: dict[str, Any], *, max_hosts: int = 20, show_code: bool = True) -> str:
    """The terminal summary (plain text, ends with a newline).

    ``max_hosts`` limits the hosts table; ``show_code=False`` omits fix code.
    """
    lines: list[str] = []
    lines += _header(report)
    lines += _banners(report)
    lines += _totals(report)
    lines += _budget(report)
    lines += _units(report)
    lines += _hosts(report, max_hosts)
    lines += _buckets(report)
    lines += _types(report)
    lines += _non_target(report)
    lines += _find(report)
    lines += _what_if(report)
    lines += _fixes(report, show_code)
    lines += _cost(report)
    lines += _diagnostics(report)
    lines += _warnings(report)
    lines += ["", footer_text(report)]
    return "\n".join(lines) + "\n"


__all__ = ["NOT_A_BILL", "TYPES_HEADING", "UNREPORTED_NOTE", "render_text"]
