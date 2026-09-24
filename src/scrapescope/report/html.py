"""report.html: one self-contained page, tables only, no scripts.

Security properties (tests enforce them):

- No ``<script>``, no event-handler attributes, no links, images, forms or any
  external resource. The only inline style is one static ``<style>`` element
  whose SHA-256 hash is pinned by a CSP meta tag:
  ``default-src 'none'; style-src 'sha256-...'; img-src 'none'; base-uri 'none';
  form-action 'none'``.
- Every string from the report goes through ``safe_text`` (or ``safe_code`` for
  fix code) and then ``html.escape(..., quote=True)``, so hosts, paths and
  warnings containing ``<script>``, ``javascript:`` or Markdown image syntax
  render as inert text.

The page keeps the report's accuracy labels and states that it is not a bill.
"""

from __future__ import annotations

import base64
import hashlib
import html
from typing import Any

from ..types import safe_code
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
    bucket_label,
    connections_text,
    find_load_label,
    find_replay_text,
    fix_views,
    flags_text,
    footer_text,
    get,
    host_path,
    host_requests_text,
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
from .text import TYPES_HEADING, UNREPORTED_NOTE

CSS = """\
:root{--bg:#ffffff;--fg:#1b1d21;--muted:#5d636b;--line:#d9dde2;--head:#f3f5f7;--warn-bg:#fff5e0;--warn-fg:#6b4200;--bad-bg:#fdecea;--bad-fg:#8a1c14;--code:#f5f6f8}
@media (prefers-color-scheme:dark){:root{--bg:#131518;--fg:#e6e8eb;--muted:#9ba1a8;--line:#33383e;--head:#1c1f23;--warn-bg:#352a12;--warn-fg:#f3cf8a;--bad-bg:#3a1714;--bad-fg:#ffb4ab;--code:#1b1e22}}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}
h2{font-size:1.1rem;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:20px 0 6px;overflow-wrap:anywhere}
p,li{max-width:80ch}
.meta,.note{color:var(--muted);font-size:.9rem}
.banner{padding:10px 14px;border-radius:6px;margin:12px 0;font-weight:600}
.bad{background:var(--bad-bg);color:var(--bad-fg)}
.warn{background:var(--warn-bg);color:var(--warn-fg)}
.scroll{overflow-x:auto;margin:8px 0}
table{border-collapse:collapse;min-width:100%;font-size:.9rem}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
thead th{background:var(--head);font-weight:600;white-space:nowrap}
.kv th{width:30%;min-width:10ch}
.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.w{overflow-wrap:anywhere;min-width:12ch}
pre{background:var(--code);padding:12px;border-radius:6px;overflow-x:auto;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}
ul{padding-left:20px}
footer{margin-top:40px;color:var(--muted);font-size:.85rem}
"""

#: Hosts shown in the HTML hosts table (report.json keeps up to 10,000).
MAX_HTML_HOSTS = 500


def style_hash() -> str:
    """``sha256-<base64>`` of the inline stylesheet, as used in the CSP."""
    return "sha256-" + base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")


def content_security_policy() -> str:
    return (
        f"default-src 'none'; style-src '{style_hash()}'; img-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )


def e(value: Any, max_len: int = 500) -> str:
    """Escape one untrusted value for HTML text or attribute context."""
    return html.escape(text(value, max_len), quote=True)


def _table(headers: list[str], rows: list[list[Any]], numeric: set[int] | None = None, wrap: set[int] | None = None) -> str:
    numeric = numeric or set()
    wrap = wrap or {0}

    def cls(i: int) -> str:
        if i in numeric:
            return ' class="n"'
        return ' class="w"' if i in wrap else ""

    head = "".join(f"<th{cls(i) if i in numeric else ''}>{e(h)}</th>" for i, h in enumerate(headers))
    body = "".join("<tr>" + "".join(f"<td{cls(i)}>{e(c)}</td>" for i, c in enumerate(row)) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _kv(rows: list[tuple[str, Any]]) -> str:
    body = "".join(f'<tr><th scope="row">{e(k)}</th><td class="w">{e(v)}</td></tr>' for k, v in rows)
    return f'<div class="scroll"><table class="kv"><tbody>{body}</tbody></table></div>'


def _list(items: list[Any]) -> str:
    return "<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items else ""


def _header(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    versions = ", ".join(f"{k} {v}" for k, v in sorted(as_dict(report.get("catalog_versions")).items()))
    return (
        f"<h1>scrapescope report: {e(report.get('command'))}</h1>"
        f'<p class="meta">scrapescope {e(report.get("tool_version"))} &middot; mode {e(report.get("mode"))} '
        f"&middot; unit {e(unit)} ({e(unit_note(unit))}) &middot; {e(report.get('started_at'))} to "
        f"{e(report.get('ended_at'))}" + (f" &middot; catalogs {e(versions)}" if versions else "") + "</p>"
    )


def _banners(report: dict[str, Any]) -> str:
    out = ""
    if report.get("incomplete") is True:
        bypass = as_dict(report.get("bypass"))
        hosts = ", ".join(text(h, 80) for h in as_list(bypass.get("hosts"))[:5]) or "-"
        requests = as_int(bypass.get("requests"))
        extra = f"; {num(requests)} request(s) found no meter tunnel to their host" if requests > 0 else ""
        out += (
            '<p class="banner bad">INCOMPLETE: helpers or hooks reported traffic that the meter did not carry '
            f"(hosts: {e(hosts)}){e(extra)}. Totals miss that traffic (see Warnings).</p>"
        )
    if get(report, "budget", "tripped") is True:
        out += '<p class="banner warn">BUDGET TRIPPED: the meter closed every tunnel and refused new ones.</p>'
    return out


def _totals(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    t = as_dict(report.get("totals"))
    estimated = t.get("with_connect_estimated") is True
    rows = [
        ("with CONNECT", size_exact(t.get("with_connect"), unit) + (" (estimated)" if estimated else "")),
        ("without CONNECT", size_exact(t.get("without_connect"), unit)),
        ("sent / received", f"{size(t.get('bytes_sent'), unit)} / {size(t.get('bytes_received'), unit)}"),
        ("tunnels", f"{num(t.get('tunnels'))} ({num(t.get('failed_tunnels'))} failed, {num(t.get('denied_tunnels'))} denied)"),
    ]
    connections = connections_text(t)
    if connections:
        rows.append(("connections", connections))
    label = "tunnel-measured" + ("; with-CONNECT estimated in sizing mode" if estimated else "")
    return f"<h2>Totals <span class=\"meta\">({e(label)})</span></h2>" + _kv(rows)


def _budget(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    b = as_dict(report.get("budget"))
    limit = b.get("limit_bytes")
    cap = b.get("max_tunnel_bytes")
    counted = as_int(b.get("counted_bytes"))
    rows: list[tuple[str, Any]] = [
        ("limit", size(limit, unit) if isinstance(limit, int) else "none"),
        ("counted", size(counted, unit) + (f" ({pct(counted / limit)})" if isinstance(limit, int) and limit > 0 else "")),
        ("per-tunnel cap", size(cap, unit) if isinstance(cap, int) else "none"),
        ("tripped", yes_no(b.get("tripped"))),
    ]
    out = "<h2>Budget <span class=\"meta\">(upstream socket bytes, both directions)</span></h2>" + _kv(rows)
    events = as_list(report.get("budget_events"))
    if events:
        ev_rows = []
        for ev in events:
            top = ", ".join(f"{text(get(h, 'host'), 80)} ({size(get(h, 'bytes'), unit)})" for h in as_list(get(ev, "top_hosts")))
            ev_rows.append(
                [get(ev, "ts"), get(ev, "kind"), size(get(ev, "counted_bytes"), unit),
                 get(ev, "host") or "-", num(get(ev, "closed_tunnels")), top or "-"]
            )
        out += _table(["time", "event", "counted", "host", "closed", "heaviest hosts (final minute)"], ev_rows, numeric={2, 4}, wrap={3, 5})
    if isinstance(limit, int) and limit > 0:
        out += (
            '<p class="note">The meter stops at its own count; bytes already in flight at the provider may add '
            "a few MB per open tunnel.</p>"
        )
    return out


def _units(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    u = as_dict(report.get("units"))
    if is_find(report):
        return "<h2>Page load (find)</h2>" + _kv([
            ("page load", "find loaded one page itself: units, per-unit and per-request attribution do not apply"),
            ("browser launches", browser_launches_text(report)),
        ])
    rows: list[tuple[str, Any]] = [
        ("units", f"{num(u.get('count'))} ({text(u.get('source'))})"),
        ("browser launches", browser_launches_text(report)),
    ]
    before = report.get("bytes_before_first_navigation")
    if isinstance(before, int):
        rows.append(("before the first navigation", size(before, unit)))
    pu = report.get("per_unit")
    if isinstance(pu, dict):
        rows.append(("first unit", size(pu.get("first_unit_bytes"), unit)))
        mean = pu.get("rest_mean_bytes")
        rows.append(
            ("rest", f"{num(pu.get('rest_units'))} unit(s), {size(pu.get('rest_bytes'), unit)}"
             + (f", mean {size(mean, unit)}" if isinstance(mean, int) else ""))
        )
    success = report.get("success")
    if isinstance(success, dict):
        rate = success.get("rate")
        rows.append(("success", f"{num(success.get('count'))} ({text(success.get('basis'))})" + (f", {pct(rate)}" if isinstance(rate, (int, float)) else "")))
    if per_unit_withheld(report):
        rows.append(("first unit vs the rest", "not shown: units started closer together than the meter's timeline step"))
    hist = as_dict(report.get("status_histogram"))
    if hist:
        rows.append((STATUS_LABEL, ", ".join(f"{text(k, 8)} x{num(v)}" for k, v in sorted(hist.items()))))
    cached = served_without_network(report)
    if cached:
        rows.append((NOT_NETWORK_LABEL, f"{num(cached)} request event(s): {NOT_NETWORK_NOTE}"))
    out = "<h2>Units</h2>" + _kv(rows)
    if u.get("low_sample_warning") is True and as_int(u.get("count")) > 0:
        out += '<p class="note">Fewer than 20 units: per-1,000 figures are unreliable.</p>'
    return out


def _hosts(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    hosts = as_list(report.get("hosts"))
    if not hosts:
        return "<h2>Hosts</h2><p>None.</p>"
    rows = []
    for h in hosts[:MAX_HTML_HOSTS]:
        rows.append(
            [get(h, "host", default="-"), num(get(h, "tunnels")), num(get(h, "failed_tunnels")),
             size(get(h, "bytes_with_connect"), unit), size(get(h, "bytes_without_connect"), unit),
             host_requests_text(report, h),
             ", ".join(sorted(text(bucket_label(report, k, get(h, "host")), 80) for k in as_dict(get(h, "buckets")))) or "-"]
        )
    note = f"showing {min(len(hosts), MAX_HTML_HOSTS)} of {len(hosts)}; tunnel-measured"
    out = f'<h2>Hosts <span class="meta">({e(note)})</span></h2>'
    out += _table(["host", "tunnels", "failed", "with CONNECT", "without", "requests", "buckets"], rows, numeric={1, 2, 3, 4, 5}, wrap={0, 6})
    path_rows = []
    for h in hosts[:MAX_HTML_HOSTS]:
        for p in as_list(get(h, "paths")):
            path_rows.append([get(h, "host"), get(p, "path"), num(get(p, "requests")), size(get(p, "reported_bytes"), unit)])
    if path_rows:
        out += "<h3>Paths (reported bytes; kept with --keep-urls, never query strings)</h3>"
        out += _table(["host", "path", "requests", "reported"], path_rows, numeric={2, 3}, wrap={0, 1})
    return out


def _buckets(report: dict[str, Any]) -> str:
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
    return '<h2>Buckets <span class="meta">(with CONNECT; they add up to the total)</span></h2>' + _table(["bucket", "bytes"], rows, numeric={1})


def _types(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    types = as_list(report.get("types"))
    if not types:
        return ""
    rows = [[get(t, "type"), num(get(t, "requests")), size(get(t, "reported_bytes"), unit), size(get(t, "allocated_bytes"), unit)] for t in types]
    heading = TYPES_HEADING.split(" (", 1)
    out = (
        f'<h2>{e(heading[0])} <span class="meta">({e(heading[1].rstrip(")"))})</span></h2>'
        + _table(["type", "requests", "reported", "allocated"], rows, numeric={1, 2, 3})
    )
    if any(get(t, "type") == UNREPORTED_TYPE for t in types):
        out += f'<p class="note">{e(UNREPORTED_NOTE)}</p>'
    return out


def _non_target(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    items = as_list(report.get("non_target"))
    if not items:
        return ""
    rows = [[get(n, "host"), get(n, "catalog_id"), num(get(n, "tunnels")), size(get(n, "bytes_sent"), unit), size(get(n, "bytes_received"), unit)] for n in items]
    return (
        '<h2>Non-target hosts <span class="meta">(carried direct, not sent to the upstream; excluded from totals)</span></h2>'
        + _table(["host", "direct.json", "tunnels", "sent", "received"], rows, numeric={2, 3, 4})
    )


def _find(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    out = ""
    for f in as_list(report.get("find")):
        out += f"<h2>find: {e(host_path(get(f, 'target_host'), get(f, 'target_path')), 300)}</h2>"
        rows: list[tuple[str, Any]] = [("result", get(f, "status")), ("values", num(get(f, "values_count"))), ("coverage", get(f, "coverage", "line"))]
        share = best_match_share_text(report, f)
        if share is not None:
            label, _, rest = share.partition(": ")
            rows.append((label, rest))
        if get(f, "challenge", "blocked") is True:
            rows.append(("challenge", get(f, "challenge", "vendor_name") or "unrecognised vendor"))
        rows.append(("replays without a browser", find_replay_text(f)))
        out += _kv(rows)
        matches = as_list(get(f, "matches"))
        if matches:
            mrows = []
            for m in matches:
                status = get(m, "status")
                mrows.append(
                    [num(get(m, "rank")), host_path(get(m, "host"), get(m, "path")), get(m, "resource_type"), get(m, "method"),
                     str(status) if isinstance(status, int) else "-", size(get(m, "billed_basis_bytes"), unit),
                     values_text(m), match_kind_text(get(m, "match_kinds")),
                     flags_text(get(m, "flags")), "yes" if get(m, "code_eligible") is True else "no"]
                )
            out += _table(["#", "response", "type", "method", "status", "billed basis", "values", "match", "flags", "code"],
                          mrows, numeric={0, 5}, wrap={1, 8})
        find_warnings = as_list(get(f, "warnings"))
        notes = []
        if get(f, "short_value_warning") is True and not any("short" in str(w).lower() for w in find_warnings):
            notes.append("A value is short or numeric; the smallest match is often a beacon or an ID.")
        notes += find_warnings
        out += _list(notes)
    return out


def _what_if(report: dict[str, Any]) -> str:
    unit = unit_of(report)
    items = as_list(report.get("what_if"))
    if not items:
        return ""
    out = '<h2>What-if <span class="meta">(allocated basis; modelled, not measured)</span></h2>'
    for w in items:
        out += (
            f"<h3>{e(get(w, 'title'))}: would remove about {e(size(get(w, 'bytes_saved'), unit))} "
            f"({e(pct(get(w, 'share')))} of this run, modelled)</h3>"
        )
        out += _list(as_list(get(w, "caveats")))
    return out


def _fixes(report: dict[str, Any]) -> str:
    fixes, generated = fix_views(report)
    if not fixes:
        return ""
    out = "<h2>Suggested fixes <span class=\"meta\">(only for detections that fired)</span></h2>"
    if not generated:
        out += ('<p class="note">Read from a report file: titles, detections, code and caveats are rebuilt by this '
                "scrapescope from each fix id and the file's own figures. Code and text stored in fixes are never "
                "shown.</p>")
    for f in fixes:
        code = get(f, "code")
        out += f"<h3>{e(get(f, 'title'))}</h3>"
        if get(f, "unknown") is True:
            out += f'<p class="meta">{e(get(f, "id"), 64)}</p>'
            continue
        out += f'<p class="meta">{e(get(f, "id"), 64)} &middot; detected: {e(get(f, "detection"))}</p>'
        out += _list(as_list(get(f, "caveats")))
        if isinstance(code, str):
            out += f"<pre><code>{html.escape(safe_code(code), quote=True)}</code></pre>"
    return out


def _cost(report: dict[str, Any]) -> str:
    c = report.get("cost")
    if not isinstance(c, dict):
        return ""
    rate = c.get("rate")
    rate_text = f"{rate:g}" if isinstance(rate, (int, float)) and not isinstance(rate, bool) else "-"
    rows: list[tuple[str, Any]] = [
        ("rate (yours)", f"{rate_text} {text(c.get('rate_unit'))}"),
        ("with CONNECT", money(c.get("with_connect"))),
        ("without CONNECT", money(c.get("without_connect"))),
    ]
    if c.get("per_1000_units") is not None:
        rows.append(("per 1,000 units", money(c.get("per_1000_units"))))
    if c.get("per_1000_successes") is not None:
        rows.append(("per 1,000 successes", money(c.get("per_1000_successes"))))
    return '<h2>Cost <span class="meta">(estimated billable transfer; not a bill)</span></h2>' + _kv(rows)


def _diagnostics(report: dict[str, Any]) -> str:
    refused = {k: v for k, v in as_dict(report.get("refused")).items() if as_int(v) > 0}
    failures = {k: v for k, v in as_dict(report.get("tunnel_failures")).items() if as_int(v) > 0}
    accept_errors = as_int(report.get("accept_limit_errors"))
    events = as_dict(report.get("helper_events"))
    rows: list[tuple[str, Any]] = []
    if refused:
        rows.append(("refused before a tunnel", ", ".join(f"{text(k, 32)} {num(v)}" for k, v in sorted(refused.items()))))
    if failures:
        rows.append(("failed tunnels", ", ".join(f"{text(k, 40)} {num(v)}" for k, v in sorted(failures.items()))))
    if accept_errors > 0:
        rows.append((ACCEPT_LIMIT_LABEL, f"{num(accept_errors)} time(s)"))
    if events:
        rows.append(("helper events", ", ".join(f"{n} {num(events.get(n))}" for n in ("attach", "launch", "request", "dropped"))))
    return "<h2>Diagnostics</h2>" + _kv(rows) if rows else ""


def _warnings(report: dict[str, Any]) -> str:
    warnings = as_list(report.get("warnings"))
    return "<h2>Warnings</h2>" + _list(warnings) if warnings else ""


def render_html(report: dict[str, Any]) -> str:
    """The self-contained report.html document."""
    body = "".join(
        [
            _header(report),
            _banners(report),
            _totals(report),
            _budget(report),
            _units(report),
            _hosts(report),
            _buckets(report),
            _types(report),
            _non_target(report),
            _find(report),
            _what_if(report),
            _fixes(report),
            _cost(report),
            _diagnostics(report),
            _warnings(report),
            f"<footer>{e(footer_text(report))}</footer>",
        ]
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(content_security_policy(), quote=True)}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        '<meta name="robots" content="noindex">\n'
        '<meta name="color-scheme" content="light dark">\n'
        "<title>scrapescope report</title>\n"
        f"<style>{CSS}</style>\n"
        "</head>\n<body>\n<main>\n"
        f"{body}\n"
        "</main>\n</body>\n</html>\n"
    )


__all__ = ["CSS", "content_security_policy", "render_html", "style_hash"]
