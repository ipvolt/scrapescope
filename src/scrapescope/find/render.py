"""Terminal rendering of a ``find`` result (the only place full URLs appear).

Plain text, no colours. Every string passes through ``types.safe_text`` (or
``safe_code`` for starter code), so hostile paths or vendor names cannot
inject terminal escape sequences or bidi overrides. The searched values are
never printed; matches refer to them as "value 1", "value 2"...

Layout: a summary line (the smallest all-values response) and a share line
comparing like with like: that response's body and headers against the page
load's DevTools-reported bytes, TLS left out of both. The share is shown only
for a code-eligible network response and is called a saving only when the
``--verify`` replay of that response returned the values found in it and
itself moved less than the page load (a gzip-only replay of a br copy can
move more); otherwise the line says why it is not (yet) a saving. Then per match one table row (rank,
billed-basis, values, status, type, method, flags, match kind) followed by the
response (host and path, shortened in the middle so the file name stays) and
one line per value with its match kind and where that value matched
(``FindMatch.locations_by_value``), so the output fits about 100 columns.
Response-level labels (iframe, service worker, served from cache) follow on
their own line. Results rebuilt from an older report without per-value
locations show the response's merged locations instead. The verify line is
left out when nothing was found and --verify was not requested.

When two listed responses share host and path, their response lines add the
query (shortened in the middle), or a short hash of it when the row carries a
random-looking token, so the rows can be told apart; the "also eligible" list
(after a blank line, at the outer indentation, so it is not copied with the
starter code) gives each rank's URL the same way. A value seen only inside a longer number
is marked "not counted". The "not found: ..." warning is printed under the
coverage line instead of at the end; for a ``not_found`` result only its
explanation follows the coverage line, which already says "not found".
The verify line names the rank that was replayed. A match that is
ineligible only because of the cookies or a token header it sent (a replay
candidate) says so instead of claiming it depends on session state, unless
its cookie-less replay failed; other ineligible matches give their own
reason's text (``heuristics.not_emitted_text``: only session state is called
session or anti-bot state).

find-r4-1: while some response holds every value, starter code is printed
only for such a response, and eligible responses that lack a value are
listed with ``(holds N of M values)``. When no response holds every value,
the starter-code heading and the verify line say ``holds N of M values
(value K is not in it)``. ``verify_line`` and ``replayed_match`` also work on
a result rebuilt from a report, so reports print the terminal's verify line
and name the replay's host.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from collections import Counter

from ..types import FindMatch, FindResult, clean_path, safe_code, safe_text
from .heuristics import NOT_EMITTED_TEXT, TOKEN_HEADER_REASON, not_emitted_text, replay_candidate, select_verify_target
from .search import WEAK_KINDS, counts_as_match

#: Longest host+path shown on a match's response line (shortened in the middle).
_RESPONSE_MAX = 90
#: Longest query shown to tell apart rows with the same host and path.
_QUERY_MAX = 32
#: Prefix of the core's "not found" warning (printed under the coverage line).
_NOT_FOUND_PREFIX = "not found: "
_WEAK_NOTE = " (only inside a longer number; not counted)"


def _flags_text(match: FindMatch) -> str:
    f = match.flags
    names = []
    if f.sent_cookies:
        names.append("sent-cookies")
    if f.sent_authorization:
        names.append("sent-authorization")
    if f.random_query_token:
        names.append("random-token")
    if f.third_party:
        names.append("third-party")
    if f.sent_token_header or match.code_ineligible_reason == TOKEN_HEADER_REASON:
        names.append("token-header")
    if f.non_get:
        names.append("non-GET")
    return ",".join(names) or "-"


def _kinds_text(match: FindMatch) -> str:
    """The table's match column: the one kind all values share, else ``mixed`` (details below)."""
    kinds = list(match.match_kinds)
    if len(set(kinds)) == 1:
        return kinds[0]
    return "mixed"


def holds_text(match: FindMatch) -> str | None:
    """``holds N of M values (value K is not in it)`` for a match without every value, else None."""
    if match.all_values or not match.match_kinds:
        return None
    missing = [str(i) for i, kind in enumerate(match.match_kinds, start=1) if not counts_as_match(kind)]
    if not missing:
        return None
    which = f"value {missing[0]} is" if len(missing) == 1 else f"values {', '.join(missing)} are"
    return f"holds {match.values_matched} of {len(match.match_kinds)} values ({which} not in it)"


def _count_text(match: FindMatch) -> str:
    """`` (holds N of M values)`` for a match without every value, else ``""`` (the "eligible" lists)."""
    if match.all_values or not match.match_kinds:
        return ""
    return f" (holds {match.values_matched} of {len(match.match_kinds)} values)"


def _per_value_lines(match: FindMatch) -> list[str]:
    """One line per value: its match kind and, when known, where it matched."""
    by_value = match.locations_by_value if len(match.locations_by_value) == len(match.match_kinds) else []
    lines = []
    for i, kind in enumerate(match.match_kinds, start=1):
        where = by_value[i - 1] if by_value and kind != "none" else []
        note = _WEAK_NOTE if kind in WEAK_KINDS else ""
        lines.append(f"value {i}: {kind}{note}" + (f" in {', '.join(where)}" if where else ""))
    return lines


def _response_labels(match: FindMatch) -> list[str]:
    """Locations that describe the response, not a value (the type label, which the table shows, excluded)."""
    per_value = {loc for locs in match.locations_by_value for loc in locs}
    return [loc for loc in match.locations[1:] if loc not in per_value]


def _display_path(result: FindResult, match: FindMatch) -> str:
    url = result.match_urls.get(str(match.rank))
    if url:
        try:
            path = clean_path(urllib.parse.urlsplit(url).path or "/")
        except ValueError:
            path = None
        if path:
            return path
    return match.path or "/(path hidden)"


def _query_text(result: FindResult, match: FindMatch) -> str:
    """``?query`` shortened in the middle, or a short hash of it for a row with a random-looking token."""
    url = result.match_urls.get(str(match.rank))
    if not url:
        return ""
    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return ""
    if not query:
        return ""
    if match.flags.random_query_token:
        digest = hashlib.sha256(query.encode("utf-8", "replace")).hexdigest()[:8]
        return f"?(query {digest})"
    return "?" + _cell(safe_text(query), _QUERY_MAX)


def _row_names(result: FindResult) -> dict[int, str]:
    """rank -> host+path, with the query added where two listed rows share host and path."""
    base = {m.rank: m.host + _display_path(result, m) for m in result.matches}
    shared = Counter(base.values())
    return {m.rank: base[m.rank] + (_query_text(result, m) if shared[base[m.rank]] > 1 else "") for m in result.matches}


def _cell(text: str, width: int) -> str:
    """``text`` shortened in the middle to ``width`` characters, keeping the last path segment when it fits."""
    if len(text) <= width:
        return text
    if width <= 5:
        return text[:width]
    last = text.rsplit("/", 1)[-1]
    tail_len = len(last) + 1 if 0 < len(last) + 1 <= (width - 3) * 2 // 3 else (width - 3) // 2
    head_len = width - 3 - tail_len
    return text[:head_len] + "..." + text[len(text) - tail_len :]


def _table(rows: list[list[str]], right: set[int]) -> list[str]:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for row in rows:
        cells = [cell.rjust(widths[i]) if i in right else cell.ljust(widths[i]) for i, cell in enumerate(row)]
        lines.append("  ".join(cells).rstrip())
    return lines


#: Verify reasons for a replay that was never sent (no target to name).
_NOT_SENT_REASONS = ("not requested", "nothing matched", "no eligible match", "blocked", "page load failed")


def _replay_sent(result: FindResult) -> bool:
    v = result.verify
    reason = v.reason or "not requested"
    return v.replays != "not_tested" or not (reason in _NOT_SENT_REASONS or reason.startswith("not sent:"))


def replayed_match(result: FindResult) -> FindMatch | None:
    """The match the --verify replay went to, or None when no replay was sent.

    Works on a result rebuilt from a report (``FindResult.from_dict``): the
    choice (``heuristics.select_verify_target``) is the same before and after
    the replay.
    """
    if not _replay_sent(result):
        return None
    target = select_verify_target(result.matches)
    if result.verify.replays == "yes" and (target is None or not target.code_eligible):
        # a result from elsewhere: a replay that said yes went to an eligible match
        return next((m for m in result.matches if m.code_eligible), None)
    return target


_verify_target = replayed_match


def verify_line(result: FindResult) -> str | None:
    """The terminal's ``replays without a browser: ...`` line (sanitised), or None when it is left out.

    It names the replayed rank and, for a match without every value, which
    value that response lacks. Works on a result rebuilt from a report.
    """
    v = result.verify
    if result.status != "found" and v.replays == "not_tested" and (v.reason or "not requested") == "not requested":
        return None  # nothing to replay and nobody asked
    target = _verify_target(result)
    rank = [f"rank {target.rank}"] if target is not None else []
    holds = holds_text(target) if target is not None else None
    if holds:
        rank.append(holds)
    if v.replays == "yes":
        detail = rank + ([f"status {v.status}"] if v.status is not None else [])
        if v.received_bytes is not None:
            detail.append(f"{v.received_bytes:,} body bytes received")
        if v.replay_billed_basis_bytes is not None:
            detail.append(f"about {v.replay_billed_basis_bytes:,} B billed-basis")
        return "replays without a browser: yes (" + safe_text(", ".join(detail)) + ")"
    if v.replays == "no":
        return "replays without a browser: no (" + safe_text(", ".join(rank + [v.reason or "unknown"])) + ")"
    return "replays without a browser: not tested (" + safe_text(", ".join(rank + [v.reason or "not requested"])) + ")"


def render_find_text(result: FindResult, *, show_code: bool = True) -> str:
    """Render a find result for the terminal (paths shown; values never shown)."""
    lines: list[str] = []
    not_found = [w for w in result.warnings if w.startswith(_NOT_FOUND_PREFIX)]
    other_warnings = [w for w in result.warnings if not w.startswith(_NOT_FOUND_PREFIX)]
    target = result.target_host + (result.target_path or "")
    lines.append(f"scrapescope find: {safe_text(target)}  ({result.values_count} value{'s' if result.values_count != 1 else ''})")
    if result.status == "blocked":
        ch = result.challenge
        name = ch.vendor_name or ch.vendor_id or "unknown vendor"
        lines.append(f"blocked; cannot search (challenge: {safe_text(name, 64)})")
        if ch.status is not None:
            lines.append(f"main document status: {ch.status}")
        if ch.signals:
            lines.append("signals: " + safe_text(", ".join(ch.signals)))
        lines.append("scrapescope classifies challenge pages only; it never tries to get past them.")
    elif result.status == "error":
        lines.append("cannot search: the page did not load (see warnings)")
    else:
        lines.append(safe_text(result.coverage.summary(result.status == "found")))
        for w in not_found:
            if result.status == "not_found":
                # the coverage line already says "not found": print only the explanation
                w = w.split("; ", 1)[1] if "; " in w else w
            lines.append(safe_text(w))
        lines.extend(_summary_lines(result))
        if result.matches:
            lines.extend(_matches_section(result, show_code=show_code))
    replay = verify_line(result)
    if replay:
        lines.append(replay)
    if other_warnings:
        lines.append("warnings:")
        lines.extend(f"  - {safe_text(w)}" for w in other_warnings)
    return "\n".join(lines) + "\n"


_NOT_NETWORK_LABELS = ("served-by-service-worker", "served-from-cache")


def page_share(result: FindResult, match: FindMatch) -> tuple[float, int] | None:
    """(percent, bytes) of ``match``'s body and headers against the page load's DevTools-reported bytes.

    Like with like (find3-1): ``page_reported_bytes`` holds DevTools sizes
    without TLS or connection overhead, so the TLS estimate in the billed basis
    is left out of the numerator. None when no page load was reported, the
    match was not a network response, or the figures do not fit (the share
    would exceed 100%).
    """
    page = result.page_reported_bytes
    if page <= 0 or any(lab in match.locations for lab in _NOT_NETWORK_LABELS):
        return None
    own = max(0, match.billed_basis_bytes - match.tls_handshake_estimate)
    if own > page:
        return None
    return 100.0 * own / page, own


def _share_qualifier(result: FindResult, top: FindMatch, own: int) -> str:
    """Whether the share is a saving: only when --verify replayed that response and it returned its values.

    A response that is the whole page load (its bytes are all the page moved)
    saves nothing, whatever the replay said. Nor does one whose replay moved
    at least as much as the page load (hon4-2): the share is the browser's
    copy (br or zstd), while the replay accepts only gzip and deflate and can
    receive a far larger body. Like with like, the replay's figure is its
    billed basis without the TLS estimate. When the replay moved noticeably
    more than the browser's copy (over 1.2 times, as ``_replay_warning`` in
    ``core``), its own share of the page load is shown next to the claim.
    """
    v = result.verify
    if own >= result.page_reported_bytes:
        return "no saving: this one response is the whole page load"
    target = _verify_target(result)
    if target is None and (v.reason or "").startswith("not sent:"):
        # --verify was asked for, but the replay was never sent (the budget tripped, the upstream failed)
        return f"not a saving yet: the --verify replay was {v.reason}"
    if target is None or target.rank != top.rank:
        return "not a saving until --verify replays it"
    if v.replays == "yes":
        moved = v.replay_billed_basis_bytes
        if moved is None:
            return "a saving: --verify replayed it without a browser"
        replay_own = max(0, moved - top.tls_handshake_estimate)
        larger = moved > top.billed_basis_bytes * 1.2
        see = " (see warnings)" if larger else ""
        if replay_own >= result.page_reported_bytes:
            # the replay's client got a larger body (no br/zstd) than the whole page load moved
            than = "more than" if replay_own > result.page_reported_bytes else "as much as"
            return (
                "no saving for a client that accepts only gzip or deflate: the --verify replay moved about "
                f"{replay_own:,} B body and headers, {than} this page load{see}"
            )
        if larger:
            # the share above is the browser's copy; say what the replay itself moved, on the same basis
            pct = 100.0 * replay_own / result.page_reported_bytes
            return (
                f"a saving: --verify replayed it without a browser, moving about {replay_own:,} B body and headers "
                f"({pct:.1f}% of this page load; see warnings)"
            )
        return "a saving: --verify replayed it without a browser"
    if v.replays == "no":
        return f"not a saving: the --verify replay failed ({v.reason or 'unknown'})"
    return f"not a saving yet: the --verify replay was not tested ({v.reason or 'unknown'})"


def _what_was_sent(match: FindMatch) -> tuple[str, str]:
    """What the browser sent that the replay leaves out, and its pronoun."""
    return ("cookies", "them") if match.flags.sent_cookies else ("a token header", "it")


def _no_share_reason(result: FindResult, top: FindMatch) -> str:
    """Why an ineligible top match gets no page-load share (honest-r3-1: savings appear only for yes)."""
    reason = top.code_ineligible_reason or "ineligible"
    if replay_candidate(top):
        sent, pronoun = _what_was_sent(top)
        target = _verify_target(result)
        if target is not None and target.rank == top.rank and result.verify.replays == "no":
            return f"it did not replay without the browser's {sent}: {result.verify.reason or 'unknown'}"
        return f"the browser sent {sent} with it; not tested without {pronoun}"
    return f"no starter code: {reason}"


def _top_complete(result: FindResult) -> FindMatch | None:
    """The smallest response holding every value, network copies first (None when there is none)."""
    complete = [m for m in result.matches if m.all_values]
    if not complete:
        return None
    network = [m for m in complete if not any(lab in m.locations for lab in _NOT_NETWORK_LABELS)]
    return (network or complete)[0]


def share_line(result: FindResult) -> str | None:
    """The page-load share line of the smallest all-values response, exactly as the terminal prints it.

    ``share: P% of this page load (...); <qualifier>`` for a code-eligible
    network response (like with like; called a saving only after a --verify
    replay said yes, never for a response that is the whole page load, and
    never when the replay itself moved at least as much as the page load),
    ``share of this page load: not shown for rank N (<why>)`` for an
    ineligible one, and None when no share applies (nothing found, no
    response with every value, no page load reported, a copy that did not
    cross the network, or figures that do not fit). Works on a result rebuilt
    from a report (``FindResult.from_dict``), so reports can print the same
    line; the text is sanitised.
    """
    if result.status != "found":
        return None
    top = _top_complete(result)
    if top is None:
        return None
    share = page_share(result, top)
    if share is None:
        return None
    if not top.code_eligible:
        return safe_text(f"share of this page load: not shown for rank {top.rank} ({_no_share_reason(result, top)})")
    pct, own = share
    return safe_text(
        f"share: {pct:.1f}% of this page load ({own:,} B body and headers against {result.page_reported_bytes:,} B "
        f"DevTools-reported, TLS left out of both); {_share_qualifier(result, top, own)}"
    )


def _summary_lines(result: FindResult) -> list[str]:
    """The smallest all-values response, and its share of the page load when that is meaningful."""
    if result.status != "found" or not result.matches:
        return []
    top = _top_complete(result)
    if top is None:
        best = max(result.matches, key=lambda m: (m.values_matched, -m.rank))
        return [
            f"no response contains all {result.values_count} values; the closest (rank {best.rank}) "
            f"contains {best.values_matched}"
        ]
    lines = [f"smallest with all values: rank {top.rank}, {top.billed_basis_bytes:,} B billed-basis"]
    share = share_line(result)
    if share is not None:
        lines.append(share)
    return lines


def _not_emitted_line(result: FindResult, match: FindMatch) -> str:
    """Why a match has no starter code (the plan's text, or what a cookie-less replay could still show)."""
    reason = safe_text(match.code_ineligible_reason or "ineligible", 80)
    if not replay_candidate(match):
        return f"rank {match.rank} ({reason}): {not_emitted_text(match.code_ineligible_reason)}"
    target = _verify_target(result)
    v = result.verify
    what, pronoun = _what_was_sent(match)
    sent = f"rank {match.rank} ({reason}): not emitted: the browser sent {what} with it"
    if target is not None and target.rank == match.rank:
        if v.replays == "no":
            return f"rank {match.rank} ({reason}): {NOT_EMITTED_TEXT}"
        return f"{sent} and the --verify replay without {pronoun} was not tested ({safe_text(v.reason or 'unknown', 80)})"
    if _replay_sent(result) and target is not None:
        return f"{sent} and it was not tested without {pronoun} (--verify replayed rank {target.rank}; one replay per run)"
    if (v.reason or "").startswith("not sent:"):
        return f"{sent} and it was not tested without {pronoun} (the --verify replay was {safe_text(v.reason or '', 80)})"
    return f"{sent} and it was not tested without {pronoun} (--verify replays it once without {pronoun})"


def _matches_section(result: FindResult, *, show_code: bool) -> list[str]:
    from .core import MULTIPLEXED_NOTE, billed_basis_note

    lines = ["", "matches (all values first, then billed-basis bytes):"]
    rows = [["rank", "billed-basis", "values", "status", "type", "method", "flags", "match"]]
    details: dict[int, list[str]] = {}
    names = _row_names(result)
    for m in result.matches:
        values = f"{'all' if m.all_values else 'some'} {m.values_matched}/{len(m.match_kinds)}"
        rows.append(
            [
                str(m.rank),
                f"{m.billed_basis_bytes:,} B",
                values,
                str(m.status) if m.status is not None else "-",
                safe_text(m.resource_type, 32),
                safe_text(m.method, 16),
                _flags_text(m),
                safe_text(_kinds_text(m), 40),
            ]
        )
        info = [_cell(safe_text(names[m.rank]), _RESPONSE_MAX)]
        info.extend(safe_text(line) for line in _per_value_lines(m))
        labels = _response_labels(m)
        if labels:
            prefix = "where" if not m.locations_by_value else "response"
            info.append(safe_text(f"{prefix}: " + ", ".join(labels)))
        if m.content_encoding:
            info.append(safe_text(f"content-encoding: {m.content_encoding}"))
        details[m.rank] = info
    table = _table(rows, right={0, 1})
    lines.append("  " + table[0])
    for m, row in zip(result.matches, table[1:]):
        lines.append("  " + row)
        lines.extend("        " + text for text in details[m.rank])
    lines.append("  " + billed_basis_note(any(m.scheme == "https" for m in result.matches)))
    multiplexed = [str(m.rank) for m in result.matches if m.multiplexed]
    if multiplexed:
        lines.append(f"  rank {', '.join(multiplexed)}: {MULTIPLEXED_NOTE}")
    lines.append("")
    eligible = [m for m in result.matches if m.code_eligible]
    if show_code:
        codes = {c.rank: c for c in result.starter_code}
        # find-r4-1: while some response holds every value, code only for such a response
        complete = any(m.all_values for m in result.matches)
        top = next((m for m in eligible if m.rank in codes and (m.all_values or not complete)), None)
        if top is not None:
            code = codes[top.rank]
            target = _verify_target(result)
            holds = holds_text(top)
            lacks = f"{holds}; " if holds else ""
            if result.verify.replays == "yes" and target is not None and target.rank == top.rank:
                lines.append(
                    f"starter code (rank {top.rank}: {lacks}one --verify replay without the browser's cookies, "
                    "headers or tokens returned the values found in it; check the site's terms):"
                )
            else:
                lines.append(
                    f"starter code (rank {top.rank}: {lacks}a GET that sent no cookies, no Authorization, no token "
                    "header and no random-looking token; verify it and check the site's terms):"
                )
            lines.append("  " + safe_code(code.curl))
            lines.append("")
            lines.extend("  " + line if line else "" for line in safe_code(code.httpx).rstrip("\n").split("\n"))
            lines.append("")
        if top is not None:
            others = [m for m in eligible if m.rank != top.rank]
            heading = "also eligible (other responses that would get starter code):"
        elif complete and not any(m.all_values for m in eligible):
            others = eligible
            heading = "eligible but missing a value (no starter code while a response holds every value):"
        else:
            others = []
        if others:
            # ux-r3-1: a heading at the outer indentation after a blank line, so it is not copied with the code
            lines.append(heading)
            for m in others:
                lines.append(f"  rank {m.rank}{_count_text(m)}: " + _cell(safe_text(names[m.rank]), _RESPONSE_MAX))
            lines.append("")
    for m in result.matches:
        if not m.code_eligible:
            lines.append(_not_emitted_line(result, m))
    return lines


__all__ = ["holds_text", "page_share", "render_find_text", "replayed_match", "share_line", "verify_line"]
