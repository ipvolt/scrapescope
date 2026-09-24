"""``run_find``: the smallest response that already contains your value.

Steps (docs/dev/contracts.md section 7):

1. Load the URL once in headless Chromium through ``proxy_url`` (the meter),
   default user agent, at most one retry after a navigation error.
2. Classify the main document with ``challenges.json`` first. A challenge page
   gives ``blocked``: nothing is searched and the result says "blocked; cannot
   search", never "not found".
3. Read text bodies from the whole browser context under the size cap, search
   every value with variants, discard the bodies.
4. Rank matching responses: those containing ALL values first, then more
   values before fewer, then fewer ``variant:substring`` hits (a value only
   inside a longer number, which never counts as matched) before more, then
   network responses before ones served by a service worker or the HTTP
   cache (their sizes do not describe a network transfer), then ascending
   *billed-basis bytes* = encoded body + response headers + request headers +
   one new TLS handshake estimate (``config.TLS_HANDSHAKE_ESTIMATE_BYTES`` =
   7,200 bytes for https, 0 for http). A copy served from the HTTP cache is
   dropped when a network copy of the same URL matched too.
5. Flag each match, decide code eligibility (a credential- or token-like
   request header also withholds code: ``sent a token header``), generate
   starter code for eligible matches, and with ``verify`` replay one match
   once (``heuristics.select_verify_target``): the top eligible match, or a
   higher-ranked one that is ineligible only because of the cookies or token
   header the browser sent, since the cookie-less replay sends neither. Such
   a match gets starter code only when that replay returned the values found in it.
   While some listed match holds every value, only such a match gets starter
   code (find-r4-1); the renderer lists the others with their count.
   The replay is not sent when ``abort_check`` reports a reason (the budget
   tripped, the upstream failed): ``not sent: <reason>``. Warnings say when
   sub-responses were challenge pages (not searched) and when a listed match
   was br/zstd-compressed, which clients without those decoders cannot
   request.

The meter's own replies are never searched. When the main document is one
(``X-Scrapescope-Error``: the meter refused a private address or a denied
host, the budget tripped, or the upstream failed), the result is ``error``
with the reason, never "not found". ``pass --allow-private-targets`` is
advised only when the refused address is the target's own host and port (any
spelling of it); a sub-request the page made, a redirect elsewhere, or a
later request to the target's own name (DNS rebinding) is named as the
page's doing, with the flag reserved for pages you trust (sec4-2). An
``http://`` site can send that header
itself: with ``meter_reply_check`` (the meter's records) such a reply is
searched as the site's response and named in a warning; without it the
warning says the reply was not checked. A value seen only inside a longer
number (``variant:substring``) is reported but does not count as found. A
warning names every value that was not found and says that only responses of
the initial page load were inspected, or, when the main document was an
error response (status 400 or more), that the site may not have served its
content. ``page_reported_bytes`` leaves out responses served by a service
worker or the HTTP cache, which never crossed the network.

Accuracy limits: billed-basis bytes are an estimate of fetching that response
alone on a fresh connection (DevTools sizes plus a typical handshake), not a
measurement or a bill. On HTTP/2 and HTTP/3 DevTools reports no wire header
sizes: the encoded body includes the response header frames, and the rebuilt
HTTP/1.1 request-header size is left out (``ObservedResponse.multiplexed``). They use the browser's encoding: a client that cannot
accept the same Content-Encoding (br, zstd) receives a larger body. The TLS
figure varies with certificate chains and session resumption. "Not found"
means not found in the responses that were inspected; the coverage line says
what was skipped.

Privacy: the result never contains a searched value. Paths are ``clean_path``
output (no query) and are set to None when they contain a value; full URLs
appear only in the terminal-only fields ``target_url``, ``match_urls`` and
``starter_code``.
"""

from __future__ import annotations

import re
import urllib.parse
from collections import Counter
from collections.abc import Callable, Sequence

from ..config import FIND_BODY_CAP_BYTES, TLS_HANDSHAKE_ESTIMATE_BYTES
from ..types import (
    COVERAGE_SKIP_LABELS,
    Catalogs,
    ChallengeResult,
    Coverage,
    FindFlags,
    FindMatch,
    FindResult,
    StarterCode,
    VerifyResult,
    clean_host,
    clean_path,
    ip_literal,
    safe_text,
)
from .browser import (
    LoadOutcome,
    MainDocument,
    MeterReplyCheck,
    ObservedResponse,
    _abort_reason,
    confirm_meter_reply,
    endpoint_host,
    is_private_literal,
    load_page,
    meter_error_code,
)
from .challenge import classify_challenge
from .heuristics import (
    code_eligibility,
    has_random_path_token,
    has_random_query_token,
    is_third_party,
    select_verify_target,
)
from .search import WEAK_KINDS, PreparedValue, contains_any_value, counts_as_match, is_short_value, prepare_values
from .heuristics import encoding_tokens
from .starter import UNCOMMON_ENCODINGS, starter_code
from .verify import ReplayDetail, verify_replay_detail

#: At most this many matches are kept (report.json allows 20).
MAX_MATCHES = 20
#: At most this many values per find (report.json allows 50).
MAX_VALUES = 50
#: Seconds for the single --verify request.
VERIFY_TIMEOUT_S = 30.0
#: Content-Encoding values kept in the report (tokens, commas and spaces only).
_ENCODING_RE = re.compile(r"[a-z0-9._+-]+(, ?[a-z0-9._+-]+)*")

SHORT_VALUE_WARNING = (
    "short or numeric-only value: the smallest match is often a beacon, a counter or an ID; "
    "check the match location before relying on it"
)


def short_value_note(indices: Sequence[int]) -> str:
    """The short-value warning naming the (0-based) values it is about, e.g. "value 2 is short or ..."."""
    listed = ", ".join(str(i + 1) for i in indices)
    one = len(indices) == 1
    subject = f"value {listed} is" if one else f"values {listed} are"
    pronoun = "it" if one else "them"
    return (
        f"{subject} short or numeric-only: a match for {pronoun} alone is often a beacon, a counter or an ID; "
        "check the match location before relying on it"
    )


def _short_value_warning(result: FindResult, values: Sequence[str]) -> str | None:
    """ux-1: the short-value warning, or None when it does not apply.

    Left out when nothing was searched (blocked, page load failed) and when the
    top match also contains, as itself, a value that is not short: that
    response is then not a coincidental beacon or ID.
    """
    short = [i for i, v in enumerate(values) if is_short_value(v)]
    if not short or result.status in ("blocked", "error"):
        return None
    if result.matches:
        top = result.matches[0]
        if any(counts_as_match(kind) and i not in short for i, kind in enumerate(top.match_kinds)):
            return None
    return short_value_note(short)
SANDBOX_WARNING = (
    "Chromium could not start with its OS sandbox here and ran without it; load only pages you trust"
)
BILLED_BASIS_NOTE = (
    "billed-basis bytes = encoded body + response headers + request headers + one new TLS "
    f"handshake estimate ({TLS_HANDSHAKE_ESTIMATE_BYTES:,} bytes, https only); an estimate, not a bill"
)
#: The note when no listed match is https (no TLS estimate is in any figure).
BILLED_BASIS_NOTE_HTTP = (
    "billed-basis bytes = encoded body + response headers + request headers (plain http: no TLS); "
    "an estimate, not a bill"
)


def billed_basis_note(any_https: bool) -> str:
    """The billed-basis note; the TLS estimate is named only when a listed match is https."""
    return BILLED_BASIS_NOTE if any_https else BILLED_BASIS_NOTE_HTTP


class FindInternalError(RuntimeError):
    """An unexpected ``ValueError`` inside find after its arguments were accepted.

    ``run_find`` raises ``ValueError`` only for bad arguments (a usage error);
    any later one is re-raised as this, so a caller that maps ``ValueError``
    to a usage error still treats it as find's own failure.
    """
#: Why a value can be missing although the page shows it (find-r2-9).
INITIAL_LOAD_NOTE = (
    "only responses of the initial page load were inspected; content loaded later by scrolling, "
    "clicking or timers is not covered"
)
#: What the meter's own error codes mean (docs/dev/contracts.md section 3).
METER_ERROR_REASONS = {
    "private-address": (
        "the meter refuses direct connections to loopback, private and link-local addresses, to this "
        "machine's own addresses and to hosts on its own IPv6 link (/64); "
        "pass --allow-private-targets to load such a target"
    ),
    "denied": "the host matches a deny rule (--deny-host or --deny-catalog)",
    "self-loop": "the target is the meter itself",
    "budget": "the byte budget tripped, so the meter refuses new requests",
    "upstream-unreachable": "the upstream proxy is unreachable",
    "upstream-timeout": "the upstream proxy timed out",
    "upstream-closed": "the upstream proxy closed the connection",
    "upstream-protocol-error": "the upstream proxy sent an invalid reply",
    "socks-auth-failed": "the SOCKS5 upstream rejected the credentials",
    "socks-no-method": "the SOCKS5 upstream accepted no offered authentication method",
    "socks-auth-unsupported": "these proxy credentials cannot be sent over SOCKS5",
    "dns-failed": "the target name did not resolve",
    "connect-refused": "the target refused the connection",
    "connect-timeout": "the target connection timed out",
    "internal-error": "the meter hit an internal error",
}
#: sec4-2: a sub-request the page chose was refused as a private address (never "pass the flag").
PRIVATE_SUBREQUEST_NOTE = (
    "the page asked for a private or local address and the meter refused it to protect this machine's "
    "network; --allow-private-targets would let the page reach it, so use it only for a page you trust"
)
#: sec4-2: the target's own host:port was refused after the page loaded from it (its name moved).
PRIVATE_OWN_NAME_NOTE = (
    "a request to the target's own host and port was refused as a private or local address although the page "
    "loaded from it: its name now resolves to such an address (DNS rebinding or split DNS); the meter refused "
    "it to protect this machine's network; use --allow-private-targets only for a site you trust"
)
#: sec4-2: the target is a name (not an address) that resolved to a private address: it may be rebinding.
PRIVATE_NAME_CAUTION = (
    "only if you expect this name on your own network: a public name that resolves to a private address "
    "can be a DNS-rebinding attack"
)
#: sec4-2: the main document was refused after a redirect to another host or port.
PRIVATE_REDIRECT_NOTE = (
    "the target redirected to a private or local address, which the meter refuses to protect this machine's "
    "network; use --allow-private-targets only for a site you trust"
)
PRIVATE_TUNNEL_HINT = (
    "the target is a loopback, private or link-local address: the meter refuses those on direct routes "
    "unless --allow-private-targets is given, and a provider cannot reach this machine's network"
)
MULTIPLEXED_NOTE = (
    "HTTP/2 or HTTP/3 (DevTools has no separate header sizes): the body figure includes the response "
    "headers, and request headers are left out"
)


def _parse_target(url: str) -> tuple[str, str | None, str]:
    """(host, raw path, scheme) of an http(s) URL; ValueError otherwise (never echoes the URL)."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("find needs an http:// or https:// URL")
    try:
        parts = urllib.parse.urlsplit(url.strip())
        _ = parts.port
    except ValueError:
        raise ValueError("find needs a valid http:// or https:// URL (bad host or port)") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("find needs an http:// or https:// URL")
    host = clean_host(parts.hostname or "")
    if host is None:
        raise ValueError("find needs a URL with a valid host")
    return host, parts.path or "/", scheme


def _target_endpoint(url: str) -> tuple[str, int] | None:
    """(host as the meter records it, port) of the find target, or None when it cannot be parsed."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    host = clean_host(parts.hostname or "")
    return (endpoint_host(host), port) if host is not None else None


def _is_name(host: str) -> bool:
    """True for a DNS name, False for an IP literal or a ``localhost`` name."""
    host = host.strip("[]").lower()
    return ip_literal(host) is None and host != "localhost" and not host.endswith(".localhost")


def _is_target(host: str, port: int, target: tuple[str, int] | None) -> bool:
    """True when host:port is the find target's own (any spelling of the same address)."""
    return target is not None and bool(host) and (endpoint_host(host), port) == target


def _safe_path(raw_path: str | None, values: Sequence[str]) -> str | None:
    if raw_path is None:
        return None
    path = clean_path(raw_path)
    if path is None or contains_any_value(raw_path, values) or contains_any_value(path, values):
        return None
    return path


def _encoding_token(value: str) -> str | None:
    """The Content-Encoding as a short token for the report ("br", "gzip", "br, gzip"...), or None."""
    token = value.strip().lower()[:32]
    return token if token and _ENCODING_RE.fullmatch(token) else None


def _url_path(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except ValueError:
        return "/"


def billed_basis(obs: ObservedResponse) -> tuple[int, int]:
    """(TLS handshake estimate, billed-basis bytes) for one response."""
    tls = TLS_HANDSHAKE_ESTIMATE_BYTES if obs.scheme == "https" else 0
    return tls, obs.encoded_body_bytes + obs.response_header_bytes + obs.request_header_bytes + tls


def _rank_key(obs: ObservedResponse) -> tuple[bool, int, int, bool, int, int]:
    assert obs.hits is not None
    return (
        not obs.hits.all,
        -obs.hits.values_matched,
        obs.hits.weak_matches,
        obs.served_by_service_worker or obs.served_from_cache,
        billed_basis(obs)[1],
        obs.seq,
    )


def _ranked_matches(responses: Sequence[ObservedResponse]) -> tuple[list[ObservedResponse], int]:
    """Matching responses in rank order, and how many cache-served duplicates were dropped.

    A copy served from the HTTP cache is the same stored response as an
    earlier network copy of that URL, so it is dropped when that network copy
    matched too (its body was searched either way).
    """
    matched = [o for o in responses if o.hits is not None and o.hits.any]
    network = {
        (o.method, o.url) for o in matched if not o.served_from_cache and not o.served_by_service_worker
    }
    kept = [o for o in matched if not (o.served_from_cache and (o.method, o.url) in network)]
    return sorted(kept, key=_rank_key), len(matched) - len(kept)


def meter_error_reason(code: str) -> str:
    """A short explanation of a meter error code (never page content)."""
    if code in METER_ERROR_REASONS:
        return METER_ERROR_REASONS[code]
    if code.startswith("socks-reply-"):
        return f"the SOCKS5 upstream refused the connection ({safe_text(code, 40)})"
    return f"the meter refused the request ({safe_text(code, 40)})"


def _meter_warning(responses: Sequence[ObservedResponse], target: tuple[str, int] | None = None) -> str | None:
    """Sub-requests the meter answered itself (refused or failed upstream); they were not searched.

    sec4-2: the page loaded, so every such request is one the page made. A
    private-address refusal is never answered with "pass
    --allow-private-targets": the page chose that address (an iframe to a
    router, or a DNS-rebinding name), and the flag would let it read that
    address. A refusal of the target's own host:port (``target``, from
    :func:`_target_endpoint`) means its name moved to a private address.
    """
    codes = Counter(o.meter_error for o in responses if o.meter_error)
    if not codes:
        return None
    n = sum(codes.values())
    listed = ", ".join(f"{safe_text(c, 40)} x{k}" for c, k in sorted(codes.items()))
    hint = ""
    private = [o for o in responses if o.meter_error == "private-address"]
    if private:
        own = any(_is_target(o.host, o.port, target) for o in private)
        hint = "; " + (PRIVATE_OWN_NAME_NOTE if own else PRIVATE_SUBREQUEST_NOTE)
    were = "request was" if n == 1 else "requests were"
    return (
        f"{n} {were} answered by the meter itself ({listed}), not by the site; not searched (counted as "
        f"skipped: failed){hint}"
    )


def _weak_only_warning(responses: Sequence[ObservedResponse], values_count: int) -> str | None:
    """Values seen only inside longer numbers and nowhere as themselves (not counted as found)."""
    found: set[int] = set()
    weak: Counter[int] = Counter()
    for obs in responses:
        if obs.hits is None:
            continue
        for i, kind in enumerate(obs.hits.kinds[:values_count]):
            if counts_as_match(kind):
                found.add(i)
            elif kind in WEAK_KINDS:
                weak[i] += 1
    only_weak = sorted(i for i in weak if i not in found)
    if not only_weak:
        return None
    parts = []
    for i in only_weak:
        n = weak[i]
        parts.append(f"value {i + 1} ({n} response{'' if n == 1 else 's'})")
    return (
        f"seen only as part of a longer number or code, never on its own (variant:substring, like 51.77 in "
        f"151.77 or 500 in 1 500): {', '.join(parts)}; not counted as found"
    )


def _missing_values(responses: Sequence[ObservedResponse], values_count: int) -> list[int]:
    """0-based indices of values that no inspected response contains as themselves."""
    found = {
        i
        for obs in responses
        if obs.hits is not None
        for i, kind in enumerate(obs.hits.kinds[:values_count])
        if counts_as_match(kind)
    }
    return [i for i in range(values_count) if i not in found]


def error_document_note(status: int, vendor: str | None = None) -> str:
    """Why a value can be missing when the main document was an error response (find3-8).

    ``vendor`` names a bot-protection or CDN vendor whose signals fired on the
    document without marking it a challenge page (catalogued challenge pages
    are "blocked" and never searched).
    """
    signals = f" ({safe_text(vendor, 64)} signals present)" if vendor else ""
    return (
        f"the main document returned status {status}{signals}, so the site may not have served the page's "
        "content (an error or block page)"
    )


def not_found_note(
    missing: Sequence[int], values_count: int, *, main_status: int | None = None, vendor: str | None = None
) -> str:
    """The warning for values that were not found (render prints it under the coverage line).

    When the main document was an error response (status 400 or more), that
    is named instead of the scrolling and clicking hint, which would point
    the wrong way.
    """
    if len(missing) == values_count:
        which = "the value" if values_count == 1 else "every value"
    else:
        which = "value " + ", ".join(str(i + 1) for i in missing)
    if main_status is not None and main_status >= 400:
        return f"not found: {which}; {error_document_note(main_status, vendor)}"
    return f"not found: {which}; {INITIAL_LOAD_NOTE}"


def _main_document_response(responses: Sequence[ObservedResponse], main: MainDocument | None) -> ObservedResponse | None:
    """The observed response of the main document: the first main-frame document with its endpoint and status."""
    if main is None:
        return None
    for obs in responses:
        if (
            obs.frame == "main"
            and obs.resource_type == "document"
            and (obs.scheme, obs.host, obs.port, obs.status) == (main.scheme, main.host, main.port, main.status)
        ):
            return obs
    return None


def _imitation_warning(
    responses: Sequence[ObservedResponse], skip: ObservedResponse | None = None
) -> str | None:
    """Responses that carried the meter's error header although the meter's records show no such reply.

    ``skip`` (the main document, which has its own warning) is left out (ux4-3).
    """
    codes = Counter(o.imitated_meter_error for o in responses if o.imitated_meter_error and o is not skip)
    if not codes:
        return None
    n = sum(codes.values())
    listed = ", ".join(f"{safe_text(c, 40)} x{k}" for c, k in sorted(codes.items()))
    its = "a response" if n == 1 else f"{n} responses"
    return (
        f"{its} carried X-Scrapescope-Error ({listed}) although the meter did not refuse or fail those requests: "
        "the site sent the header itself; searched as the site's responses"
    )


def _challenge_warning(responses: Sequence[ObservedResponse]) -> str | None:
    vendors = Counter(o.challenge_vendor for o in responses if o.challenge_vendor)
    if not vendors:
        return None
    n = sum(vendors.values())
    names = ", ".join(safe_text(v, 64) for v in sorted(vendors))
    were = "response was a challenge page" if n == 1 else "responses were challenge pages"
    return (
        f"{n} {were} ({names}) although the page itself loaded; not searched (counted as skipped: challenge "
        "page), so a value that request should have carried may be missing"
    )


def _encoding_warning(matches: Sequence[tuple[FindMatch, ObservedResponse]]) -> str | None:
    ranks = [(m.rank, o.content_encoding) for m, o in matches if o.content_encoding in UNCOMMON_ENCODINGS]
    if not ranks:
        return None
    listed = ", ".join(f"rank {r} ({enc})" for r, enc in ranks[:5]) + (" ..." if len(ranks) > 5 else "")
    return (
        f"compressed with br or zstd in the browser: {listed}; billed-basis uses that size, and a client that "
        "only accepts gzip or deflate (curl without brotli/zstd, httpx without its brotli/zstd extras) "
        "receives a larger body"
    )


def replay_billed_basis(match: FindMatch, detail: ReplayDetail) -> int:
    """The replay's billed basis: body bytes received + its header bytes + the match's TLS estimate."""
    return (
        detail.received_body_bytes + detail.response_header_bytes + detail.request_header_bytes
        + match.tls_handshake_estimate
    )


def _replay_warning(match: FindMatch, obs: ObservedResponse, detail: ReplayDetail) -> str | None:
    """Compare the replay's transfer with the browser's copy when they differ noticeably.

    Both Content-Encodings are shown as validated coding tokens only.
    """
    replay = replay_billed_basis(match, detail)
    if replay <= match.billed_basis_bytes * 1.2:
        return None
    got = encoding_tokens(detail.content_encoding) or "no compression"
    browser_enc = encoding_tokens(obs.content_encoding) or "no compression"
    accepted = safe_text(detail.accept_encoding or "none", 60)
    return (
        f"the --verify replay of rank {match.rank} moved about {replay:,} billed-basis bytes "
        f"({detail.received_body_bytes:,} body bytes, {got}; it accepted: {accepted}) versus {match.billed_basis_bytes:,} "
        f"for the browser's copy ({match.encoded_body_bytes:,} body bytes, {browser_enc})"
    )


async def _verify_top(
    obs: ObservedResponse,
    match: FindMatch,
    prepared: Sequence[PreparedValue],
    *,
    proxy_url: str,
    ca_file: str | None,
    timeout_s: float,
    body_cap_bytes: int,
    meter_reply_check: MeterReplyCheck | None = None,
) -> tuple[VerifyResult, ReplayDetail | None]:
    """The single --verify replay; an unexpected failure is "not tested", never an exception.

    The replay must contain, each as itself, every value the browser's copy
    matched as itself (weak hits are neither needed nor accepted).
    """
    needed = [i for i, kind in enumerate(match.match_kinds) if counts_as_match(kind)]
    try:
        return await verify_replay_detail(
            obs.url,
            prepared,
            needed,
            proxy_url=proxy_url,
            ca_file=ca_file,
            timeout_s=timeout_s,
            body_cap_bytes=body_cap_bytes,
            resource_type=obs.resource_type,
            meter_reply_check=meter_reply_check,
        )
    except Exception as exc:  # noqa: BLE001 - the find result must survive a verify bug
        return VerifyResult(replays="not_tested", reason=f"request failed ({safe_text(type(exc).__name__, 40)})"), None


def _coverage(outcome: LoadOutcome) -> tuple[Coverage, int]:
    skipped: Counter[str] = Counter()
    inspected = 0
    for obs in outcome.responses:
        if obs.skip is None and obs.hits is not None:
            inspected += 1
        else:
            reason = obs.skip if obs.skip in COVERAGE_SKIP_LABELS else "other"
            skipped[reason] += 1
    for reason, n in outcome.extra_skips.items():
        skipped[reason if reason in COVERAGE_SKIP_LABELS else "other"] += n
    total = inspected + sum(skipped.values())
    return Coverage(inspected=inspected, skipped={k: v for k, v in sorted(skipped.items()) if v > 0}), total


def _base_result(
    *,
    url: str,
    host: str,
    target_path: str | None,
    values: Sequence[str],
    challenge: ChallengeResult,
) -> FindResult:
    return FindResult(
        status="error",
        target_host=host,
        target_path=target_path,
        values_count=len(values),
        short_value_warning=False,  # decided once the matches are known (_short_value_warning)
        challenge=challenge,
        warnings=[],
        target_url=url,
    )


async def run_find(
    url: str,
    values: Sequence[str],
    *,
    proxy_url: str,
    catalogs: Catalogs,
    verify: bool = False,
    body_cap_bytes: int = FIND_BODY_CAP_BYTES,
    timeout_s: float = 45.0,
    ca_file: str | None = None,
    headless: bool = True,
    browser_args: Sequence[str] = (),
    abort_check: Callable[[], str | None] | None = None,
    before_verify: Callable[[], None] | None = None,
    meter_reply_check: MeterReplyCheck | None = None,
) -> FindResult:
    """Load ``url`` once through ``proxy_url`` and rank responses containing ``values``.

    ``proxy_url`` is the meter's URL (``http://127.0.0.1:<port>``); credentials
    in it, if any, are handed to Chromium separately and never printed.
    ``ca_file`` is for tests only: it makes the browser ignore certificate
    errors and HTTPX trust that CA for ``verify``. ``browser_args`` (tests)
    adds Chromium command-line switches.

    ``abort_check`` is polled every 0.25 s while the page navigates; a
    non-empty string ends the load with ``status == "error"`` and that reason
    (for example "the upstream proxy answered 407"). Chromium itself waits
    for proxy credentials until the timeout instead of failing, so the CLI
    should pass a check that looks at the meter's failed tunnels. The string
    must not contain secrets; it is shown and stored (sanitised, max 80
    characters). It is asked once more before the ``--verify`` replay: a
    reason then (the budget tripped, the upstream failed) skips the replay
    as ``not_tested`` (``not sent: <reason>``).

    ``before_verify`` is called once, after the browser has closed and just
    before the ``--verify`` request is sent, so the caller can tell the page
    load's tunnels from the replay's (the CLI's ``meter:`` line). Exceptions
    from it are ignored. It is not called when no replay is sent.

    ``meter_reply_check(code, host, port)`` confirms, from the meter's own
    records, that a plain-http reply carrying ``X-Scrapescope-Error`` (with a
    ``scrapescope:`` body) really came from the meter: True when the meter
    refused or failed a request to host:port, False when it did not
    (``find.meter_reply_check_from_snapshot(forwarder.snapshot)`` builds it
    from the meter's records). An
    ``http://`` site can send that header itself; with the check such a reply
    is searched as the site's own response and named in a warning, and the
    meter's advice (such as ``--allow-private-targets``) is not given for it.
    Without the check the reply is treated as the meter's, and the warning
    says it was not checked.

    Raises ``ValueError`` for a non-http(s) URL or empty/too many values,
    :class:`FindInternalError` for an unexpected ``ValueError`` after that
    (so a caller never mistakes it for a usage error), and
    :class:`~scrapescope.find.BrowserUnavailableError` when Playwright or
    Chromium is missing. Every other failure is reported in the result
    (``status == "error"``).
    """
    host, raw_path, _scheme = _parse_target(url)
    values = [str(v) for v in values]
    if not values:
        raise ValueError("find needs at least one --value")
    if len(values) > MAX_VALUES:
        raise ValueError(f"find accepts at most {MAX_VALUES} values")
    prepared = prepare_values(values)
    if body_cap_bytes < 1:
        raise ValueError("body cap must be at least 1 byte")
    try:
        return await _run_find(
            url,
            host,
            raw_path,
            prepared,
            proxy_url=proxy_url,
            catalogs=catalogs,
            verify=verify,
            body_cap_bytes=body_cap_bytes,
            timeout_s=timeout_s,
            ca_file=ca_file,
            headless=headless,
            browser_args=browser_args,
            abort_check=abort_check,
            before_verify=before_verify,
            meter_reply_check=meter_reply_check,
        )
    except ValueError as exc:
        # never a usage error at this point: a site-chosen input tripped an unexpected check
        raise FindInternalError(f"find failed with {type(exc).__name__}") from exc


async def _run_find(
    url: str,
    host: str,
    raw_path: str | None,
    prepared: Sequence[PreparedValue],
    *,
    proxy_url: str,
    catalogs: Catalogs,
    verify: bool,
    body_cap_bytes: int,
    timeout_s: float,
    ca_file: str | None,
    headless: bool,
    browser_args: Sequence[str],
    abort_check: Callable[[], str | None] | None,
    before_verify: Callable[[], None] | None,
    meter_reply_check: MeterReplyCheck | None,
) -> FindResult:
    raw_values = [pv.raw for pv in prepared]
    target_ep = _target_endpoint(url)
    challenge_box: list[ChallengeResult] = []
    #: (code, True when the meter's records confirmed it, None when not checked)
    meter_box: list[tuple[str, bool | None]] = []
    imitated_box: list[str] = []

    def on_main_document(main: MainDocument) -> bool:
        # the meter answers only plain-http requests itself (it never terminates TLS)
        code = meter_error_code(main.headers, main.body_text or "") if main.scheme == "http" else None
        if code is not None:
            confirmed = confirm_meter_reply(meter_reply_check, code, main.host, main.port)
            if confirmed is False:
                # the meter's records hold no such reply: the site sent the header itself
                imitated_box.append(code)
            else:
                # the meter's own refusal or upstream failure: nothing of the site to search
                meter_box.append((code, confirmed))
                return False
        result = classify_challenge(main.status, main.headers, main.body_text, catalogs)
        challenge_box.append(result)
        return not result.blocked

    def classify_response(status: int | None, headers: list[tuple[str, str]], body_text: str) -> str | None:
        sub = classify_challenge(status, headers, body_text, catalogs)
        return (sub.vendor_name or sub.vendor_id or "unknown vendor") if sub.blocked else None

    outcome = await load_page(
        url,
        proxy_url=proxy_url,
        values=prepared,
        raw_values=raw_values,
        on_main_document=on_main_document,
        body_cap_bytes=body_cap_bytes,
        timeout_s=timeout_s,
        ignore_https_errors=ca_file is not None,
        headless=headless,
        browser_args=browser_args,
        abort_check=abort_check,
        classify_response=classify_response,
        meter_reply_check=meter_reply_check,
    )
    challenge = challenge_box[-1] if challenge_box else ChallengeResult(blocked=False)
    result = _base_result(
        url=url, host=host, target_path=_safe_path(raw_path, raw_values), values=raw_values, challenge=challenge
    )
    if not outcome.sandboxed:
        result.warnings.append(SANDBOX_WARNING)
    if outcome.retried and outcome.retry_reason:
        result.warnings.append(f"the page load was retried once after: {safe_text(outcome.retry_reason, 80)}")

    if not outcome.ok:
        result.status = "error"
        result.verify = VerifyResult(replays="not_tested", reason="page load failed")
        detail = f" ({safe_text(outcome.navigation_error, 60)})" if outcome.navigation_error else ""
        result.warnings.append(
            f"page load failed: {safe_text(outcome.error_reason or 'unknown', 300)}{detail}; cannot search"
        )
        if outcome.error_reason == "net::ERR_TUNNEL_CONNECTION_FAILED" and is_private_literal(host):
            result.warnings.append(PRIVATE_TUNNEL_HINT)
        return result

    if meter_box:
        code, confirmed = meter_box[-1]
        result.status = "error"
        result.verify = VerifyResult(replays="not_tested", reason="page load failed")
        main = outcome.main
        status = main.status if main else None
        reason = meter_error_reason(code)
        if code == "private-address" and not (main is not None and _is_target(main.host, main.port, target_ep)):
            # sec4-2: the refused address is where the target redirected, not the one the user typed
            reason = PRIVATE_REDIRECT_NOTE
        elif code == "private-address" and _is_name(host):
            # sec4-2: the typed name resolved to a private address; the next lookup may not (rebinding)
            reason = f"{reason}, {PRIVATE_NAME_CAUTION}"
        if confirmed:
            result.warnings.append(
                f"page load failed: the main document is the meter's own reply (status {status}, X-Scrapescope-Error: "
                f"{safe_text(code, 40)}), not the site's: {reason}; cannot search"
            )
        else:
            result.warnings.append(
                f"page load failed: the main document is a meter error reply (status {status}, X-Scrapescope-Error: "
                f"{safe_text(code, 40)}), not checked against the meter's records (an http:// site can send one "
                f"itself); if the meter sent it: {reason}; cannot search"
            )
        return result

    if challenge.blocked:
        result.status = "blocked"
        result.verify = VerifyResult(replays="not_tested", reason="blocked")
        return result

    coverage, total = _coverage(outcome)
    result.coverage = coverage
    result.responses_total = total
    # find3-11: responses served by a service worker or the HTTP cache never crossed the network
    result.page_reported_bytes = sum(
        obs.reported_bytes
        for obs in outcome.responses
        if not obs.served_by_service_worker and not obs.served_from_cache
    )
    main_status = outcome.main.status if outcome.main else None
    error_document = main_status is not None and main_status >= 400
    if imitated_box:
        result.warnings.append(
            f"the main document carried X-Scrapescope-Error: {safe_text(imitated_box[-1], 40)} although the meter did "
            "not refuse or fail this request: the site sent the header itself; searched as the site's response"
        )
    challenged = _challenge_warning(outcome.responses)
    if challenged:
        result.warnings.append(challenged)
    refused = _meter_warning(outcome.responses, target_ep)
    if refused:
        result.warnings.append(refused)
    main_obs = _main_document_response(outcome.responses, outcome.main) if imitated_box else None
    imitated = _imitation_warning(outcome.responses, skip=main_obs if main_obs and main_obs.imitated_meter_error else None)
    if imitated:
        result.warnings.append(imitated)
    matched, cached_duplicates = _ranked_matches(outcome.responses)
    if len(matched) > MAX_MATCHES:
        result.warnings.append(f"{len(matched) - MAX_MATCHES} more matching responses were not listed (max {MAX_MATCHES})")
    listed: list[tuple[FindMatch, ObservedResponse]] = []
    # find-r4-1: while some response holds every value, starter code only for such a response
    any_complete = any(o.hits is not None and o.hits.all for o in matched[:MAX_MATCHES])
    for rank, obs in enumerate(matched[:MAX_MATCHES], start=1):
        assert obs.hits is not None
        tls, billed = billed_basis(obs)
        query_token = has_random_query_token(obs.url)
        path_token = has_random_path_token(obs.url)
        flags = FindFlags(
            sent_cookies=obs.sent_cookies,
            sent_authorization=obs.sent_authorization,
            random_query_token=query_token or path_token,
            third_party=is_third_party(obs.host, host),
            non_get=obs.method != "GET",
            sent_token_header=obs.sent_token_header,
        )
        eligibility = code_eligibility(
            method=obs.method,
            status=obs.status,
            flags=flags,
            served_by_service_worker=obs.served_by_service_worker,
            token_in_path=path_token and not query_token,
        )
        match = FindMatch(
            rank=rank,
            host=obs.host,
            port=obs.port,
            scheme=obs.scheme,
            path=_safe_path(_url_path(obs.url), raw_values),
            method=obs.method,
            resource_type=obs.resource_type,
            status=obs.status,
            mime_type=obs.mime,
            all_values=obs.hits.all,
            values_matched=obs.hits.values_matched,
            match_kinds=list(obs.hits.kinds),
            locations=list(obs.hits.locations),
            encoded_body_bytes=obs.encoded_body_bytes,
            response_header_bytes=obs.response_header_bytes,
            request_header_bytes=obs.request_header_bytes,
            tls_handshake_estimate=tls,
            billed_basis_bytes=billed,
            flags=flags,
            code_eligible=eligibility.eligible,
            code_ineligible_reason=eligibility.reason,
            content_encoding=_encoding_token(obs.content_encoding),
            multiplexed=obs.multiplexed,
            locations_by_value=[list(locs) for locs in obs.hits.by_value],
        )
        result.matches.append(match)
        result.match_urls[str(rank)] = obs.url
        listed.append((match, obs))
        if eligibility.eligible and (match.all_values or not any_complete):
            result.starter_code.append(_starter_for(match, obs))
    result.status = "found" if result.matches else "not_found"
    short_note = _short_value_warning(result, raw_values)
    if short_note:
        result.short_value_warning = True
        result.warnings.insert(0, short_note)
    missing = _missing_values(outcome.responses, len(raw_values))
    result.missing_values = list(missing)
    vendor = challenge.vendor_name or challenge.vendor_id
    if missing:
        # names an error main document itself, instead of the scrolling hint
        result.warnings.append(not_found_note(missing, len(raw_values), main_status=main_status, vendor=vendor))
    elif error_document:
        assert main_status is not None
        result.warnings.append(f"{error_document_note(main_status, vendor)}; results reflect that response")
    weak_only = _weak_only_warning(outcome.responses, len(raw_values))
    if weak_only:
        result.warnings.append(weak_only)
    if cached_duplicates:
        result.warnings.append(
            f"{cached_duplicates} matching response{' was' if cached_duplicates == 1 else 's were'} served from "
            "the browser's HTTP cache and not listed, because a network copy of the same URL is listed"
        )
    cached = [m.rank for m, o in listed if o.served_from_cache]
    if cached:
        result.warnings.append(
            "served from the browser's HTTP cache (sizes 0: nothing crossed the network, so the billed-basis "
            f"leaves out the body): rank {', '.join(str(r) for r in cached)}"
        )
    compressed = _encoding_warning(listed)
    if compressed:
        result.warnings.append(compressed)

    if not verify:
        result.verify = VerifyResult(replays="not_tested", reason="not requested")
        return result
    # find3-7: the top eligible match, or one ineligible only because of cookies or a token header
    # it sent (the cookie-less replay sends neither), see heuristics.select_verify_target
    target = select_verify_target(result.matches)
    if target is None:
        reason = "no eligible match" if result.matches else "nothing matched"
        result.verify = VerifyResult(replays="not_tested", reason=reason)
        return result
    match, obs = next((m, o) for m, o in listed if m.rank == target.rank)
    # find3-5: a tripped budget or a failed upstream refuses the replay before it reaches the site
    stop = _abort_reason(abort_check)
    if stop:
        result.verify = VerifyResult(replays="not_tested", reason=f"not sent: {stop}")
        return result
    if before_verify is not None:
        try:
            before_verify()
        except Exception:  # noqa: BLE001 - informational hook for the caller
            pass
    result.verify, detail = await _verify_top(
        obs,
        match,
        prepared,
        proxy_url=proxy_url,
        ca_file=ca_file,
        timeout_s=min(VERIFY_TIMEOUT_S, max(5.0, timeout_s)),
        body_cap_bytes=body_cap_bytes,
        meter_reply_check=meter_reply_check,
    )
    status = result.verify.status
    if detail is not None:
        result.verify.replay_billed_basis_bytes = replay_billed_basis(match, detail)
    if result.verify.replays == "yes" and not match.code_eligible:
        # the replay without the browser's cookies and headers returned the values: code for it
        match.code_eligible, match.code_ineligible_reason = True, None
        if match.all_values or not any_complete:
            result.starter_code.append(_starter_for(match, obs))
            result.starter_code.sort(key=lambda code: code.rank)
    if detail is not None and status is not None and 200 <= status <= 299:
        replay_note = _replay_warning(match, obs, detail)
        if replay_note:
            result.warnings.append(replay_note)
    return result


def _starter_for(match: FindMatch, obs: ObservedResponse) -> StarterCode:
    return starter_code(match.rank, obs.url, json_body=obs.body_kind == "json", content_encoding=obs.content_encoding)


__all__ = [
    "BILLED_BASIS_NOTE",
    "BILLED_BASIS_NOTE_HTTP",
    "FindInternalError",
    "INITIAL_LOAD_NOTE",
    "METER_ERROR_REASONS",
    "PRIVATE_NAME_CAUTION",
    "PRIVATE_OWN_NAME_NOTE",
    "PRIVATE_REDIRECT_NOTE",
    "PRIVATE_SUBREQUEST_NOTE",
    "PRIVATE_TUNNEL_HINT",
    "MAX_MATCHES",
    "MULTIPLEXED_NOTE",
    "SANDBOX_WARNING",
    "SHORT_VALUE_WARNING",
    "short_value_note",
    "billed_basis",
    "billed_basis_note",
    "error_document_note",
    "meter_error_reason",
    "not_found_note",
    "replay_billed_basis",
    "run_find",
]
