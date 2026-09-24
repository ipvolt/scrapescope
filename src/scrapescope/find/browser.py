"""Playwright driver for ``find``: one page load, context-level response collection.

The page is loaded once in headless Chromium with a browser-wide proxy (the
meter) and Chromium's default user agent; nothing is spoofed. Responses are
collected at the *context* level (``requestfinished``/``requestfailed``), which
in Playwright covers the main frame, iframes (including out-of-process
cross-site ones), dedicated workers (reported as requests of the page's
frame, so they cannot be told apart from frame requests) and, when the
service worker is running with a valid certificate, the service worker's own
network requests. Each text body is read as soon as its request finishes (so
Chromium's buffers cannot evict it later), searched in memory, and dropped.

Coverage is counted per request, never estimated: every finished or failed
http(s) request is either inspected or skipped with one reason from
``types.COVERAGE_SKIP_LABELS``:

- ``binary``: not a text type (images, fonts, media, octet-stream...);
- ``over_cap``: encoded size, Content-Length or decoded size over the cap;
- ``no_body``: HEAD, 1xx, 204, 304 and redirects;
- ``failed``: the request failed before a response;
- ``evicted``: Chromium no longer had the body;
- ``no_session``: the body belonged to a worker or frame whose session had
  gone (for example a service worker that stopped);
- ``websocket``: WebSocket connections (never read);
- ``challenge``: a sub-response that was itself a challenge page (below);
- ``other``: anything else, including requests still unfinished when the
  load's time budget ran out.

HTTP-cache hits: Playwright has no cache flag, but Chromium reports a
disk-cache hit with a body size equal to minus its header size (Playwright
computes the body size as ``encodedDataLength`` minus the header size, and a
cache hit has ``encodedDataLength`` 0). Such responses (not served by a
service worker) get ``served_from_cache`` and all sizes 0, since nothing
crossed the network; their bodies are still read and searched.

Challenge pages below the main document: with ``classify_response``, text
responses other than the main document (XHR, fetch, iframes, and any non-2xx
or 202 response) are classified with the same catalog before searching. A
challenged response is not searched; it is counted as skipped
(``challenge``) and carries ``challenge_vendor``, so a "not found" can say that
the data request was challenged.

The meter's own replies: for an ``http://`` request the meter answers
itself when it refuses (a private address, a deny rule, the budget) or cannot
reach the upstream, with ``X-Scrapescope-Error: <code>`` and a one-line body.
Such a sub-response is never searched; it is counted as skipped (``failed``)
and carries ``meter_error``. An ``http://`` site can send the same header, so
with ``meter_reply_check`` (the caller's lookup in the meter's records,
:func:`meter_reply_check_from_snapshot`) a reply the meter did not send is
searched as the site's own response and carries ``imitated_meter_error``
instead. The main document is checked the
same way by the caller (:func:`meter_error_code`).

WebRTC: Chromium is launched with
``--force-webrtc-ip-handling-policy=disable_non_proxied_udp``. Without it a
page's ``RTCPeerConnection`` sends STUN over UDP straight from this machine's
network interfaces, around the meter and any provider, and the page learns
the machine's own addresses. UDP cannot go through an HTTP or SOCKS proxy, so
with this policy WebRTC uses only proxied TCP or nothing.

Accuracy limits: sizes are DevTools' (``request.sizes()``); a response served
by a service worker reports its own sizes although it never crossed the
network (negative sizes are clamped to 0). Memory-cache hits that Chromium
never reports are not seen at all. Requests Playwright does not surface (for
example some extension or browser-internal fetches) are not counted at all;
the meter's tunnel totals remain the authoritative bytes.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import urllib.parse
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..helpers.playwright import WEBRTC_PROXIED_ONLY_ARGS, _proxy_hop_bytes, is_multiplexed
from ..types import canonical_host, clean_host, safe_text
from .heuristics import body_kind, decode_body, is_token_header, looks_binary, mime_of
from .search import BodyHits, PreparedValue, parse_json_text, search_body

#: Characters of the main document body handed to the challenge classifier.
MAIN_BODY_WINDOW_BYTES = 64 * 1024
#: The load is considered settled after this long without network activity.
QUIET_S = 1.0
#: A request pending this long without any other activity no longer blocks settling.
STALLED_S = 3.0
#: Longest wait for the page's load event after the document arrived.
LOAD_EVENT_WAIT_S = 10.0
#: Concurrent body reads.
BODY_READ_CONCURRENCY = 6
#: Seconds allowed for one protocol call (sizes, headers, body).
PROTOCOL_CALL_TIMEOUT_S = 20.0
#: Chromium switches find always sets. WebRTC may use proxied connections only, so a page
#: cannot send STUN over UDP from this machine's interfaces (bypassing the meter and the
#: provider) or learn its addresses.
FIND_CHROMIUM_ARGS: tuple[str, ...] = WEBRTC_PROXIED_ONLY_ARGS
#: Header on the meter's own replies (docs/dev/contracts.md section 3).
METER_ERROR_HEADER = "x-scrapescope-error"
_METER_CODE_RE = re.compile(r"[a-z0-9-]{1,40}")

_NETWORK_SCHEMES = ("http", "https")
_METHOD_RE = re.compile(r"[A-Z]{1,16}")
_RESOURCE_TYPE_RE = re.compile(r"[a-z_]{1,32}")
_LOCATION_NAME_RE = re.compile(r"[a-z][a-z0-9+_-]{0,31}")


class BrowserUnavailableError(RuntimeError):
    """Playwright or its Chromium is not installed (CLI exit 3)."""


#: Advice when the Playwright package is missing (uv, pipx or pip, as in the README's Install section;
#: the package is installed from GitHub, it is not on PyPI yet).
INSTALL_HINT = (
    "install the browser extra and Playwright's Chromium the way scrapescope was installed: "
    "uv tool install 'scrapescope[browser] @ git+https://github.com/ipvolt/scrapescope'"
    " --with-executables-from playwright, "
    "or pipx inject --include-apps scrapescope playwright, "
    "or pip install 'scrapescope[browser] @ git+https://github.com/ipvolt/scrapescope'; "
    "then playwright install chromium"
)
#: Advice when Playwright is present but its Chromium cannot start.
CHROMIUM_HINT = (
    "install it with the Playwright of the environment scrapescope runs in (playwright install chromium; "
    "on Linux, playwright install-deps chromium adds missing system libraries)"
)


@dataclass
class ObservedResponse:
    """One finished or failed request of the load (metadata plus search hits only)."""

    seq: int
    url: str
    host: str
    port: int
    scheme: str
    method: str
    resource_type: str
    frame: str = "other"
    status: int | None = None
    mime: str | None = None
    body_kind: str | None = None
    served_by_service_worker: bool = False
    #: Served from Chromium's HTTP cache (sizes are then 0: nothing crossed the network).
    served_from_cache: bool = False
    #: The response's Content-Encoding, lowercased ("" when none or unknown).
    content_encoding: str = ""
    #: HTTP/2 or HTTP/3: DevTools header sizes are not wire sizes, so both header
    #: fields are 0 and the encoded body already includes the response header frames.
    multiplexed: bool = False
    #: Vendor name when this sub-response was a challenge page (then not searched).
    challenge_vendor: str | None = None
    #: The meter's error code when the meter answered this request itself (then not searched).
    meter_error: str | None = None
    #: The X-Scrapescope-Error code of a reply the meter's records say it did not send (searched).
    imitated_meter_error: str | None = None
    encoded_body_bytes: int = 0
    response_header_bytes: int = 0
    request_header_bytes: int = 0
    request_body_bytes: int = 0
    sent_cookies: bool = False
    sent_authorization: bool = False
    #: The request carried a credential- or token-like header (``heuristics.is_token_header``; presence only).
    sent_token_header: bool = False
    #: Coverage skip reason, or None when the body was searched.
    skip: str | None = None
    hits: BodyHits | None = None

    @property
    def reported_bytes(self) -> int:
        return self.encoded_body_bytes + self.response_header_bytes + self.request_header_bytes + self.request_body_bytes


@dataclass
class MainDocument:
    status: int | None
    headers: list[tuple[str, str]]
    body_text: str | None
    #: The document's final URL scheme ("http" or "https"; "" when unknown).
    scheme: str = ""
    #: The document's final host (``clean_host``) and port; "" and 0 when unknown.
    host: str = ""
    port: int = 0


@dataclass
class LoadOutcome:
    """Everything the page load produced (no bodies)."""

    ok: bool
    error_reason: str | None = None
    main: MainDocument | None = None
    #: False when the main-document callback stopped the load (challenge page).
    searched: bool = False
    responses: list[ObservedResponse] = field(default_factory=list)
    #: Skips without an ObservedResponse (websockets, unfinished requests).
    extra_skips: Counter[str] = field(default_factory=Counter)
    retried: bool = False
    retry_reason: str | None = None
    #: False when Chromium could not start with its OS sandbox and ran without it.
    sandboxed: bool = True
    #: The navigation error behind ``error_reason`` when ``abort_check`` explained it.
    navigation_error: str | None = None


def playwright_proxy(proxy_url: str) -> dict[str, str]:
    """Playwright ``proxy=`` settings for ``proxy_url`` (credentials passed separately)."""
    parts = urllib.parse.urlsplit(proxy_url if "://" in proxy_url else "http://" + proxy_url)
    host = parts.hostname or "127.0.0.1"
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        netloc += f":{parts.port}"
    proxy = {"server": f"{parts.scheme or 'http'}://{netloc}"}
    if parts.username is not None:
        proxy["username"] = urllib.parse.unquote(parts.username)
        proxy["password"] = urllib.parse.unquote(parts.password or "")
    return proxy


def _clamp(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


#: ``(code, host, port) -> bool | None``: True when the meter's records show it answered a request to
#: host:port itself (a refusal or a failed or denied tunnel), False when they show it did not (the
#: site sent a look-alike reply), None when unknown (the reply is then treated as the meter's).
MeterReplyCheck = Callable[[str, str, int], "bool | None"]


#: Meter error codes for requests it refuses before any tunnel exists, with their
#: ``MeterSnapshot.refused`` counter (docs/dev/contracts.md section 3.2).
_REFUSAL_COUNTERS = {
    "budget": "budget",
    "self-loop": "self_loop",
    "bad-request": "bad_request",
    "https-absolute-form": "https_absolute_form",
    "token-required": "token_required",
    "bad-token": "bad_token",
    "auth-challenge": "auth_challenge",
}
#: Meter error codes sent for a tunnel to the request's own host:port, with that
#: ``TunnelRecord.status`` (docs/dev/contracts.md section 3.2 and the failure table).
_TUNNEL_STATUS_OF_CODE = {
    "denied": "denied",
    "private-address": "failed:private_address",
    "self-loop": "failed:self_loop",
    "upstream-unreachable": "failed:upstream_unreachable",
    "upstream-timeout": "failed:upstream_timeout",
    "upstream-closed": "failed:upstream_closed",
    "upstream-protocol-error": "failed:upstream_protocol",
    "socks-auth-failed": "failed:socks_auth",
    "socks-no-method": "failed:socks_method",
    "socks-auth-unsupported": "failed:socks_auth_unsupported",
    "dns-failed": "failed:dns",
    "connect-refused": "failed:connect_refused",
    "connect-timeout": "failed:connect_timeout",
    "local-limit": "failed:local_limit",
    "internal-error": "failed:internal",
    "bad-request": "failed:bad_request",
}


def endpoint_host(host: str) -> str:
    """``host`` as the meter records it: ``clean_host`` form with IP literals canonical (``types.canonical_host``).

    ``[::ffff:127.0.0.1]``, ``::ffff:7f00:1`` and ``127.0.0.1`` all give
    ``127.0.0.1``; a name gives its lowercase, IDNA form. A host that
    ``clean_host`` rejects is compared lowercased without brackets.
    """
    cleaned = clean_host(host) or host.strip().strip("[]").lower()
    return canonical_host(cleaned)


def meter_reply_check_from_snapshot(snapshot: Callable[[], Any]) -> MeterReplyCheck:
    """A :data:`MeterReplyCheck` that looks the reply up in the meter's own records.

    ``snapshot`` is the forwarder's ``snapshot`` method (a ``MeterSnapshot``).
    The meter records every refusal and failure before it writes its reply
    (a refusal counter, or the tunnel's final status), so by the time the
    browser or HTTPX sees a reply the record is there. The check answers
    True when the snapshot holds the refusal that code stands for: the
    ``refused`` counter (budget, self-loop, malformed request...), or a tunnel
    to that host and port with the matching status (``failed:private_address``
    for ``private-address``, ``denied`` for ``denied``, ``failed:dns`` for
    ``dns-failed``...); for a ``socks-reply-<n>`` code, ``failed:socks_reply_<n>``;
    for a code the meter does not send, any failed or denied tunnel to that
    host and port. Otherwise False: the site sent the header itself. A
    snapshot that cannot be taken gives None (unknown). Hosts are compared in
    their canonical spelling (:func:`endpoint_host`), as the meter records
    them: ``::ffff:7f00:1`` and ``[::ffff:127.0.0.1]`` are ``127.0.0.1``.

    Pass it to ``run_find(meter_reply_check=...)``.
    """

    def check(code: str, host: str, port: int) -> bool | None:
        try:
            snap = snapshot()
            tunnels = list(snap.tunnels)
            refused = dict(snap.refused or {})
        except Exception:  # noqa: BLE001 - an advisory lookup
            return None
        counter = _REFUSAL_COUNTERS.get(code)
        if counter is not None and int(refused.get(counter, 0) or 0) > 0:
            return True
        if code == "budget" and bool(getattr(snap, "budget_tripped", False)):
            return True
        if code == "internal-error" and int(getattr(snap, "internal_errors", 0) or 0) > 0:
            return True
        # sec4-3: the meter records the canonical spelling (1.2.3.4 for ::ffff:1.2.3.4), while
        # Chromium and HTTPX keep the URL's ([::ffff:7f00:1]); compare both sides canonically
        want_host = endpoint_host(str(host))
        mine = [t for t in tunnels if endpoint_host(str(t.host)) == want_host and int(t.port) == int(port)]
        if code.startswith("socks-reply-"):
            expected: str | None = "failed:socks_reply_" + code[len("socks-reply-") :]
        else:
            expected = _TUNNEL_STATUS_OF_CODE.get(code)
        if expected is not None:
            return any(str(t.status) == expected for t in mine)
        if counter is not None:
            return False
        return any(str(t.status) == "denied" or str(t.status).startswith("failed:") for t in mine)

    return check


def confirm_meter_reply(check: MeterReplyCheck | None, code: str, host: str, port: int) -> bool | None:
    """``check(code, host, port)``, with None for no check or a check that fails."""
    if check is None:
        return None
    try:
        answer = check(code, host, port)
    except Exception:  # noqa: BLE001 - an advisory lookup must not break the load
        return None
    return answer if isinstance(answer, bool) else None


def meter_error_code(headers: Sequence[tuple[str, str]], body_text: str | None = None) -> str | None:
    """The ``X-Scrapescope-Error`` code when a response is the meter's own reply, else None.

    Call it for plain-http responses only: the meter never terminates TLS, so
    an https response with this header came from the origin. With
    ``body_text`` the one-line body must also start with ``scrapescope:``, as
    every meter reply does; this makes an origin that merely sends the header
    less convincing, although an http site can still imitate a reply, which
    only the meter's records can tell apart (:data:`MeterReplyCheck`). A code
    outside ``[a-z0-9-]{1,40}`` is reported as ``other``.
    """
    values = [str(v).strip().lower() for n, v in headers if str(n).strip().lower() == METER_ERROR_HEADER]
    if not values:
        return None
    if body_text is not None and not body_text.lstrip().startswith("scrapescope:"):
        return None
    return values[0] if _METER_CODE_RE.fullmatch(values[0]) else "other"


def is_private_literal(host: str) -> bool:
    """True for ``localhost`` names and IP literals that are not global (no DNS lookup)."""
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def served_from_http_cache(sizes: Any, *, served_by_service_worker: bool) -> bool:
    """True when ``request.sizes()`` describe an HTTP-cache hit (body + headers <= 0, no service worker)."""
    if served_by_service_worker or not isinstance(sizes, dict):
        return False
    body, head = sizes.get("responseBodySize"), sizes.get("responseHeadersSize")
    return _is_int(body) and _is_int(head) and body + head <= 0


#: Navigation errors that a retry cannot fix (the same URL fails the same way).
DETERMINISTIC_NAVIGATION_ERRORS = frozenset(
    {
        "net::ERR_UNSAFE_PORT",
        "net::ERR_NAME_NOT_RESOLVED",
        "net::ERR_INVALID_URL",
        "net::ERR_DISALLOWED_URL_SCHEME",
        "net::ERR_UNKNOWN_URL_SCHEME",
        "net::ERR_BLOCKED_BY_CLIENT",
        "net::ERR_BLOCKED_BY_ADMINISTRATOR",
        "net::ERR_BLOCKED_BY_RESPONSE",
        "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
        "net::ERR_BAD_SSL_CLIENT_AUTH_CERT",
        "net::ERR_TOO_MANY_REDIRECTS",
        "net::ERR_INVALID_REDIRECT",
    }
)


def navigation_retryable(reason: str) -> bool:
    """False for a timeout (the retry would only get the rest of the budget) and deterministic errors."""
    if reason == "timeout" or reason in DETERMINISTIC_NAVIGATION_ERRORS:
        return False
    return not reason.startswith("net::ERR_CERT_")


#: Resource types whose 2xx responses are also classified (data requests and frames);
#: 2xx scripts and stylesheets are not, since vendor scripts can contain challenge markers.
_CLASSIFIED_TYPES = frozenset({"document", "xhr", "fetch", "eventsource", "other"})


def should_classify(obs: ObservedResponse) -> bool:
    """Whether a sub-response is run through the challenge classifier (never the main document)."""
    if obs.frame == "main" and obs.resource_type == "document":
        return False
    status = obs.status or 0
    return obs.resource_type in _CLASSIFIED_TYPES or not 200 <= status <= 299 or status == 202


def body_error_reason(message: str) -> str:
    """Map a Playwright body-read error message to a coverage skip reason."""
    m = message.lower()
    if "no resource with given identifier" in m or "no data found" in m or "evict" in m:
        return "evicted"
    if "redirect" in m:
        return "no_body"
    if any(s in m for s in ("worker closed", "target closed", "session closed", "detached", "has been closed")):
        return "no_session"
    return "other"


def navigation_error_reason(exc: BaseException) -> str:
    """A short reason for a failed navigation that never contains the URL."""
    text = str(exc)
    m = re.search(r"net::ERR_[A-Z0-9_]{1,64}", text)
    if m:
        return m.group(0)
    first = text.strip().splitlines()[0] if text.strip() else ""
    if type(exc).__name__ == "TimeoutError" or "timeout" in first.lower():
        return "timeout"
    return "browser error"


def _frame_kind(request: Any) -> str:
    try:
        if request.service_worker is not None:
            return "service_worker"
    except Exception:  # noqa: BLE001 - older Playwright or a closed worker
        pass
    try:
        frame = request.frame
    except Exception:  # noqa: BLE001 - "Service Worker requests do not have an associated frame"
        return "other"
    try:
        return "main" if frame.parent_frame is None else "sub"
    except Exception:  # noqa: BLE001
        return "other"


def _base_locations(resource_type: str, frame: str, served_by_sw: bool, served_from_cache: bool = False) -> list[str]:
    out = [resource_type] if _LOCATION_NAME_RE.fullmatch(resource_type) else ["other"]
    if frame == "sub":
        out.append("iframe")
    elif frame == "service_worker":
        out.append("service-worker")
    if served_by_sw:
        out.append("served-by-service-worker")
    if served_from_cache:
        out.append("served-from-cache")
    return out


async def _bounded(awaitable: Any, timeout: float = PROTOCOL_CALL_TIMEOUT_S) -> Any:
    return await asyncio.wait_for(awaitable, timeout)


#: ``(status, headers, first 64 KiB of the body) -> vendor name`` when the response is a challenge page.
ResponseClassifier = Callable[[int | None, list[tuple[str, str]], str], "str | None"]


class _Collector:
    """Context-level listener: reads and searches bodies as requests finish."""

    def __init__(
        self,
        values: Sequence[PreparedValue],
        raw_values: Sequence[str],
        body_cap_bytes: int,
        error_type: type[BaseException],
        classify_response: ResponseClassifier | None = None,
        meter_reply_check: MeterReplyCheck | None = None,
    ) -> None:
        self._loop = asyncio.get_running_loop()
        self._classify = classify_response
        self._meter_reply_check = meter_reply_check
        self._values = list(values)
        self._raw_values = list(raw_values)
        self._cap = body_cap_bytes
        self._error_type = error_type
        self._sem = asyncio.Semaphore(BODY_READ_CONCURRENCY)
        self._seq = 0
        self._seq_of: dict[Any, int] = {}
        self.pending: set[Any] = set()
        self.tasks: set[asyncio.Task[None]] = set()
        self.responses: list[ObservedResponse] = []
        self.extra_skips: Counter[str] = Counter()
        self.last_activity = self._loop.time()
        self.stopped = False

    # -- wiring ---------------------------------------------------------------
    def attach(self, context: Any) -> None:
        context.on("request", self._on_request)
        context.on("requestfinished", self._on_finished)
        context.on("requestfailed", self._on_failed)
        context.on("page", self._on_page)

    def _touch(self) -> None:
        self.last_activity = self._loop.time()

    def _on_page(self, page: Any) -> None:
        page.on("websocket", self._on_websocket)

    def _on_websocket(self, _ws: Any) -> None:
        if not self.stopped:
            self.extra_skips["websocket"] += 1
            self._touch()

    def _on_request(self, request: Any) -> None:
        if self.stopped or not str(request.url).lower().startswith(("http://", "https://")):
            return
        self._seq += 1
        self._seq_of[request] = self._seq
        self.pending.add(request)
        self._touch()

    def _on_finished(self, request: Any) -> None:
        if self.stopped or request not in self.pending:
            return
        self.pending.discard(request)
        self._touch()
        task = self._loop.create_task(self._process(request, self._seq_of.get(request, 0)))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def _on_failed(self, request: Any) -> None:
        if self.stopped or request not in self.pending:
            return
        self.pending.discard(request)
        self._touch()
        obs = self._skeleton(request, self._seq_of.get(request, 0))
        if obs is None:
            self.extra_skips["failed"] += 1
            return
        obs.skip = "failed"
        self.responses.append(obs)

    # -- processing -----------------------------------------------------------
    def _skeleton(self, request: Any, seq: int) -> ObservedResponse | None:
        url = str(request.url)
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        host = clean_host(parts.hostname or "")
        if host is None or scheme not in _NETWORK_SCHEMES:
            return None
        method = str(request.method).upper()
        resource_type = str(request.resource_type)
        return ObservedResponse(
            seq=seq,
            url=url,
            host=host,
            port=port or (443 if scheme == "https" else 80),
            scheme=scheme,
            method=method if _METHOD_RE.fullmatch(method) else "OTHER",
            resource_type=resource_type if _RESOURCE_TYPE_RE.fullmatch(resource_type) else "other",
            frame=_frame_kind(request),
        )

    async def _process(self, request: Any, seq: int) -> None:
        obs = self._skeleton(request, seq)
        if obs is None:
            self.extra_skips["other"] += 1
            return
        try:
            async with self._sem:
                await self._observe(request, obs)
        except asyncio.CancelledError:
            # Cut off by the time budget: counted, never silently dropped.
            if obs.hits is None:
                obs.skip = obs.skip or "other"
            self.responses.append(obs)
            raise
        except Exception:  # noqa: BLE001 - one odd response must not end the load
            obs.hits = None
            obs.skip = obs.skip or "other"
        self.responses.append(obs)

    async def _observe(self, request: Any, obs: ObservedResponse) -> None:
        response = await _bounded(request.response())
        if response is None:
            obs.skip = "failed"
            return
        obs.status = response.status
        try:
            obs.served_by_service_worker = bool(response.from_service_worker)
        except Exception:  # noqa: BLE001
            obs.served_by_service_worker = False
        try:
            sizes = await _bounded(request.sizes())
        except (self._error_type, asyncio.TimeoutError):
            sizes = {}
        if not isinstance(sizes, dict):
            sizes = {}
        if obs.status is not None and served_from_http_cache(
            sizes, served_by_service_worker=obs.served_by_service_worker
        ):
            # Nothing crossed the network: the sizes would only describe the cached headers.
            obs.served_from_cache = True
        else:
            obs.encoded_body_bytes = _clamp(sizes.get("responseBodySize"))
            obs.response_header_bytes = _clamp(sizes.get("responseHeadersSize"))
            obs.request_header_bytes = _clamp(sizes.get("requestHeadersSize"))
            obs.request_body_bytes = _clamp(sizes.get("requestBodySize"))
        try:
            sent = await _bounded(request.all_headers())
        except (self._error_type, asyncio.TimeoutError):
            sent = {}
        names = {str(k).lower() for k in sent}
        obs.sent_token_header = any(is_token_header(str(k), str(v)) for k, v in sent.items())
        if not obs.served_from_cache and is_multiplexed(sizes, names, obs.status):
            # HTTP/2 or HTTP/3: requestHeadersSize is rebuilt HTTP/1.1 text (HPACK/QPACK
            # sends far less) and responseHeadersSize is 0 because the response header
            # frames are already inside responseBodySize. Neither is a wire size.
            obs.multiplexed = True
            obs.request_header_bytes = 0
            obs.response_header_bytes = 0
        elif not obs.served_from_cache and obs.scheme == "http":
            # meas4-5: for plain http:// Chromium's requestHeadersSize includes the headers it
            # sends to the meter as its proxy (Proxy-Connection; Proxy-Authorization after a 407),
            # which the meter removes and a standalone fetch does not send (as the helper does)
            obs.request_header_bytes = max(0, obs.request_header_bytes - _proxy_hop_bytes(sent))
        obs.sent_cookies = "cookie" in names
        obs.sent_authorization = "authorization" in names
        try:
            received = await _bounded(response.all_headers())
        except (self._error_type, asyncio.TimeoutError):
            received = {}
        meter_code = (
            meter_error_code([(str(k), str(v)) for k, v in received.items()]) if obs.scheme == "http" else None
        )
        if meter_code is not None:
            if confirm_meter_reply(self._meter_reply_check, meter_code, obs.host, obs.port) is False:
                # the meter's records hold no such reply: the site sent the header itself
                obs.imitated_meter_error = meter_code
            else:
                # the meter answered itself (refusal or upstream failure): not the site's response
                obs.meter_error = meter_code
                obs.skip = "failed"
                return
        content_type = received.get("content-type")
        obs.content_encoding = str(received.get("content-encoding") or "").strip().lower()[:32]
        obs.mime = mime_of(content_type)
        kind = body_kind(obs.mime, obs.resource_type)
        obs.body_kind = kind
        status = obs.status or 0
        if obs.method == "HEAD" or status < 200 or status in (204, 304) or 300 <= status < 400:
            obs.skip = "no_body"
            return
        if kind is None:
            obs.skip = "binary"
            return
        declared = received.get("content-length", "")
        if obs.encoded_body_bytes > self._cap or (declared.isdigit() and int(declared) > self._cap):
            obs.skip = "over_cap"
            return
        try:
            data = await _bounded(response.body())
        except asyncio.TimeoutError:
            obs.skip = "other"
            return
        except self._error_type as exc:
            obs.skip = body_error_reason(str(exc))
            return
        if len(data) > self._cap:
            obs.skip = "over_cap"
            return
        if obs.mime is None and looks_binary(data):
            obs.skip = "binary"
            return
        text = decode_body(data, content_type, kind)
        del data
        if self._classify is not None and should_classify(obs):
            headers = [(str(k), str(v)) for k, v in received.items()]
            vendor = self._classify(obs.status, headers, text[:MAIN_BODY_WINDOW_BYTES])
            if vendor:
                obs.challenge_vendor = safe_text(str(vendor), 64)
                obs.skip = "challenge"
                return
        if kind == "text" and parse_json_text(text) is not None:
            kind = "json"
            obs.body_kind = kind
        base = _base_locations(obs.resource_type, obs.frame, obs.served_by_service_worker, obs.served_from_cache)
        text_label = "svg-text" if obs.mime == "image/svg+xml" else None
        obs.hits = await asyncio.to_thread(
            search_body, text, kind, self._values, base_locations=base, raw_values=self._raw_values,
            text_label=text_label,
        )
        del text

    # -- settling -------------------------------------------------------------
    async def settle(self, deadline: float) -> None:
        """Wait until the context has been quiet for QUIET_S (or the deadline)."""
        while self._loop.time() < deadline:
            idle = self._loop.time() - self.last_activity
            if not self.pending and not self.tasks and idle >= QUIET_S:
                return
            if idle >= STALLED_S and not self.tasks:
                return
            await asyncio.sleep(0.1)

    async def drain(self, deadline: float) -> None:
        """Wait for body reads until the deadline; cancel and count the rest as ``other``."""
        # Stop accepting new work first: requests finishing from now on stay in
        # ``pending`` and are counted as "other" below.
        self.stopped = True
        remaining = deadline - self._loop.time()
        if self.tasks:
            _done, not_done = await asyncio.wait(set(self.tasks), timeout=max(0.0, remaining))
            for task in not_done:
                task.cancel()
            if not_done:
                await asyncio.gather(*not_done, return_exceptions=True)
        if self.pending:
            self.extra_skips["other"] += len(self.pending)
            self.pending.clear()

    async def cancel(self) -> None:
        self.stopped = True
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)


async def _main_document(response: Any, error_type: type[BaseException], body_cap_bytes: int) -> MainDocument:
    """Status, headers and the first 64 KiB of the main document for the classifier.

    A document whose Content-Length exceeds the body cap is classified from
    its status and headers only.
    """
    status = response.status
    try:
        headers = [(str(h["name"]), str(h["value"])) for h in await _bounded(response.headers_array())]
    except (error_type, asyncio.TimeoutError):
        headers = []
    content_type = next((v for n, v in headers if n.lower() == "content-type"), None)
    declared = next((v.strip() for n, v in headers if n.lower() == "content-length"), "")
    body_text: str | None = None
    if not (declared.isdigit() and int(declared) > body_cap_bytes):
        try:
            data = await _bounded(response.body())
            body_text = decode_body(data[:MAIN_BODY_WINDOW_BYTES], content_type, "html")
            del data
        except (error_type, asyncio.TimeoutError):
            body_text = None
    scheme, host, port = "", "", 0
    try:
        parts = urllib.parse.urlsplit(str(getattr(response, "url", "") or ""))
        scheme = parts.scheme.lower()
        host = clean_host(parts.hostname or "") or ""
        port = parts.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)
    except ValueError:
        pass
    return MainDocument(status=status, headers=headers, body_text=body_text, scheme=scheme, host=host, port=port)


MainDocumentCallback = Callable[[MainDocument], bool]
#: Polled while navigating; a non-empty string ends the load with that reason.
AbortCheck = Callable[[], "str | None"]
#: Seconds between abort_check polls.
ABORT_POLL_S = 0.25
#: Longest abort reason kept. The caller's reasons are its own sentences (the CLI's name the
#: flag to pass, or why not to pass it), so the cap only bounds a runaway string.
ABORT_REASON_MAX = 300


def _abort_reason(abort_check: AbortCheck | None) -> str | None:
    if abort_check is None:
        return None
    try:
        reason = abort_check()
    except Exception:  # noqa: BLE001 - a broken check must not break the load
        return None
    return safe_text(str(reason), ABORT_REASON_MAX) if reason else None


async def _abort_after_failure(abort_check: AbortCheck | None) -> str | None:
    """``abort_check`` right after a failed navigation (and once more after a poll interval).

    A refusal or upstream failure can end the navigation before the next
    poll, so the check is asked here too; its reason (for example "the
    upstream proxy is unreachable") says more than ``net::ERR_TUNNEL_CONNECTION_FAILED``.
    """
    if abort_check is None:
        return None
    reason = _abort_reason(abort_check)
    if reason is None:
        await asyncio.sleep(ABORT_POLL_S)
        reason = _abort_reason(abort_check)
    return reason


def _target_is_private_literal(url: str) -> bool:
    try:
        return is_private_literal(urllib.parse.urlsplit(url).hostname or "")
    except ValueError:
        return False


async def _goto(page: Any, url: str, nav_ms: float, abort_check: AbortCheck | None) -> tuple[Any, str | None]:
    """``page.goto`` that returns early with a reason when ``abort_check`` fires.

    On abort the navigation is still running; the caller closes the context,
    which ends it, and then awaits the returned task via ``_finish``.
    """
    nav = asyncio.ensure_future(page.goto(url, wait_until="domcontentloaded", timeout=nav_ms))
    if abort_check is None:
        return await nav, None
    while True:
        done, _ = await asyncio.wait({nav}, timeout=ABORT_POLL_S)
        if done:
            return nav.result(), None
        reason = _abort_reason(abort_check)
        if reason:
            return nav, reason


async def load_page(
    url: str,
    *,
    proxy_url: str,
    values: Sequence[PreparedValue],
    raw_values: Sequence[str],
    on_main_document: MainDocumentCallback,
    body_cap_bytes: int,
    timeout_s: float,
    ignore_https_errors: bool = False,
    headless: bool = True,
    browser_args: Sequence[str] = (),
    abort_check: AbortCheck | None = None,
    classify_response: ResponseClassifier | None = None,
    meter_reply_check: MeterReplyCheck | None = None,
) -> LoadOutcome:
    """Load ``url`` once (at most one retry after a navigation error) and collect responses.

    ``on_main_document`` receives the main document (status, headers, first
    64 KiB of its body) as soon as navigation commits; returning False stops
    the load there (a challenge page), and no search results are kept.

    A navigation that fails fast (for example ``net::ERR_TUNNEL_CONNECTION_FAILED``)
    is retried once in a fresh context; a timeout is not retried, because the
    retry would only get the rest of the budget, and neither are errors a
    retry cannot fix (:data:`DETERMINISTIC_NAVIGATION_ERRORS`, certificate
    errors). ``classify_response`` classifies sub-responses (see the module
    docstring). Chromium does not fail a
    navigation when the proxy answers 407: it waits for credentials until the
    timeout. ``abort_check`` (polled every 0.25 s while navigating) lets the
    caller end the load early, for example when the meter saw the upstream
    answer 407; its string becomes the error reason. ``meter_reply_check``
    confirms sub-responses that look like the meter's own replies (see the
    module docstring).

    After a failed navigation ``abort_check`` is asked once more; a reason
    from it replaces the navigation error (kept in
    ``LoadOutcome.navigation_error``) and the load is not retried. A tunnel
    failure to a loopback, private or link-local literal (or ``localhost``)
    is not retried either: the meter refuses those deterministically unless
    private targets are allowed.

    Chromium always gets :data:`FIND_CHROMIUM_ARGS` (WebRTC over proxied
    connections only) before ``browser_args``.

    Raises :class:`BrowserUnavailableError` when Playwright or Chromium is
    missing or Chromium cannot start.
    """
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except ImportError:
        raise BrowserUnavailableError(f"Playwright is not installed; {INSTALL_HINT}") from None

    loop = asyncio.get_running_loop()
    start = loop.time()
    deadline = start + max(1.0, timeout_s)
    outcome = LoadOutcome(ok=False)
    async with async_playwright() as playwright:
        launch_kwargs = {
            "headless": headless,
            "proxy": playwright_proxy(proxy_url),
            "args": [*FIND_CHROMIUM_ARGS, *browser_args],
        }
        try:
            # find loads untrusted pages: ask for Chromium's OS sandbox (Playwright's default
            # is off) and fall back only where the sandbox cannot start (e.g. some containers).
            browser = await playwright.chromium.launch(chromium_sandbox=True, **launch_kwargs)
        except PlaywrightError:
            try:
                browser = await playwright.chromium.launch(chromium_sandbox=False, **launch_kwargs)
            except PlaywrightError:
                raise BrowserUnavailableError(f"Chromium could not be started; {CHROMIUM_HINT}") from None
            outcome.sandboxed = False
        try:
            for attempt in (1, 2):
                context = await browser.new_context(ignore_https_errors=ignore_https_errors)
                collector = _Collector(
                    values, raw_values, body_cap_bytes, PlaywrightError, classify_response, meter_reply_check
                )
                collector.attach(context)
                try:
                    page = await context.new_page()
                    nav_ms = max(1000.0, (deadline - loop.time()) * 0.7 * 1000)
                    response, aborted = await _goto(page, url, nav_ms, abort_check)
                except PlaywrightError as exc:
                    reason = navigation_error_reason(exc)
                    await collector.cancel()
                    await context.close()
                    explained = await _abort_after_failure(abort_check)
                    if explained:
                        outcome.error_reason, outcome.navigation_error = explained, reason
                        return outcome
                    private_tunnel = reason == "net::ERR_TUNNEL_CONNECTION_FAILED" and _target_is_private_literal(url)
                    if (
                        attempt == 1
                        and navigation_retryable(reason)
                        and not private_tunnel
                        and deadline - loop.time() >= 5.0
                    ):
                        outcome.retried, outcome.retry_reason = True, reason
                        continue
                    outcome.error_reason = reason
                    return outcome
                if aborted:
                    await collector.cancel()
                    await context.close()
                    await asyncio.gather(response, return_exceptions=True)
                    outcome.error_reason = aborted
                    return outcome
                if response is None:
                    await collector.cancel()
                    await context.close()
                    outcome.error_reason = "no document response"
                    return outcome
                outcome.ok = True
                outcome.main = await _main_document(response, PlaywrightError, body_cap_bytes)
                if not on_main_document(outcome.main):
                    await collector.cancel()
                    outcome.responses = list(collector.responses)
                    await context.close()
                    return outcome
                outcome.searched = True
                reserve = min(5.0, timeout_s * 0.15)
                try:
                    # Capped: one hanging subresource must not hold every find to the
                    # full timeout; settle() below still waits for network quiet.
                    load_ms = min(LOAD_EVENT_WAIT_S, deadline - reserve - loop.time()) * 1000
                    if load_ms > 0:
                        await page.wait_for_load_state("load", timeout=load_ms)
                except PlaywrightError:
                    pass  # a slow subresource: search what arrived
                await collector.settle(deadline - reserve)
                await collector.drain(deadline)
                outcome.responses = sorted(collector.responses, key=lambda r: r.seq)
                outcome.extra_skips = collector.extra_skips
                await context.close()
                return outcome
        finally:
            await browser.close()
    return outcome


__all__ = [
    "BrowserUnavailableError",
    "DETERMINISTIC_NAVIGATION_ERRORS",
    "FIND_CHROMIUM_ARGS",
    "METER_ERROR_HEADER",
    "CHROMIUM_HINT",
    "MeterReplyCheck",
    "INSTALL_HINT",
    "LoadOutcome",
    "MainDocument",
    "ObservedResponse",
    "body_error_reason",
    "confirm_meter_reply",
    "endpoint_host",
    "is_private_literal",
    "load_page",
    "meter_error_code",
    "meter_reply_check_from_snapshot",
    "navigation_error_reason",
    "navigation_retryable",
    "playwright_proxy",
    "served_from_http_cache",
    "should_classify",
]
