"""Playwright helpers (sync and async APIs) for jobs run under ``scrapescope run``.

Contract: docs/dev/contracts.md section 5.2. Playwright is imported lazily, so
importing this module works without the ``[browser]`` extra.

Typical use::

    from playwright.sync_api import sync_playwright
    from scrapescope.helpers import playwright as ssp

    with sync_playwright() as p:
        browser = ssp.launch(p.chromium)          # browser-wide proxy = the meter
        context = browser.new_context()            # instrumented automatically
        page = context.new_page()
        page.goto("https://example.com/")

What the helpers record (metadata only, appended to ``SCRAPESCOPE_EVENTS``):
one ``attach`` event per instrumented context, one ``launch`` event per
browser, and one ``request`` event per finished or failed network request in
the context (pages, iframes including out-of-process ones, dedicated workers
and service workers, as far as Playwright reports them). Never bodies,
cookies, header values, credentials or query strings; paths only with
``SCRAPESCOPE_KEEP_URLS=1``.

Accuracy limits, stated honestly:

- Sizes come from DevTools via ``request.sizes()``. They are client-reported,
  not wire bytes: TLS, CONNECT and idle connections are only visible in the
  meter's tunnel totals, which stay authoritative.
- HTTP/2 and HTTP/3: Playwright rebuilds ``requestHeadersSize`` as HTTP/1.1
  text (about 550-780 B per request, while HPACK/QPACK send far less), and
  ``responseHeadersSize`` is 0 because Chromium has no header text for these
  protocols; the header frames are counted inside ``responseBodySize``
  (DevTools ``encodedDataLength``). The helper recognises such responses
  (pseudo-headers such as ``:authority`` among the request headers actually
  sent, or a zero header size on a network response) and writes both header
  sizes as unknown (null); ``encoded_body_bytes`` then includes the response
  header frames.
- Plain http:// requests: Chromium sends them to the meter (an HTTP proxy)
  with ``Proxy-Connection`` (and, with proxy credentials,
  ``Proxy-Authorization``), which ``requestHeadersSize`` includes. The meter
  does not pass ``Proxy-Connection`` on (the socks5 and direct routes send the
  origin a request without it; the http-connect route strips it), and proxy
  credentials are proxy negotiation (the SOCKS5 handshake, nothing in direct
  mode, the configured or passed-through credentials on the http-connect
  route). The helper leaves both headers out, so the size describes the
  request the origin receives; on the http-connect route the absolute-form
  request line and the credentials the upstream receives count as tunnel
  overhead, like a CONNECT. Playwright rebuilds the size from the raw headers
  with an origin-form request line, without the query string and the final
  blank line, so it is slightly below the wire size on every route.
- Failed requests: Playwright falls back to the declared ``Content-Length`` for
  the body of a request that failed after its response headers, which is not
  what was transferred, so ``encoded_body_bytes`` is written as unknown.
- Requests still in flight when a page navigates away or the context closes
  get no ``requestfinished``/``requestfailed`` event from Playwright. The
  helper keeps the requests it saw start and, when the context closes (or, for
  a context never closed, at interpreter exit), writes the ones that never
  finished as failed events with unknown sizes (status set when the response
  headers had arrived). Their transfer size is unknown, so attribution reports
  the tunnel bytes they used as ``unreported``.
- ``from_cache``: Playwright has no cache flag. Two heuristics, checked with
  Chromium 153: a memory-cache hit reports ``responseBodySize ==
  -responseHeadersSize`` (so ``responseBodySize < 0``); a disk-cache hit reports
  the full cached size but carries only the provisional request headers (no
  ``Host``/``:authority``, ``Accept-Encoding`` or other headers the network
  stack adds). The second test is off while a route or HTTP/proxy credentials
  are active on the page or context, because request interception (which
  Playwright enables for routes and credentials, and which also disables the
  cache) makes network requests look the same, and it needs evidence that this
  context's network requests do show those headers: a request that did, or a
  response whose ``server_addr()`` is not the meter (a disk-cache entry keeps
  the address it was fetched from, e.g. an earlier run's meter port in a
  reused persistent profile). Without such evidence the event is held until
  it appears; when the context closes without it, held events are written as
  cache hits for Chromium (whose network requests always carry those headers
  outside interception) and as network requests for other browsers.
  Redirects, failed requests and service-worker script fetches (whose
  DevTools request headers are always provisional) are never called cache
  hits. Cache hits are written with sizes 0.
- Firefox and WebKit: Playwright has no DevTools network data for them, so
  neither Chromium signature exists; their HTTP-cache hits report full sizes.
  A response without a server address (``response.server_addr()`` None) is
  written as a cache hit (checked with Firefox 155 and WebKit 26.6: every
  cache hit had none, every network response had one). This is less certain
  than the Chromium checks; attribution says so in a warning.
- Requests that never reached the network are marked ``no_network`` in the
  events file and left out of network figures: ``fulfilled`` (answered by
  ``route.fulfill``, including ``route_from_har``), ``aborted``
  (``route.abort``) and ``blocked`` (stopped by the browser before anything
  was sent: mixed content, CSP, a DevTools block list such as the CDP
  ``Network.setBlockedURLs`` fix, an extension). Routes are recognised by
  wrapping Playwright's ``Route.fulfill``/``Route.abort`` (the helper only tags
  the request); if that wrapper cannot be installed, a fulfilled response is
  recognised by ``response.server_addr()`` being None while a route is active.
  Bytes that ``route.fetch()`` downloads are made by Playwright, not by the
  page: they appear in the meter's tunnel totals only.
- Worker scripts: DevTools reports ``responseBodySize`` 0 for dedicated-worker
  and service-worker scripts, so those bytes (including a service worker's
  update checks) appear only in the tunnel totals.
- ``from_service_worker`` comes from ``response.from_service_worker``; the
  service worker's own fetch is a separate event with ``frame
  "service_worker"``, so each service-worker-handled request is counted once
  (the worker-owned copy). Exception: Chromium also sets the flag on a
  navigation it sent to the network itself while the worker was starting (a
  warm profile), where the worker made no fetch. Such a response shows the
  wire-level request headers (or, under request interception, a server
  address), which a worker-built or worker-fetched response never has; it is
  written as a network request with an unknown body size (DevTools reports 0).
- ``frame "worker"``: Playwright attributes dedicated-worker requests to the
  page's main frame. The helper recognises them when the request's Referer
  equals the URL of a dedicated worker the page started (compared in memory,
  never stored). With a referrer policy that strips it (for example
  cross-origin requests under the default policy) they are reported as the
  owning frame. Shared workers are not exposed by Playwright.
- WebSockets are recorded once, when they close (or when their context
  closes while they are still open), with the payload bytes of the frames seen
  (``encoded_body_bytes`` = received, ``request_body_bytes`` = sent); frame
  overhead, compression and the handshake are not included.
- Playwright on Chromium disables the HTTP cache (``Network.setCacheDisabled``)
  whenever it holds proxy or HTTP credentials. ``proxy_settings()`` without
  credentials keeps the cache: the meter injects the upstream credentials.
  Passing a username/password (per context or at launch) makes later page
  loads re-download cached assets.
- ``instrument(context)`` records the context's browser as launched (once per
  browser), so ``proxy_settings()`` + ``instrument()`` count browser launches
  too. Playwright 1.63 gives a persistent context a Browser as well; older
  versions give None, so call ``record_launch(context)`` for a persistent
  context: it counts the same browser once whichever of the two runs first.
- Per-context and launch ``proxy=`` servers are rerouted to the meter, which
  chains to the ONE upstream configured for the run, with their credentials
  passed through. When the runner provides ``SCRAPESCOPE_UPSTREAM_ID`` (a
  salted fingerprint of the upstream's host:port, see :func:`scrapescope.config.upstream_id`),
  only a server matching it is rerouted; any other proxy is left untouched
  (its traffic then bypasses the meter, which the report flags) with one
  ``RuntimeWarning``. Without it, every server is rerouted and a
  ``RuntimeWarning`` is issued when two different servers are rerouted in one
  process, because their credentials all go to the configured upstream.

Everything here is a no-op, with one ``RuntimeWarning`` per process, when
``SCRAPESCOPE_EVENTS`` (instrumentation) or ``SCRAPESCOPE_PROXY_URL`` (proxy
settings) is unset. The helpers never raise into the user's code because of
scrapescope problems.
"""

from __future__ import annotations

import asyncio
import atexit
import base64
import functools
import hashlib
import hmac
import inspect
import os
import re
import urllib.parse
import warnings
from typing import Any

from ..config import (
    ENV_AUTH_PROXY_URL,
    ENV_PROXY_URL,
    ENV_UPSTREAM_ID,
    UPSTREAM_ID_PREFIX,
    upstream_fingerprint,
    upstream_id,  # noqa: F401 - re-exported for callers and tests (ssp.upstream_id)
)
from ..types import AttachEvent, LaunchEvent, RequestEvent, clean_host
from . import events as _events

_STATE_ATTR = "_scrapescope_state"
_WRAPPED_ATTR = "_scrapescope_wrapped"
_LAUNCH_ATTR = "_scrapescope_launch_recorded"
_TS_ATTR = "_scrapescope_ts"
_RESOURCE_TYPE_RE = re.compile(r"[a-z_]{1,32}")
_METHOD_RE = re.compile(r"[A-Z]{1,16}")
_BROWSERS = ("chromium", "firefox", "webkit")
#: How long an async close waits for pending size lookups before closing anyway.
DRAIN_TIMEOUT_S = 10.0
#: Browser-reported start times further than this from our clock are ignored.
_MAX_CLOCK_SKEW_S = 3600.0
#: Attribute the Route wrappers set on Playwright's request object: "fulfilled" or "aborted".
_ROUTE_ATTR = "_scrapescope_route"
#: DevTools ``blockedReason`` values (Playwright's failure text when there is no error text) for
#: requests the renderer stopped before anything was sent. Response-based blocks (CORP, COEP,
#: ``content-type``/nosniff, ORB) arrive with a ``net::`` error text and are network requests.
_BLOCKED_BEFORE_SEND = frozenset({"mixed-content", "csp", "inspector", "subresource-filter"})
_UPSTREAM_ID_PREFIX = UPSTREAM_ID_PREFIX
_DEFAULT_PROXY_PORTS = {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080, "socks4": 1080, "socks": 1080}

#: Pending async size lookups across all contexts (see :func:`drain`).
_pending: set[asyncio.Task[Any]] = set()
#: Instrumented contexts not closed yet; their unfinished requests are written at interpreter exit.
_open_states: set[Any] = set()
_atexit_registered = False
#: True once Playwright's Route.fulfill/abort are wrapped to tag the requests they handle.
_routes_tagged = False
#: Proxy servers (host, port) rerouted to the meter in this process (in memory only).
_rerouted_servers: set[tuple[str, int]] = set()
_warned_proxy: set[str] = set()


def _flush_open_contexts() -> None:
    """atexit: a script that never closed its context still gets its unfinished requests written."""
    for state in list(_open_states):
        _flush_unfinished(state)


def _track_open(state: Any) -> None:
    global _atexit_registered
    _open_states.add(state)
    if not _atexit_registered:
        atexit.register(_flush_open_contexts)
        _atexit_registered = True


# ---------------------------------------------------------------------------
# Proxy settings
# ---------------------------------------------------------------------------


def proxy_settings(*, username: str | None = None, password: str | None = None) -> dict[str, str] | None:
    """Browser-wide proxy settings for ``launch(proxy=...)`` pointing at the meter.

    Without credentials: ``{"server": $SCRAPESCOPE_PROXY_URL}``. The meter then
    injects the configured upstream credentials, and Playwright keeps its HTTP
    cache enabled. With ``username``/``password``: ``{"server":
    $SCRAPESCOPE_AUTH_PROXY_URL (fallback $SCRAPESCOPE_PROXY_URL), "username":
    ..., "password": ...}``; the credentials are passed through to the upstream
    unchanged (the auth listener answers 407 so Chromium presents them).
    Returns None, with the single per-process warning, when
    ``SCRAPESCOPE_PROXY_URL`` is unset.
    """
    meter = os.environ.get(ENV_PROXY_URL)
    if not meter:
        _events.warn_inactive(ENV_PROXY_URL)
        return None
    if username is None and password is None:
        return {"server": meter}
    settings = {"server": os.environ.get(ENV_AUTH_PROXY_URL) or meter}
    if username is not None:
        settings["username"] = username
    if password is not None:
        settings["password"] = password
    return settings


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _fingerprint(key: bytes, host: str, port: int) -> bytes:
    return upstream_fingerprint(key, host, port)


def _proxy_endpoint(server: Any) -> tuple[str, int] | None:
    """(host, port) of a Playwright proxy server ("http://h:p", "socks5://h:p" or "h:p"), else None."""
    if not isinstance(server, str) or not server.strip():
        return None
    text = server.strip()
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urllib.parse.urlsplit(text)
        host = clean_host(parts.hostname or "")
        port = parts.port or _DEFAULT_PROXY_PORTS.get(parts.scheme.lower())
    except ValueError:
        return None
    if host is None or port is None:
        return None
    return host, port


def _meter_endpoints() -> set[tuple[str, int]]:
    out = set()
    for name in (ENV_PROXY_URL, ENV_AUTH_PROXY_URL):
        endpoint = _proxy_endpoint(os.environ.get(name))
        if endpoint is not None:
            out.add(endpoint)
    return out


def _is_run_upstream(endpoint: tuple[str, int] | None) -> bool | None:
    """Whether ``endpoint`` is the run's upstream per ``SCRAPESCOPE_UPSTREAM_ID``; None when that is unset or invalid."""
    value = os.environ.get(ENV_UPSTREAM_ID)
    if not value:
        return None
    try:
        prefix, key_text, digest_text = value.strip().split(".")
        key, digest = _unb64(key_text), _unb64(digest_text)
    except (ValueError, TypeError):
        return None
    if prefix != _UPSTREAM_ID_PREFIX or not key or len(digest) != hashlib.sha256().digest_size:
        return None
    if endpoint is None:
        return False
    return hmac.compare_digest(_fingerprint(key, *endpoint), digest)


_PROXY_WARNINGS = {
    "foreign": (
        "scrapescope: a Playwright proxy= server that is not the upstream this run was started with was left "
        "unchanged, so its traffic does not pass through the meter and the report flags it as bypassing the "
        "meter; meter each provider in its own scrapescope run"
    ),
    "several": (
        "scrapescope: Playwright proxy= settings named more than one proxy server; all of them were rerouted "
        "through the meter to the single upstream this run was started with, and their usernames and passwords "
        "went to that upstream; meter each provider in its own scrapescope run"
    ),
}


def _warn_proxy(kind: str) -> None:
    """One RuntimeWarning per kind and process; never names the server or its credentials."""
    if kind in _warned_proxy:
        return
    _warned_proxy.add(kind)
    try:
        warnings.warn(_PROXY_WARNINGS[kind], RuntimeWarning, stacklevel=4)
    except Exception:  # warnings configured as errors must not reach the user's code
        pass


def _rewrite_proxy(proxy: Any) -> Any:
    """Point a Playwright proxy dict at the meter, keeping username/password unchanged.

    The server becomes ``SCRAPESCOPE_AUTH_PROXY_URL`` when a username is present
    (else ``SCRAPESCOPE_PROXY_URL``). Other keys (``bypass``) are kept. Unchanged
    when the meter URL is unset or ``proxy`` is not a mapping. The meter chains
    to the upstream configured for the run, so the credentials go to that
    provider: with ``SCRAPESCOPE_UPSTREAM_ID`` set, a server that is not that
    upstream is left unchanged (with one warning); without it, rerouting two
    different servers in one process gives one warning.
    """
    meter = os.environ.get(ENV_PROXY_URL)
    if not meter or not isinstance(proxy, dict):
        return proxy
    endpoint = _proxy_endpoint(proxy.get("server"))
    if endpoint not in _meter_endpoints():
        verdict = _is_run_upstream(endpoint)
        if verdict is False:
            _warn_proxy("foreign")
            return proxy
        if endpoint is not None:
            _rerouted_servers.add(endpoint)
            if verdict is None and len(_rerouted_servers) > 1:
                _warn_proxy("several")
    rewritten = dict(proxy)
    if proxy.get("username"):
        rewritten["server"] = os.environ.get(ENV_AUTH_PROXY_URL) or meter
    else:
        rewritten["server"] = meter
    return rewritten


def _rewrite_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    if kwargs.get("proxy") is not None:
        kwargs = dict(kwargs)
        kwargs["proxy"] = _rewrite_proxy(kwargs["proxy"])
    return kwargs


#: Chromium switch that lets WebRTC use proxied connections only: no STUN or other UDP from this
#: machine's own interfaces (which would bypass the meter and the provider and can reveal this
#: machine's addresses to the page). ``find`` always sets it; ``launch(..., webrtc_proxied_only=True)``
#: adds it for your own jobs. It changes what pages can do with WebRTC, so it is opt-in there.
WEBRTC_PROXIED_ONLY_ARGS: tuple[str, ...] = ("--force-webrtc-ip-handling-policy=disable_non_proxied_udp",)


def _launch_kwargs(kwargs: dict[str, Any], webrtc_proxied_only: bool = False) -> dict[str, Any]:
    kwargs = dict(kwargs)
    if webrtc_proxied_only:
        args = list(kwargs.get("args") or [])
        kwargs["args"] = args + [a for a in WEBRTC_PROXIED_ONLY_ARGS if a not in args]
    if kwargs.get("proxy") is not None:
        kwargs["proxy"] = _rewrite_proxy(kwargs["proxy"])
    else:
        settings = proxy_settings()
        if settings is not None:
            kwargs["proxy"] = settings
    return kwargs


# ---------------------------------------------------------------------------
# Context instrumentation
# ---------------------------------------------------------------------------


class _ContextState:
    """Per-context bookkeeping (in memory only)."""

    def __init__(self, context_id: str, is_async: bool, context: Any = None, browser: str = "other") -> None:
        self.context_id = context_id
        self.is_async = is_async
        #: The instrumented context (for the route/credential check of the disk-cache heuristic).
        self.context = context
        #: chromium | firefox | webkit | other (decides held disk-cache candidates at close).
        self.browser = browser
        #: Disk-cache candidates waiting for wire-header evidence: (parts, static, sizes, headers).
        self.held: list[tuple[Any, Any, Any, Any]] = []
        #: URLs of dedicated workers the context's pages started (for frame "worker").
        self.worker_urls: set[str] = set()
        #: ids of pages already watched.
        self.pages: set[int] = set()
        self.pending: set[asyncio.Task[Any]] = set()
        #: Requests seen starting that have not finished or failed yet, by id().
        self.inflight: dict[int, Any] = {}
        #: WebSockets seen opening that have not closed yet.
        self.websockets: set[_WebSocketTally] = set()
        #: True once a request in this context carried headers only the network stack adds
        #: (so request interception is not hiding them): enables the disk-cache heuristic.
        self.saw_wire_headers = False
        self.closed = False
        #: ids of requests written at context close (a late event for them is ignored).
        self.flushed: set[int] = set()


class _Static:
    """Request fields that need no round trip to the Playwright driver."""

    __slots__ = ("frame", "from_sw", "is_navigation", "method", "resource_type", "response", "status", "sw_network",
                 "ts")

    def __init__(self) -> None:
        self.ts = _events.now()
        self.method = "GET"
        self.resource_type = "other"
        self.is_navigation = False
        self.frame = "other"
        self.response: Any = None
        self.status: int | None = None
        self.from_sw = False
        #: ``from_service_worker`` was reported, but the response came from the network (see
        #: :func:`_sw_went_to_network`): written as a network request with an unknown body size.
        self.sw_network = False


def _is_async(obj: Any) -> bool:
    """True for async-API Playwright objects (and fakes whose close() is a coroutine function)."""
    try:
        from playwright.async_api import Browser as _AsyncBrowser
        from playwright.async_api import BrowserContext as _AsyncContext

        if isinstance(obj, (_AsyncBrowser, _AsyncContext)):
            return True
        from playwright.sync_api import Browser as _SyncBrowser
        from playwright.sync_api import BrowserContext as _SyncContext

        if isinstance(obj, (_SyncBrowser, _SyncContext)):
            return False
    except ImportError:
        pass
    return inspect.iscoroutinefunction(getattr(obj, "close", None))


def instrument(context: Any) -> Any:
    """Attach context-level listeners that append request metadata events; idempotent.

    Writes one ``attach`` event, then listens on the CONTEXT for ``request``,
    ``requestfinished`` and ``requestfailed`` (which cover every page, iframe,
    dedicated worker and service worker Playwright reports for the context),
    plus each page's ``worker`` and ``websocket`` events. One ``request`` event
    is written per finished or failed network request.

    Sync contexts gather sizes inside the event handler. Async contexts gather
    them in a task; ``context.close()`` is wrapped to await those tasks first
    (bounded by :data:`DRAIN_TIMEOUT_S`), and :func:`drain` awaits them
    explicitly. Returns ``context``. No-op with one warning when
    ``SCRAPESCOPE_EVENTS`` is unset.
    """
    try:
        if context is None or getattr(context, _STATE_ATTR, None) is not None:
            return context
        if _events.events_path() is None:
            _events.warn_inactive()
            return context
        state = _ContextState(_events.new_context_id(), _is_async(context), context, _browser_name(context))
        setattr(context, _STATE_ATTR, state)
        _tag_routes()
        _events.emit(
            AttachEvent(ts=_events.now(), source="playwright", pid=os.getpid(), context=state.context_id)
        )
        _record_context_browser(context)
        # Always register fresh closures, never a shared function: Playwright caches its
        # API-flavour wrapper on the handler object, so a function registered once from the
        # sync API would hand sync-API objects to later async contexts (and vice versa).
        context.on("request", lambda request: _on_request(state, request))
        context.on("requestfinished", lambda request: _on_done(state, request, failed=False))
        context.on("requestfailed", lambda request: _on_done(state, request, failed=True))
        context.on("page", lambda page: _watch_page(state, page))
        context.on("response", lambda response: _on_response(state, response))
        context.on("close", lambda _context: _flush_unfinished(state))
        _track_open(state)
        for page in list(getattr(context, "pages", []) or []):
            _watch_page(state, page)
        if state.is_async:
            _wrap_async_close(context, state)
    except Exception:
        pass
    return context


def _record_context_browser(context: Any) -> None:
    """Count the context's browser as launched (idempotent per browser, see :func:`record_launch`).

    Older Playwright versions give a persistent context no Browser; nothing is recorded then.
    """
    try:
        browser = getattr(context, "browser", None)
        if browser is not None:
            record_launch(browser)
    except Exception:
        pass


def _on_request(state: _ContextState, request: Any) -> None:
    try:
        setattr(request, _TS_ATTR, _events.now())
    except Exception:
        pass
    try:
        if not state.closed:
            state.inflight[id(request)] = request
    except Exception:
        pass


def _tag_routes() -> None:
    """Wrap Playwright's Route.fulfill/abort once so the requests they handle are recognised.

    The wrappers only set an attribute on Playwright's request object before
    calling the original method; nothing else changes. If Playwright's internals
    differ, nothing is wrapped and fulfilled responses are recognised by
    ``server_addr()`` instead (see the module docstring).
    """
    global _routes_tagged
    if _routes_tagged:
        return
    try:
        from playwright._impl._network import Route
    except Exception:
        return
    try:
        for name, outcome in (("fulfill", "fulfilled"), ("abort", "aborted")):
            original = getattr(Route, name)
            if getattr(original, _ROUTE_ATTR, None):
                continue
            setattr(Route, name, _route_wrapper(original, outcome))
        _routes_tagged = True
    except Exception:
        pass


def _route_wrapper(original: Any, outcome: str) -> Any:
    @functools.wraps(original)
    async def method(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            setattr(self.request, _ROUTE_ATTR, outcome)
        except Exception:
            pass
        return await original(self, *args, **kwargs)

    setattr(method, _ROUTE_ATTR, outcome)
    return method


def _route_outcome(request: Any) -> str | None:
    """"fulfilled" or "aborted" when a route handled ``request`` (sync or async API object)."""
    try:
        impl = getattr(request, "_impl_obj", request)
        outcome = getattr(impl, _ROUTE_ATTR, None)
    except Exception:
        return None
    return outcome if outcome in ("fulfilled", "aborted") else None


def _blocked_before_send(request: Any) -> bool:
    """A failure the browser gave before sending anything (mixed content, CSP, a block list, an extension)."""
    try:
        failure = request.failure
        if isinstance(failure, dict):  # very old Playwright versions
            failure = failure.get("errorText")
    except Exception:
        return False
    if not isinstance(failure, str):
        return False
    failure = failure.strip()
    return (
        failure in _BLOCKED_BEFORE_SEND
        or failure == "net::ERR_BLOCKED_BY_CLIENT"
        or failure.endswith(".Inspector")
    )


def _no_network(state: _ContextState, request: Any, st: _Static, failed: bool) -> str | None:
    """fulfilled | aborted | blocked for a request that never reached the network, else None."""
    outcome = _route_outcome(request)
    if outcome == "fulfilled" and not failed and st.status is not None:
        return outcome
    if outcome == "aborted" and failed:
        return outcome
    if failed and st.status is None and _blocked_before_send(request):
        return "blocked"
    return None


def _needs_server_addr(state: _ContextState, request: Any, st: _Static, failed: bool, candidate: bool) -> bool:
    """Whether ``response.server_addr()`` can decide something for this request (one driver round trip)."""
    if candidate:
        return not state.saw_wire_headers
    # Route wrappers missing: a fulfilled response is the one without a server address.
    return (not _routes_tagged and st.status is not None and not failed and not st.from_sw
            and _intercepting(state, request))


def _elsewhere(addr: Any) -> bool:
    """True when a response's server address is known and is not this run's meter (a cache entry's address)."""
    meters = _meter_endpoints()
    if not meters or not isinstance(addr, dict):
        return False
    ip, port = addr.get("ipAddress"), addr.get("port")
    if not isinstance(ip, str) or not isinstance(port, int):
        return False
    ip = ip.strip("[]").lower()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    loopback = ip in ("127.0.0.1", "localhost", "::1")
    return not (loopback and any(port == p for _, p in meters))


def _saw_wire(state: _ContextState) -> None:
    """The context showed wire-level request headers: held disk-cache candidates are cache hits."""
    if state.saw_wire_headers:
        return
    state.saw_wire_headers = True
    _release_held(state, as_cache=True)


def _release_held(state: _ContextState, *, as_cache: bool) -> None:
    held, state.held = state.held, []
    for parts, st, sizes, info in held:
        try:
            _events.emit(_build_request_event(state, parts, st, sizes, info, False, disk_cache=as_cache))
        except Exception:
            continue


def _note_wire_headers(state: _ContextState, raw: Any, request: Any) -> None:
    if _wire_header_names(_header_names(raw), _header_names(getattr(request, "headers", {}) or {})):
        _saw_wire(state)


async def _probe_async(state: _ContextState, request: Any) -> None:
    try:
        _note_wire_headers(state, await request.all_headers(), request)
    except Exception:
        pass


def _on_response(state: _ContextState, response: Any) -> None:
    """Navigation responses: learn early whether this context's requests show wire-level headers.

    The disk-cache heuristic needs that evidence. A document's response arrives
    before its subresources start, so checking navigations here (one extra
    driver round trip per navigation) lets cached subresources that finish
    before the document be recognised too.
    """
    try:
        if state.saw_wire_headers:
            return
        request = response.request
        if not request.is_navigation_request():
            return
        if state.is_async:
            task = asyncio.get_running_loop().create_task(_probe_async(state, request))
            state.pending.add(task)
            _pending.add(task)
            task.add_done_callback(state.pending.discard)
            task.add_done_callback(_pending.discard)
        else:
            _note_wire_headers(state, request.all_headers(), request)
    except Exception:
        pass


def _flush_unfinished(state: _ContextState) -> None:
    """Context closed: write requests that never finished or failed, and WebSockets still open.

    Playwright emits no event for a request that was in flight when its page
    navigated away or closed. Such requests are written as failed with unknown
    sizes; everything used here is already on the client (no driver round trip).
    """
    try:
        _open_states.discard(state)
        state.closed = True
        # No wire-header evidence ever came: Chromium sends those headers on every network request
        # outside interception, so provisional-only responses were served from its cache.
        _release_held(state, as_cache=state.browser == "chromium")
        leftovers = list(state.inflight.values())
        state.inflight.clear()
        state.flushed.update(id(request) for request in leftovers)
        for request in leftovers:
            try:
                parts = _events.url_parts(request.url)
                if parts is None:
                    continue
                st = _static_fields(state, request)
                _apply_response(st, getattr(request, "existing_response", None))
                names = _header_names(getattr(request, "headers", {}) or {})
                _events.emit(_build_request_event(state, parts, st, None, names, True))
            except Exception:
                continue
        for tally in list(state.websockets):
            tally.finish()
    except Exception:
        pass


def _strip_fragment(url: Any) -> str | None:
    if not isinstance(url, str) or not url:
        return None
    return url.split("#", 1)[0]


def _watch_page(state: _ContextState, page: Any) -> None:
    try:
        if id(page) in state.pages:
            return
        state.pages.add(id(page))
        page.on("worker", lambda worker: _add_worker(state, worker))
        page.on("websocket", lambda ws: _watch_websocket(state, ws))
        for worker in list(getattr(page, "workers", []) or []):
            _add_worker(state, worker)
    except Exception:
        pass


def _add_worker(state: _ContextState, worker: Any) -> None:
    try:
        url = _strip_fragment(worker.url)
        if url:
            state.worker_urls.add(url)
    except Exception:
        pass


def _frame_kind(state: _ContextState, request: Any) -> str:
    """main | sub | worker | service_worker | other (see the module docstring)."""
    try:
        if request.service_worker is not None:
            return "service_worker"
    except Exception:
        pass
    if state.worker_urls:
        try:
            referer = _strip_fragment(request.headers.get("referer"))
        except Exception:
            referer = None
        if referer is not None and referer in state.worker_urls:
            return "worker"
    try:
        frame = request.frame
    except Exception:  # service-worker requests have no frame
        return "other"
    try:
        return "main" if frame.parent_frame is None else "sub"
    except Exception:
        return "other"


def _start_ts(request: Any) -> float:
    """Request start: DevTools startTime (wall clock) when sane, else when "request" fired."""
    now = _events.now()
    recorded = getattr(request, _TS_ATTR, None)
    try:
        start_ms = request.timing.get("startTime")
        if isinstance(start_ms, (int, float)) and start_ms > 0:
            start = float(start_ms) / 1000.0
            if abs(start - now) <= _MAX_CLOCK_SKEW_S:
                return start
    except Exception:
        pass
    if isinstance(recorded, float):
        return recorded
    return now


def _static_fields(state: _ContextState, request: Any) -> _Static:
    st = _Static()
    st.ts = _start_ts(request)
    try:
        method = str(request.method).upper()
        if _METHOD_RE.fullmatch(method):
            st.method = method
    except Exception:
        pass
    try:
        resource_type = str(request.resource_type).lower()
        if _RESOURCE_TYPE_RE.fullmatch(resource_type):
            st.resource_type = resource_type
    except Exception:
        pass
    try:
        st.is_navigation = bool(request.is_navigation_request())
    except Exception:
        pass
    st.frame = _frame_kind(state, request)
    return st


def _apply_response(st: _Static, response: Any) -> None:
    st.response = response
    if response is None:
        return
    try:
        status = response.status
        if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999:
            st.status = status
    except Exception:
        pass
    try:
        st.from_sw = bool(response.from_service_worker)
    except Exception:
        pass


def _header_names(headers: Any) -> set[str]:
    try:
        return {str(name).lower() for name in headers}
    except Exception:
        return set()


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _wire_header_names(raw: set[str], provisional: set[str] | None) -> bool:
    """True when the headers actually sent include ones only the network stack adds.

    Chromium's provisional headers (``request.headers``) never contain ``Host``,
    ``:authority`` or ``Accept-Encoding``; the raw headers of a request that went
    to the network (``all_headers()``, from DevTools extra info) do, unless
    request interception replaced them with the provisional set.
    """
    if not raw:
        return False
    if any(name.startswith(":") for name in raw):
        return True
    return provisional is not None and bool(raw - provisional)


def _intercepting(state: _ContextState, request: Any) -> bool:
    """True unless the page and context are known to have no routes and no HTTP/proxy credentials.

    Uses Playwright's client-side bookkeeping (``_routes``, context ``_options``);
    anything unknown counts as intercepting, which only disables the disk-cache
    heuristic.
    """
    try:
        context = getattr(state.context, "_impl_obj", state.context)
        routes = getattr(context, "_routes", None)
        options = getattr(context, "_options", None)
        if routes is None or routes or not isinstance(options, dict):
            return True
        proxy = options.get("proxy")
        if options.get("httpCredentials") or (isinstance(proxy, dict) and proxy.get("username")):
            return True
        page = None
        if getattr(request, "service_worker", None) is None:
            page = request.frame.page
        if page is not None:
            page_routes = getattr(getattr(page, "_impl_obj", page), "_routes", None)
            if page_routes is None or page_routes:
                return True
        return False
    except Exception:
        return True


def is_multiplexed(sizes: Any, header_names: Any = None, status: int | None = None) -> bool:
    """True when Playwright's ``sizes()`` describe an HTTP/2 or HTTP/3 response.

    Signals: a pseudo-header (``:authority``, ``:method``) among the names of
    the request headers actually sent (``request.all_headers()``), or a zero
    ``responseHeadersSize`` on a response with a status (Chromium has header
    text only for HTTP/1.x; for a cache hit the size is computed and never 0).
    For such responses ``requestHeadersSize`` is rebuilt HTTP/1.1 text (not the
    HPACK/QPACK bytes sent), ``responseHeadersSize`` is unavailable and
    ``responseBodySize`` already includes the response header frames. ``find``
    can use this to keep header estimates out of its billed basis.
    """
    try:
        if header_names is not None and any(str(name).startswith(":") for name in header_names):
            return True
        head = sizes.get("responseHeadersSize") if isinstance(sizes, dict) else None
        return status is not None and _is_number(head) and head == 0
    except Exception:
        return False


class _HeaderInfo:
    """Header names of one request (names only, never values) and the size of its proxy-hop headers."""

    __slots__ = ("names", "provisional", "proxy_hop", "raw_ok")

    def __init__(self, names: set[str], provisional: set[str] | None = None, raw_ok: bool = False,
                 proxy_hop: int = 0) -> None:
        #: Names of the headers actually sent (raw), or the provisional ones when raw failed.
        self.names = names
        #: Names of the provisional headers (``request.headers``), when read.
        self.provisional = provisional
        #: True when ``names`` came from ``all_headers()``.
        self.raw_ok = raw_ok
        #: Bytes that the proxy-hop headers (see :data:`_PROXY_HOP_HEADERS`) add to ``requestHeadersSize``.
        self.proxy_hop = proxy_hop


#: Headers Chromium adds to a plain-http request it sends to an HTTP proxy (the meter). The origin never
#: receives them: the meter drops Proxy-Connection on every route, and credentials are proxy negotiation
#: (the SOCKS5 handshake, nothing in direct mode, the upstream's Proxy-Authorization on http-connect).
_PROXY_HOP_HEADERS = ("proxy-connection", "proxy-authorization")


def _proxy_hop_bytes(raw: Any) -> int:
    """What the proxy-hop headers of a request add to Playwright's ``requestHeadersSize``.

    Playwright counts each raw header as ``len(name) + len(value) + 4`` (``": "`` and CRLF). Values are
    measured here and never kept.
    """
    total = 0
    try:
        for name, value in raw.items():
            if str(name).lower() in _PROXY_HOP_HEADERS and isinstance(value, str):
                total += len(str(name)) + len(value) + 4
    except Exception:
        return 0
    return total


def _cacheable(st: _Static, failed: bool) -> bool:
    """Only a response that arrived and is not a redirect hop can be a cache hit."""
    return st.status is not None and not failed and not (300 <= st.status <= 399 and st.status != 304)


def _worker_script(st: _Static, info: _HeaderInfo) -> bool:
    """A service-worker script fetch: DevTools shows only provisional request headers even from the network."""
    if "service-worker" in (info.provisional or ()):
        return True
    return st.frame == "service_worker" and st.resource_type == "script"


def _disk_cache_candidate(state: _ContextState, st: _Static, sizes: Any, info: _HeaderInfo, failed: bool,
                          request: Any) -> bool:
    """A response that carries only the provisional request headers: a disk-cache hit given evidence."""
    if st.from_sw or not isinstance(sizes, dict) or not _cacheable(st, failed):
        return False
    body = sizes.get("responseBodySize")
    if _is_number(body) and body < 0:
        return False  # memory-cache hit: recognised by _build_request_event itself
    if not (info.raw_ok and info.provisional is not None and info.names == info.provisional):
        return False
    return not _worker_script(st, info) and not _intercepting(state, request)


def _build_request_event(
    state: _ContextState,
    parts: _events.UrlParts,
    st: _Static,
    sizes: Any,
    headers: set[str] | _HeaderInfo,
    failed: bool,
    request: Any = None,
    *,
    disk_cache: bool = False,
    no_network: str | None = None,
) -> RequestEvent:
    info = headers if isinstance(headers, _HeaderInfo) else _HeaderInfo(set(headers))
    header_names = info.names
    if info.raw_ok and _wire_header_names(info.names, info.provisional):
        _saw_wire(state)
    encoded = response_headers = request_headers = request_body = None
    from_cache = False
    if (st.from_sw and not st.sw_network) or no_network is not None:
        # Answered by a service worker (its own fetch is a separate event) or never sent to the
        # network (fulfilled, aborted or blocked): nothing crossed the network for this event.
        encoded = response_headers = request_headers = request_body = 0
    elif isinstance(sizes, dict):
        body = sizes.get("responseBodySize")
        head = sizes.get("responseHeadersSize")
        if not st.sw_network and _cacheable(st, failed) and _is_number(body) and body < 0:
            # Memory-cache hit: Playwright reports body == -headers when nothing was received.
            from_cache = True
        elif disk_cache:
            # HTTP-cache hit: a Chromium disk-cache hit (only the provisional request headers, see
            # _disk_cache_candidate) or a Firefox/WebKit response without a server address.
            from_cache = True
        if from_cache:
            encoded = response_headers = request_headers = request_body = 0
        else:
            multiplexed = is_multiplexed(sizes, header_names if info.raw_ok else None, st.status)
            if failed or (st.sw_network and not (_is_number(body) and body > 0)):
                # A service-worker fallback to the network reports encodedDataLength 0 (body == -headers):
                # its body size is unknown, not 0.
                encoded = None
            else:
                encoded = _events.count(body)
            if not multiplexed:
                response_headers = _events.count(head)
                request_headers = _events.count(sizes.get("requestHeadersSize"))
                if request_headers is not None and parts.scheme == "http" and info.proxy_hop:
                    # The proxy hop's own headers never reach the upstream as sent (_PROXY_HOP_HEADERS).
                    request_headers = max(0, request_headers - info.proxy_hop)
            request_body = _events.count(sizes.get("requestBodySize"))
    return RequestEvent(
        ts=st.ts,
        source="playwright",
        host=parts.host,
        port=parts.port,
        scheme=parts.scheme,
        path=parts.path,
        method=st.method,
        resource_type=st.resource_type,
        status=st.status,
        failed=failed,
        from_cache=from_cache,
        from_service_worker=st.from_sw and not st.sw_network,
        frame=st.frame,  # type: ignore[arg-type]
        is_navigation=st.is_navigation,
        encoded_body_bytes=encoded,
        response_header_bytes=response_headers,
        request_header_bytes=request_headers,
        request_body_bytes=request_body,
        sent_cookies="cookie" in header_names,
        sent_authorization="authorization" in header_names,
        context=state.context_id,
    )


#: Browsers without DevTools (CDP) network data in Playwright: their HTTP-cache hits carry full sizes
#: and no memory-cache or provisional-header signature, but no server address (see _Decision).
_NON_CDP_BROWSERS = frozenset({"firefox", "webkit"})


class _Decision:
    """What one finished or failed request is, decided before it is written (see :func:`_decide`)."""

    __slots__ = ("cache_hit", "candidate", "elsewhere", "need_addr", "no_network")

    def __init__(self) -> None:
        #: fulfilled | aborted | blocked, else None (see _no_network).
        self.no_network: str | None = None
        #: A Chromium disk-cache candidate (provisional request headers only).
        self.candidate = False
        #: The candidate's server address is known and is not this run's meter.
        self.elsewhere = False
        #: A Firefox/WebKit HTTP-cache hit (no server address).
        self.cache_hit = False
        #: Why ``response.server_addr()`` is needed (one driver round trip), else None:
        #: "sw" (service-worker network fallback under interception), "non_cdp" (Firefox/WebKit cache
        #: hit), "cdp" (Chromium disk-cache candidate or fulfilled response without route wrappers).
        self.need_addr: str | None = None


def _decide(state: _ContextState, request: Any, st: _Static, sizes: Any, info: _HeaderInfo, failed: bool,
            response: Any) -> _Decision:
    """First half of the decision; :func:`_apply_addr` finishes it when ``need_addr`` is set.

    Service workers: ``from_service_worker`` is also reported for a navigation Chromium sent to the
    network itself (a warm profile whose worker was not running: Chromium races the network request
    against starting the worker, and the worker fell back). Such a response carries the wire-level
    request headers and a server address, while a response the worker built or fetched for the page
    carries neither (the worker's own fetch is a separate event). It is written as a network request
    with an unknown body size (DevTools reports ``encodedDataLength`` 0 for it). Under request
    interception the wire headers are hidden, so the server address decides.
    """
    d = _Decision()
    d.no_network = _no_network(state, request, st, failed)
    if d.no_network is not None or response is None:
        return d
    if st.from_sw:
        if not failed and info.raw_ok and _wire_header_names(info.names, info.provisional):
            st.sw_network = True
        elif not failed and _intercepting(state, request):
            d.need_addr = "sw"
        return d
    if state.browser in _NON_CDP_BROWSERS:
        if _cacheable(st, failed):
            d.need_addr = "non_cdp"
        return d
    d.candidate = _disk_cache_candidate(state, st, sizes, info, failed, request)
    if _needs_server_addr(state, request, st, failed, d.candidate):
        d.need_addr = "cdp"
    return d


def _apply_addr(state: _ContextState, request: Any, st: _Static, d: _Decision, addr: Any) -> None:
    """Finish :func:`_decide` with ``response.server_addr()`` (``_MISSING`` when it failed)."""
    if d.need_addr == "sw":
        if addr is not None and addr is not _MISSING:
            st.sw_network = True
    elif d.need_addr == "non_cdp":
        # Firefox and WebKit give no server address for a response served from their HTTP cache
        # (checked with Firefox 155 and WebKit 26.6 through a proxy); a network response has one.
        if addr is None:
            if not _routes_tagged and _intercepting(state, request):
                d.no_network = "fulfilled"
            else:
                d.cache_hit = True
    elif d.need_addr == "cdp":
        if addr is None and not d.candidate:
            d.no_network = "fulfilled"
        d.elsewhere = d.candidate and _elsewhere(addr)


def _record(state: _ContextState, parts: _events.UrlParts, st: _Static, sizes: Any, info: _HeaderInfo,
            failed: bool, request: Any, d: _Decision) -> None:
    """Write one finished or failed request, or hold a disk-cache candidate until evidence arrives."""
    if d.no_network is not None:
        event = _build_request_event(state, parts, st, sizes, info, failed, request, no_network=d.no_network)
        _events.emit(event, no_network=d.no_network)
        return
    if d.cache_hit:
        _events.emit(_build_request_event(state, parts, st, sizes, info, failed, request, disk_cache=True))
        return
    candidate = d.candidate
    if candidate and not state.saw_wire_headers and not d.elsewhere:
        if not state.closed:
            state.held.append((parts, st, sizes, info))
            return
        candidate = state.browser == "chromium"  # late event after close: decide as at close
    _events.emit(_build_request_event(state, parts, st, sizes, info, failed, request, disk_cache=candidate))


def _on_done(state: _ContextState, request: Any, *, failed: bool) -> None:
    """requestfinished / requestfailed handler. Never raises into Playwright's dispatcher."""
    try:
        state.inflight.pop(id(request), None)
        if id(request) in state.flushed:
            return  # already written when the context closed
    except Exception:
        pass
    try:
        parts = _events.url_parts(request.url)
        if parts is None:
            return
        if state.is_async:
            task = asyncio.get_running_loop().create_task(_collect_async(state, request, parts, failed))
            state.pending.add(task)
            _pending.add(task)
            task.add_done_callback(state.pending.discard)
            task.add_done_callback(_pending.discard)
        else:
            _collect_sync(state, request, parts, failed)
    except Exception:
        pass


_MISSING = object()


def _collect_sync(state: _ContextState, request: Any, parts: _events.UrlParts, failed: bool) -> None:
    try:
        st = _static_fields(state, request)
        response = getattr(request, "existing_response", _MISSING)
        if response is _MISSING:  # Playwright < 1.53
            try:
                response = request.response()
            except Exception:
                response = None
        _apply_response(st, response)
        sizes = None
        if response is not None:
            try:
                sizes = request.sizes()
            except Exception:
                sizes = None
        provisional = _header_names(getattr(request, "headers", {}) or {})
        try:
            raw = request.all_headers()
            info = _HeaderInfo(_header_names(raw), provisional, raw_ok=True, proxy_hop=_proxy_hop_bytes(raw))
        except Exception:
            info = _HeaderInfo(provisional, provisional)
        if info.raw_ok and _wire_header_names(info.names, info.provisional):
            _saw_wire(state)
        decision = _decide(state, request, st, sizes, info, failed, response)
        if decision.need_addr is not None:
            try:
                addr = response.server_addr()
            except Exception:
                addr = _MISSING
            _apply_addr(state, request, st, decision, addr)
        _record(state, parts, st, sizes, info, failed, request, decision)
    except Exception:
        pass


async def _collect_async(state: _ContextState, request: Any, parts: _events.UrlParts, failed: bool) -> None:
    try:
        st = _static_fields(state, request)
        response = getattr(request, "existing_response", _MISSING)
        if response is _MISSING:  # Playwright < 1.53
            try:
                response = await request.response()
            except Exception:
                response = None
        _apply_response(st, response)
        sizes = None
        if response is not None:
            try:
                sizes = await request.sizes()
            except Exception:
                sizes = None
        provisional = _header_names(getattr(request, "headers", {}) or {})
        try:
            raw = await request.all_headers()
            info = _HeaderInfo(_header_names(raw), provisional, raw_ok=True, proxy_hop=_proxy_hop_bytes(raw))
        except Exception:
            info = _HeaderInfo(provisional, provisional)
        if info.raw_ok and _wire_header_names(info.names, info.provisional):
            _saw_wire(state)
        decision = _decide(state, request, st, sizes, info, failed, response)
        if decision.need_addr is not None:
            try:
                addr = await response.server_addr()
            except Exception:
                addr = _MISSING
            _apply_addr(state, request, st, decision, addr)
        _record(state, parts, st, sizes, info, failed, request, decision)
    except Exception:
        pass


class _WebSocketTally:
    """Payload byte counts for one WebSocket (payloads are measured, never kept)."""

    def __init__(self, state: _ContextState, parts: _events.UrlParts) -> None:
        self.state = state
        self.parts = parts
        self.ts = _events.now()
        self.sent = 0
        self.received = 0
        self.frames = 0
        self.error = False
        self.done = False

    @staticmethod
    def _size(payload: Any) -> int:
        if isinstance(payload, (bytes, bytearray, memoryview)):
            return len(payload)
        if isinstance(payload, str):
            return len(payload.encode("utf-8", "replace"))
        return 0

    def on_sent(self, payload: Any) -> None:
        self.sent += self._size(payload)
        self.frames += 1

    def on_received(self, payload: Any) -> None:
        self.received += self._size(payload)
        self.frames += 1

    def on_error(self, _error: Any = None) -> None:
        self.error = True

    def finish(self, _ws: Any = None) -> None:
        try:
            self.state.websockets.discard(self)
            if self.done:
                return
            self.done = True
            status = None if (self.error and self.frames == 0) else 101
            _events.emit(
                RequestEvent(
                    ts=self.ts,
                    source="playwright",
                    host=self.parts.host,
                    port=self.parts.port,
                    scheme=self.parts.scheme,
                    path=self.parts.path,
                    method="GET",
                    resource_type="websocket",
                    status=status,
                    failed=self.error,
                    frame="other",
                    encoded_body_bytes=self.received,
                    request_body_bytes=self.sent,
                    context=self.state.context_id,
                )
            )
        except Exception:
            pass


def _watch_websocket(state: _ContextState, ws: Any) -> None:
    try:
        parts = _events.url_parts(ws.url)
        if parts is None:
            return
        tally = _WebSocketTally(state, parts)
        if not state.closed:
            state.websockets.add(tally)
        ws.on("framesent", lambda payload: tally.on_sent(payload))
        ws.on("framereceived", lambda payload: tally.on_received(payload))
        ws.on("socketerror", lambda error: tally.on_error(error))
        ws.on("close", lambda _ws: tally.finish())
    except Exception:
        pass


async def _wait(tasks: set[asyncio.Task[Any]], timeout: float) -> None:
    try:
        loop = asyncio.get_running_loop()
        mine = [t for t in list(tasks) if not t.done() and t.get_loop() is loop]
        if mine:
            await asyncio.wait(mine, timeout=timeout)
    except Exception:
        pass


async def drain(timeout: float = DRAIN_TIMEOUT_S) -> None:
    """Await pending async size lookups (all contexts, this event loop); never raises."""
    await _wait(_pending, timeout)


def _wrap_async_close(context: Any, state: _ContextState) -> None:
    original = context.close

    async def close(*args: Any, **kwargs: Any) -> Any:
        await _wait(state.pending, DRAIN_TIMEOUT_S)
        return await original(*args, **kwargs)

    try:
        context.close = close
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Browsers
# ---------------------------------------------------------------------------


def _browser_name(obj: Any) -> str:
    candidates = []
    for getter in (
        lambda o: o.browser_type.name,  # Browser
        lambda o: o.name,  # BrowserType
        lambda o: o.browser.browser_type.name,  # BrowserContext (None for persistent contexts)
    ):
        try:
            candidates.append(getter(obj))
        except Exception:
            continue
    for name in candidates:
        if isinstance(name, str) and name in _BROWSERS:
            return name
    return "other"


def _launch_marks(obj: Any) -> list[Any]:
    """The objects that remember a recorded launch: ``obj`` and, for a context, the Browser behind it.

    Playwright 1.63 gives a persistent context a Browser (``context.browser``);
    older versions give None. Marking both means ``record_launch(context)``
    and ``instrument(context)`` (which records ``context.browser``) count one
    browser once, in either order.
    """
    marks = [obj]
    try:
        inner = getattr(obj, "browser", None)
    except Exception:
        inner = None
    if inner is not None and inner is not obj and not callable(inner):
        marks.append(inner)
    return marks


def record_launch(browser: Any) -> None:
    """Write one ``launch`` event per browser (idempotent).

    Accepts a Browser (``browser.browser_type.name``), a BrowserType, or a
    context, for example from ``launch_persistent_context``. A context counts
    as its Browser when Playwright exposes one (``context.browser``,
    Playwright 1.63 also for persistent contexts), so ``record_launch(context)``
    and :func:`instrument` together still write one launch; on versions whose
    persistent context has no Browser, ``instrument`` records nothing and this
    call is what counts the launch. No-op with one warning when
    ``SCRAPESCOPE_EVENTS`` is unset.
    """
    try:
        if _events.events_path() is None:
            _events.warn_inactive()
            return
        marks = _launch_marks(browser) if browser is not None else []
        if any(getattr(mark, _LAUNCH_ATTR, False) is True for mark in marks):
            for mark in marks:
                _set_mark(mark)
            return
        _events.emit(
            LaunchEvent(ts=_events.now(), source="playwright", browser=_browser_name(browser), pid=os.getpid())  # type: ignore[arg-type]
        )
        for mark in marks:
            _set_mark(mark)
    except Exception:
        pass


def _set_mark(obj: Any) -> None:
    try:
        setattr(obj, _LAUNCH_ATTR, True)
    except Exception:
        pass


def wrap_new_context(browser: Any) -> Any:
    """Route per-context proxies through the meter and instrument every context; idempotent.

    Patches ``browser.new_context`` and ``browser.new_page`` (sync or async):
    a ``proxy={"server", "username", "password"}`` argument gets
    ``server=$SCRAPESCOPE_AUTH_PROXY_URL`` when a username is present (else
    ``$SCRAPESCOPE_PROXY_URL``) with username and password passed through
    unchanged, and every new context is :func:`instrument`-ed. Existing
    contexts are instrumented too. For async browsers ``close()`` first awaits
    pending size lookups (:func:`drain`). Returns ``browser``.
    """
    try:
        if browser is None or getattr(browser, _WRAPPED_ATTR, False):
            return browser
        if not os.environ.get(ENV_PROXY_URL) and _events.events_path() is None:
            _events.warn_inactive()
            return browser
        original_new_context = browser.new_context
        original_new_page = browser.new_page
        if _is_async(browser):
            original_close = browser.close

            async def new_context(*args: Any, **kwargs: Any) -> Any:
                context = await original_new_context(*args, **_rewrite_kwargs(kwargs))
                return instrument(context)

            async def new_page(*args: Any, **kwargs: Any) -> Any:
                page = await original_new_page(*args, **_rewrite_kwargs(kwargs))
                _instrument_page_context(page)
                return page

            async def close(*args: Any, **kwargs: Any) -> Any:
                await drain()
                return await original_close(*args, **kwargs)

            browser.close = close
        else:

            def new_context(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
                context = original_new_context(*args, **_rewrite_kwargs(kwargs))
                return instrument(context)

            def new_page(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
                page = original_new_page(*args, **_rewrite_kwargs(kwargs))
                _instrument_page_context(page)
                return page

        browser.new_context = new_context
        browser.new_page = new_page
        setattr(browser, _WRAPPED_ATTR, True)
        for context in list(getattr(browser, "contexts", []) or []):
            instrument(context)
    except Exception:
        pass
    return browser


def _instrument_page_context(page: Any) -> None:
    try:
        instrument(page.context)
    except Exception:
        pass


def launch(browser_type: Any, *, webrtc_proxied_only: bool = False, **kwargs: Any) -> Any:
    """Sync API: launch with the meter as browser-wide proxy, record the launch, wrap contexts.

    ``proxy`` defaults to :func:`proxy_settings`; a ``proxy`` you pass is
    rewritten like a per-context proxy (server = the meter, credentials passed
    through). ``webrtc_proxied_only=True`` adds :data:`WEBRTC_PROXIED_ONLY_ARGS`
    (Chromium only), so WebRTC cannot send UDP from this machine around the
    meter and the provider. Errors from Playwright's own ``launch`` propagate
    unchanged.
    """
    browser = browser_type.launch(**_launch_kwargs(kwargs, webrtc_proxied_only))
    record_launch(browser)
    wrap_new_context(browser)
    return browser


async def async_launch(browser_type: Any, *, webrtc_proxied_only: bool = False, **kwargs: Any) -> Any:
    """Async API counterpart of :func:`launch`."""
    browser = await browser_type.launch(**_launch_kwargs(kwargs, webrtc_proxied_only))
    record_launch(browser)
    wrap_new_context(browser)
    return browser


__all__ = [
    "DRAIN_TIMEOUT_S",
    "WEBRTC_PROXIED_ONLY_ARGS",
    "async_launch",
    "drain",
    "instrument",
    "is_multiplexed",
    "launch",
    "proxy_settings",
    "record_launch",
    "wrap_new_context",
]
