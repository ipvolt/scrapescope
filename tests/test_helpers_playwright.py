"""Playwright helper tests.

Unit tests use small fakes of the Playwright objects (no browser). Browser
tests (``@pytest.mark.browser``) load the fixture shop through the FIXTURE
upstreams directly (no forwarder) and check the events file: main frame,
cross-site iframe, dedicated worker and service worker requests, cache and
service-worker exclusions, and that no query string, cookie or credential is
ever written.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from scrapescope.attribution import attribute, read_events
from scrapescope.config import (
    ENV_AUTH_PROXY_URL,
    ENV_EVENTS,
    ENV_KEEP_URLS,
    ENV_PROXY_URL,
    PRECONNECT_IDLE_MAX_RECEIVED,
    PRECONNECT_IDLE_MAX_SENT,
    PrivateEventsFile,
)
from scrapescope.helpers import events as ev
from scrapescope.helpers import playwright as ssp
from scrapescope.types import AttachEvent, Catalogs, LaunchEvent, MeterSnapshot, RequestEvent, TunnelRecord
from tests.fixtures import SESSION_PASSWORD, UPSTREAM_PASSWORD, UPSTREAM_USERNAME, site
from tests.fixtures.browser import (
    CONTEXT_KWARGS,
    PAGE_DONE_PREDICATE,
    chromium_launch_kwargs,
    chromium_unavailable_reason,
)

METER = "http://127.0.0.1:40001"
AUTH_METER = "http://127.0.0.1:40002"


@pytest.fixture(autouse=True)
def _fresh_writer_state(monkeypatch: pytest.MonkeyPatch):
    ev._reset_for_tests()
    for name in (ENV_PROXY_URL, ENV_AUTH_PROXY_URL, ENV_KEEP_URLS, ssp.ENV_UPSTREAM_ID):
        monkeypatch.delenv(name, raising=False)
    ssp._rerouted_servers.clear()
    ssp._warned_proxy.clear()
    yield
    ssp._open_states.clear()  # fake contexts left open must not be flushed at interpreter exit
    ssp._rerouted_servers.clear()
    ssp._warned_proxy.clear()
    ev._reset_for_tests()


@pytest.fixture
def events_file(monkeypatch: pytest.MonkeyPatch):
    private = PrivateEventsFile.create()
    monkeypatch.setenv(ENV_EVENTS, str(private.path))
    yield private.path
    ev._reset_for_tests()
    private.cleanup()


def _events(path: Path) -> list[Any]:
    log = read_events(path)
    assert log.dropped == 0
    return log.events


def _requests(path: Path) -> list[RequestEvent]:
    return [e for e in _events(path) if isinstance(e, RequestEvent)]


# ---------------------------------------------------------------------------- fakes


class Emitter:
    def __init__(self) -> None:
        self.handlers: dict[str, list[Any]] = defaultdict(list)

    def on(self, name: str, fn: Any) -> None:
        self.handlers[name].append(fn)

    def fire(self, name: str, *args: Any) -> None:
        for fn in list(self.handlers[name]):
            fn(*args)


class FakeFrame:
    def __init__(self, parent: FakeFrame | None = None) -> None:
        self.parent_frame = parent


MAIN = FakeFrame()
SUB = FakeFrame(MAIN)


_NO_ADDR: Any = object()


class FakeResponse:
    def __init__(self, status: int = 200, from_sw: bool = False, server_addr: Any = _NO_ADDR) -> None:
        self.status = status
        self.from_service_worker = from_sw
        self._addr = server_addr
        self.addr_calls = 0

    def server_addr(self) -> Any:
        self.addr_calls += 1
        if self._addr is _NO_ADDR:
            raise AttributeError("server_addr not faked")
        return self._addr


_DEFAULT: Any = object()


class FakeRequest:
    def __init__(self, url: str, *, method: str = "GET", resource_type: str = "document", nav: bool = False,
                 frame: Any = MAIN, service_worker: Any = None, response: Any = _DEFAULT,
                 sizes: Any = None, headers: dict[str, str] | None = None,
                 all_headers: dict[str, str] | None = None, start_ms: float | None = None,
                 failure: str | None = None) -> None:
        self.url = url
        self.failure = failure
        self.method = method
        self.resource_type = resource_type
        self._nav = nav
        self._frame = frame
        self.service_worker = service_worker
        self.existing_response = FakeResponse() if response is _DEFAULT else response
        self._sizes = sizes if sizes is not None else {
            "requestBodySize": 0, "requestHeadersSize": 500, "responseBodySize": 1000, "responseHeadersSize": 200}
        self.headers = headers or {"accept": "*/*"}
        self._all = all_headers if all_headers is not None else dict(self.headers)
        self.timing = {"startTime": start_ms if start_ms is not None else time.time() * 1000}

    @property
    def frame(self) -> Any:
        if self.service_worker is not None:
            raise RuntimeError("Service Worker requests do not have an associated frame.")
        return self._frame

    def is_navigation_request(self) -> bool:
        return self._nav

    def sizes(self) -> dict[str, int]:
        if isinstance(self._sizes, Exception):
            raise self._sizes
        return self._sizes

    def all_headers(self) -> dict[str, str]:
        return self._all


class FakeAsyncRequest(FakeRequest):
    async def sizes(self) -> dict[str, int]:  # type: ignore[override]
        await asyncio.sleep(0)
        return FakeRequest.sizes(self)

    async def all_headers(self) -> dict[str, str]:  # type: ignore[override]
        await asyncio.sleep(0)
        return self._all


class FakePage(Emitter):
    def __init__(self, context: Any = None) -> None:
        super().__init__()
        self.workers: list[Any] = []
        self.context = context


class FakeContext(Emitter):
    def __init__(self) -> None:
        super().__init__()
        self.pages: list[FakePage] = []
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeAsyncContext(Emitter):
    def __init__(self) -> None:
        super().__init__()
        self.pages: list[FakePage] = []
        self.closed = False
        self.pending_at_close: int | None = None

    async def close(self) -> None:
        self.closed = True


class FakeBrowserType:
    def __init__(self, name: str = "chromium") -> None:
        self.name = name
        self.launch_kwargs: dict[str, Any] | None = None

    def launch(self, **kwargs: Any) -> FakeBrowser:
        self.launch_kwargs = kwargs
        return FakeBrowser(self)


class FakeBrowser:
    def __init__(self, browser_type: FakeBrowserType | None = None) -> None:
        self.browser_type = browser_type or FakeBrowserType()
        self.contexts: list[Any] = []
        self.calls: list[dict[str, Any]] = []

    def new_context(self, **kwargs: Any) -> FakeContext:
        self.calls.append(kwargs)
        ctx = FakeContext()
        self.contexts.append(ctx)
        return ctx

    def new_page(self, **kwargs: Any) -> FakePage:
        ctx = self.new_context(**kwargs)
        page = FakePage(ctx)
        ctx.pages.append(page)
        return page

    def close(self) -> None:
        pass


class FakeAsyncBrowser:
    def __init__(self) -> None:
        self.browser_type = FakeBrowserType()
        self.contexts: list[Any] = []
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    async def new_context(self, **kwargs: Any) -> FakeAsyncContext:
        self.calls.append(kwargs)
        ctx = FakeAsyncContext()
        self.contexts.append(ctx)
        return ctx

    async def new_page(self, **kwargs: Any) -> FakePage:
        ctx = await self.new_context(**kwargs)
        return FakePage(ctx)

    async def close(self) -> None:
        self.closed = True


class FakeWebSocket(Emitter):
    def __init__(self, url: str) -> None:
        super().__init__()
        self.url = url


# ---------------------------------------------------------------------------- proxy settings


def test_proxy_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.warns(RuntimeWarning, match="SCRAPESCOPE_PROXY_URL is not set"):
        assert ssp.proxy_settings() is None
    monkeypatch.setenv(ENV_PROXY_URL, METER)
    assert ssp.proxy_settings() == {"server": METER}
    assert ssp.proxy_settings(username="u", password="p") == {"server": METER, "username": "u", "password": "p"}
    monkeypatch.setenv(ENV_AUTH_PROXY_URL, AUTH_METER)
    assert ssp.proxy_settings(username="u", password="p") == {"server": AUTH_METER, "username": "u", "password": "p"}
    assert ssp.proxy_settings() == {"server": METER}


def test_rewrite_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    given = {"server": "http://gw.provider.example:7777", "username": "cust-session-1", "password": "pw",
             "bypass": ".internal"}
    assert ssp._rewrite_proxy(given) == given  # meter URL unset: unchanged
    monkeypatch.setenv(ENV_PROXY_URL, METER)
    monkeypatch.setenv(ENV_AUTH_PROXY_URL, AUTH_METER)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # one provider: no warning
        rewritten = ssp._rewrite_proxy(given)
        assert ssp._rewrite_proxy({**given, "username": "cust-session-2"})["server"] == AUTH_METER
        assert ssp._rewrite_proxy({"server": METER}) == {"server": METER}  # already the meter
    assert rewritten == {**given, "server": AUTH_METER}
    assert given["server"] == "http://gw.provider.example:7777"  # the caller's dict is not mutated
    with pytest.warns(RuntimeWarning, match="more than one proxy server") as record:
        assert ssp._rewrite_proxy({"server": "http://x:1"}) == {"server": METER}
    assert "x:1" not in str(record[0].message) and "cust-session" not in str(record[0].message)
    assert ssp._rewrite_proxy({"server": "http://x:1", "username": ""}) == {"server": METER, "username": ""}
    assert ssp._rewrite_proxy("not a dict") == "not a dict"


@pytest.mark.parametrize("server", ["http://GW.Provider.example:7777", "gw.provider.example:7777",
                                    "socks5://gw.provider.example:7777"])
def test_rewrite_proxy_reroutes_only_the_runs_upstream_when_its_fingerprint_is_given(
    monkeypatch: pytest.MonkeyPatch, server: str
) -> None:
    """sec2-8: provider B's credentials must not be sent to the run's upstream A."""
    monkeypatch.setenv(ENV_PROXY_URL, METER)
    monkeypatch.setenv(ENV_AUTH_PROXY_URL, AUTH_METER)
    fingerprint = ssp.upstream_id("gw.provider.example", 7777)
    assert "gw.provider" not in fingerprint and fingerprint != ssp.upstream_id("gw.provider.example", 7777)
    monkeypatch.setenv(ssp.ENV_UPSTREAM_ID, fingerprint)
    mine = {"server": server, "username": "userA-1", "password": "pa"}
    assert ssp._rewrite_proxy(mine) == {**mine, "server": AUTH_METER}
    other = {"server": "http://gw.other-provider.example:7777", "username": "userB-session-1", "password": "passB"}
    with pytest.warns(RuntimeWarning, match="left unchanged") as record:
        assert ssp._rewrite_proxy(other) == other
    assert "userB" not in str(record[0].message) and "other-provider" not in str(record[0].message)
    assert ssp._launch_kwargs({"proxy": {"server": "socks5://other.example:1080"}})["proxy"] == {
        "server": "socks5://other.example:1080"}
    assert ssp._rewrite_proxy({"server": "http://gw.provider.example:7778"})["server"].endswith(":7778")
    monkeypatch.setenv(ssp.ENV_UPSTREAM_ID, "garbage")  # invalid: behaves as unset
    with pytest.warns(RuntimeWarning, match="more than one proxy server") as record:
        assert ssp._rewrite_proxy(other)["server"] == AUTH_METER  # the second server rerouted in this process
    assert "userB" not in str(record[0].message) and "other-provider" not in str(record[0].message)


# ---------------------------------------------------------------------------- wrapping and launch (fakes)


def test_wrap_new_context_sync(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_PROXY_URL, METER)
    monkeypatch.setenv(ENV_AUTH_PROXY_URL, AUTH_METER)
    browser = FakeBrowser()
    existing = browser.new_context()
    assert ssp.wrap_new_context(browser) is browser
    assert ssp.wrap_new_context(browser) is browser  # idempotent
    ctx = browser.new_context(proxy={"server": "http://gw.example:1", "username": "sess-1", "password": "pw"},
                              locale="en-US")
    assert browser.calls[-1] == {"proxy": {"server": AUTH_METER, "username": "sess-1", "password": "pw"},
                                 "locale": "en-US"}
    browser.new_context(proxy={"server": "http://gw.example:1"})
    assert browser.calls[-1] == {"proxy": {"server": METER}}
    browser.new_context()
    assert browser.calls[-1] == {}
    page = browser.new_page(proxy={"server": "http://gw.example:1", "username": "sess-2", "password": "pw"})
    assert browser.calls[-1]["proxy"]["server"] == AUTH_METER
    for c in (existing, ctx, page.context):
        assert getattr(c, "_scrapescope_state", None) is not None
        assert "requestfinished" in c.handlers and "requestfailed" in c.handlers and "request" in c.handlers
    attaches = [e for e in _events(events_file) if isinstance(e, AttachEvent)]
    assert len(attaches) == 5 and len({a.context for a in attaches}) == 5
    assert "sess-1" not in events_file.read_text()


def test_wrap_new_context_async_drains_before_close(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_PROXY_URL, METER)

    async def main() -> None:
        browser = FakeAsyncBrowser()
        ssp.wrap_new_context(browser)
        ctx = await browser.new_context(proxy={"server": "http://gw.example:1", "username": "s", "password": "p"})
        assert browser.calls[-1]["proxy"]["server"] == METER  # no auth URL set: falls back to the meter URL
        assert ctx._scrapescope_state.is_async is True
        ctx.fire("requestfinished", FakeAsyncRequest("https://origin-a.test/", nav=True))
        ctx.fire("requestfinished", FakeAsyncRequest("https://origin-a.test/app.js", resource_type="script"))
        assert _requests(events_file) == []  # still pending in tasks
        await ctx.close()  # the wrapped close awaits pending lookups first
        assert ctx.closed
        assert len(_requests(events_file)) == 2
        ctx2 = await browser.new_context()
        ctx2.fire("requestfinished", FakeAsyncRequest("https://origin-b.test/"))
        await browser.close()  # drains every context
        assert browser.closed

    asyncio.run(main())
    assert len(_requests(events_file)) == 3


def test_launch_sets_proxy_records_launch_and_wraps(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_PROXY_URL, METER)
    bt = FakeBrowserType()
    browser = ssp.launch(bt, headless=True)
    assert bt.launch_kwargs == {"headless": True, "proxy": {"server": METER}}
    assert getattr(browser, "_scrapescope_wrapped", False)
    bt2 = FakeBrowserType("firefox")
    ssp.launch(bt2, proxy={"server": "http://gw.example:1", "username": "u", "password": "p"})
    assert bt2.launch_kwargs == {"proxy": {"server": METER, "username": "u", "password": "p"}}
    launches = [e for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert [e.browser for e in launches] == ["chromium", "firefox"]


def test_launch_offers_the_webrtc_switch_find_uses(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """sec2-1: launch(..., webrtc_proxied_only=True) keeps WebRTC off this machine's own UDP; opt-in, args kept."""
    from scrapescope.find.browser import FIND_CHROMIUM_ARGS

    monkeypatch.setenv(ENV_PROXY_URL, METER)
    assert ssp.WEBRTC_PROXIED_ONLY_ARGS == FIND_CHROMIUM_ARGS == (
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    )
    bt = FakeBrowserType()
    ssp.launch(bt, webrtc_proxied_only=True, args=["--lang=en-GB"])
    assert bt.launch_kwargs["args"] == ["--lang=en-GB", *ssp.WEBRTC_PROXIED_ONLY_ARGS]
    bt2 = FakeBrowserType()
    ssp.launch(bt2, args=["--lang=en-GB"])
    assert bt2.launch_kwargs["args"] == ["--lang=en-GB"]  # off by default: the job's own WebRTC is unchanged


def test_async_launch(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_PROXY_URL, METER)

    class AsyncBT:
        name = "webkit"
        kwargs: dict[str, Any] = {}

        async def launch(self, **kwargs: Any) -> FakeAsyncBrowser:
            AsyncBT.kwargs = kwargs
            return FakeAsyncBrowser()

    browser = asyncio.run(ssp.async_launch(AsyncBT()))
    assert AsyncBT.kwargs == {"proxy": {"server": METER}}
    assert isinstance(browser, FakeAsyncBrowser)
    (launch,) = [e for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert launch.browser == "chromium"  # FakeAsyncBrowser.browser_type is a chromium FakeBrowserType


def test_record_launch_variants_and_idempotence(events_file: Path) -> None:
    browser = FakeBrowser(FakeBrowserType("webkit"))
    ssp.record_launch(browser)
    ssp.record_launch(browser)
    ssp.record_launch(FakeBrowserType("firefox"))

    class PersistentContext:
        browser = None

    ssp.record_launch(PersistentContext())
    ssp.record_launch(object())
    names = [e.browser for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert names == ["webkit", "firefox", "other", "other"]


def test_helpers_inactive_without_events(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_EVENTS, raising=False)
    ctx = FakeContext()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert ssp.instrument(ctx) is ctx
        ssp.record_launch(FakeBrowser())
        browser = FakeBrowser()
        assert ssp.wrap_new_context(browser) is browser
        bt = FakeBrowserType()
        ssp.launch(bt, headless=True)
    assert len(caught) == 1 and "helpers inactive" in str(caught[0].message)
    assert ctx.handlers == {} and not hasattr(ctx, "_scrapescope_state")
    assert bt.launch_kwargs == {"headless": True}  # no proxy injected without SCRAPESCOPE_PROXY_URL
    assert not getattr(browser, "_scrapescope_wrapped", False)


# ---------------------------------------------------------------------------- event mapping (fakes)


def test_each_context_gets_its_own_handler_objects(events_file: Path) -> None:
    """Regression: Playwright caches its API wrapper on the handler object, so a shared handler
    registered from the sync API would hand sync objects to async contexts. Handlers must be fresh."""
    first, second = FakeContext(), FakeAsyncContext()
    ssp.instrument(first)
    ssp.instrument(second)
    for name in ("request", "requestfinished", "requestfailed", "page"):
        assert first.handlers[name][0] is not second.handlers[name][0]


def _instrumented(events_file: Path) -> FakeContext:
    ctx = FakeContext()
    ssp.instrument(ctx)
    assert ssp.instrument(ctx) is ctx  # idempotent: one attach
    return ctx


def test_frame_kinds_and_flags(events_file: Path) -> None:
    ctx = _instrumented(events_file)
    page = FakePage(ctx)
    ctx.fire("page", page)
    worker = type("W", (), {"url": "https://origin-a.test/static/worker.js#frag"})()
    page.fire("worker", worker)
    sw = object()
    reqs = [
        FakeRequest("https://origin-a.test/", nav=True),
        FakeRequest("https://origin-b.test/embed", nav=True, frame=SUB),
        FakeRequest("https://origin-a.test/api/worker.json", resource_type="fetch",
                    headers={"referer": "https://origin-a.test/static/worker.js"}),
        FakeRequest("https://origin-a.test/api/sw-backend.json", resource_type="fetch", service_worker=sw),
        FakeRequest("https://origin-a.test/x", frame=None),  # frame without parent info -> other
        FakeRequest("https://origin-a.test/api/session-product.json", resource_type="fetch",
                    all_headers={"cookie": site.SESSION_COOKIE_VALUE, "authorization": "Bearer SECRET-XYZ"}),
        FakeRequest("https://origin-a.test/api/collect", method="post", resource_type="fetch",
                    sizes={"requestBodySize": 32, "requestHeadersSize": 600, "responseBodySize": 41,
                           "responseHeadersSize": 204}),
    ]
    for r in reqs:
        ctx.fire("request", r)
        ctx.fire("requestfinished", r)
    events = _requests(events_file)
    assert [e.frame for e in events] == ["main", "sub", "worker", "service_worker", "other", "main", "main"]
    assert events[0].is_navigation and events[0].resource_type == "document"
    assert events[5].sent_cookies and events[5].sent_authorization
    assert events[6].method == "POST" and events[6].request_body_bytes == 32
    assert events[0].encoded_body_bytes == 1000 and events[0].response_header_bytes == 200
    assert all(e.context == events[0].context and e.source == "playwright" for e in events)
    text = events_file.read_text()
    assert site.SESSION_COOKIE_VALUE not in text and "SECRET-XYZ" not in text and "worker.js" not in text


def test_cache_and_service_worker_sizes(events_file: Path) -> None:
    ctx = _instrumented(events_file)
    cached = FakeRequest("https://origin-a.test/static/img/hero-1.png", resource_type="image",
                         sizes={"requestBodySize": 0, "requestHeadersSize": 351, "responseBodySize": -200,
                                "responseHeadersSize": 200})
    served_by_sw = FakeRequest("https://origin-a.test/api/sw.json", resource_type="fetch",
                               response=FakeResponse(200, from_sw=True),
                               sizes={"requestBodySize": 0, "requestHeadersSize": 332, "responseBodySize": -49,
                                      "responseHeadersSize": 49})
    revalidated = FakeRequest("https://origin-a.test/static/app.js", resource_type="script",
                              response=FakeResponse(304),
                              sizes={"requestBodySize": 0, "requestHeadersSize": 400, "responseBodySize": 0,
                                     "responseHeadersSize": 180})
    script_body_unknown = FakeRequest("https://origin-a.test/static/worker.js", resource_type="script",
                                      sizes={"requestBodySize": 0, "requestHeadersSize": 390,
                                             "responseBodySize": 0, "responseHeadersSize": 275})
    odd = FakeRequest("https://origin-a.test/odd", sizes={"requestBodySize": -1, "requestHeadersSize": 10,
                                                          "responseBodySize": 5, "responseHeadersSize": -1})
    for r in (cached, served_by_sw, revalidated, script_body_unknown, odd):
        ctx.fire("requestfinished", r)
    a, b, c, d, e = _requests(events_file)
    assert a.from_cache and not a.hit_network and a.reported_bytes == 0
    assert b.from_service_worker and not b.from_cache and not b.hit_network and b.reported_bytes == 0
    assert c.hit_network and c.status == 304 and c.response_header_bytes == 180
    assert d.hit_network and d.encoded_body_bytes == 0 and d.response_header_bytes == 275
    assert e.request_body_bytes is None and e.response_header_bytes is None and e.encoded_body_bytes == 5


def test_failed_requests_and_non_network_urls(events_file: Path) -> None:
    ctx = _instrumented(events_file)

    failed = FakeRequest("https://nonexistent.test/", nav=True, response=None,
                         sizes=RuntimeError("Unable to fetch sizes"))
    ctx.fire("requestfailed", failed)
    for url in ("data:image/png;base64,AAAA", "blob:https://origin-a.test/1", "about:blank",
                "chrome-extension://abc/x.js"):
        ctx.fire("requestfinished", FakeRequest(url))
    (event,) = _requests(events_file)
    assert event.failed and event.status is None and event.encoded_body_bytes is None
    assert event.host == "nonexistent.test" and event.is_navigation


def test_handlers_never_raise(events_file: Path) -> None:
    ctx = _instrumented(events_file)

    class Exploding:
        @property
        def url(self) -> str:
            raise RuntimeError("boom")

    class HalfBroken(FakeRequest):
        @property
        def method(self) -> str:  # type: ignore[override]
            raise RuntimeError("boom")

        @method.setter
        def method(self, value: str) -> None:
            pass

        def all_headers(self) -> dict[str, str]:
            raise RuntimeError("target closed")

    ctx.fire("requestfinished", Exploding())
    ctx.fire("request", Exploding())
    ctx.fire("requestfinished", HalfBroken("https://origin-a.test/y", headers={"cookie": "x"}))
    (event,) = _requests(events_file)
    assert event.method == "GET" and event.sent_cookies is True  # provisional headers as fallback


def test_start_time_prefers_browser_clock(events_file: Path) -> None:
    ctx = _instrumented(events_file)
    now = time.time()
    ctx.fire("requestfinished", FakeRequest("https://origin-a.test/1", start_ms=(now - 3) * 1000))
    ctx.fire("requestfinished", FakeRequest("https://origin-a.test/2", start_ms=0))
    ctx.fire("requestfinished", FakeRequest("https://origin-a.test/3", start_ms=(now - 10 * 86400) * 1000))
    first, second, third = _requests(events_file)
    assert abs(first.ts - (now - 3)) < 0.01
    assert abs(second.ts - now) < 5 and abs(third.ts - now) < 5


def test_keep_urls_writes_paths_without_queries(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    ctx = _instrumented(events_file)
    ctx.fire("requestfinished", FakeRequest(f"https://origin-a.test/api/offer.json?sig={site.SIGNED_QUERY_TOKEN}"))
    (event,) = _requests(events_file)
    assert event.path == "/api/offer.json"
    assert site.SIGNED_QUERY_TOKEN not in events_file.read_text()


def test_websocket_tally(events_file: Path) -> None:
    ctx = _instrumented(events_file)
    page = FakePage(ctx)
    ctx.pages.append(page)
    ctx.fire("page", page)  # already watched pages are not watched twice
    ws = FakeWebSocket("wss://stream.test/feed?token=SECRET-WS")
    page.fire("websocket", ws)
    ws.fire("framesent", "hello")
    ws.fire("framereceived", b"\x00" * 100)
    ws.fire("framereceived", "\u00e9t\u00e9")
    ws.fire("close", ws)
    ws.fire("close", ws)
    bad = FakeWebSocket("ws://down.test/")
    page.fire("websocket", bad)
    bad.fire("socketerror", "refused")
    bad.fire("close", bad)
    good, failed = _requests(events_file)
    assert (good.scheme, good.host, good.port, good.resource_type, good.status) == ("wss", "stream.test", 443,
                                                                                    "websocket", 101)
    assert good.request_body_bytes == 5 and good.encoded_body_bytes == 105 and not good.failed  # 100 + UTF-8 "\u00e9t\u00e9"
    assert failed.failed and failed.status is None and failed.port == 80
    assert "SECRET-WS" not in events_file.read_text() and "hello" not in events_file.read_text()


def test_async_context_via_instrument(events_file: Path) -> None:
    async def main() -> None:
        ctx = FakeAsyncContext()
        ssp.instrument(ctx)
        ctx.fire("requestfinished", FakeAsyncRequest("https://origin-a.test/", nav=True,
                                                     all_headers={"cookie": "c"}))
        ctx.fire("requestfailed", FakeAsyncRequest("https://gone.test/", sizes=RuntimeError("no sizes"),
                                                   response=None))
        await ssp.drain()
        await ctx.close()
        assert ctx.closed

    asyncio.run(main())
    by_host = {e.host: e for e in _requests(events_file)}  # tasks may finish in any order
    ok, failed = by_host["origin-a.test"], by_host["gone.test"]
    assert ok.sent_cookies and ok.encoded_body_bytes == 1000
    assert failed.failed and failed.encoded_body_bytes is None and failed.status is None


# ---------------------------------------------------------------------------- real browser


def _assert_private(path: Path, *extra: str) -> None:
    text = path.read_text(encoding="utf-8")
    for secret in (UPSTREAM_USERNAME, UPSTREAM_PASSWORD, SESSION_PASSWORD, site.SESSION_COOKIE_VALUE,
                   site.SIGNED_QUERY_TOKEN, "sig=", "?", *extra):
        assert secret not in text, secret
    assert base64.b64encode(f"{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}".encode()).decode() not in text


def _load_shop(page: Any, path: str = "/") -> None:
    page.goto(f"https://origin-a.test{path}", wait_until="load")
    page.wait_for_function(PAGE_DONE_PREDICATE, timeout=30_000)
    page.wait_for_timeout(300)  # let the last requestfinished events arrive


#: Starts a fetch of the (%r-quoted) path and counts the body bytes received so far in ``window.__received``.
_COUNTING_FETCH_JS = """
window.__received = 0;
fetch(%r).then(r => {
  const reader = r.body.getReader();
  const pump = () => reader.read().then(({done, value}) => {
    if (done) return;
    window.__received += value.byteLength;
    return pump();
  });
  return pump();
}).catch(() => 0);
1
"""


def _by_path(events: list[RequestEvent], host: str, path: str) -> list[RequestEvent]:
    return [e for e in events if e.host == host and e.path == path]


def _tunnels_from_upstream(records: list[Any]) -> list[TunnelRecord]:
    """The fixture upstream counts the same socket bytes the meter would (see tests/fixtures/README.md)."""
    tunnels = []
    for i, rec in enumerate(records):
        if rec.kind != "connect" or not rec.target:
            continue
        host, _, port = rec.target.rpartition(":")
        tunnels.append(TunnelRecord(
            id=i + 1, host=host, port=int(port), kind="connect", route="http-connect",
            opened_at=rec.started_at, closed_at=rec.ended_at,
            status="ok" if rec.tunnel_established else "failed:upstream_status",
            upstream_bytes_sent=rec.bytes_from_client, upstream_bytes_received=rec.bytes_to_client,
            negotiation_bytes_sent=rec.negotiation_from_client, negotiation_bytes_received=rec.negotiation_to_client,
            upstream_status=rec.statuses[-1] if rec.statuses else None,
        ))
    return tunnels


def _snapshot(tunnels: list[TunnelRecord], started: float) -> MeterSnapshot:
    return MeterSnapshot(taken_at=time.time(), started_at=started, mode="http-connect", port=1, auth_port=None,
                         tunnels=tunnels, counted_bytes=sum(t.counted_bytes for t in tunnels),
                         budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False)


def _fixture_catalogs() -> Catalogs:
    entries = [
        {"id": "optimization-guide", "hosts": ["optimizationguide-pa.googleapis.com"]},
        {"id": "component-updater", "hosts": ["update.googleapis.com", "clients2.google.com",
                                              "clients2.googleusercontent.com", "edgedl.me.gvt1.com"]},
        {"id": "safe-browsing", "hosts": ["safebrowsing.googleapis.com"]},
    ]
    for entry in entries:
        entry.update(component="c", evidence=["https://github.com/puppeteer/puppeteer/issues/7042"],
                     security_tradeoff="t", last_verified="2026-09-23")
    return Catalogs.from_documents({"version": "t", "entries": entries}, {"version": "t", "vendors": []},
                                   {"version": "t", "entries": []})


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_sync_browser_events_cover_frames_workers_and_service_worker(
    fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    started = time.time()
    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream.server,
                                    username=UPSTREAM_USERNAME, password=UPSTREAM_PASSWORD)
    with sync_playwright() as p:
        browser = p.chromium.launch(**kwargs)
        try:
            ssp.record_launch(browser)
            ssp.wrap_new_context(browser)
            context = browser.new_context(**CONTEXT_KWARGS)  # instrumented by the wrapper
            page = context.new_page()
            _load_shop(page)
            context.close()
        finally:
            browser.close()
    assert fresh_world.wait_idle(15)

    events = _events(events_file)
    launches = [e for e in events if isinstance(e, LaunchEvent)]
    attaches = [e for e in events if isinstance(e, AttachEvent)]
    reqs = [e for e in events if isinstance(e, RequestEvent)]
    assert [l.browser for l in launches] == ["chromium"] and len(attaches) == 1
    assert all(r.context == attaches[0].context for r in reqs)

    (doc,) = _by_path(reqs, "origin-a.test", "/")
    assert (doc.frame, doc.is_navigation, doc.resource_type, doc.status) == ("main", True, "document", 200)
    assert doc.encoded_body_bytes and doc.response_header_bytes and doc.request_header_bytes
    (iframe,) = _by_path(reqs, "origin-b.test", "/embed")
    assert (iframe.frame, iframe.is_navigation) == ("sub", True)
    (embed_png,) = _by_path(reqs, "origin-b.test", site.EMBED_IMAGE)
    assert embed_png.frame == "sub" and embed_png.resource_type == "image"
    (worker_json,) = _by_path(reqs, "origin-a.test", "/api/worker.json")
    assert worker_json.frame == "worker" and worker_json.hit_network
    (sw_backend,) = _by_path(reqs, "origin-a.test", "/api/sw-backend.json")
    assert sw_backend.frame == "service_worker" and sw_backend.hit_network
    (sw_page,) = _by_path(reqs, "origin-a.test", "/api/sw.json")
    assert sw_page.from_service_worker and not sw_page.hit_network and sw_page.reported_bytes == 0
    (session_json,) = _by_path(reqs, "origin-a.test", "/api/session-product.json")
    assert session_json.sent_cookies and not session_json.sent_authorization
    (product_json,) = _by_path(reqs, "origin-a.test", "/api/product.json")
    assert not product_json.sent_cookies  # the cookie is path-scoped
    (offer,) = _by_path(reqs, "origin-a.test", "/api/offer.json")
    assert offer.status == 200
    (beacon,) = _by_path(reqs, "origin-a.test", "/api/collect")
    assert beacon.method == "POST" and beacon.request_body_bytes and beacon.request_body_bytes > 0
    for image, (w, h, _seed) in site.IMAGES.items():
        (img,) = _by_path(reqs, "origin-a.test", image)
        assert img.resource_type == "image" and img.encoded_body_bytes == len(site.image(image))
    (font,) = _by_path(reqs, "origin-a.test", site.FONT_PATH)
    assert font.resource_type == "font" and font.encoded_body_bytes == site.FONT_SIZE
    _assert_private(events_file)

    # Attribution over the tunnels the upstream saw: iframe, worker and service-worker hosts are
    # attributed, never background, and each service-worker-handled request counts once.
    result = attribute(_snapshot(_tunnels_from_upstream(fresh_world.http_upstream.records()), started),
                       events, _fixture_catalogs())
    rows = {h.host: h for h in result.hosts}
    assert set(rows["origin-a.test"].buckets) == {"attributed"}
    assert set(rows["origin-b.test"].buckets) == {"attributed"}
    assert result.buckets.background == {}
    assert result.units.count == 1 and result.units.source == "navigations"
    assert result.bypass.incomplete is False
    fetch = next(t for t in result.types if t.type == "fetch")
    assert fetch.requests == sum(1 for r in reqs if r.resource_type == "fetch" and r.hit_network)
    assert sum(t.allocated_bytes for t in result.types) == result.buckets.attributed


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_second_load_cache_hits_are_flagged(fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without proxy credentials Playwright keeps Chromium's HTTP cache; cache hits are not network requests."""
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream_noauth.server)
    with sync_playwright() as p:
        browser = p.chromium.launch(**kwargs)
        try:
            context = ssp.instrument(browser.new_context(**CONTEXT_KWARGS))
            page = context.new_page()
            _load_shop(page, "/")
            _load_shop(page, "/product/2")
            context.close()
        finally:
            browser.close()
    reqs = _requests(events_file)
    hero = _by_path(reqs, "origin-a.test", "/static/img/hero-1.png")
    assert len(hero) == 2
    assert hero[0].hit_network and hero[0].encoded_body_bytes == len(site.image("/static/img/hero-1.png"))
    assert hero[1].from_cache and not hero[1].hit_network and hero[1].reported_bytes == 0
    result = attribute(_snapshot([], time.time()), [*_events(events_file)], _fixture_catalogs())
    assert result.units.count == 2 and result.multi_page_context is True


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_per_context_credentials_pass_through_unchanged(
    fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch, closed_port: int
) -> None:
    """wrap_new_context sends per-context usernames to the auth URL, which passes them through unchanged.

    Here the fixture upstreams stand in for the meter's two listeners: the
    "main" URL is the no-auth upstream, the "auth" URL the challenging one.
    The per-context server given by the "job" is a closed loopback port, so a
    missing rewrite fails locally instead of reaching anything.
    """
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_PROXY_URL, fresh_world.http_upstream_noauth.server)
    monkeypatch.setenv(ENV_AUTH_PROXY_URL, fresh_world.http_upstream.server)
    users = ["customer-x-session-111", "customer-x-session-222"]

    def scenario(p: Any) -> None:
        browser = ssp.launch(p.chromium, args=fresh_world.chromium_args())
        try:
            for user in users:
                context = browser.new_context(
                    proxy={"server": f"http://127.0.0.1:{closed_port}", "username": user,
                           "password": SESSION_PASSWORD},
                    **CONTEXT_KWARGS,
                )
                page = context.new_page()
                page.goto("https://origin-a.test/api/product.json")
                context.close()
            plain = browser.new_context(**CONTEXT_KWARGS)
            plain.new_page().goto("https://origin-c.test/")
            plain.close()
        finally:
            browser.close()

    with sync_playwright() as p:
        try:
            scenario(p)
        except PlaywrightError as exc:
            # Chromium occasionally fails every per-context proxy connection of one browser
            # instance with ERR_PROXY_CONNECTION_FAILED before contacting the proxy (reproduced
            # with plain Playwright, no scrapescope code involved). Retry once with a new browser.
            if "ERR_PROXY_CONNECTION_FAILED" not in str(exc):
                raise
            fresh_world.reset()
            events_file.write_text("")
            scenario(p)
    assert fresh_world.wait_idle(15)
    seen = {r.username for r in fresh_world.http_upstream.records() if r.target == "origin-a.test:443"}
    assert seen == set(users)
    assert "origin-c.test:443" in [r.target for r in fresh_world.http_upstream_noauth.records()]
    events = _events(events_file)
    assert len([e for e in events if isinstance(e, LaunchEvent)]) == 1
    assert len([e for e in events if isinstance(e, AttachEvent)]) == 3
    assert {e.host for e in events if isinstance(e, RequestEvent)} == {"origin-a.test", "origin-c.test"}
    _assert_private(events_file, *users)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_async_api_browser(fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from playwright.async_api import async_playwright

    monkeypatch.setenv(ENV_PROXY_URL, fresh_world.http_upstream_noauth.server)

    async def main() -> None:
        async with async_playwright() as p:
            browser = await ssp.async_launch(p.chromium, args=fresh_world.chromium_args())
            try:
                context = await browser.new_context(**CONTEXT_KWARGS)
                page = await context.new_page()
                await page.goto("https://origin-a.test/", wait_until="load")
                await page.wait_for_function(PAGE_DONE_PREDICATE, timeout=30_000)
                await page.wait_for_timeout(300)
                await context.close()  # drains pending size lookups first
            finally:
                await browser.close()

    asyncio.run(main())
    reqs = _requests(events_file)
    frames = {e.frame for e in reqs}
    assert {"main", "sub", "worker", "service_worker"} <= frames
    docs = [e for e in reqs if e.is_navigation and e.frame == "main"]
    assert len(docs) == 1, docs
    doc = docs[0]
    assert doc.encoded_body_bytes and doc.status == 200, doc
    assert any(e.from_service_worker for e in reqs)
    images = [e for e in reqs if e.resource_type == "image" and e.host == "origin-a.test"]
    assert len(images) == 3 and all(e.encoded_body_bytes and e.encoded_body_bytes > 150_000 for e in images)
    _assert_private(events_file)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_full_chromium_preconnect_and_background_buckets(
    fresh_world, events_file: Path, tmp_path: Path
) -> None:
    """Full build + persistent context: idle preconnect, background hosts, never 'background' when uncatalogued."""
    reason = chromium_unavailable_reason(full_chromium=True)
    if reason is not None:
        pytest.skip(reason)
    from playwright.sync_api import sync_playwright

    started = time.time()
    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream_noauth.server, full_chromium=True)
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(str(tmp_path / "profile"), **kwargs, **CONTEXT_KWARGS)
        try:
            ssp.record_launch(p.chromium)
            ssp.instrument(context)
            page = context.pages[0] if context.pages else context.new_page()
            _load_shop(page)
            deadline = time.monotonic() + 10
            origin_c = fresh_world.origin("origin-c.test")
            while not origin_c.connections() and time.monotonic() < deadline:
                time.sleep(0.1)
        finally:
            context.close()
    assert fresh_world.wait_idle(15)
    events = _events(events_file)
    tunnels = _tunnels_from_upstream(fresh_world.http_upstream_noauth.records())
    snapshot = _snapshot(tunnels, started)
    result = attribute(snapshot, events, _fixture_catalogs())
    rows = {h.host: h for h in result.hosts}
    assert set(rows["origin-a.test"].buckets) == {"attributed"}
    assert set(rows["origin-b.test"].buckets) == {"attributed"}
    # The idle preconnect is never background and never attributed. Whether it is "preconnect_idle"
    # depends on its measured payload against config.PRECONNECT_IDLE_MAX_SENT/RECEIVED: Chromium's
    # post-quantum ClientHello puts it at roughly 2.0-2.1 KB up, right at the 2 KB limit.
    # Chromium does not preconnect on every run; check the bucket whenever it did.
    origin_c = [t for t in tunnels if t.host == "origin-c.test"]
    expected = {
        "preconnect_idle" if (t.payload_bytes_sent <= PRECONNECT_IDLE_MAX_SENT
                              and t.payload_bytes_received <= PRECONNECT_IDLE_MAX_RECEIVED) else "unattributed"
        for t in origin_c
    }
    if origin_c:
        assert set(rows["origin-c.test"].buckets) == expected
    catalogued = {"optimizationguide-pa.googleapis.com", "update.googleapis.com", "clients2.google.com",
                  "clients2.googleusercontent.com", "edgedl.me.gvt1.com", "safebrowsing.googleapis.com"}
    for host, row in rows.items():
        if host not in catalogued:
            assert not any(name.startswith("background:") for name in row.buckets), host
            assert row.background_id is None
    total = result.buckets
    assert (total.attributed + total.preconnect_idle + total.before_attach + total.unattributed
            + sum(total.background.values())) == snapshot.totals().with_connect
    _assert_private(events_file)


# ---------------------------------------------------------------------------- HTTP/2 sizes, cache heuristics,
# ---------------------------------------------------------------------------- unfinished requests, launches

# Header names Chromium puts in the raw (DevTools extra-info) request headers of an HTTP/2 request,
# and the provisional ones Playwright's request.headers holds. Values never matter here.
H2_RAW = {":authority": "a", ":method": "GET", ":path": "/", ":scheme": "https", "accept": "*/*",
          "accept-encoding": "gzip", "user-agent": "x", "referer": "r"}
H1_RAW = {"host": "a", "connection": "keep-alive", "accept": "*/*", "accept-encoding": "gzip", "user-agent": "x",
          "referer": "r"}
PROVISIONAL = {"accept": "*/*", "user-agent": "x", "referer": "r"}


class RoutedFrame:
    def __init__(self, routes: list[Any] | None = None) -> None:
        self.parent_frame = None
        self.page = type("P", (), {"_routes": routes if routes is not None else []})()


def _plain_context(events_file: Path, *, routes: list[Any] | None = None, options: dict[str, Any] | None = None):
    ctx = FakeContext()
    ctx._routes = routes if routes is not None else []  # type: ignore[attr-defined]
    ctx._options = options if options is not None else {}  # type: ignore[attr-defined]
    ssp.instrument(ctx)
    return ctx


def test_http2_header_sizes_are_unknown_and_the_body_keeps_the_header_frames(events_file: Path) -> None:
    # meas-3 / data-1: on h2 Playwright gives requestHeadersSize as rebuilt HTTP/1.1 text (684 B here)
    # and responseHeadersSize 0; the header frames are inside responseBodySize.
    ctx = _instrumented(events_file)
    h2 = FakeRequest("https://origin-a.test/", nav=True, headers=PROVISIONAL, all_headers=H2_RAW,
                     sizes={"requestBodySize": 0, "requestHeadersSize": 684, "responseBodySize": 2939,
                            "responseHeadersSize": 0})
    # With request interception the raw headers are the provisional ones; the zero header size still says h2.
    h2_routed = FakeRequest("https://origin-a.test/a.js", resource_type="script", headers=PROVISIONAL,
                            all_headers=PROVISIONAL,
                            sizes={"requestBodySize": 0, "requestHeadersSize": 560, "responseBodySize": 4089,
                                   "responseHeadersSize": 0})
    h1 = FakeRequest("https://origin-a.test/s.css", resource_type="stylesheet", headers=PROVISIONAL,
                     all_headers=H1_RAW,
                     sizes={"requestBodySize": 0, "requestHeadersSize": 480, "responseBodySize": 4089,
                            "responseHeadersSize": 190})
    for r in (h2, h2_routed, h1):
        ctx.fire("requestfinished", r)
    a, b, c = _requests(events_file)
    for e in (a, b):
        assert e.hit_network and e.encoded_body_bytes in (2939, 4089)
        assert e.request_header_bytes is None and e.response_header_bytes is None
    assert a.reported_bytes == 2939  # not 2939 + 684 of phantom header text
    assert (c.request_header_bytes, c.response_header_bytes, c.encoded_body_bytes) == (480, 190, 4089)


def test_proxy_hop_headers_are_left_out_of_plain_http_request_sizes(events_file: Path) -> None:
    # meas4-5: Proxy-Connection (and Proxy-Authorization) belong to the hop to the meter, which never
    # passes them on as sent; Playwright counts each raw header as len(name) + len(value) + 4.
    ctx = _instrumented(events_file)
    hop = {"proxy-connection": "keep-alive", "proxy-authorization": "Basic dXNlcjpwYXNz"}
    raw = {"host": "origin-a.test", "accept-encoding": "gzip", "accept": "*/*", **hop}
    sizes = {"requestBodySize": 0, "requestHeadersSize": 480, "responseBodySize": 1000, "responseHeadersSize": 190}
    plain = FakeRequest("http://origin-a.test/", nav=True, all_headers=raw, sizes=dict(sizes))
    tls = FakeRequest("https://origin-a.test/", nav=True, all_headers=raw, sizes=dict(sizes))
    direct = FakeRequest("http://origin-a.test/x", all_headers={"host": "origin-a.test", "accept": "*/*"},
                         sizes=dict(sizes))
    for r in (plain, tls, direct):
        ctx.fire("requestfinished", r)
    a, b, c = _requests(events_file)
    hop_bytes = sum(len(name) + len(value) + 4 for name, value in hop.items())
    assert a.request_header_bytes == 480 - hop_bytes
    assert b.request_header_bytes == 480  # inside a CONNECT tunnel such headers are the page's own
    assert c.request_header_bytes == 480  # no proxy hop (no proxy, or not a plain-http proxy request)
    assert "keep-alive" not in events_file.read_text() and "dXNlcjpwYXNz" not in events_file.read_text()


def test_h2_redirects_and_failures_after_headers_are_not_cache_hits(events_file: Path) -> None:
    # meas-4: Playwright forces the body size of a redirect to Content-Length (none: 0) and h2 header
    # size is 0, so the old "body + headers <= 0" test called real network responses cache hits.
    ctx = _instrumented(events_file)
    redirect = FakeRequest("https://origin-b.test/r", nav=True, response=FakeResponse(302), headers=PROVISIONAL,
                           all_headers=H2_RAW, sizes={"requestBodySize": 0, "requestHeadersSize": 600,
                                                      "responseBodySize": 0, "responseHeadersSize": 0})
    failed = FakeRequest("https://origin-a.test/b?i=1", method="POST", resource_type="fetch",
                         response=FakeResponse(200), headers=PROVISIONAL, all_headers=H2_RAW,
                         sizes={"requestBodySize": 1, "requestHeadersSize": 700, "responseBodySize": 0,
                                "responseHeadersSize": 0})
    aborted_h1 = FakeRequest("https://origin-a.test/big.bin", resource_type="fetch", headers=PROVISIONAL,
                             all_headers=H1_RAW, sizes={"requestBodySize": 0, "requestHeadersSize": 400,
                                                        "responseBodySize": 50_000_000, "responseHeadersSize": 120})
    ctx.fire("requestfinished", redirect)
    ctx.fire("requestfailed", failed)
    ctx.fire("requestfailed", aborted_h1)
    r, f, a = _requests(events_file)
    assert r.status == 302 and not r.from_cache and r.hit_network and r.host == "origin-b.test"
    assert f.failed and f.status == 200 and not f.from_cache and f.hit_network
    assert f.encoded_body_bytes is None and f.request_body_bytes == 1
    # A failed request's body size is Playwright's Content-Length fallback, not what was transferred.
    assert a.failed and a.encoded_body_bytes is None and a.response_header_bytes == 120
    result = attribute(_snapshot([], time.time()), _events(events_file), _fixture_catalogs())
    assert result.status_histogram == {"200": 2, "302": 1}


def test_disk_cache_hits_are_recognised_by_their_provisional_headers(events_file: Path) -> None:
    # meas-5: a disk-cache hit reports the full cached size (7619 + 181 computed header bytes) but
    # only the provisional request headers.
    ctx = _plain_context(events_file)
    sizes_cached = {"requestBodySize": 0, "requestHeadersSize": 334, "responseBodySize": 7619,
                    "responseHeadersSize": 181}

    def cached_image() -> FakeRequest:
        return FakeRequest("https://origin-a.test/img/12.jpg", resource_type="image", frame=RoutedFrame(),
                           headers=PROVISIONAL, all_headers=dict(PROVISIONAL), sizes=dict(sizes_cached))

    ctx.fire("requestfinished", cached_image())  # no wire headers seen yet in this context: held
    assert _requests(events_file) == []
    ctx.fire("requestfinished", FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(),
                                            headers=PROVISIONAL, all_headers=H2_RAW))
    ctx.fire("requestfinished", cached_image())  # recognised at once
    # meas2-3: the held event is written as a cache hit once the context shows wire headers.
    first, network, second = _requests(events_file)
    assert first.from_cache and not first.hit_network and first.reported_bytes == 0
    assert network.hit_network and network.is_navigation
    assert second.from_cache and not second.hit_network and second.reported_bytes == 0


def _warm_profile_image(addr: Any = _NO_ADDR, **kw: Any) -> FakeRequest:
    return FakeRequest("https://cdn.test/i.png", resource_type="image", frame=RoutedFrame(), headers=PROVISIONAL,
                       all_headers=dict(PROVISIONAL), response=FakeResponse(200, server_addr=addr),
                       sizes={"requestBodySize": 0, "requestHeadersSize": 191, "responseBodySize": 119_895,
                              "responseHeadersSize": 105}, **kw)


@pytest.mark.parametrize("browser,expect_cache", [("chromium", True), ("other", False)])
def test_held_candidates_are_decided_when_the_context_closes(events_file: Path, browser: str,
                                                             expect_cache: bool) -> None:
    """meas2-3: a reused persistent profile can serve a whole context from its disk cache.

    No request then shows wire headers. Chromium sends them on every network request outside
    interception, so the held events are cache hits; an unknown browser may never expose them.
    Firefox and WebKit are decided at once by their server address (meas3-2, tested below).
    """
    ctx = FakeContext()
    ctx._routes = []  # type: ignore[attr-defined]
    ctx._options = {}  # type: ignore[attr-defined]
    ctx.browser = FakeBrowser(FakeBrowserType(browser))  # type: ignore[attr-defined]
    ssp.instrument(ctx)
    ctx.fire("requestfinished", _warm_profile_image())
    assert _requests(events_file) == []
    ctx.fire("close", ctx)
    (event,) = _requests(events_file)
    assert event.from_cache is expect_cache and event.hit_network is not expect_cache
    ctx.fire("requestfinished", _warm_profile_image())  # a late event after close is decided the same way
    assert _requests(events_file)[-1].from_cache is expect_cache


def test_a_cache_entry_from_an_earlier_meter_is_a_cache_hit_at_once(events_file: Path,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """meas2-3: a disk-cache entry keeps the server address it was fetched from (an earlier run's meter)."""
    monkeypatch.setenv(ENV_PROXY_URL, METER)
    ctx = _plain_context(events_file)
    earlier = _warm_profile_image({"ipAddress": "127.0.0.1", "port": 55730})
    ctx.fire("requestfinished", earlier)
    (event,) = _requests(events_file)
    assert event.from_cache and event.reported_bytes == 0
    assert earlier.existing_response.addr_calls == 1
    # The current meter's own address is no evidence: the event waits for wire headers.
    ctx.fire("requestfinished", _warm_profile_image({"ipAddress": "127.0.0.1", "port": 40001}))
    assert len(_requests(events_file)) == 1
    ctx.fire("requestfinished", FakeRequest("https://www.test/", nav=True, frame=RoutedFrame(),
                                            headers=PROVISIONAL, all_headers=H1_RAW))
    events = _requests(events_file)
    assert [e.from_cache for e in events] == [True, True, False]
    # Once wire headers were seen no server address is asked for.
    later = _warm_profile_image({"ipAddress": "127.0.0.1", "port": 40001})
    ctx.fire("requestfinished", later)
    assert _requests(events_file)[-1].from_cache and later.existing_response.addr_calls == 0


def test_service_worker_scripts_are_never_cache_hits(events_file: Path) -> None:
    """meas2-11: /sw.js comes from the network with only its provisional headers and body size 0."""
    ctx = _plain_context(events_file)
    ctx.fire("requestfinished", FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(),
                                            headers=PROVISIONAL, all_headers=H1_RAW))
    sw_headers = {"accept": "*/*", "service-worker": "script"}
    sw_script = FakeRequest("https://origin-a.test/sw.js", resource_type="script", service_worker=object(),
                            headers=sw_headers, all_headers=dict(sw_headers),
                            sizes={"requestBodySize": 0, "requestHeadersSize": 58, "responseBodySize": 0,
                                   "responseHeadersSize": 226})
    ctx.fire("requestfinished", sw_script)
    _, event = _requests(events_file)
    assert event.hit_network and not event.from_cache and event.frame == "service_worker"
    assert event.response_header_bytes == 226 and event.encoded_body_bytes == 0


_METER_ADDR = {"ipAddress": "127.0.0.1", "port": 40001}
#: What Chromium 153 reported for the warm-profile race (meas3-1): the network answered, sizes as for a
#: memory-cache hit (encodedDataLength 0, so body == -headers), response.from_service_worker True.
_RACE_SIZES = {"requestBodySize": 0, "requestHeadersSize": 647, "responseBodySize": -318, "responseHeadersSize": 318}


def test_a_navigation_the_network_answered_while_the_worker_started_is_a_network_request(events_file: Path) -> None:
    """meas3-1: Chromium flags a network navigation from_service_worker when a registered worker was not
    running (warm persistent profile). It carries wire headers and a server address; a response the
    worker built or fetched for the page carries neither (checked: plain and pass-through workers)."""
    ctx = _plain_context(events_file)
    raced = FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(), headers=PROVISIONAL,
                        all_headers=H1_RAW, response=FakeResponse(200, from_sw=True, server_addr=_METER_ADDR),
                        sizes=dict(_RACE_SIZES))
    answered = FakeRequest("https://origin-a.test/api/sw.json", resource_type="fetch", frame=RoutedFrame(),
                           headers=PROVISIONAL, all_headers=dict(PROVISIONAL),
                           response=FakeResponse(200, from_sw=True, server_addr=None),
                           sizes={"requestBodySize": 0, "requestHeadersSize": 302, "responseBodySize": -49,
                                  "responseHeadersSize": 49})
    ctx.fire("requestfinished", raced)
    ctx.fire("requestfinished", answered)
    network, by_worker = _requests(events_file)
    assert network.hit_network and not network.from_service_worker and not network.from_cache
    assert network.encoded_body_bytes is None  # unknown, not 0
    assert (network.request_header_bytes, network.response_header_bytes) == (647, 318)
    assert by_worker.from_service_worker and not by_worker.hit_network and by_worker.reported_bytes == 0
    # The worker-built answer needs no server-address round trip: its missing wire headers decide.
    assert answered.existing_response.addr_calls == 0 and raced.existing_response.addr_calls == 0
    result = attribute(_snapshot([], time.time()), _events(events_file), _fixture_catalogs())
    assert result.status_histogram == {"200": 1} and result.units.count == 1


def test_under_interception_the_server_address_tells_a_worker_fallback_from_a_worker_answer(
    events_file: Path,
) -> None:
    # Routes and credentials hide the wire headers; a response the worker answered has no server address.
    ctx = _plain_context(events_file, routes=[object()])
    raced = FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(), headers=PROVISIONAL,
                        all_headers=dict(PROVISIONAL), response=FakeResponse(200, from_sw=True, server_addr=_METER_ADDR),
                        sizes=dict(_RACE_SIZES))
    answered = FakeRequest("https://origin-a.test/api/sw.json", resource_type="fetch", frame=RoutedFrame(),
                           headers=PROVISIONAL, all_headers=dict(PROVISIONAL),
                           response=FakeResponse(200, from_sw=True, server_addr=None))
    ctx.fire("requestfinished", raced)
    ctx.fire("requestfinished", answered)
    network, by_worker = _requests(events_file)
    assert network.hit_network and network.encoded_body_bytes is None and network.response_header_bytes == 318
    assert by_worker.from_service_worker and not by_worker.hit_network


def test_without_interception_or_wire_headers_a_worker_response_stays_a_worker_answer(events_file: Path) -> None:
    # Outside interception every network request shows wire headers; a server address alone can be an
    # HTTP-cache entry's, so it is not taken as network evidence (no round trip is made for it).
    ctx = _plain_context(events_file)
    cached_fallback = FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(), headers=PROVISIONAL,
                                  all_headers=dict(PROVISIONAL),
                                  response=FakeResponse(200, from_sw=True, server_addr=_METER_ADDR),
                                  sizes=dict(_RACE_SIZES))
    ctx.fire("requestfinished", cached_fallback)
    (event,) = _requests(events_file)
    assert event.from_service_worker and not event.hit_network and event.reported_bytes == 0
    assert cached_fallback.existing_response.addr_calls == 0


def _non_cdp_context(browser: str) -> FakeContext:
    ctx = FakeContext()
    ctx._routes = []  # type: ignore[attr-defined]
    ctx._options = {}  # type: ignore[attr-defined]
    ctx.browser = FakeBrowser(FakeBrowserType(browser))  # type: ignore[attr-defined]
    ssp.instrument(ctx)
    return ctx


@pytest.mark.parametrize("browser", ["firefox", "webkit"])
def test_firefox_and_webkit_cache_hits_are_recognised_by_their_missing_server_address(
    events_file: Path, browser: str
) -> None:
    """meas3-2: Firefox and WebKit report an HTTP-cache hit with its full size; before, every one was
    written as a network request (font.woff2 counted 3 times, reported bytes above the tunnel bytes)."""
    ctx = _non_cdp_context(browser)
    sizes = {"requestBodySize": 0, "requestHeadersSize": 434, "responseBodySize": 49152, "responseHeadersSize": 221}
    fetched = FakeRequest("https://origin-a.test/static/font.woff2", resource_type="font", frame=RoutedFrame(),
                          headers=PROVISIONAL, all_headers=dict(PROVISIONAL),
                          response=FakeResponse(200, server_addr=_METER_ADDR), sizes=dict(sizes))
    cached = FakeRequest("https://origin-a.test/static/font.woff2", resource_type="font", frame=RoutedFrame(),
                         headers=PROVISIONAL, all_headers=dict(PROVISIONAL),
                         response=FakeResponse(200, server_addr=None), sizes=dict(sizes))
    redirect = FakeRequest("https://origin-a.test/r", nav=True, frame=RoutedFrame(), headers=PROVISIONAL,
                           all_headers=dict(PROVISIONAL), response=FakeResponse(302, server_addr=None))
    for r in (fetched, cached, redirect):
        ctx.fire("requestfinished", r)
    # Written at once (Firefox shows no wire-level headers, so nothing may wait for them).
    network, hit, hop = _requests(events_file)
    assert network.hit_network and network.encoded_body_bytes == 49152
    assert hit.from_cache and not hit.hit_network and hit.reported_bytes == 0
    assert hop.hit_network and hop.status == 302 and redirect.existing_response.addr_calls == 0
    ctx.fire("close", ctx)
    assert len(_requests(events_file)) == 3


def _routed(request: Any, outcome: str) -> Any:
    setattr(request, ssp._ROUTE_ATTR, outcome)  # what the Route.fulfill/abort wrappers do
    return request


def test_requests_that_never_reached_the_network_are_marked(events_file: Path) -> None:
    """meas2-1: route.fulfill/abort and browser blocks are not network requests."""
    ctx = _plain_context(events_file, routes=[object()])
    fulfilled = _routed(FakeRequest("https://stub.invalid/a.js", resource_type="script"), "fulfilled")
    aborted = _routed(FakeRequest("https://origin-a.test/img/1.png", resource_type="image", response=None,
                                  failure="net::ERR_FAILED"), "aborted")
    mixed = FakeRequest("http://ajax.googleapis.com/jquery.js", resource_type="script", response=None,
                        failure="mixed-content")
    cdp_block = FakeRequest("https://origin-a.test/font.woff2", resource_type="font", response=None,
                            failure="inspector")
    extension = FakeRequest("https://ads.test/x.js", resource_type="script", response=None,
                            failure="net::ERR_BLOCKED_BY_CLIENT")
    network_failure = FakeRequest("https://origin-a.test/api", resource_type="fetch", response=None,
                                  failure="net::ERR_CONNECTION_RESET")
    ctx.fire("requestfinished", fulfilled)
    for r in (aborted, mixed, cdp_block, extension, network_failure):
        ctx.fire("requestfailed", r)
    lines = [json.loads(line) for line in events_file.read_text().splitlines()]
    requests = [line for line in lines if line["kind"] == "request"]
    assert [r.get("no_network") for r in requests] == ["fulfilled", "aborted", "blocked", "blocked", "blocked", None]
    events = _requests(events_file)
    assert all(not e.hit_network and e.reported_bytes == 0 for e in events[:5])
    assert events[0].status == 200 and not events[0].failed and events[1].failed
    assert events[5].hit_network and events[5].failed
    result = attribute(_snapshot([], time.time()), _events(events_file), _fixture_catalogs())
    assert result.status_histogram == {"failed": 1}
    assert result.bypass.incomplete is False and result.bypass.requests == 0
    assert any("never reached the network" in w for w in result.warnings)


def test_fulfilled_responses_are_recognised_by_their_missing_server_address_without_the_route_wrappers(
    events_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # As when Playwright's Route class could not be wrapped: nothing tags the requests.
    monkeypatch.setattr(ssp, "_tag_routes", lambda: None)
    monkeypatch.setattr(ssp, "_routes_tagged", False)
    ctx = _plain_context(events_file, routes=[object()])
    stub = FakeRequest("https://stub.invalid/a.js", resource_type="script", response=FakeResponse(200, server_addr=None))
    real = FakeRequest("https://origin-a.test/a.js", resource_type="script",
                       response=FakeResponse(200, server_addr={"ipAddress": "127.0.0.1", "port": 40001}))
    ctx.fire("requestfinished", stub)
    ctx.fire("requestfinished", real)
    a, b = _requests(events_file)
    assert not a.hit_network and b.hit_network and b.encoded_body_bytes == 1000


def test_route_wrappers_tag_the_request_and_keep_the_original_behaviour() -> None:
    # pkg-r3-1: Playwright is an optional extra; the suite's non-browser part runs without it.
    Route = pytest.importorskip("playwright._impl._network").Route

    ssp._tag_routes()
    assert getattr(Route.fulfill, ssp._ROUTE_ATTR) == "fulfilled" and getattr(Route.abort, ssp._ROUTE_ATTR) == "aborted"
    ssp._tag_routes()  # idempotent: not wrapped twice
    assert getattr(Route.fulfill.__wrapped__, ssp._ROUTE_ATTR, None) is None

    class R:
        request = type("Q", (), {})()

    calls = []

    async def original(self: Any, *args: Any, **kwargs: Any) -> str:
        calls.append((args, kwargs))
        return "done"

    route = R()
    assert asyncio.run(ssp._route_wrapper(original, "aborted")(route, "failed", x=1)) == "done"
    assert calls == [(("failed",), {"x": 1})] and ssp._route_outcome(route.request) == "aborted"


@pytest.mark.parametrize(
    "setup",
    ["context-route", "page-route", "http-credentials", "proxy-credentials", "raw-headers-failed", "unknown-page"],
)
def test_disk_cache_heuristic_is_off_when_interception_hides_the_wire_headers(events_file: Path, setup: str) -> None:
    # Routes and credentials make Playwright intercept requests (and disable the cache); every network
    # request then carries only the provisional headers, so it must never be called a cache hit.
    ctx = _plain_context(
        events_file,
        routes=[object()] if setup == "context-route" else [],
        options={"httpCredentials": {"username": "u", "password": "p"}} if setup == "http-credentials"
        else {"proxy": {"server": "x", "username": "u"}} if setup == "proxy-credentials" else {},
    )
    frame: Any = RoutedFrame([object()] if setup == "page-route" else [])
    if setup == "unknown-page":
        frame = MAIN  # no page information: counts as intercepting
    ctx.fire("requestfinished", FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(),
                                            headers=PROVISIONAL, all_headers=H1_RAW))
    later = FakeRequest("https://origin-a.test/img/1.jpg", resource_type="image", frame=frame,
                        headers=PROVISIONAL,
                        all_headers=RuntimeError("closed") if setup == "raw-headers-failed" else dict(PROVISIONAL),
                        sizes={"requestBodySize": 0, "requestHeadersSize": 334, "responseBodySize": 7619,
                               "responseHeadersSize": 181})
    if setup == "raw-headers-failed":
        later.all_headers = lambda: (_ for _ in ()).throw(RuntimeError("closed"))  # type: ignore[method-assign]
    ctx.fire("requestfinished", later)
    _, event = _requests(events_file)
    assert event.hit_network and not event.from_cache and event.encoded_body_bytes == 7619


def test_unfinished_requests_are_written_as_failed_when_the_context_closes(events_file: Path) -> None:
    # meas-1: Playwright never reports a request that was in flight when its page navigated away.
    ctx = _instrumented(events_file)
    page = FakePage(ctx)
    ctx.fire("page", page)
    done = FakeRequest("https://origin-a.test/", nav=True)
    aborted = FakeRequest("https://origin-a.test/big.bin?size=50000000", resource_type="fetch",
                          response=FakeResponse(200), sizes=RuntimeError("target closed"))
    never_answered = FakeRequest("https://origin-b.test/slow", resource_type="xhr", response=None)
    for r in (done, aborted, never_answered):
        ctx.fire("request", r)
    ctx.fire("requestfinished", done)
    ws = FakeWebSocket("wss://stream.test/feed")
    page.fire("websocket", ws)
    ws.fire("framereceived", b"\x00" * 70)
    assert len(_requests(events_file)) == 1
    ctx.fire("close", ctx)
    ctx.fire("close", ctx)  # idempotent
    ctx.fire("requestfailed", aborted)  # a late event for a request already written is ignored
    events = _requests(events_file)
    by_host = {(e.host, e.resource_type): e for e in events}
    big = by_host[("origin-a.test", "fetch")]
    assert big.failed and big.status == 200 and big.encoded_body_bytes is None and big.reported_bytes == 0
    slow = by_host[("origin-b.test", "xhr")]
    assert slow.failed and slow.status is None
    stream = by_host[("stream.test", "websocket")]
    assert stream.encoded_body_bytes == 70 and not stream.failed
    assert len([e for e in events if e.resource_type == "fetch"]) == 1
    assert "size=" not in events_file.read_text()


def test_instrument_records_the_context_browser_once(events_file: Path) -> None:
    # meas-6 / data-6: proxy_settings() + instrument(context) used to report 0 browser launches.
    browser = FakeBrowser()
    for _ in range(2):
        ctx = FakeContext()
        ctx.browser = browser  # type: ignore[attr-defined]
        ssp.instrument(ctx)
    persistent = FakeContext()
    persistent.browser = None  # type: ignore[attr-defined]
    ssp.instrument(persistent)
    launches = [e for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert [e.browser for e in launches] == ["chromium"]
    ssp.record_launch(browser)  # already recorded by instrument()
    assert len([e for e in _events(events_file) if isinstance(e, LaunchEvent)]) == 1


@pytest.mark.parametrize("order", ["record_first", "instrument_first"])
def test_a_persistent_context_with_a_browser_counts_one_launch_in_either_order(events_file: Path, order: str) -> None:
    """meas4-2: Playwright 1.63 gives a persistent context a Browser (``context.browser``).
    ``record_launch(context)`` (the documented call) and ``instrument(context)`` (which records
    ``context.browser``) used to write two launch events for that one browser."""
    context = FakeContext()
    context.browser = FakeBrowser()  # type: ignore[attr-defined]
    calls = [ssp.record_launch, ssp.instrument]
    for call in calls if order == "record_first" else calls[::-1]:
        call(context)
    ssp.record_launch(context.browser)  # type: ignore[attr-defined]
    ssp.record_launch(context)
    launches = [e for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert [e.browser for e in launches] == ["chromium"]
    # A second persistent context (a second browser) is a second launch.
    other = FakeContext()
    other.browser = FakeBrowser(FakeBrowserType("webkit"))  # type: ignore[attr-defined]
    ssp.record_launch(other)
    ssp.instrument(other)
    launches = [e for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert [e.browser for e in launches] == ["chromium", "webkit"]


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_the_generated_persistent_profile_fix_records_one_launch(
    events_file: Path, tmp_path: Path, closed_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """meas4-2 with real Chromium: the chromium-background-flags fix calls record_launch(context) and
    then instrument(context) on a persistent context; the events file must hold one launch."""
    import types as pytypes

    from playwright.sync_api import sync_playwright

    from scrapescope.snippets import templates

    fix = pytypes.ModuleType("scrapescope_fix_under_test")
    code = templates.CHROMIUM_BACKGROUND_FLAGS.replace("{hosts}", "optimizationguide-pa.googleapis.com")
    exec(compile(code, "<fix>", "exec"), fix.__dict__)  # __name__ != "__main__": nothing launches
    fix.USER_DATA_DIR = str(tmp_path / "profile")
    # The "meter" is a dead loopback port: whatever the browser tries to fetch fails locally.
    monkeypatch.setenv(ENV_PROXY_URL, f"http://127.0.0.1:{closed_port}")
    with sync_playwright() as p:
        context = fix.launch_context(p)  # proxy=proxy_settings(), as under scrapescope run
        context.close()  # Playwright 1.63 gives this persistent context a Browser (context.browser)
    kinds = [e.kind for e in _events(events_file) if isinstance(e, (AttachEvent, LaunchEvent))]
    assert sorted(kinds) == ["attach", "launch"], kinds


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_fetch_aborted_by_navigation_is_written_at_close_and_its_bytes_stay_unreported(
    fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """meas-1 end to end: Playwright never reports a fetch the next navigation aborted.

    Before the fix the events file had no event for it, and attribution scaled the host's images
    up to the tunnel total (images "allocated" about 4 MB against 0.6 MB reported).
    """
    from playwright.sync_api import sync_playwright

    from scrapescope.attribution.core import (
        OVERHEAD_PER_TUNNEL_BYTES,
        OVERHEAD_SHARE,
        UNKNOWN_HEADERS_BYTES,
        UNREPORTED_TYPE,
    )
    from scrapescope.model import compute_what_if

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    started = time.time()
    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream_noauth.server)
    # The origin sends exactly this much of a 50 MB body and then stalls until the client goes away, and
    # the page counts what arrived, so the navigation aborts a transfer of a known size on every machine
    # instead of whatever a fixed sleep let through (608 kB on a slow runner, 5 MB on a fast one).
    stall_after = 2_000_000
    with sync_playwright() as p:
        browser = p.chromium.launch(**kwargs)
        try:
            context = ssp.instrument(browser.new_context(**CONTEXT_KWARGS))
            page = context.new_page()
            _load_shop(page)
            page.evaluate(_COUNTING_FETCH_JS % f"/big.bin?size=50000000&stall_after={stall_after}")
            page.wait_for_function(f"window.__received >= {stall_after}", timeout=60_000)
            _load_shop(page, "/product/2")
            context.close()
        finally:
            browser.close()
    assert fresh_world.wait_idle(15)
    events = _events(events_file)
    requests = [e for e in events if isinstance(e, RequestEvent)]
    (big,) = _by_path(requests, "origin-a.test", "/big.bin")
    assert big.failed and big.encoded_body_bytes is None and big.reported_bytes == 0
    snapshot = _snapshot(_tunnels_from_upstream(fresh_world.http_upstream_noauth.records()), started)
    result = attribute(snapshot, events, _fixture_catalogs())
    row = next(h for h in result.hosts if h.host == "origin-a.test")
    host_requests = [e for e in requests if e.host == "origin-a.test" and e.hit_network]
    reported = sum(e.reported_bytes for e in host_requests)
    # The host's tunnels carried the whole aborted transfer beyond every reported byte...
    assert row.bytes_with_connect - reported >= stall_after
    # ...and attribution shows it as unreported (less at most the overhead allowance it grants the reported
    # requests, bounded here with every host tunnel and request counted) rather than scaling up the images.
    host_tunnels = [t for t in snapshot.tunnels if t.host == "origin-a.test"]
    allowance = (OVERHEAD_PER_TUNNEL_BYTES * len(host_tunnels) + UNKNOWN_HEADERS_BYTES * len(host_requests)
                 + int(reported * OVERHEAD_SHARE))
    assert row.allocated_by_type[UNREPORTED_TYPE] >= stall_after - allowance > 1_000_000
    image = next(t for t in result.types if t.type == "image")
    assert image.allocated_bytes < 1.3 * image.reported_bytes + 200_000
    (block,) = [w for w in compute_what_if(result, snapshot.totals(), _fixture_catalogs())
                if w.id == "block-images-media-fonts"]
    assert block.share < 0.5
    assert any("unreported" in w for w in result.warnings)
    _assert_private(events_file, "size=", "stall_after=")


def test_unfinished_requests_of_a_context_never_closed_are_written_at_exit(events_file: Path) -> None:
    ctx = _instrumented(events_file)
    pending = FakeRequest("https://origin-a.test/big.bin?size=9", resource_type="fetch", response=FakeResponse(200))
    ctx.fire("request", pending)
    assert _requests(events_file) == []
    ssp._flush_open_contexts()  # what the atexit hook runs
    (event,) = _requests(events_file)
    assert event.failed and event.status == 200 and event.encoded_body_bytes is None
    ssp._flush_open_contexts()
    ctx.fire("close", ctx)
    assert len(_requests(events_file)) == 1


def test_navigation_response_gives_wire_evidence_before_cached_subresources_finish(events_file: Path) -> None:
    # A large document can finish after its cached images; its response (headers) comes first.
    ctx = _plain_context(events_file)
    doc = FakeRequest("https://origin-a.test/", nav=True, frame=RoutedFrame(), headers=PROVISIONAL, all_headers=H2_RAW)
    response = FakeResponse(200)
    response.request = doc  # type: ignore[attr-defined]
    ctx.fire("response", response)
    cached = FakeRequest("https://origin-a.test/img/1.png", resource_type="image", frame=RoutedFrame(),
                         headers=PROVISIONAL, all_headers=dict(PROVISIONAL),
                         sizes={"requestBodySize": 0, "requestHeadersSize": 334, "responseBodySize": 7619,
                                "responseHeadersSize": 181})
    ctx.fire("requestfinished", cached)
    ctx.fire("requestfinished", doc)
    image, document = _requests(events_file)
    assert image.from_cache and document.hit_network


# ---------------------------------------------------------------------------- round 2, real browser:
# ---------------------------------------------------------------------------- interception and warm profiles


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_fulfilled_aborted_and_blocked_requests_are_not_network_requests_in_chromium(
    fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """meas2-1 end to end: a route.fulfill stub for a host no tunnel carries, a fulfilled font and an
    aborted image on a metered host, and a mixed-content script Chromium blocks before sending."""
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    started = time.time()
    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream_noauth.server)
    stub_headers = {"access-control-allow-origin": "*"}
    with sync_playwright() as p:
        browser = p.chromium.launch(**kwargs)
        try:
            context = ssp.instrument(browser.new_context(**CONTEXT_KWARGS))
            context.route("https://stub.invalid/**", lambda route: route.fulfill(
                status=200, content_type="application/javascript", headers=stub_headers, body="/* stub */"))
            context.route(f"**{site.FONT_PATH}", lambda route: route.fulfill(
                status=200, content_type="font/woff2", body=b"\0" * 64))
            context.route("**/static/img/hero-1.png", lambda route: route.abort())
            page = context.new_page()
            _load_shop(page)
            page.evaluate("() => fetch('https://stub.invalid/a.js').then(r => r.text()).catch(() => '')")
            page.evaluate("""() => new Promise(done => {
                const s = document.createElement('script');
                s.src = 'http://origin-b.test/mixed.js';
                s.onload = s.onerror = () => done();
                document.head.appendChild(s);
            })""")
            # Let every real request the page started finish before the context closes; a request
            # still in flight at close is recorded as failed, which on a slow machine would put a
            # spurious "failed" into the status histogram.
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(300)
            context.close()
        finally:
            browser.close()
    assert fresh_world.wait_idle(15)

    lines = [json.loads(line) for line in events_file.read_text().splitlines()]
    marker = {(line["host"], line.get("path")): line.get("no_network") for line in lines if line["kind"] == "request"}
    assert marker[("stub.invalid", "/a.js")] == "fulfilled"
    assert marker[("origin-a.test", site.FONT_PATH)] == "fulfilled"
    assert marker[("origin-a.test", "/static/img/hero-1.png")] == "aborted"
    assert marker[("origin-b.test", "/mixed.js")] == "blocked"
    assert marker[("origin-a.test", "/")] is None and marker[("origin-a.test", "/static/img/hero-2.png")] is None
    _assert_private(events_file)

    events = _events(events_file)
    tunnels = _tunnels_from_upstream(fresh_world.http_upstream_noauth.records())
    assert "stub.invalid" not in {t.host for t in tunnels}
    result = attribute(_snapshot(tunnels, started), events, _fixture_catalogs())
    assert result.bypass.incomplete is False, result.warnings
    failed_events = [
        {k: v for k, v in e.to_dict().items() if k in ("host", "path", "resource_type", "status", "failed", "failure", "frame", "from_service_worker", "no_network")}
        for e in events if isinstance(e, RequestEvent) and e.failed
    ]
    assert "failed" not in result.status_histogram, failed_events
    types = {t.type: t for t in result.types}
    assert "font" not in types  # the fulfilled font takes no share of origin-a.test's tunnel bytes
    network_images = [e for e in events if isinstance(e, RequestEvent) and e.resource_type == "image" and e.hit_network]
    assert types["image"].requests == len(network_images) and "/static/img/hero-1.png" not in {
        e.path for e in network_images}
    assert any(w.startswith("4 request events never reached the network") for w in result.warnings), result.warnings


@pytest.mark.browser
@pytest.mark.timeout(180)
def test_a_warm_profile_with_a_service_worker_keeps_its_network_navigations(
    fresh_world, events_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """meas3-1 end to end: the second run of a persistent profile starts with the fixture's service
    worker registered but not running. Chromium sent the first navigation to the network and still
    reported it from_service_worker; the helper wrote it as a zero-size worker answer, so the
    document dropped out of the network requests. Every document the origin served must appear as
    a network request, and the worker's own answers (/api/sw.json) must not."""
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream_noauth.server)
    profile = str(tmp_path / "profile")
    origin = fresh_world.origin("origin-a.test")
    documents = ("/", "/product/2")

    def run() -> tuple[list[RequestEvent], dict[str, int]]:
        events_file.write_text("")
        ev._reset_for_tests()
        before = len(origin.requests())
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, **kwargs, **CONTEXT_KWARGS)
            try:
                ssp.record_launch(context)
                ssp.instrument(context)
                page = context.pages[0] if context.pages else context.new_page()
                for path in documents:
                    _load_shop(page, path)
            finally:
                context.close()
        assert fresh_world.wait_idle(15)
        served = [r.path for r in origin.requests()[before:]]
        return _requests(events_file), {path: served.count(path) for path in documents}

    for _ in range(2):
        events, served = run()
        for path in documents:
            network = [e for e in _by_path(events, "origin-a.test", path) if e.hit_network]
            assert len(network) == served[path], (path, served, _by_path(events, "origin-a.test", path))
        answered = _by_path(events, "origin-a.test", "/api/sw.json")
        assert answered and all(e.from_service_worker and not e.hit_network for e in answered)
    result = attribute(_snapshot([], time.time()), _events(events_file), _fixture_catalogs())
    assert result.units.count == len(documents)
    _assert_private(events_file)


@pytest.mark.browser
@pytest.mark.timeout(180)
@pytest.mark.parametrize("name", ["firefox", "webkit"])
def test_firefox_and_webkit_cache_hits_match_what_the_origin_served(
    fresh_world, events_file: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """meas3-2 end to end: before, every Firefox/WebKit cache hit was a network request (font.woff2
    served once, counted 3 times; 3.8 MB reported for 1.39 MB carried). The static assets' network
    events must match what the origin served."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    static = ("/static/style.css", "/static/app.js", site.FONT_PATH, *site.IMAGES)
    origin = fresh_world.origin("origin-a.test")
    with sync_playwright() as p:
        try:
            browser = getattr(p, name).launch(proxy={"server": fresh_world.http_upstream_noauth.server})
        except PlaywrightError as exc:
            pytest.skip(f"{name} is not available here: {str(exc).splitlines()[0]}")
        try:
            ssp.wrap_new_context(browser)
            context = browser.new_context(**CONTEXT_KWARGS)
            page = context.new_page()
            for path in ("/", "/product/2", "/"):
                page.goto(f"https://origin-a.test{path}", wait_until="load")
                page.wait_for_timeout(1500)
            context.close()
        finally:
            browser.close()
    assert fresh_world.wait_idle(15)
    served = [r.path for r in origin.requests()]
    events = _requests(events_file)
    assert any(e.from_cache for e in events), "no cache hit recognised"
    for path in static:
        network = [e for e in _by_path(events, "origin-a.test", path) if e.hit_network]
        assert len(network) == served.count(path), (path, served.count(path), _by_path(events, "origin-a.test", path))
    launches = [e for e in _events(events_file) if isinstance(e, LaunchEvent)]
    assert [e.browser for e in launches] == [name]
    result = attribute(_snapshot(_tunnels_from_upstream(fresh_world.http_upstream_noauth.records()), time.time() - 60),
                       _events(events_file), _fixture_catalogs())
    assert result.bypass.incomplete is False
    assert any(w.startswith("per-type figures for") for w in result.warnings)


class _CachingOriginProxy:
    """A loopback plain-HTTP proxy that answers www.test and cdn.test itself, cacheable for an hour.

    Chromium sends every request to it (absolute-form for http://, CONNECT for https://, which is
    refused), so nothing leaves this machine. ``served`` lists the requests it answered.
    """

    def __init__(self) -> None:
        import http.server
        import threading
        import urllib.parse

        html = (b"<!doctype html><html><head><title>warm</title></head><body><h1>cached</h1>"
                b"<img src='http://cdn.test/i.png'></body></html>")
        png = site.image(site.EMBED_IMAGE)
        served: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 (http.server API)
                url = urllib.parse.urlsplit(self.path)
                body, kind = {("www.test", "/"): (html, "text/html"), ("cdn.test", "/i.png"): (png, "image/png")}.get(
                    (url.hostname or "", url.path), (b"", ""))
                served.append(f"{url.hostname}{url.path}")
                self.send_response(200 if body else 404)
                if body:
                    self.send_header("Content-Type", kind)
                    self.send_header("Cache-Control", "public, max-age=3600")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_CONNECT(self) -> None:  # noqa: N802
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True

            def log_message(self, *args: Any) -> None:
                pass

        self.served = served
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_a_persistent_profile_run_twice_writes_its_warm_cache_hits_as_cache_hits(
    events_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """meas2-3: a reused persistent profile serves the second run from its disk cache, so no
    response of that context ever shows wire-level request headers.

    The reviewer's Chromium reported one such disk-cache hit with its full size and only the
    provisional headers; it was written as a network request, and its host, which no tunnel
    carried, made the run "incomplete". The Chromium here reports these hits with the negative
    body size of a memory-cache hit, so this end-to-end run checks the outcome (cache hits, no
    status line, no bypass); the full-size signature, which is held until wire headers appear or
    the context closes, is covered with the recorded sizes by
    ``test_held_candidates_are_decided_when_the_context_closes``.
    """
    from playwright.sync_api import sync_playwright

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    origin = _CachingOriginProxy()
    profile = tmp_path / "profile"

    def run() -> list[RequestEvent]:
        events_file.write_text("")
        ev._reset_for_tests()
        origin.served.clear()
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(str(profile), proxy={"server": origin.url})
            try:
                ssp.record_launch(context)
                ssp.instrument(context)
                page = context.pages[0] if context.pages else context.new_page()
                page.goto("http://www.test/", wait_until="load")
                page.wait_for_timeout(300)
            finally:
                context.close()
        return _requests(events_file)

    try:
        first = run()
        assert origin.served == ["www.test/", "cdn.test/i.png"]
        # Events are written in completion order, and the image can finish before the document
        # on a slow machine, so compare per host rather than by position.
        assert {(e.host, e.from_cache) for e in first} == {("www.test", False), ("cdn.test", False)}
        assert len(first) == 2
        assert next(e for e in first if e.host == "cdn.test").encoded_body_bytes == len(site.image(site.EMBED_IMAGE))
        second = run()
    finally:
        origin.close()
    if origin.served:
        pytest.skip(f"Chromium did not serve run 2 from its disk cache here ({origin.served})")
    assert {e.host for e in second} == {"www.test", "cdn.test"}
    assert all(e.from_cache and not e.hit_network and e.reported_bytes == 0 for e in second), second
    result = attribute(_snapshot([], time.time()), _events(events_file), _fixture_catalogs())
    assert result.bypass.incomplete is False and result.status_histogram == {}


def _origin_head_size(record: Any) -> int:
    """Bytes of the request head the fixture origin received (request line, headers, blank line)."""
    target = record.path + (f"?{record.query}" if record.query else "")
    line = f"{record.method} {target} HTTP/1.1\r\n"
    return len(line) + sum(len(name) + 2 + len(value) + 2 for name, value in record.headers) + 2


@pytest.mark.browser
@pytest.mark.timeout(120)
@pytest.mark.parametrize("route", ["socks5", "direct"])
def test_plain_http_request_headers_leave_out_the_proxy_hop(
    fresh_world, events_file: Path, hosts_map: Any, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """meas4-5: for a plain http:// request Chromium sends the meter ``Proxy-Connection: keep-alive``,
    which DevTools counts in ``requestHeadersSize``; the meter never passes it on (socks5 and direct
    routes send the origin its own request, the http-connect route strips the header). Reported sizes
    then exceeded what the tunnels carried. The helper now leaves that proxy-hop header out, so each
    reported request head is at most what the origin received and the host reports no more than
    its tunnels carried."""
    from playwright.sync_api import sync_playwright

    from tests.test_forwarder_helpers import make_config, running, settle

    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    if route == "socks5":
        config, connect_map = make_config(fresh_world.socks_upstream_noauth.url), None
    else:
        config, connect_map = make_config(None), dict(hosts_map)
    origin = fresh_world.origin("origin-a.test", "http")
    with running(config, connect_map=connect_map) as fw:
        with sync_playwright() as p:
            browser = p.chromium.launch(**chromium_launch_kwargs(fresh_world, server=fw.url))
            try:
                ssp.record_launch(browser)
                context = ssp.instrument(browser.new_context(**CONTEXT_KWARGS))
                page = context.new_page()
                for path in ("/", "/product/2"):
                    page.goto(f"http://origin-a.test{path}", wait_until="load")
                    page.wait_for_timeout(300)
                context.close()
            finally:
                browser.close()
        snapshot = settle(fresh_world, fw, timeout=20)
    events = [e for e in _requests(events_file) if e.host == "origin-a.test" and e.scheme == "http"]
    sent = [e for e in events if e.hit_network and e.request_header_bytes is not None]
    assert len(sent) >= 4, events
    heads: dict[str, list[int]] = defaultdict(list)
    for record in origin.requests():
        heads[record.path].append(_origin_head_size(record))
    reported_heads: dict[str, list[int]] = defaultdict(list)
    for event in sent:
        reported_heads[str(event.path)].append(int(event.request_header_bytes or 0))
    for path, sizes in reported_heads.items():
        received = sorted(heads.get(path, []))
        assert len(received) == len(sizes), (path, sizes, received)
        # Each reported head is at most what the origin received for that request (Playwright rebuilds
        # the head without its final CRLF and query string, so it is a little smaller).
        assert all(r <= w for r, w in zip(sorted(sizes), received)), (path, sorted(sizes), received)
    result = attribute(snapshot, _events(events_file), _fixture_catalogs())
    row = next(h for h in result.hosts if h.host == "origin-a.test")
    reported = sum(e.reported_bytes for e in events if e.hit_network)
    assert reported <= row.bytes_with_connect, (reported, row.bytes_with_connect)
    for t in result.types:
        assert t.reported_bytes <= t.allocated_bytes, t
