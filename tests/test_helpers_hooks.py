"""Requests and HTTPX hooks against the fixture upstreams (no forwarder, no internet)."""

from __future__ import annotations

import asyncio
import base64
import gc
import json
import time
import warnings
from pathlib import Path

import httpx
import pytest
import requests

from scrapescope.attribution import attribute, read_events
from scrapescope.catalog import load_catalogs
from scrapescope.config import ENV_EVENTS, ENV_KEEP_URLS, PrivateEventsFile
from scrapescope.helpers import events as ev
from scrapescope.helpers import hooks
from scrapescope.types import AttachEvent, MeterSnapshot, RequestEvent, TunnelRecord
from tests.fixtures import SESSION_PASSWORD, UPSTREAM_PASSWORD, UPSTREAM_USERNAME, site

BASE = "https://origin-a.test"
USER_SECRET = "hook-user-pw-7c1d9e"


@pytest.fixture(autouse=True)
def _fresh_writer_state():
    ev._reset_for_tests()
    yield
    ev._reset_for_tests()


@pytest.fixture
def events_file(monkeypatch: pytest.MonkeyPatch):
    private = PrivateEventsFile.create()
    monkeypatch.setenv(ENV_EVENTS, str(private.path))
    monkeypatch.delenv(ENV_KEEP_URLS, raising=False)
    yield private.path
    ev._reset_for_tests()
    private.cleanup()


def _requests_events(path: Path) -> list[RequestEvent]:
    log = read_events(path)
    assert log.dropped == 0
    return [e for e in log.events if isinstance(e, RequestEvent)]


def _attaches(path: Path) -> list[AttachEvent]:
    return [e for e in read_events(path).events if isinstance(e, AttachEvent)]


def _assert_private(path: Path, *secrets: str) -> None:
    text = path.read_text(encoding="utf-8")
    for secret in (UPSTREAM_USERNAME, UPSTREAM_PASSWORD, site.SESSION_COOKIE_VALUE, site.SIGNED_QUERY_TOKEN,
                   "sig=", "?", *secrets):
        assert secret not in text, secret
    basic = base64.b64encode(f"{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}".encode()).decode()
    assert basic not in text


def _session(world, *, socks: bool = False) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    proxy = world.socks_upstream.url_h if socks else world.http_upstream.url
    session.proxies = {"http": proxy, "https": proxy}
    session.verify = world.ca_pem
    return session


def _origin_body(world, path: str, method: str = "GET") -> int:
    records = [r for r in world.origin("origin-a.test", "https").requests() if r.path == path and r.method == method]
    assert records, path
    return records[-1].response_body_bytes


# ---------------------------------------------------------------------------- requests


def test_requests_session_records_each_response(world, events_file: Path) -> None:
    world.reset()
    session = hooks.instrument_requests(_session(world))
    try:
        assert session.get(f"{BASE}/api/product.json").status_code == 200
        assert session.get(f"{BASE}/redirect").status_code == 200  # 302 hop + final page
        assert session.get(f"{BASE}/status/404").status_code == 404
        assert session.head(f"{BASE}/api/product.json").status_code == 200
        assert session.post(f"{BASE}/echo", data=b"x" * 1234).status_code == 200
    finally:
        session.close()
    world.wait_idle()
    events = _requests_events(events_file)
    assert [(e.method, e.status) for e in events] == [
        ("GET", 200), ("GET", 302), ("GET", 200), ("GET", 404), ("HEAD", 200), ("POST", 200),
    ]
    for e in events:
        assert (e.source, e.resource_type, e.frame, e.is_navigation) == ("requests", "http_client", "other", False)
        assert (e.host, e.port, e.scheme, e.path) == ("origin-a.test", 443, "https", None)
        assert e.response_header_bytes and e.response_header_bytes > 50
        assert e.request_header_bytes and e.request_header_bytes > 50
        assert not e.failed and not e.from_cache and not e.from_service_worker
    product = events[0]
    assert product.encoded_body_bytes == _origin_body(world, "/api/product.json")  # Content-Length, encoded
    assert events[4].encoded_body_bytes == 0  # HEAD
    assert events[5].request_body_bytes == 1234
    assert len(_attaches(events_file)) == 1
    _assert_private(events_file)


def test_requests_presence_flags_without_values(world, events_file: Path) -> None:
    session = hooks.instrument_requests(_session(world))
    try:
        session.cookies.set(site.SESSION_COOKIE_NAME, site.SESSION_COOKIE_VALUE, domain="origin-a.test")
        session.get(f"{BASE}/api/session-product.json")
        session.get(f"{BASE}/api/product.json", auth=("someone", USER_SECRET), cookies={})
        session.cookies.clear()
        session.get(f"{BASE}/api/offer.json", params={"sig": site.SIGNED_QUERY_TOKEN})
    finally:
        session.close()
    first, second, third = _requests_events(events_file)
    assert first.sent_cookies is True and first.status == 200
    assert second.sent_authorization is True
    assert third.sent_cookies is False and third.sent_authorization is False and third.status == 200
    _assert_private(events_file, USER_SECRET, base64.b64encode(f"someone:{USER_SECRET}".encode()).decode())


def test_requests_keep_urls_paths_never_queries(world, events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    session = hooks.instrument_requests(_session(world))
    try:
        session.get(f"{BASE}/api/offer.json?sig={site.SIGNED_QUERY_TOKEN}")
    finally:
        session.close()
    (event,) = _requests_events(events_file)
    assert event.path == "/api/offer.json"
    _assert_private(events_file)


def test_requests_through_socks_upstream(world, events_file: Path) -> None:
    session = hooks.instrument_requests(_session(world, socks=True))
    try:
        assert session.get(f"{BASE}/api/product.json").status_code == 200
        streamed = session.get(f"{BASE}/big.bin?size=70000", stream=True)
        size = sum(len(chunk) for chunk in streamed.iter_content(8192))
        streamed.close()
    finally:
        session.close()
    events = _requests_events(events_file)
    assert size == 70000
    assert events[1].encoded_body_bytes == 70000  # raw bytes read, the whole streamed body here
    _assert_private(events_file)


def _upstream_tunnels(world) -> list[TunnelRecord]:
    """The fixture upstream counts the same socket bytes the meter would (tests/fixtures/README.md)."""
    tunnels = []
    for i, rec in enumerate(world.http_upstream.records()):
        if rec.kind != "connect" or not rec.targets:
            continue
        host, _, port = rec.targets[0].rpartition(":")
        tunnels.append(TunnelRecord(
            id=i + 1, host=host, port=int(port), kind="connect", route="http-connect", opened_at=rec.started_at,
            closed_at=rec.ended_at, status="ok", upstream_bytes_sent=rec.bytes_from_client,
            upstream_bytes_received=rec.bytes_to_client, negotiation_bytes_sent=rec.negotiation_from_client,
            negotiation_bytes_received=rec.negotiation_to_client,
        ))
    return tunnels


def _attribute(world, path: Path, started: float):
    tunnels = _upstream_tunnels(world)
    snapshot = MeterSnapshot(taken_at=time.time(), started_at=started, mode="http-connect", port=1, auth_port=None,
                             tunnels=tunnels, counted_bytes=sum(t.counted_bytes for t in tunnels), budget_bytes=None,
                             max_tunnel_bytes=None, budget_tripped=False)
    return attribute(snapshot, read_events(path).events, load_catalogs())


def test_requests_stream_read_in_part_reports_the_bytes_read_not_the_content_length(world, events_file: Path) -> None:
    """meas2-2: stream=True, one chunk read, then close(): the declared 5 MB never crossed the tunnel.

    The hook used to write Content-Length, so attribution called the run incomplete ("most of that
    traffic went around the meter") although every byte went through it.
    """
    world.reset()
    started = time.time()
    session = hooks.instrument_requests(_session(world))
    try:
        for i in range(3):
            response = session.get(f"{BASE}/big.bin?size=5000000&chunk=65536&delay_ms=5", stream=True)
            assert len(next(response.iter_content(65536))) == 65536
            assert len(_requests_events(events_file)) == i  # written when the response is closed
            response.close()
            assert len(_requests_events(events_file)) == i + 1
    finally:
        session.close()
    assert world.wait_idle()
    events = _requests_events(events_file)
    assert len(events) == 3
    for event in events:
        assert event.status == 200 and not event.failed
        assert event.encoded_body_bytes is not None and 65536 <= event.encoded_body_bytes < 1_000_000
    result = _attribute(world, events_file, started)
    assert result.bypass.incomplete is False, result.warnings
    assert not any("went around the meter" in w for w in result.warnings)


def test_requests_body_sizes_are_written_when_read_closed_or_collected(world, events_file: Path) -> None:
    session = hooks.instrument_requests(_session(world))
    try:
        response = session.get(f"{BASE}/big.bin?size=300000&chunk=16384", stream=True)
        assert _requests_events(events_file) == []  # nothing read yet: the event waits
        next(response.iter_content(16384))
        del response
        gc.collect()  # never closed: written when collected, with what was read
        (collected,) = _requests_events(events_file)
        assert 16384 <= collected.encoded_body_bytes < 300000
        session.get(f"{BASE}/chunked?n=3&size=1000")
        chunked = _requests_events(events_file)[-1]
        assert chunked.status == 200 and chunked.encoded_body_bytes is None  # urllib3 does not count chunks
        head = session.head(f"{BASE}/big.bin?size=300000")
        assert head.status_code == 200 and _requests_events(events_file)[-1].encoded_body_bytes == 0
    finally:
        session.close()


def test_requests_http2_responses_have_unknown_header_sizes(events_file: Path) -> None:
    """meas2-5: urllib3 can speak HTTP/2; its header blocks are HPACK-compressed on the wire."""
    import io

    import urllib3

    class H2Adapter(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):  # type: ignore[override]
            raw = urllib3.HTTPResponse(body=io.BytesIO(b"x" * 500), headers={"content-type": "text/plain",
                                       "content-length": "500"}, status=200, version=20, preload_content=False)
            return self.build_response(request, raw)

    session = hooks.instrument_requests(requests.Session())
    session.mount("https://", H2Adapter())
    assert session.get(f"{BASE}/api/product.json").content == b"x" * 500
    (event,) = _requests_events(events_file)
    assert event.response_header_bytes is None and event.request_header_bytes is None
    assert event.encoded_body_bytes == 500


def test_requests_failure_is_recorded_and_reraised(world, events_file: Path, closed_port: int) -> None:
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"https": f"http://127.0.0.1:{closed_port}"}
    hooks.instrument_requests(session)
    with pytest.raises(requests.exceptions.ProxyError):
        session.get(f"{BASE}/api/product.json", timeout=5)
    session.close()
    (event,) = _requests_events(events_file)
    assert event.failed is True and event.status is None
    assert event.encoded_body_bytes is None and event.host == "origin-a.test"


def test_requests_instrumentation_is_idempotent_and_keeps_user_hooks(world, events_file: Path) -> None:
    seen: list[int] = []
    session = _session(world)
    session.hooks["response"].append(lambda r, *a, **k: seen.append(r.status_code))
    assert hooks.instrument_requests(session) is session
    hooks.instrument_requests(session)
    try:
        session.get(f"{BASE}/api/product.json")
    finally:
        session.close()
    assert seen == [200]
    assert len(_requests_events(events_file)) == 1
    assert len(_attaches(events_file)) == 1


def test_requests_inactive_without_events_file(world, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_EVENTS, raising=False)
    session = _session(world)
    original_send = session.send
    with pytest.warns(RuntimeWarning, match="SCRAPESCOPE_EVENTS is not set"):
        assert hooks.instrument_requests(session) is session
    assert session.hooks["response"] == [] and session.send == original_send
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        hooks.instrument_requests(_session(world))  # no second warning in this process
    session.close()


# ---------------------------------------------------------------------------- httpx (sync)


def _client(world, **kw) -> httpx.Client:
    return httpx.Client(proxy=world.http_upstream.url, verify=world.tls.client_context(), trust_env=False, **kw)


def test_httpx_client_records_downloaded_bytes(world, events_file: Path) -> None:
    world.reset()
    with hooks.instrument_httpx(_client(world, follow_redirects=True)) as client:
        assert client.get(f"{BASE}/api/product.json").status_code == 200
        assert client.get(f"{BASE}/chunked?n=3&size=1000").status_code == 200
        assert client.get(f"{BASE}/redirect").status_code == 200
        assert client.post(f"{BASE}/echo", content=b"y" * 777).status_code == 200
    world.wait_idle()
    events = _requests_events(events_file)
    assert [(e.method, e.status) for e in events] == [("GET", 200), ("GET", 200), ("GET", 302), ("GET", 200),
                                                      ("POST", 200)]
    assert events[0].encoded_body_bytes == _origin_body(world, "/api/product.json")
    assert events[1].encoded_body_bytes == _origin_body(world, "/chunked")
    assert events[4].request_body_bytes == 777
    for e in events:
        assert (e.source, e.resource_type, e.frame, e.is_navigation) == ("httpx", "http_client", "other", False)
        assert e.response_header_bytes and e.request_header_bytes
    assert len(_attaches(events_file)) == 1
    _assert_private(events_file)


def test_httpx_streams_are_recorded_when_closed(world, events_file: Path) -> None:
    with hooks.instrument_httpx(_client(world)) as client:
        with client.stream("GET", f"{BASE}/big.bin?size=200000&chunk=16384") as response:
            total = sum(len(chunk) for chunk in response.iter_raw())
        assert total == 200000
        assert len(_requests_events(events_file)) == 1  # emitted on close, not before
        with client.stream("GET", f"{BASE}/big.bin?size=500000&chunk=16384") as response:
            for _chunk in response.iter_raw():
                break  # stop early
    first, partial = _requests_events(events_file)
    assert first.encoded_body_bytes == 200000
    assert 0 < partial.encoded_body_bytes < 500000
    assert partial.failed is False


def test_httpx_unclosed_stream_is_recorded_at_garbage_collection(world, events_file: Path) -> None:
    client = hooks.instrument_httpx(_client(world))
    try:
        response = client.send(client.build_request("GET", f"{BASE}/api/product.json"), stream=True)
        assert _requests_events(events_file) == []
        del response
        gc.collect()
        (event,) = _requests_events(events_file)
        assert event.status == 200 and event.encoded_body_bytes == 0  # body never read
    finally:
        client.close()


def test_httpx_failure_before_response(events_file: Path, closed_port: int) -> None:
    client = hooks.instrument_httpx(httpx.Client(proxy=f"http://127.0.0.1:{closed_port}", trust_env=False))
    with pytest.raises(httpx.ConnectError):
        client.get(f"{BASE}/api/product.json", headers={"Authorization": "Bearer " + USER_SECRET})
    with pytest.raises(httpx.HTTPError):
        client.get(f"{BASE}/api/product.json")
    client.close()
    events = _requests_events(events_file)
    assert len(events) == 2
    assert all(e.failed and e.status is None for e in events)
    assert events[0].sent_authorization is True
    _assert_private(events_file, USER_SECRET)


@pytest.mark.parametrize("version", ["HTTP/2", "HTTP/3"])
def test_httpx_http2_and_http3_header_sizes_are_unknown(events_file: Path, version: str) -> None:
    """meas2-5: httpx.Client(http2=True) sends HPACK-compressed headers; rebuilt HTTP/1.1 text overstates them.

    (The h2 package is not installed here, so the version comes from a mock transport, as httpx's
    own HTTP/2 transport reports it.)
    """
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"z" * 500), headers={"content-type": "application/json"},
                              extensions={"http_version": version.encode()})

    with hooks.instrument_httpx(httpx.Client(transport=httpx.MockTransport(handler))) as client:
        client.get("https://mock.test/api", headers={"x-long": "v" * 400})
    (event,) = _requests_events(events_file)
    assert event.response_header_bytes is None and event.request_header_bytes is None
    assert event.encoded_body_bytes == 500 and event.reported_bytes == 500


def test_httpx_body_read_failure_is_marked_failed_once(events_file: Path) -> None:
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b"abc"
            raise httpx.ReadError("connection reset")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=Broken())

    client = hooks.instrument_httpx(httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(httpx.ReadError):
        client.get("https://mock.test/x")
    client.close()
    (event,) = _requests_events(events_file)
    assert event.failed is True and event.status == 200 and event.encoded_body_bytes == 3


def test_httpx_event_hooks_dict_and_user_hooks(world, events_file: Path) -> None:
    seen: list[int] = []
    event_hooks = hooks.httpx_event_hooks()
    event_hooks["response"].append(lambda r: seen.append(r.status_code))
    with httpx.Client(proxy=world.http_upstream.url, verify=world.tls.client_context(), trust_env=False,
                      event_hooks=event_hooks) as client:
        client.get(f"{BASE}/api/product.json")
    assert seen == [200]
    (event,) = _requests_events(events_file)
    assert event.source == "httpx" and event.encoded_body_bytes > 0
    assert len(_attaches(events_file)) == 1


def test_httpx_instrument_keeps_existing_hooks_and_is_idempotent(world, events_file: Path) -> None:
    seen: list[str] = []
    client = _client(world, event_hooks={"request": [lambda r: seen.append("req")],
                                         "response": [lambda r: seen.append("resp")]})
    hooks.instrument_httpx(client)
    hooks.instrument_httpx(client)
    with client:
        client.get(f"{BASE}/api/product.json")
    assert seen == ["req", "resp"]
    assert len(_requests_events(events_file)) == 1 and len(_attaches(events_file)) == 1


def test_httpx_through_socks_upstream(world, events_file: Path) -> None:
    with hooks.instrument_httpx(httpx.Client(proxy=world.socks_upstream.url, verify=world.tls.client_context(),
                                             trust_env=False)) as client:
        assert client.get(f"{BASE}/api/product.json").status_code == 200
    (event,) = _requests_events(events_file)
    assert event.status == 200 and event.encoded_body_bytes > 0
    _assert_private(events_file)


def test_httpx_session_username_is_not_recorded(world, events_file: Path) -> None:
    user = "customer-x-session-4242"
    proxy = world.http_upstream.proxy_url(user, SESSION_PASSWORD)
    with hooks.instrument_httpx(httpx.Client(proxy=proxy, verify=world.tls.client_context(),
                                             trust_env=False)) as client:
        client.get(f"{BASE}/api/product.json")
    _assert_private(events_file, user, SESSION_PASSWORD)


def test_httpx_inactive_without_events_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_EVENTS, raising=False)
    client = httpx.Client(trust_env=False)
    with pytest.warns(RuntimeWarning, match="helpers inactive"):
        assert hooks.instrument_httpx(client) is client
    assert client.event_hooks == {"request": [], "response": []}
    assert hooks.httpx_event_hooks() == {"request": [], "response": []}
    assert hooks.async_httpx_event_hooks() == {"request": [], "response": []}
    client.close()


# ---------------------------------------------------------------------------- httpx (async)


def test_async_httpx_client(world, events_file: Path, closed_port: int) -> None:
    async def main() -> None:
        async with hooks.instrument_httpx(
            httpx.AsyncClient(proxy=world.http_upstream.url, verify=world.tls.client_context(), trust_env=False,
                              follow_redirects=True)
        ) as client:
            assert (await client.get(f"{BASE}/api/product.json")).status_code == 200
            assert (await client.get(f"{BASE}/redirect")).status_code == 200
            async with client.stream("GET", f"{BASE}/big.bin?size=90000") as response:
                async for _chunk in response.aiter_raw():
                    pass
        async with httpx.AsyncClient(proxy=world.http_upstream.url, verify=world.tls.client_context(),
                                     trust_env=False, event_hooks=hooks.async_httpx_event_hooks()) as client2:
            await client2.get(f"{BASE}/api/worker.json")
        failing = hooks.instrument_httpx(httpx.AsyncClient(proxy=f"http://127.0.0.1:{closed_port}", trust_env=False))
        with pytest.raises(httpx.HTTPError):
            await failing.get(f"{BASE}/api/product.json")
        await failing.aclose()

    asyncio.run(main())
    events = _requests_events(events_file)
    assert [(e.status, e.failed) for e in events] == [(200, False), (302, False), (200, False), (200, False),
                                                      (200, False), (None, True)]
    assert events[0].encoded_body_bytes == _origin_body(world, "/api/product.json")
    assert events[3].encoded_body_bytes == 90000
    assert all(e.source == "httpx" for e in events)
    assert len(_attaches(events_file)) == 3
    _assert_private(events_file)


def test_hook_lines_are_valid_json(world, events_file: Path) -> None:
    with hooks.instrument_httpx(_client(world)) as client:
        client.get(f"{BASE}/api/product.json")
    for line in events_file.read_text().splitlines():
        obj = json.loads(line)
        assert obj["v"] == 1
        assert set(obj) <= {"v", "kind", "ts", "source", "pid", "context", "host", "port", "scheme", "path",
                            "method", "resource_type", "status", "failed", "from_cache", "from_service_worker",
                            "frame", "is_navigation", "encoded_body_bytes", "response_header_bytes",
                            "request_header_bytes", "request_body_bytes", "sent_cookies", "sent_authorization",
                            "browser"}


# ---------------------------------------------------------------------------- IP literals (meas4-1)


def test_ip_literals_in_any_spelling_are_attributed_to_the_tunnel_that_carried_them(
    world, hosts_map, events_file: Path
) -> None:
    """The meter files tunnels under types.canonical_host; the hooks used to write the URL's spelling
    (a legacy IPv4 form, an uncompressed IPv6 address), so the tunnel that carried each request got no
    requests and the request itself was called bypass ("no meter tunnel carried")."""
    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import ForwarderThread

    origin = hosts_map[("origin-a.test", 80)]
    connect_map = {("1.2.3.4", 80): origin, ("2001:db8::1", 80): origin}
    with ForwarderThread(ForwarderConfig(), connect_map=connect_map) as fw:
        session = hooks.instrument_requests(requests.Session())
        session.trust_env = False
        session.proxies = {"http": fw.url}
        # HTTPX 0.28 refuses 1.2.3.04 and sends IPv6 absolute-form targets without brackets (which the
        # meter rejects as malformed), so only Requests can take these URLs through a proxy.
        try:
            for url in ("http://1.2.3.04/plain.html", "http://[2001:db8:0:0::1]/plain.html"):
                assert session.get(url).status_code == 200
        finally:
            session.close()
        snapshot = fw.stop()  # the final snapshot: every tunnel closed and counted
    assert sorted({t.host for t in snapshot.tunnels}) == ["1.2.3.4", "2001:db8::1"]
    events = _requests_events(events_file)
    assert sorted(e.host for e in events) == ["1.2.3.4", "2001:db8::1"]
    result = attribute(snapshot, read_events(events_file).events, load_catalogs())
    assert result.bypass.incomplete is False and result.bypass.requests == 0, result.warnings
    for host in ("1.2.3.4", "2001:db8::1"):
        row = next(h for h in result.hosts if h.host == host)
        assert row.requests == 1 and set(row.buckets) == {"attributed"}, row
        assert set(row.allocated_by_type) == {"http_client"}
    assert result.buckets.preconnect_idle == result.buckets.unattributed == 0
