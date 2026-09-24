"""Integration checks that the meter is transparent to the provider and the origin.

- The meter never changes the number of connections: origins see the same TLS
  handshakes and connections with and without it (plan Appendix A: "tested by
  equal origin handshake counts with and without the meter").
- SOCKS5 has no HTTP proxy semantics: a plain-HTTP request reaches the origin
  in origin form, without Proxy-Authorization or Proxy-Connection.
"""

from __future__ import annotations

import socket

import httpx
import pytest
import requests

from scrapescope.config import ForwarderConfig, parse_upstream_url
from scrapescope.forwarder import ForwarderThread
from tests.fixtures import TestWorld

pytestmark = pytest.mark.timeout(60)


def _client_session(world: TestWorld, proxy: str) -> tuple[httpx.Client, requests.Session]:
    client = httpx.Client(proxy=proxy, verify=world.tls.client_context(), trust_env=False, timeout=20)
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"https": proxy, "http": proxy}
    session.verify = world.ca_pem
    return client, session


def _workload(world: TestWorld, proxy: str) -> None:
    client, session = _client_session(world, proxy)
    with client:
        for path in ("/api/product.json", "/static/style.css", "/api/worker.json"):
            assert client.get(f"https://origin-a.test{path}").status_code == 200
        assert client.get("https://origin-b.test/embed").status_code == 200
        assert client.get("http://origin-a.test/plain.html").status_code == 200
    with session:
        for _ in range(2):
            assert session.get("https://origin-c.test/").status_code == 200


def _origin_view(world: TestWorld) -> dict[str, tuple[int, int]]:
    """{origin: (connections, TLS handshakes)} after the world went idle."""
    world.wait_idle()
    view = {}
    for (host, scheme), origin in world.origins.items():
        conns = origin.connections()
        if conns:
            view[f"{scheme}://{host}"] = (len(conns), sum(c.tls_handshakes for c in conns))
    return view


def test_origin_connections_and_tls_handshakes_are_equal_with_and_without_the_meter(fresh_world: TestWorld) -> None:
    world = fresh_world
    _workload(world, world.http_upstream.url)
    without = _origin_view(world)
    upstream_without = len(world.http_upstream.records())
    world.reset()
    config = ForwarderConfig(upstream=parse_upstream_url(world.http_upstream.url))
    with ForwarderThread(config) as fw:
        _workload(world, fw.url)
        world.wait_idle()
        snapshot = fw.snapshot()
    with_meter = _origin_view(world)
    assert with_meter == without
    assert len(world.http_upstream.records()) == upstream_without == len(snapshot.target_tunnels())
    assert without["https://origin-a.test"] == (1, 1)  # keep-alive preserved through the meter


def test_socks5_plain_http_reaches_the_origin_in_origin_form(fresh_world: TestWorld) -> None:
    world = fresh_world
    config = ForwarderConfig(upstream=parse_upstream_url(world.socks_upstream.url), token="tok-abcdefghijklmnopqrstuv")
    request = (
        b"GET http://origin-a.test/plain.html?x=1 HTTP/1.1\r\nHost: origin-a.test\r\n"
        b"Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic c3MtdG9rLWFiY2RlZmdoaWprbG1ub3BxcnN0dXY6\r\n"
        b"Connection: close\r\n\r\n"
    )
    with ForwarderThread(config) as fw:
        with socket.create_connection(("127.0.0.1", fw.port), timeout=10) as sock:
            sock.sendall(request)
            reply = b""
            while chunk := sock.recv(65536):
                reply += chunk
        world.wait_idle()
        snapshot = fw.snapshot()
    assert reply.startswith(b"HTTP/1.1 200 ")
    (req,) = world.origin("origin-a.test", "http").requests()
    assert (req.path, req.query) == ("/plain.html", "x=1")
    assert req.header("Proxy-Authorization") is None and req.header("Proxy-Connection") is None
    (record,) = world.socks_upstream.records()
    assert record.atyp == "domain" and record.target_host == "origin-a.test"  # remote DNS
    (tunnel,) = snapshot.target_tunnels()
    assert (tunnel.kind, tunnel.route, tunnel.auth) == ("http", "socks5", "injected")
