"""Real Chromium through the meter to an HTTP/2 origin: helper sizes, cache flags and attribution.

The fixture world speaks HTTP/1.1 only (tests/fixtures/README.md), but most
HTTPS sites use HTTP/2, where Playwright's ``sizes()`` are not wire figures
(the request header size is rebuilt HTTP/1.1 text, the response header size is
0 and the header frames are inside the body size). This module starts a small
Node.js ``node:http2`` origin (skipped when ``node`` is not installed), sends
Chromium through a direct-mode meter whose test connect map points the fixture
hostnames at it, and checks:

- HTTP/2 events carry unknown (null) header sizes, so reported bytes are not
  inflated above the tunnel bytes (meas-3 / data-1);
- a host that only served a redirect is attributed, not an idle preconnect
  (meas-4);
- disk-cache hits (undecodable images drop out of Blink's memory cache and
  reload from disk) are flagged as cache hits, so the network events match the
  streams the origin served (meas-5).
"""

from __future__ import annotations

import json
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Iterator

import pytest

from scrapescope.attribution import attribute, read_events
from scrapescope.config import ENV_AUTH_PROXY_URL, ENV_EVENTS, ENV_KEEP_URLS, ENV_PROXY_URL, PrivateEventsFile
from scrapescope.helpers import events as ev
from scrapescope.helpers import playwright as ssp
from scrapescope.types import Catalogs, RequestEvent
from tests.fixtures.browser import CONTEXT_KWARGS
from tests.fixtures.world import free_port
from tests.test_forwarder_helpers import make_config, running, wait_tunnels_closed

pytestmark = [pytest.mark.browser, pytest.mark.timeout(120)]

NODE_ORIGIN = r"""
import http2 from 'node:http2';
import fs from 'node:fs';
import crypto from 'node:crypto';
const [keyPath, certPath, port, statsPath] = process.argv.slice(2);
const IMAGES = {};
for (let i = 0; i < 6; i++) IMAGES[`/img/${i}.png`] = crypto.randomBytes(4000 + i * 700);  // not decodable
const CSS = Buffer.from('body{margin:0}\n'.repeat(150));
function page(n) {
  let imgs = '';
  for (let i = 0; i < 6; i++) imgs += `<img src="/img/${i}.png">`;
  return Buffer.from(`<!doctype html><html><head><title>p${n}</title><link rel="stylesheet" href="/s.css"></head>` +
    `<body><h1>Page ${n}</h1>${imgs}<script>fetch('/data.json').then(r => r.text()).then(() => ` +
    `{ document.documentElement.dataset.done = '1'; });</script></body></html>`);
}
const server = http2.createSecureServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) });
server.on('stream', (stream, headers) => {
  const path = headers[':path'].split('?')[0];
  const host = headers[':authority'];
  fs.appendFileSync(statsPath, JSON.stringify({ host, path }) + '\n');
  if (path === '/r') { stream.respond({ ':status': 302, location: 'https://origin-a.test/p/2', 'cache-control': 'no-store' }); stream.end(); return; }
  let body, type, cache = 'public, max-age=3600';
  if (path === '/' || path.startsWith('/p/')) { body = page(path.length > 3 ? +path.slice(3) : 1); type = 'text/html'; cache = 'no-store'; }
  else if (IMAGES[path]) { body = IMAGES[path]; type = 'image/png'; }
  else if (path === '/s.css') { body = CSS; type = 'text/css'; }
  else if (path === '/data.json') { body = Buffer.from(JSON.stringify({ rows: Array.from({ length: 50 }, (_, i) => i) })); type = 'application/json'; cache = 'no-store'; }
  else { stream.respond({ ':status': 404, 'cache-control': 'no-store' }); stream.end(); return; }
  stream.respond({ ':status': 200, 'content-type': type, 'content-length': body.length, 'cache-control': cache });
  stream.end(body);
});
server.listen(+port, '127.0.0.1', () => console.log('listening'));
process.on('SIGTERM', () => process.exit(0));
"""


@pytest.fixture(autouse=True)
def _fresh_writer_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    ev._reset_for_tests()
    for name in (ENV_PROXY_URL, ENV_AUTH_PROXY_URL, ENV_KEEP_URLS):
        monkeypatch.delenv(name, raising=False)
    yield
    ev._reset_for_tests()


@pytest.fixture
def events_file(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    private = PrivateEventsFile.create()
    monkeypatch.setenv(ENV_EVENTS, str(private.path))
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    yield private.path
    ev._reset_for_tests()
    private.cleanup()


@pytest.fixture
def h2_origin(world: Any, tmp_path: Path) -> Iterator[dict[str, Any]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed (needed for the HTTP/2 origin)")
    key, cert, script, stats = (tmp_path / n for n in ("leaf.key", "leaf.pem", "origin.mjs", "stats.json"))
    world.tls.leaf.private_key_pem.write_to_path(str(key))
    cert.write_bytes(b"".join(blob.bytes() for blob in world.tls.leaf.cert_chain_pems))
    script.write_text(NODE_ORIGIN)
    port = free_port()
    proc = subprocess.Popen([node, str(script), str(key), str(cert), str(port), str(stats)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline() if proc.stdout else ""
        if "listening" not in line:
            pytest.skip(f"the Node.js HTTP/2 origin did not start: {proc.stderr.read() if proc.stderr else ''}"[:300])
        yield {"port": port, "stats": stats}
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _catalogs() -> Catalogs:
    return Catalogs.from_documents({"version": "t", "entries": []}, {"version": "t", "vendors": []},
                                   {"version": "t", "entries": []})


def test_http2_sizes_redirect_host_and_disk_cache_hits(world: Any, h2_origin: dict[str, Any], events_file: Path) -> None:
    from playwright.sync_api import sync_playwright

    port = h2_origin["port"]
    connect_map = {("origin-a.test", 443): ("127.0.0.1", port), ("origin-b.test", 443): ("127.0.0.1", port)}
    started = time.time()
    with running(make_config(None), connect_map=connect_map) as fw:
        with sync_playwright() as p:
            browser = p.chromium.launch(proxy={"server": fw.url}, args=world.chromium_args())
            try:
                context = ssp.instrument(browser.new_context(**CONTEXT_KWARGS))
                page = context.new_page()
                for url in ("https://origin-b.test/r", "https://origin-a.test/p/3", "https://origin-a.test/p/4"):
                    page.goto(url, wait_until="load")
                    page.wait_for_function("document.documentElement.dataset.done === '1'", timeout=30_000)
                    page.wait_for_timeout(300)
                context.close()
            finally:
                browser.close()
        snapshot = wait_tunnels_closed(fw, 20)

    log = read_events(events_file)
    assert log.dropped == 0
    reqs = [e for e in log.events if isinstance(e, RequestEvent)]
    network_a = [e for e in reqs if e.host == "origin-a.test" and e.hit_network]
    assert network_a, reqs
    # meas-3: every HTTP/2 network event has unknown header sizes (no phantom HTTP/1.1 header text).
    assert all(e.request_header_bytes is None and e.response_header_bytes is None for e in network_a), network_a
    # meas-4: the host that only answered with a redirect has one network 302, not a cache hit.
    (redirect,) = [e for e in reqs if e.host == "origin-b.test"]
    assert redirect.status == 302 and not redirect.from_cache and redirect.hit_network

    result = attribute(snapshot, log.events, _catalogs())
    rows = {h.host: h for h in result.hosts}
    assert set(rows["origin-b.test"].buckets) == {"attributed"}
    assert result.status_histogram.get("302") == 1
    # Reported sizes are not inflated above what the host's tunnels carried.
    reported_a = sum(e.reported_bytes for e in network_a)
    assert reported_a <= rows["origin-a.test"].bytes_with_connect
    assert sum(t.allocated_bytes for t in result.types) == result.buckets.attributed
    assert result.bypass.incomplete is False
    assert all(r.ts >= started - 1 for r in reqs)

    # meas-5: compare with the streams the origin actually served. Pages 3 and 4 reuse the images and
    # the stylesheet from the HTTP cache (disk cache for the undecodable images).
    served = [json.loads(line) for line in h2_origin["stats"].read_text().splitlines() if line]
    served_a = [s for s in served if s["host"] == "origin-a.test" and s["path"] != "/favicon.ico"]
    images = [e for e in reqs if e.resource_type == "image"]
    assert len(images) == 18 and sum(1 for e in images if e.hit_network) == 6, [
        (e.path, e.from_cache, e.encoded_body_bytes) for e in images]
    assert len(network_a) == len(served_a), (sorted(e.path or "" for e in network_a), sorted(s["path"] for s in served_a))



def test_find_on_http2_keeps_rebuilt_header_sizes_out_of_the_billed_basis(world: Any, h2_origin: dict[str, Any]) -> None:
    """data-1 (find part): on HTTP/2, DevTools' request-header size is rebuilt HTTP/1.1 text, not wire bytes.

    The match is marked multiplexed, both header fields are 0, the billed basis is
    the encoded body (which already holds the response header frames) plus the TLS
    estimate, and the page's DevTools-reported bytes stay below what its tunnels carried.
    """
    import asyncio

    from scrapescope.config import TLS_HANDSHAKE_ESTIMATE_BYTES
    from scrapescope.find import render_find_text, run_find

    port = h2_origin["port"]
    connect_map = {("origin-a.test", 443): ("127.0.0.1", port)}
    with running(make_config(None), connect_map=connect_map) as fw:
        result = asyncio.run(
            run_find("https://origin-a.test/p/5", ["Page 5"], proxy_url=fw.url, catalogs=_catalogs(),
                     ca_file=world.ca_pem, browser_args=world.chromium_args(), timeout_s=40.0)
        )
        snapshot = wait_tunnels_closed(fw, 20)
    assert result.status == "found", result.warnings
    doc = result.matches[0]
    assert doc.resource_type == "document" and doc.multiplexed is True
    assert doc.request_header_bytes == 0 and doc.response_header_bytes == 0
    assert doc.billed_basis_bytes == doc.encoded_body_bytes + TLS_HANDSHAKE_ESTIMATE_BYTES
    assert doc.locations_by_value and doc.locations_by_value[0], doc.locations
    tunnel_bytes = sum(t.upstream_bytes_sent + t.upstream_bytes_received for t in snapshot.tunnels
                       if t.host == "origin-a.test")
    assert 0 < result.page_reported_bytes <= tunnel_bytes, (result.page_reported_bytes, tunnel_bytes)
    text = render_find_text(result)
    assert "HTTP/2 or HTTP/3" in text and "request headers are left out" in text
