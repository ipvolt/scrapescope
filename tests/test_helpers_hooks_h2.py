"""HTTPX with ``http2=True`` against a real HTTP/2 origin through the meter (meas2-5).

The MockTransport tests in test_helpers_hooks.py cover the hook's HTTP/2
branch; this one checks it against a real HTTP/2 connection: the Node.js
``node:http2`` origin of test_helpers_playwright_h2.py behind a direct-mode
meter. It needs ``node`` and the ``h2`` package (the ``dev`` extra lists it)
and is skipped without them.
"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import httpx
import pytest

from scrapescope.attribution import read_events
from scrapescope.helpers import hooks
from scrapescope.types import RequestEvent
from tests.test_forwarder_helpers import make_config, running, wait_tunnels_closed
from tests.test_helpers_playwright_h2 import _fresh_writer_state, events_file, h2_origin  # noqa: F401 - fixtures

pytest.importorskip("h2", reason="the h2 package (httpx[http2]) is not installed")

pytestmark = pytest.mark.timeout(60)


def test_httpx_http2_through_the_meter_writes_unknown_header_sizes(
    world: Any, h2_origin: dict[str, Any], events_file: Path  # noqa: F811 - fixtures imported above
) -> None:
    connect_map = {("origin-a.test", 443): ("127.0.0.1", h2_origin["port"])}
    with running(make_config(None), connect_map=connect_map) as fw:
        client = httpx.Client(http2=True, proxy=fw.url, verify=ssl.create_default_context(cafile=world.ca_pem), trust_env=False, timeout=20)
        with hooks.instrument_httpx(client):
            response = client.get("https://origin-a.test/data.json")
            assert response.status_code == 200 and response.http_version == "HTTP/2"
            body = response.content
        snapshot = wait_tunnels_closed(fw, 20)

    log = read_events(events_file)
    assert log.dropped == 0
    (event,) = [e for e in log.events if isinstance(e, RequestEvent)]
    assert event.source == "httpx" and event.host == "origin-a.test" and event.status == 200
    # HPACK on the wire: the rebuilt HTTP/1.1 header blocks would overstate them, so both are unknown.
    assert event.request_header_bytes is None and event.response_header_bytes is None
    assert event.encoded_body_bytes == len(body)  # no content coding: downloaded bytes = body
    (tunnel,) = snapshot.target_tunnels()
    assert event.reported_bytes < tunnel.upstream_bytes_received
