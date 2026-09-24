"""Deterministic content and routing for the fixture origins.

Every byte served here is deterministic (images, fonts and ``/big.bin`` come
from SHAKE-256 of fixed seeds; gzip uses ``mtime=0``), except the ``Date``
header added by the HTTP server. Marker strings are exported as constants so
tests never hard-code them.

Sites (selected by the hostname an origin listener serves):
- ``a``: origin-a.test, the product shop (page, assets, APIs, challenges).
- ``b``: origin-b.test, cross-site iframe content (``/embed``).
- ``c``: origin-c.test, the preconnect target (tiny ``/``).
- ``openai``: api.openai.com (``/v1/models``).
- ``background``: catalogued Chromium background hosts (tiny ``/``).
- ``badcert``: badcert.test (served with an untrusted certificate).
Common routes (``/big.bin``, ``/chunked``, ...) exist on every site.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import struct
import time
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from functools import cache
from urllib.parse import parse_qs

# --------------------------------------------------------------------------- markers
PRODUCT_NAME = "Widget Pro"
PRODUCT_PRICE = "129.99"
PRODUCT_CURRENCY = "EUR"
PRODUCT_SKU = "WP-1000"
#: The price as it appears in the HTML with a narrow no-break space (U+202F).
PRICE_NNBSP_TEXT = "129,99 €"
#: The cookie set by '/' (Path-scoped to the session endpoint only).
SESSION_COOKIE_NAME = "ss_session"
SESSION_COOKIE_VALUE = "cookie-sentinel-5c0ffee1d"
#: Random-looking query token required by ``/api/offer.json``.
SIGNED_QUERY_TOKEN = "k7Qx9Lm2Vb8Rt4Zp1Nw6Yc3Hs5Jd0FaE"
WORKER_MARKER = "WORKER-STOCK-4242"
SW_MARKER = "SW-MARKER-7331"
EMBED_MARKER = "EMBED-MARKER-2718"
NEXT_DATA_MARKER = "NEXT-DATA-1618"
#: The beacon's response ``{"ok":true,"seq":129}`` coincidentally contains "129".
BEACON_SEQ = 129
#: Paths requested by ``/hostile`` (percent-encoded as sent on the wire).
HOSTILE_PATHS = (
    "/hostile/%3Cscript%3Ealert(1)%3C/script%3E.png",
    "/hostile/javascript:alert(1).png",
    "/hostile/![x](https:%2F%2Fexample.invalid%2Fx.png).png",
)

#: Hostname -> site id.
SITE_OF_HOST = {
    "origin-a.test": "a",
    "origin-b.test": "b",
    "origin-c.test": "c",
    "api.openai.com": "openai",
    "optimizationguide-pa.googleapis.com": "background",
    "update.googleapis.com": "background",
    "clients2.google.com": "background",
    "clients2.googleusercontent.com": "background",
    "edgedl.me.gvt1.com": "background",
    "safebrowsing.googleapis.com": "background",
    "badcert.test": "badcert",
}

#: Image paths on origin-a with their (width, height); each PNG is 150-250 KB.
IMAGES = {
    "/static/img/hero-1.png": (280, 200, b"hero-1"),
    "/static/img/hero-2.png": (300, 230, b"hero-2"),
    "/static/img/hero-3.png": (320, 240, b"hero-3"),
}
EMBED_IMAGE = "/static/embed.png"
FONT_PATH = "/static/font.woff2"
FONT_SIZE = 49_152

COMPRESSIBLE_TYPES = ("text/html", "application/json", "application/javascript", "text/css", "text/plain")


# --------------------------------------------------------------------------- binary content
def png_bytes(width: int, height: int, seed: bytes) -> bytes:
    """A valid, incompressible RGB PNG (zlib level 0 over SHAKE-256 noise)."""
    raw = hashlib.shake_256(b"scrapescope-png:" + seed).digest(width * height * 3)
    stride = width * 3
    rows = b"".join(b"\x00" + raw[y * stride : (y + 1) * stride] for y in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows, 0)) + chunk(b"IEND", b"")


@cache
def image(path: str) -> bytes:
    if path == EMBED_IMAGE:
        return png_bytes(100, 70, b"embed")
    if path.startswith("/hostile/"):
        return png_bytes(4, 4, b"hostile")
    width, height, seed = IMAGES[path]
    return png_bytes(width, height, seed)


@cache
def font() -> bytes:
    """Deterministic bytes labelled font/woff2 (not a decodable font; Chromium still downloads it)."""
    return b"wOF2" + hashlib.shake_256(b"scrapescope-font").digest(FONT_SIZE - 4)


_BIG_BLOCK = hashlib.shake_256(b"scrapescope-big").digest(65536)
_BIG_BLOCK2 = _BIG_BLOCK * 2


def big_bytes(offset: int, n: int) -> bytes:
    """Bytes ``[offset, offset+n)`` of the infinite /big.bin stream (n <= 65536)."""
    start = offset % 65536
    return _BIG_BLOCK2[start : start + n]


def big_stream(size: int, chunk: int = 65536, delay: float = 0.0) -> Iterator[bytes]:
    chunk = max(1, min(chunk, 65536))
    sent = 0
    while sent < size:
        n = min(chunk, size - sent)
        yield big_bytes(sent, n)
        sent += n
        if delay and sent < size:
            time.sleep(delay)


# --------------------------------------------------------------------------- text content
def _description() -> str:
    sentences = [
        "The Widget Pro is a deterministic test product used by the scrapescope fixture shop.",
        "It ships with a brushed aluminium housing, a replaceable battery and a two-year warranty.",
        "Every paragraph on this page is padding so the document has a realistic size.",
        "Nothing here is a real offer, and no real shop sells this item.",
        "Images, fonts and scripts load from the same origin so they share one tunnel.",
    ]
    paras = []
    for i in range(12):
        rotated = sentences[i % 5 :] + sentences[: i % 5]
        paras.append(f'<p class="d{i}">' + " ".join(rotated) + "</p>")
    return "\n".join(paras)


def product_html(scheme: str, number: int | None = None) -> str:
    title = PRODUCT_NAME if number is None else f"{PRODUCT_NAME} (page {number})"
    ld = json.dumps(
        {
            "@context": "https://schema.org",
            "@type": "Product",
            "name": PRODUCT_NAME,
            "sku": PRODUCT_SKU,
            "brand": {"@type": "Brand", "name": "Fixture Works"},
        },
        separators=(",", ":"),
    )
    next_data = json.dumps(
        {"props": {"pageProps": {"sku": PRODUCT_SKU, "marker": NEXT_DATA_MARKER}}, "page": "/product/[id]"},
        separators=(",", ":"),
    )
    imgs = "\n".join(
        f'<img src="{p}" width="{w}" height="{h}" alt="{PRODUCT_NAME} view {i + 1}">'
        for i, (p, (w, h, _)) in enumerate(IMAGES.items())
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} | Fixture Shop</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://origin-c.test">
<link rel="stylesheet" href="/static/style.css">
<script type="application/ld+json">{ld}</script>
<script id="__NEXT_DATA__" type="application/json">{next_data}</script>
</head>
<body>
<header><h1 class="brand">Fixture Shop</h1></header>
<main>
<h2 id="name">{PRODUCT_NAME}</h2>
<p>Price: <span id="price" data-state="pending">loading</span></p>
<p class="price-split">List price: <span class="int">129</span>.<span class="dec">99</span> EUR</p>
<p class="price-local" lang="fr">Prix : <span>{PRICE_NNBSP_TEXT}</span></p>
<div class="gallery">
{imgs}
</div>
<section class="description">
{_description()}
</section>
<iframe src="https://origin-b.test/embed" title="Reviews" width="320" height="120"></iframe>
</main>
<script src="/static/app.js"></script>
</body>
</html>
"""


STYLE_CSS = """@font-face {
  font-family: "FixtureSans";
  src: url("/static/font.woff2") format("woff2");
  font-display: swap;
}
body { font-family: sans-serif; margin: 0 auto; max-width: 960px; padding: 0 16px; }
.brand { font-family: "FixtureSans", sans-serif; letter-spacing: 0.02em; }
.gallery { display: flex; flex-wrap: wrap; gap: 8px; }
.gallery img { max-width: 100%; height: auto; }
.description p { line-height: 1.5; }
iframe { border: 1px solid #ccc; }
"""

APP_JS = (
    """(function () {
  'use strict';
  var state = { price: null, session: null, offer: null, beacon: null, worker: null, sw: null };
  window.__fixture = state;
  function done(key, value) {
    state[key] = value;
    var all = Object.keys(state).every(function (k) { return state[k] !== null; });
    if (all) { document.documentElement.setAttribute('data-fixture-state', 'done'); }
  }
  function json(r) { return r.ok ? r.json() : Promise.resolve({ price: 'status-' + r.status }); }

  fetch('/api/product.json').then(json).then(function (d) {
    var el = document.getElementById('price');
    el.textContent = d.price + ' ' + d.currency;
    el.setAttribute('data-state', 'loaded');
    done('price', d.price);
  }).catch(function () { done('price', 'error'); });

  fetch('/api/session-product.json', { credentials: 'include' }).then(json)
    .then(function (d) { done('session', d.price); })
    .catch(function () { done('session', 'error'); });

  fetch('/api/offer.json?sig=__TOKEN__').then(json)
    .then(function (d) { done('offer', d.price); })
    .catch(function () { done('offer', 'error'); });

  fetch('/api/collect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event: 'view', sku: '__SKU__' })
  }).then(function (r) { return r.json(); })
    .then(function (d) { done('beacon', d.seq); })
    .catch(function () { done('beacon', 'error'); });

  try {
    var w = new Worker('/static/worker.js');
    w.onmessage = function (e) { done('worker', (e.data && e.data.marker) || 'error'); };
    w.onerror = function () { done('worker', 'error'); };
  } catch (e) { done('worker', 'unsupported'); }

  function whenControlled() {
    return new Promise(function (resolve, reject) {
      if (navigator.serviceWorker.controller) { resolve(); return; }
      var timer = setTimeout(function () { reject(new Error('timeout')); }, 10000);
      navigator.serviceWorker.addEventListener('controllerchange', function () { clearTimeout(timer); resolve(); });
      if (navigator.serviceWorker.controller) { clearTimeout(timer); resolve(); }
    });
  }
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .then(whenControlled)
      .then(function () { return fetch('/api/sw.json').then(function (r) { return r.json(); }); })
      .then(function (d) { done('sw', d.marker + ':' + d.via); })
      .catch(function (e) { done('sw', 'error:' + (e && e.message ? e.message : e)); });
  } else {
    done('sw', 'unsupported');
  }
})();
"""
    .replace("__TOKEN__", SIGNED_QUERY_TOKEN)
    .replace("__SKU__", PRODUCT_SKU)
)

WORKER_JS = """fetch('/api/worker.json')
  .then(function (r) { return r.json(); })
  .then(function (d) { postMessage(d); })
  .catch(function () { postMessage({ marker: 'error' }); });
"""

SW_JS = """self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (event) {
  var url = new URL(event.request.url);
  if (url.pathname === '/api/sw.json') {
    event.respondWith(
      fetch('/api/sw-backend.json')
        .then(function (r) { return r.json(); })
        .then(function (d) {
          d.via = 'service-worker';
          return new Response(JSON.stringify(d), { headers: { 'Content-Type': 'application/json' } });
        })
    );
  }
});
"""

EMBED_HTML = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Embedded reviews</title></head>
<body>
<p>Reviews widget {EMBED_MARKER}</p>
<img src="{EMBED_IMAGE}" width="100" height="70" alt="reviewer">
</body>
</html>
"""

PLAIN_HTML = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Plain page</title></head>
<body><h1>Plain HTTP page</h1><p>{PRODUCT_NAME} costs {PRODUCT_PRICE} {PRODUCT_CURRENCY}.</p></body>
</html>
"""

HOSTILE_HTML = (
    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Hostile paths</title></head>\n<body>\n"
    + "\n".join(f'<img src="{p}" alt="">' for p in HOSTILE_PATHS)
    + "\n</body>\n</html>\n"
)

CF_CHALLENGE_HTML = """<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="robots" content="noindex,nofollow"></head>
<body><div class="main-wrapper" role="main"><div class="main-content">
<noscript><div class="h2">Enable JavaScript and cookies to continue</div></noscript>
</div></div>
<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=0000000000000000"></script>
</body></html>
"""

AWS_CHALLENGE_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title></title>
<script>window.awsWafCookieDomainList = []; window.gokuProps = {};</script>
<script src="/challenge-aws/challenge.js"></script></head>
<body><div id="challenge-container"></div><noscript><h1>JavaScript is disabled</h1></noscript></body></html>
"""


def _json(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


PRODUCT_JSON = _json(
    {
        "name": PRODUCT_NAME,
        "price": PRODUCT_PRICE,
        "currency": PRODUCT_CURRENCY,
        "sku": PRODUCT_SKU,
        "availability": "in_stock",
        "variants": [{"id": 1, "color": "graphite"}, {"id": 2, "color": "silver"}],
    }
)
SESSION_PRODUCT_JSON = _json({"name": PRODUCT_NAME, "price": PRODUCT_PRICE, "currency": PRODUCT_CURRENCY, "session": True})
OFFER_JSON = _json({"offer": "spring", "price": PRODUCT_PRICE, "currency": PRODUCT_CURRENCY})
WORKER_JSON = _json({"marker": WORKER_MARKER, "source": "dedicated-worker", "stock": 42})
SW_BACKEND_JSON = _json({"marker": SW_MARKER, "source": "sw-backend"})
BEACON_JSON = _json({"ok": True, "seq": BEACON_SEQ})
OPENAI_MODELS_JSON = _json({"object": "list", "data": [{"id": "fixture-model-1", "object": "model", "owned_by": "fixture"}]})


# --------------------------------------------------------------------------- responses
@dataclass
class Request:
    site: str
    scheme: str
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes = b""

    def cookies(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in self.headers.get("cookie", "").split(";"):
            name, sep, value = part.strip().partition("=")
            if sep:
                out[name] = value
        return out


@dataclass
class Response:
    status: int
    content_type: str | None = None
    body: bytes | Callable[[], Iterator[bytes]] = b""
    headers: list[tuple[str, str]] = field(default_factory=list)
    #: Length of a streamed body (``body`` callable) when known.
    length: int | None = None
    #: "length" (Content-Length), "chunked" or "close" (close-delimited).
    framing: str = "length"
    cache: str = "no-store"
    #: Value for the Server header (defaults to "fixture-origin").
    server: str | None = None

    @property
    def compressible(self) -> bool:
        return isinstance(self.body, bytes) and (self.content_type or "").split(";")[0] in COMPRESSIBLE_TYPES


def _text(status: int, text: str, ctype: str = "text/plain; charset=utf-8", **kw) -> Response:
    return Response(status, ctype, text.encode("utf-8"), **kw)


def not_found() -> Response:
    return _text(404, "not found\n")


def _common(req: Request) -> Response | None:
    path, q = req.path, parse_qs(req.query)
    if path == "/big.bin":
        try:
            size = int(q.get("size", ["1048576"])[0])
            chunk = int(q.get("chunk", ["65536"])[0])
            delay = int(q.get("delay_ms", ["0"])[0]) / 1000.0
        except ValueError:
            return _text(400, "bad size\n")
        size = max(0, min(size, 8 * 1024**3))
        return Response(200, "application/octet-stream", lambda: big_stream(size, chunk, delay), length=size)
    if path == "/chunked":
        n = int(q.get("n", ["4"])[0])
        size = max(1, min(int(q.get("size", ["1000"])[0]), 65536))
        return Response(200, "application/octet-stream", lambda: (big_bytes(i * size, size) for i in range(n)), framing="chunked")
    if path == "/close-delimited":
        size = int(q.get("size", ["5000"])[0])
        return Response(200, "application/octet-stream", lambda: big_stream(size), framing="close")
    if path.startswith("/status/"):
        try:
            code = int(path.rsplit("/", 1)[1])
        except ValueError:
            return _text(400, "bad status\n")
        if not 200 <= code <= 599:
            return _text(400, "status must be 200-599\n")
        if code in (204, 304):
            return Response(code)
        return _text(code, f"status {code}\n")
    if path == "/echo":
        return Response(
            200,
            "application/json",
            _json({"method": req.method, "body_bytes": len(req.body), "sha256": hashlib.sha256(req.body).hexdigest()}),
        )
    if path == "/redirect":
        return Response(302, "text/plain", b"redirect\n", headers=[("Location", "/")])
    if path == "/plain.html":
        return Response(200, "text/html; charset=utf-8", PLAIN_HTML.encode("utf-8"), cache="no-cache")
    return None


def _site_a(req: Request) -> Response | None:
    path = req.path
    static = "public, max-age=3600"
    if path == "/" or (path.startswith("/product/") and path[9:].isdigit()):
        number = int(path[9:]) if path.startswith("/product/") else None
        secure = "; Secure" if req.scheme == "https" else ""
        cookie = f"{SESSION_COOKIE_NAME}={SESSION_COOKIE_VALUE}; Path=/api/session-product.json; SameSite=Lax{secure}"
        return Response(
            200,
            "text/html; charset=utf-8",
            product_html(req.scheme, number).encode("utf-8"),
            headers=[("Set-Cookie", cookie)],
            cache="no-cache",
        )
    if path == "/static/style.css":
        return Response(200, "text/css; charset=utf-8", STYLE_CSS.encode(), cache=static)
    if path == "/static/app.js":
        return Response(200, "application/javascript; charset=utf-8", APP_JS.encode(), cache=static)
    if path == "/static/worker.js":
        return Response(200, "application/javascript; charset=utf-8", WORKER_JS.encode(), cache=static)
    if path == "/sw.js":
        return Response(200, "application/javascript; charset=utf-8", SW_JS.encode(), cache="no-cache")
    if path in IMAGES:
        return Response(200, "image/png", image(path), cache=static)
    if path == FONT_PATH:
        return Response(200, "font/woff2", font(), cache=static)
    if path == "/api/product.json":
        return Response(200, "application/json", PRODUCT_JSON)
    if path == "/api/worker.json":
        return Response(200, "application/json", WORKER_JSON)
    if path == "/api/sw-backend.json":
        return Response(200, "application/json", SW_BACKEND_JSON)
    if path == "/api/session-product.json":
        if req.cookies().get(SESSION_COOKIE_NAME) != SESSION_COOKIE_VALUE:
            return Response(401, "application/json", _json({"error": "session required"}))
        return Response(200, "application/json", SESSION_PRODUCT_JSON)
    if path == "/api/offer.json":
        if parse_qs(req.query).get("sig", [""])[0] != SIGNED_QUERY_TOKEN:
            return Response(403, "application/json", _json({"error": "bad signature"}))
        return Response(200, "application/json", OFFER_JSON)
    if path == "/api/collect":
        if req.method != "POST":
            return Response(405, "application/json", _json({"error": "POST only"}), headers=[("Allow", "POST")])
        return Response(200, "application/json", BEACON_JSON)
    if path == "/challenge-cf":
        return Response(
            403,
            "text/html; charset=UTF-8",
            CF_CHALLENGE_HTML.encode(),
            headers=[("cf-mitigated", "challenge"), ("cf-ray", "0000000000000000-FIX")],
            server="cloudflare",
        )
    if path.startswith("/cdn-cgi/challenge-platform/") or path == "/challenge-aws/challenge.js":
        return Response(200, "application/javascript", b"/* inert fixture challenge script */\n")
    if path == "/challenge-aws":
        return Response(202, "text/html; charset=utf-8", AWS_CHALLENGE_HTML.encode(), headers=[("x-amzn-waf-action", "challenge")])
    if path == "/challenge-aws-captcha":
        return Response(405, "text/html; charset=utf-8", AWS_CHALLENGE_HTML.encode(), headers=[("x-amzn-waf-action", "captcha")])
    if path == "/hostile":
        return Response(200, "text/html; charset=utf-8", HOSTILE_HTML.encode(), cache="no-cache")
    if path.startswith("/hostile/"):
        return Response(200, "image/png", image("/hostile/x"))
    return None


def _site_b(req: Request) -> Response | None:
    if req.path == "/embed":
        return Response(200, "text/html; charset=utf-8", EMBED_HTML.encode(), cache="no-cache")
    if req.path == EMBED_IMAGE:
        return Response(200, "image/png", image(EMBED_IMAGE), cache="public, max-age=3600")
    if req.path == "/":
        return _text(200, "origin-b\n")
    return None


def _site_simple(label: str) -> Callable[[Request], Response | None]:
    def handler(req: Request) -> Response | None:
        if req.path == "/":
            return _text(200, f"{label}\n")
        return None

    return handler


def _site_openai(req: Request) -> Response | None:
    if req.path == "/v1/models":
        return Response(200, "application/json", OPENAI_MODELS_JSON)
    if req.path == "/":
        return _text(200, "fixture api.openai.com\n")
    return None


_SITES: dict[str, Callable[[Request], Response | None]] = {
    "a": _site_a,
    "b": _site_b,
    "c": _site_simple("origin-c"),
    "openai": _site_openai,
    "background": _site_simple("background-host"),
    "badcert": _site_simple("badcert"),
}


def handle(req: Request) -> Response:
    """Route one request for ``req.site``."""
    site_handler = _SITES.get(req.site)
    resp = site_handler(req) if site_handler else None
    if resp is None:
        resp = _common(req)
    return resp if resp is not None else not_found()


def gzip_body(body: bytes) -> bytes:
    return gzip.compress(body, compresslevel=6, mtime=0)
