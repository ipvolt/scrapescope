# tests/fixtures: the local test world

A self-contained, deterministic stand-in for "the internet plus a proxy
provider", used by every scrapescope test. It never imports `scrapescope` and
never touches the network beyond loopback: fake hostnames resolve only through
a hosts map, and the fixture upstreams refuse every name that is not in it.

```python
from tests.fixtures import TestWorld, site, UPSTREAM_USERNAME, UPSTREAM_PASSWORD
```

Always import from `tests.fixtures` (pyproject sets `pythonpath = ["."]`, and
`tests/conftest.py` also puts the repository root on `sys.path`). Do not import
it as `fixtures`; that would create a second copy of every module.

## pytest fixtures (tests/conftest.py)

| Fixture | Scope | What it is |
|---|---|---|
| `world` | session | The running `TestWorld` (all servers below). Counters are shared across tests. |
| `fresh_world` | function | `world` after `world.reset()` (waits up to 5 s for idle, then forgets every record). |
| `ca_pem` | session | Path of the fixture CA certificate (PEM). |
| `hosts_map` | session | `{(fake_host, port): ("127.0.0.1", real_port)}`. |
| `connect_map_json` | session | Value for `SCRAPESCOPE_TEST_CONNECT_MAP`: `{"host:port": "ip:port"}`. |
| `subprocess_env` | function | `os.environ` copy for child processes (see below). |
| `chromium_args` | session | Chromium launch args that make the fixture certificate valid. |
| `http_upstream` / `http_upstream_noauth` | session | HTTP CONNECT upstreams, with and without Basic auth. |
| `socks_upstream` / `socks_upstream_noauth` | session | SOCKS5 upstreams, with RFC 1929 auth and without. |
| `origin_a` | session | The `OriginServer` for `https://origin-a.test`. |
| `closed_port` | function | A loopback port with no listener (for "upstream unreachable"). |

Session-wide autouse behaviour:
- `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY` (both cases), `NODE_USE_ENV_PROXY`,
  `SCRAPESCOPE_PROXY_URL`, `SCRAPESCOPE_AUTH_PROXY_URL` and `SCRAPESCOPE_EVENTS`
  are removed from `os.environ` for the whole session and restored afterwards.
- Tests marked `@pytest.mark.browser` are skipped with a reason when Playwright
  cannot launch Chromium (checked once by really launching it). Set
  `SCRAPESCOPE_SKIP_BROWSER_TESTS=1` to skip them deliberately.

`pyproject.toml` sets a 60 s default per-test timeout; browser tests here use
`@pytest.mark.timeout(120)`.

## Hostnames

| Name | Ports | Content |
|---|---|---|
| `origin-a.test` | 443, 80 | The product shop (site `a`) |
| `origin-b.test` | 443, 80 | Cross-site iframe content (`/embed`) |
| `origin-c.test` | 443, 80 | Preconnect target; tiny `/` |
| `api.openai.com` | 443, 80 | Fake LLM API: `/v1/models` (for `direct.json` routing tests) |
| `optimizationguide-pa.googleapis.com`, `update.googleapis.com`, `clients2.google.com`, `clients2.googleusercontent.com`, `edgedl.me.gvt1.com`, `safebrowsing.googleapis.com` | 443 (80 for update, clients2.google.com, edgedl) | Documented Chromium background hosts, served locally (tiny `/`, 404 elsewhere, plus the common routes) |
| `badcert.test` | 443 | Certificate from an untrusted CA (TLS-error tests) |

Every other name gets `502` + `X-Fixture-Proxy-Error: host_unknown` from the
HTTP upstream and reply `0x04` from the SOCKS5 upstream. The full Chromium
build also contacts `www.google.com`, `accounts.google.com` and
`android.clients.google.com`; those are deliberately unmapped (uncatalogued
hosts must never be called background).

One trustme leaf certificate covers every name above except `badcert.test`
(plus `localhost` and `127.0.0.1`). All origins speak HTTP/1.1 only (ALPN).

The fixture world itself stays HTTP/1.1. Most real HTTPS sites use HTTP/2,
where Playwright's `sizes()` are not wire figures (rebuilt HTTP/1.1 request
headers, no response-header size, header frames inside the body size), so
HTTP/2 coverage comes from `tests/test_helpers_playwright_h2.py`. It starts a
small Node.js `node:http2` origin with the world's leaf certificate, maps the
fixture hostnames to it through a direct-mode meter, and checks the helper's
null header sizes, cache flags and attribution, and `find`'s billed basis. It
is skipped when `node` is not installed.

## The product site (origin-a.test)

Constants live in `tests.fixtures.site`; never hard-code them.

| Path | Notes |
|---|---|
| `/`, `/product/<n>` | Product page (6.4 KB HTML, about 1 KB gzipped when accepted, `Cache-Control: no-cache`). Sets `Set-Cookie: ss_session=...; Path=/api/session-product.json`, so only that endpoint ever receives the cookie. Contains: `<link rel="preconnect" href="https://origin-c.test">`, JSON-LD with the name, `__NEXT_DATA__` with `NEXT_DATA_MARKER`, the price split across tags (`<span>129</span>.<span>99</span>`), the price as `PRICE_NNBSP_TEXT` (`129,99` U+202F `€`), 3 images, a cross-site iframe `https://origin-b.test/embed`, `app.js`. The exact string `129.99` does not occur in the HTML. |
| `/static/style.css` | `@font-face` for `/static/font.woff2` (used by the `h1`, so Chromium downloads it) |
| `/static/font.woff2` | 49,152 deterministic bytes, `font/woff2` (not decodable; Chromium still downloads it) |
| `/static/img/hero-{1,2,3}.png` | Valid, incompressible PNGs: 168,283 / 207,313 / 230,728 bytes (`site.IMAGES`) |
| `/static/app.js` | Fetches `/api/product.json` (writes the price into `#price`), `/api/session-product.json` (credentials), `/api/offer.json?sig=SIGNED_QUERY_TOKEN`, POSTs `/api/collect`, starts the dedicated worker, registers the service worker and fetches `/api/sw.json` once controlled. Sets `window.__fixture` and `data-fixture-state="done"` on `<html>` when everything has finished (`browser.PAGE_DONE_PREDICATE`). |
| `/static/worker.js` | Dedicated worker; fetches `/api/worker.json` |
| `/sw.js` | Service worker (`skipWaiting` + `clients.claim`); answers `/api/sw.json` by fetching `/api/sw-backend.json` and adding `"via":"service-worker"`. `/api/sw.json` therefore never reaches the network. |
| `/api/product.json` | `{"name":"Widget Pro","price":"129.99","currency":"EUR","sku":"WP-1000",...}` (164 bytes, `no-store`) |
| `/api/session-product.json` | 401 without the `ss_session` cookie, else the price |
| `/api/offer.json?sig=...` | 403 unless `sig == SIGNED_QUERY_TOKEN` (random-looking token), else the price |
| `/api/collect` | POST beacon, responds `{"ok":true,"seq":129}` (coincidental match for the value "129"); GET gets 405 |
| `/api/worker.json`, `/api/sw-backend.json` | Contain `WORKER_MARKER` / `SW_MARKER` |
| `/challenge-cf` | 403, `cf-mitigated: challenge`, `Server: cloudflare`, body "Just a moment..." with a `/cdn-cgi/challenge-platform/` script |
| `/challenge-aws` | 202, `x-amzn-waf-action: challenge` |
| `/challenge-aws-captcha` | 405, `x-amzn-waf-action: captcha` |
| `/hostile` | Page whose images use `site.HOSTILE_PATHS` (`<script>`, `javascript:`, Markdown image syntax in paths); each returns a tiny PNG |

`origin-b.test/embed` shows `EMBED_MARKER` and loads `/static/embed.png` (~21 KB).

Static assets carry `Cache-Control: public, max-age=3600` and a strong ETag
(`If-None-Match` gives 304). HTML, JSON, JS, CSS and text are gzipped (with
`mtime=0`, so deterministically) only when `Accept-Encoding` includes gzip;
they carry `Vary: Accept-Encoding`. The only non-deterministic bytes are the
`Date` header's value (its length is constant).

### Routes on every host

| Path | Notes |
|---|---|
| `/big.bin?size=N[&chunk=C][&delay_ms=D][&stall_after=S]` | Exactly N deterministic bytes (`site.big_bytes`), `Content-Length`, streamed in chunks of C (<= 64 KiB) with an optional delay between chunks. With `stall_after=S` (S < N) the origin sends exactly S body bytes, then stops and waits for the client to go away (60 s at most) before closing the incomplete response: a transfer of known size for tests of aborted requests |
| `/chunked?n=K&size=S` | Chunked response of K chunks of S bytes (S capped at 65,536) |
| `/close-delimited?size=N` | HTTP/1.1 response without length, `Connection: close` |
| `/status/<code>` | That status for 200-599 (204/304 without body); other codes get 400 |
| `/echo` | Any method; `{"method","body_bytes","sha256"}`; accepts chunked bodies and `Expect: 100-continue` |
| `/redirect` | 302 to `/` |
| `/plain.html` | Small page containing the price (meant for `http://origin-a.test/plain.html`) |

## Upstream proxies

Credentials (deliberately distinctive, for sentinel greps):
`UPSTREAM_USERNAME` / `UPSTREAM_PASSWORD`; additionally **any username** is
accepted with `SESSION_PASSWORD` (models provider session usernames such as
`customer-x-session-123`). The `*_noauth` upstreams accept everything.

URLs: `http_upstream.url` (with credentials), `.server` (`http://127.0.0.1:PORT`,
for Playwright `proxy.server`), `.proxy_url(username, password)`;
`socks_upstream.url` (`socks5://...`, httpx), `.url_h` (`socks5h://...`,
requests and curl need the `h` for remote DNS), `.proxy_url(user, pw, scheme=)`.

### HTTP upstream (`UpstreamHTTPProxy`)
- `CONNECT host:port` with Basic `Proxy-Authorization` -> exactly
  `CONNECT_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"`, then a
  byte-for-byte tunnel with half-close propagation.
- Missing credentials: `407`, `Proxy-Authenticate: Basic realm="fixture-upstream"`,
  `X-Fixture-Proxy-Error: auth_required`. Wrong ones: same with `bad_auth`.
  The connection stays open, so a client may retry on it (Chromium does).
- Unknown host: `502` + `X-Fixture-Proxy-Error: host_unknown`; origin refused:
  `502` + `connect_failed`. Header name: `VENDOR_ERROR_HEADER`.
- Absolute-form `http://` requests are forwarded with keep-alive (one origin
  connection reused per host). Absolute-form `https://` gets `400`
  (`https_absolute_form_unsupported`); origin-form gets `400` (`not_a_proxy_request`).
- Records: `http_upstream.records()` -> `HTTPProxyRecord` per client connection:
  `kind` (`connect`/`http`), `targets` (`host:port` per request), `methods`,
  `usernames` (as presented, `None` if absent), `auth_ok`, `statuses`,
  `request_headers` (Proxy-Authorization value shown as `<redacted>`),
  `errors`, `tunnel_established`, `bytes_from_client`, `bytes_to_client`,
  `negotiation_from_client`, `negotiation_to_client`, `payload_*`,
  `bytes_to_origin`, `bytes_from_origin`, `origin_connections`, `closed`, and the
  convenience properties `target` and `username` (last accepted).

### SOCKS5 upstream (`UpstreamSocks5Proxy`)
- Methods: 0x02 (RFC 1929) when auth is required; 0x00 otherwise. Wrong
  credentials: status 0x01, connection closed.
- ATYP 3 (domain) resolved through the hosts map; unknown names -> reply 0x04.
  IPv4/IPv6 literals are accepted only for loopback addresses. `atyp` is
  recorded so tests can assert that clients sent the hostname (remote DNS).
- Records: `SocksRecord` with `methods_offered`, `method_selected`, `username`,
  `auth_ok`, `atyp`, `target`, `reply_code`, the negotiation parts
  (`greeting_bytes`, `method_reply_bytes`, `auth_request_bytes`,
  `auth_reply_bytes`, `request_bytes`, `reply_bytes`), totals and `payload_*`.
  A successful auth + domain CONNECT always has `negotiation_to_client == 14`.

## Origins (`OriginServer`)

`world.origin("origin-a.test", "https")`. Each listener is a counting relay in
front of a threaded HTTP(S) server, so `connections()` gives exact wire bytes
per client connection (`bytes_in`, `bytes_out`, TLS included) plus
`tls_handshakes`, `tls_failures`, `sni` and `requests` (`OriginRequestRecord`:
method, path, query, headers, status, body sizes, `header(name)`). Also
`requests()`, `paths()`, `totals()`, `wait_for_path(path)`.

## Counting rules and consistency

- Upstreams count the CLIENT-side socket: bytes consumed from it and handed to
  it. Once a connection has closed, this equals what crossed the socket.
- `negotiation_*` is the CONNECT exchange (all pre-tunnel bytes including 407
  round trips and the 200 line) or the SOCKS greeting/auth/request/reply; it is
  0 for plain-HTTP connections.
- For every tunnel: `payload_from_client == bytes_to_origin == origin conn.bytes_in`
  and `payload_to_client == bytes_from_origin == origin conn.bytes_out`.
- Read counters after `world.wait_idle()` (or the server's own `wait_idle()`);
  records of open connections keep changing.
- `wait_idle()` runs `gc.collect()` once, because some clients keep sockets
  open until collection: requests keeps a socket open while its `Response`
  objects are referenced (return plain values from a helper, as the self-check
  does), requests + PySocks and httpcore's SOCKS error path hold sockets in
  reference cycles (the latter shows up as a `ResourceWarning` under `-W default`).

## Direct mode: the connect map

`world.connect_map_json()` returns `{"host:port": "127.0.0.1:port"}` for every
mapped name, the format `scrapescope.config.parse_connect_map` reads from
`SCRAPESCOPE_TEST_CONNECT_MAP` (honoured only with `SCRAPESCOPE_TESTING=1`).
Dial the mapped address and use the fake hostname for SNI and `Host`.

`world.subprocess_env(extra=None, trust_ca=True)` builds a child environment:
proxy variables removed, `SCRAPESCOPE_TESTING=1`, `SCRAPESCOPE_TEST_CONNECT_MAP`,
`SCRAPESCOPE_TEST_CA`, and (with `trust_ca`) `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` pointing at the fixture CA.

Caution for direct-mode browser tests: the connect map only covers the names
above. The full Chromium build contacts unmapped Google hosts; a forwarder in
test mode should refuse names missing from the map, or those tests should use
the default headless shell, which sent no background traffic in our runs.

## Clients

```python
# httpx
httpx.Client(proxy=world.http_upstream.url, verify=world.tls.client_context(), trust_env=False)
httpx.Client(proxy=world.socks_upstream.url, verify=world.tls.client_context(), trust_env=False)
# requests
s = requests.Session(); s.trust_env = False
s.get(url, proxies={"https": world.socks_upstream.url_h}, verify=world.ca_pem)
# curl (-q ignores ~/.curlrc)
curl -q --proxy http://127.0.0.1:PORT --proxy-user USER:PASS --cacert CA.pem https://origin-a.test/
curl -q --proxy socks5h://127.0.0.1:PORT --proxy-user USER:PASS --cacert CA.pem https://origin-a.test/
```

### Chromium (Playwright) — measured with Playwright 1.63, Chromium 153

```python
from tests.fixtures.browser import chromium_launch_kwargs, CONTEXT_KWARGS, PAGE_DONE_PREDICATE
browser = p.chromium.launch(**chromium_launch_kwargs(world, server=world.http_upstream.server,
                                                     username=UPSTREAM_USERNAME, password=UPSTREAM_PASSWORD))
context = browser.new_context(**CONTEXT_KWARGS)          # ignore_https_errors=True
page = context.new_page(); page.goto("https://origin-a.test/")
page.wait_for_function(PAGE_DONE_PREDICATE)
```

- `ignore_https_errors=True` alone is not enough: Chromium refuses to register
  the service worker on a certificate error. `world.chromium_args()` adds
  `--ignore-certificate-errors-spki-list=<leaf SPKI>`, which makes the fixture
  certificate valid; the service worker then works and Chromium reuses
  connections normally (with certificate errors it opened about twice as many).
- With proxy credentials, Chromium sends CONNECT without them, gets 407 and
  retries on the same connection (`statuses == [407, 200]`).
- Idle preconnect to `origin-c.test` (a tunnel + TLS handshake, no request)
  happens only with the full build (`full_chromium=True`, i.e.
  `channel="chromium"`) and `launch_persistent_context`; the default headless
  shell and non-persistent contexts do not preconnect.
- The full build also sends background traffic through the proxy
  (update.googleapis.com, clients2.google.com:80, www.google.com, ...). The
  default headless shell sent none in our runs.
- Chromium does not support SOCKS5 authentication; use `socks_upstream_noauth`
  for SOCKS browser tests.

## Adding to the world

Keep everything deterministic, local and free of real third-party URLs (a page
that references a real host would make the browser try to reach it). New fake
names must be added to `tls.TRUSTED_NAMES`, `site.SITE_OF_HOST` and
`world.HTTPS_HOSTS`/`HTTP_HOSTS`. Run `tests/test_fixtures_selfcheck.py` after
any change.
