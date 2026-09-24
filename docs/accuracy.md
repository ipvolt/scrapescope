# Accuracy: what each figure means

scrapescope measures on your machine. Your provider bills from its own meter.
This document says how close each scrapescope figure can be to what a
provider bills, where the two can differ, and what has and has not been
checked. [method.md](method.md) describes how each figure is computed.

> **Status.** No reconciliation against any provider's billing has been
> published yet. Until one passes for a kind of workload, no scrapescope figure
> is billing-grade, and every cost is an estimate. Behaviour claims are tracked
> in [method.md](method.md#claims-to-verify), where each names its test. The
> local tests show that scrapescope's counts equal the bytes the test provider
> counted on the same connections; they say nothing about any real provider's
> billing.

## Labels

Every figure in the terminal summary, report.json and report.html carries one
of these labels.

| Label | Figures | Source | How close to a bill |
|---|---|---|---|
| **tunnel-measured** | totals; per-host bytes; tunnel and failed-tunnel counts | bytes written to and read from the socket to your provider, both directions, TLS included, with and without the CONNECT exchange | Every byte on that socket is counted. A provider may count a different subset (see below) |
| **estimated** (direct mode, "with CONNECT" only) | the with-CONNECT total in sizing mode | tunnel bytes plus, per CONNECT tunnel, the CONNECT head your client actually sent (without `Proxy-Authorization`) and a typical `200 Connection established` reply | An estimate of the negotiation part only; your provider credentials would add their `Proxy-Authorization` line on top |
| **allocated** | per-request and per-resource-type bytes; what-if figures | each host's tunnel bytes shared in proportion to the reported sizes, scaled down or up (scaling up is capped; see below) | Approximate. Per-host sums always equal the host's tunnel bytes; the split between types is an allocation |
| **unreported** (a resource type) | a host's tunnel bytes beyond its reported sizes plus an overhead allowance | tunnel records minus allocated bytes | Measured bytes that no reported request explains; never counted in what-if figures or fixes |
| **preconnect_idle**, **background:&lt;id&gt;**, **before_attach**, **unattributed** | tunnel bytes with no matching request | tunnel records plus catalogs and timestamps | The bytes are measured; the bucket is a rule-based label |
| **non-target** | direct.json hosts under `--env-all` | tunnel records | Measured, but never sent to your provider and excluded from totals |
| **hook-reported** | request sizes from the Requests and HTTPX hooks | what the library exposes | Approximate; tunnel totals stay authoritative |
| **estimated billable transfer** | every cost | tunnel-measured bytes × your rate | An estimate: see the list below |

Only [method.md](method.md) calls tunnel counts "exact", and only in the
narrow sense of a complete count of the bytes at scrapescope's upstream
socket. Elsewhere they are "tunnel-measured".

## Why a provider's figure can differ from the tunnel-measured total

- **The CONNECT exchange.** Some providers may count the CONNECT request and
  reply (including your `Proxy-Authorization` header), others only the tunnel
  payload. scrapescope reports both totals. Which one a given provider bills is
  unverified. Through a provider, the CONNECT head scrapescope forwards is your
  client's own, unchanged apart from `Proxy-Authorization`: Chromium's is
  about 236 bytes (`Host`, `Proxy-Connection` and its `User-Agent`), before
  credentials. In sizing mode the "with CONNECT" estimate uses that same head
  as your client sent it, without `Proxy-Authorization`; with a provider, the
  credentials line (`Proxy-Authorization: Basic ` plus the base64 of
  `username:password`, often 50 to 150 bytes) comes on top, per tunnel. That
  matters for workloads that open many short tunnels.
- **Plain `http://` requests in sizing mode.** scrapescope sends them to the
  target in origin form (`GET /path`) without `Proxy-Authorization`. Through
  an HTTP CONNECT provider every request carries the absolute-form target
  (`http://host[:port]` more per request line) and the credentials line
  instead. scrapescope adds no estimate for this, and the "estimated" mark on
  the with-CONNECT total reflects CONNECT tunnels only. In one local test, ten
  small identical requests moved 87 bytes up per request in sizing mode and
  196 through the test provider, 20% more for that small response.
- **Plain `http://` requests through an HTTP CONNECT provider.** A client
  sends proxy-hop headers to its proxy; Chromium sends `Proxy-Connection:
  keep-alive` (30 bytes with its line ending). scrapescope is that proxy, so
  it removes them, as it removes every hop-by-hop header, and your provider
  receives about 30 bytes less per plain `http://` request than the same
  client would send it directly. HTTPS traffic is unaffected: CONNECT heads
  are forwarded unchanged apart from `Proxy-Authorization`.
- **TLS handshakes.** They are inside the tunnel, so scrapescope counts them.
  At least one provider's public traffic documentation says it bills them
  (checked 2026-09-23); many providers do not say.
- **Units.** scrapescope defaults to GB = 10^9 bytes; `--gib` switches to
  GiB = 2^30, which is about 7.4% larger. Check which your provider uses.
- **Errors.** Providers differ on whether target error responses (403, 404,
  5xx) and their own errors (for example a 502 from the provider) are billed.
  scrapescope counts every byte on the socket, including failed tunnels.
- **Slow CONNECT replies.** scrapescope waits up to 600 seconds (its idle
  timeout) for a provider's CONNECT or SOCKS5 reply; only name resolution and
  the TCP connect have the 30-second connect timeout. A client that gives up
  and closes its connection while scrapescope waits ends the wait at once
  (status `failed:client_closed`), so the provider sees the attempt
  abandoned as it would without scrapescope. A provider may still bill an
  attempt that it was working on when the client left.
- **Rounding, minimums and dashboard lag.** A provider may round per request or
  per session, apply minimum charges, or update its dashboard hours later.
- **Plain `http://` framing.** scrapescope counts what it reads from the
  provider, before it re-frames a plain-HTTP response for your client (it
  may choose other chunk sizes, and it removes whitespace before a header
  colon, which RFC 9112 has a proxy remove). Bytes between scrapescope and
  your client can therefore differ slightly from the counted bytes; the
  counted bytes are what crossed the provider connection. A response that
  uses a transfer coding other than chunked (`gzip, chunked`) reaches
  HTTP/1.1 clients as sent; HTTP/1.0 clients get `502
  upstream-protocol-error` for it.
- **Layer.** scrapescope counts application-layer bytes on its socket. It does
  not count TCP/IP headers or retransmissions. A provider measuring at a
  different layer, or between its own servers and the target, can differ.
- **Bytes after a budget trip.** The meter stops at its own count. Data already
  in flight when the budget trips can reach the provider after scrapescope
  stops reading: roughly a few MB per open tunnel.
- **Traffic that skipped scrapescope.** A client not pointed at scrapescope is
  billed by your provider but not counted here. The bypass detector catches
  this only for clients that use the helpers or hooks.

A reconciliation protocol is planned: separate bulk, handshake-heavy and
CONNECT-heavy phases against a controlled origin, compared with two providers'
settled dashboards, in GB and GiB, with and without CONNECT. A single mixed test
would agree within a few percent whether or not per-connection overhead is
billed, because bulk bytes dominate it, so the phases are measured separately.
Results will be published as dated, per-workload statements with "estimated"
kept in the label.

## Allocated figures

A request cannot be tied to a tunnel. Chromium's connection ids are internal,
and a proxied request reports the proxy's address, not the tunnel's. So
scrapescope works per host:

- The host's tunnel bytes are measured.
- The browser reports sizes per request (encoded body, response headers,
  request headers, request body).
- The host's tunnel bytes are shared among its requests in proportion to those
  sizes, scaled down or up, so the difference (TLS handshakes and records, the
  CONNECT exchange, idle preconnects to the same host) is shared in the same
  proportion.
- Scaling down is unlimited. Scaling up is capped: the reported sizes may grow
  by an allowance of 16,448 bytes (for each tunnel that opened its own
  upstream connection) plus the negotiation bytes per tunnel, 25% of
  the reported sizes, and 512 bytes per request whose header sizes are unknown.
  Tunnel bytes beyond that go to the type `unreported`, which what-if figures
  and fixes ignore; a warning names hosts with at least 64 KB of it. Hosts with
  a successful response of unknown size (a Requests hook on a chunked body) are
  not capped.

Consequences:

- Per-type totals always add up to the host totals, but a type that happens to
  share a host with many small requests may carry more or less overhead than it
  really caused.
- Tunnel bytes are attributed to the authority in the CONNECT request. If a
  client reuses one tunnel for several hostnames (HTTP/2 connection
  coalescing), all of that tunnel's bytes count under the authority named in
  its CONNECT request.
- **Request header sizes (HTTP/1.1).** Playwright rebuilds
  `requestHeadersSize` as the method, the URL's path, ` HTTP/1.1` and the raw
  headers, without the query string and without the final blank line. That
  is not the request line a proxy receives, so reported request heads sit
  slightly below the wire on every route; the allocation's allowance absorbs
  the difference. For plain `http://` requests the helper also leaves out
  the proxy-hop headers Chromium sends to scrapescope (`Proxy-Connection`,
  and `Proxy-Authorization` after a 407), which scrapescope removes; `find`
  does the same for its billed basis.
- **HTTP/2 and HTTP/3.** Playwright rebuilds the request-header size as
  HTTP/1.1 text (about 550-780 bytes per request, while HPACK and QPACK send far
  less) and reports no response-header size. For such requests (a
  pseudo-header such as `:authority` in `all_headers()`, or
  `responseHeadersSize == 0` on a response) the helper writes both header
  sizes as null, and `encoded_body_bytes` includes the response header frames.
  Without this, per-type sizes on HTTP/2 sites would add up to more than the
  tunnels carried.
- **Failed requests** have `encoded_body_bytes` null: Playwright's figure there
  is the declared `Content-Length`, not what was transferred.
- **Requests in flight at navigation or close** get no Playwright event. The
  helper writes them as failed with unknown sizes when the context or browser
  closes, or at interpreter exit for contexts never closed; WebSockets still
  open at close are written too. Their bytes then appear as `unreported`.
- **HTTP cache.** Whether a response came from the cache is inferred, because
  Playwright exposes no flag. A memory-cache hit is recognised by
  `responseBodySize < 0`. A disk-cache hit reports its full size and is
  recognised by carrying only the provisional request headers. That test is
  used only after the context has shown wire-level headers and while no route
  or HTTP/proxy credentials are active, because request interception makes
  network requests look the same, and a candidate is held until the context
  has shown wire-level headers, or decided at once when its response came from
  a proxy other than the current meter (an entry cached by an earlier run), or
  decided when the context closes (a cache hit for Chromium and unknown
  browsers). Service-worker script fetches are never cache candidates;
  DevTools reports the bodies of worker and service-worker scripts as 0.
  Redirects and failed requests are never cache hits. Checked with Chromium
  153. In Firefox and WebKit contexts a cacheable response whose
  `response.server_addr()` is empty is a cache hit, written at once with
  sizes 0 (checked with Firefox 155 and WebKit 26.6); this costs one extra
  Playwright round trip per cacheable request there. A request that shows
  wire-level request headers, or under request interception has a server
  address, is a network request even if Playwright marks it as served by a
  service worker: with a warm profile the worker may not be running yet and
  the network answers. It is written with the header sizes as reported and
  an unknown body size (DevTools reports 0). The report's status line is labelled "status (network
  requests; failed = no response)", and next to it "not network requests: N
  request event(s)" counts HTTP-cache hits, service-worker answers, and
  requests answered or stopped before the network (`route.fulfill`,
  `route.abort`, browser blocks such as mixed content). Those events stay out
  of the status line, the per-type figures and the bypass check, and a warning
  counts them by kind.
- Dedicated-worker requests are recognised by a heuristic (Playwright reports
  them as requests of the page's frame). Shared workers are not exposed.

### Proxy credentials turn off Chromium's HTTP cache

Playwright disables Chromium's HTTP cache whenever a browser or context holds
proxy or HTTP credentials. With the helper's `proxy_settings()` or `launch()`
without a username, the cache stays on, because scrapescope adds your provider
credentials itself. If your job passes a username and password (at launch or
per context), later page loads re-download assets they would otherwise take
from the cache. That is also how the job behaves without scrapescope, so the
measurement is faithful, but a fix that assumes a warm cache will overstate its
saving.

## Buckets

Tunnels of hosts with no matching request are labelled by rules, not by
observation of what the browser intended:

- **background:&lt;id&gt;** only for hosts in the background catalog, each entry
  backed by an evidence link. Chromium traffic to an uncatalogued host lands in
  `unattributed` rather than being guessed.
- **preconnect_idle** applies only to tunnels that did not fail, and uses
  thresholds of 3,072 payload bytes up and 6,144 down,
  typical of a TLS handshake with no request. The upload limit is 3 KB rather
  than 2 KB because Chromium's post-quantum TLS ClientHello alone is about 2 KB
  (measured with Chromium 153). A short real request to a host the helper did
  not see could fall under the same threshold.
- **before_attach** depends on wall-clock timestamps from two processes, the job
  and scrapescope, on the same machine.

## Units, per-unit figures and success

- **Units** are Playwright main-frame navigations (excluding 3xx redirect hops),
  or hook-counted requests (excluding 3xx), or `--units N`. A navigation is not
  necessarily a page of results; use `--units` when your job's unit is
  different. Fewer than 20 units carries a warning, because per-1,000 figures
  from a handful of pages are noisy.
- **First unit versus the rest** and **bytes before the first navigation** come
  from a timeline kept at 0.25-second resolution, so they are approximate to one
  timeline step, and concurrent pages blur the split. A timeline step that
  starts before the first navigation but ends after it is counted in the first
  unit, so pages that load within one step are not reported as traffic before
  the first navigation. A navigation unit starts at the start of its redirect
  chain: the first 3xx main-frame navigation in the same context since that
  context's previous non-3xx navigation, each hop within 30 seconds. The step
  that straddles the second unit's start goes to the rest, mirroring the rule
  for the first unit. When the first two units started less than one step
  apart, the first-unit/rest split (`per_unit`) is withheld (null, with a
  warning), because the first unit would absorb the others; the bytes before
  the first navigation are still given.
- **Browser launches** come from `launch` events: `launch()` and
  `instrument(context)` record them, once per underlying browser. For a
  persistent context, `record_launch(context)` covers Playwright releases
  whose persistent context has no Browser; Playwright 1.63 exposes
  `context.browser` there, and `record_launch(context)` plus
  `instrument(context)` count one launch in either order. When browser request types exist but no launch was
  recorded, the report says "browser launches: not recorded" instead of 0.
- **Success** is a 2xx or 304 status on a unit request that did not fail. A 200
  can still be a challenge or an empty page; scrapescope does not inspect page
  content outside `find`.

## Hook-reported sizes

- **HTTPX**: `response.num_bytes_downloaded` when the response is closed, that
  is after the body is read (bytes as received, before decompression). A
  streamed response that is never closed is recorded when it is garbage
  collected.
- **Requests**: Requests runs response hooks before it reads the body, so the
  hook writes its event later: when your code has read the body to the end or
  closed the response, or when the response is garbage-collected or the
  interpreter exits. The body size is then the raw bytes urllib3 read
  (before decoding; for a `stream=True` response read only in part, what was
  read). It is unknown (null) for chunked bodies, and never the declared
  `Content-Length`.
- Header sizes are rebuilt as HTTP/1.1 header blocks from the headers the
  library exposes; headers added below the library are not seen. On HTTP/2
  and HTTP/3 (`httpx.Client(http2=True)`, an HTTP/2-capable urllib3) both
  header sizes are written as unknown (null), because HPACK and QPACK send far
  fewer bytes than the rebuilt text; attribution then applies its allowance
  for unknown headers.
- HTTPX 0.28 cannot send a plain `http://` request to an IPv6 literal
  through an HTTP proxy (it writes the absolute-form target without brackets,
  `GET http://::1:8080/x`, and scrapescope answers `400 bad-request`), and it
  rejects legacy IPv4 spellings such as `1.2.3.04`. The same limit applies
  to `find --verify`, which uses HTTPX: the replay of such a URL is `not
  tested (the meter answered itself (bad-request))`.
- Requests that fail before any response are recorded only by
  `instrument_requests()` and `instrument_httpx()`, which wrap `send`; the plain
  `httpx_event_hooks()` dictionaries cannot see them.
- Hook figures are for per-request context; tunnel totals remain the
  authoritative figures.

## find's billed basis

`find` ranks matches by encoded body bytes + response header bytes + request
header bytes + a fixed TLS handshake estimate of 7,200 bytes for `https`. It
approximates one standalone fetch of that response on a new connection, by a
client that accepts the same compression as the browser. It does not include
the CONNECT exchange, a second handshake after a failed resumption, or
redirects. The 7,200-byte figure is a typical value from local measurements,
not a constant; certificate chains vary by site.

- **HTTP/2 and HTTP/3** responses (most HTTPS sites) have no separate header
  sizes in DevTools: the encoded body already includes the response header
  frames, and the rebuilt HTTP/1.1 request-header size is left out. Such
  matches are marked `multiplexed` and both header fields are 0.
- **Compression.** The body size is what the browser received, often `br` or
  `zstd`. A client that cannot decode those gets a larger body: `curl
  --compressed` only asks for `br`/`zstd` when curl was built with brotli and
  zstd (stock macOS curl 8.7.1 has neither), and HTTPX needs
  `httpx[brotli,zstd]`. For the books.toscrape.com product page on
  2026-09-23, a client that accepted `br` received 2,391 body bytes and a
  gzip-only client 9,279 bytes, uncompressed. `find` records each match's Content-Encoding, warns about
  `br`/`zstd` matches, and the httpx snippet says which extras to install.
- **`--verify`** reports the body bytes the replay received and the replay's
  billed basis (those bytes + its header bytes + the same TLS estimate); a
  warning compares it with the browser's figure when it is more than 1.2 times
  larger, and names what the replay accepted. The replay always sends
  `Accept-Encoding: gzip, deflate` and decodes the body itself under the size
  cap, so its Accept-Encoding differs from the starter code's when brotli or
  zstandard are installed. A response with several content codings or with
  `br`/`zstd` is `not tested` ("unsupported content encoding").
- **The share line** (`share: P% of this page load (...)`) compares like with
  like: the top match's body and headers against the DevTools-reported bytes
  of the page load, with the TLS estimate left out of both. The page load
  leaves out responses served by a service worker or the HTTP cache. The top
  match is the first-ranked response with all values, network copies before
  cached or service-worker ones. The share is shown only when that response
  gets starter code; it is called a saving only when the `--verify` replay of
  that response returned its values and the replay itself moved less than the
  page load, never for a response that is the whole page load, and otherwise
  the line says why not (not replayed yet, the replay failed or was not
  sent). The replay's figure is compared like for like too: its body and
  headers, with the TLS estimate left out. When it moved more than 1.2 times
  the browser's copy (a `br` copy replayed with gzip and deflate only), the
  line adds what the replay moved and its own share of the page load; when
  it moved at least as much as the whole page load, the line reads `no
  saving for a client that accepts only gzip or deflate: the --verify replay
  moved about X B body and headers, more than this page load` (or `as much
  as`). For the README's books.toscrape.com demo on 2026-09-24: 1.4% for the
  browser's `br` copy (2,592 B), and about 9,753 B, 5.3% of the page load,
  for the replay. An ineligible top match gets `share of this page
  load: not shown for rank N (<why>)`. The report prints the terminal's own
  line. The hosts table names the `--verify` replay only on the host of the
  match actually replayed, chosen as `find` chose it: a higher-ranked match
  withheld only for the cookies or token header it sent stays ineligible when
  its replay said no, and still carried the replay. A known limit: the
  labels (`labels.unattributed`, the buckets and the hosts table) name the
  replay only when it said `yes` or `no`. A replay that was sent but came
  back `not tested` (a gateway error, over the size cap, an unsupported
  encoding, past its deadline) still moved tunnel bytes, which the totals
  and the `meter:` line's replay figure include, but the labels then read
  "find page load".
- **Responses served from Chromium's HTTP cache** (body + headers ≤ 0) are
  labelled `served-from-cache` with sizes 0, since nothing crossed the network;
  they are dropped when a network copy of the same URL matched. Warnings report
  both cases.

Other limits of `find`:

- A `--verify` "yes" is a single spot check from your machine at one moment. It
  does not show that the response will keep working, at volume, or from other
  exit locations.
- Requests from dedicated workers cannot be told apart from frame requests in
  Playwright, so they are inspected but labelled by resource type only.
- When your provider answers 407, Chromium waits for credentials instead of
  failing. scrapescope watches its own tunnel records and ends the page load
  early with "the upstream proxy answered 407"; the same applies to a SOCKS5
  authentication failure or an unreachable provider.
- XHR, fetch, iframe documents and any non-2xx or 202 sub-response are
  classified with the challenge catalog. A challenged one is not searched and is
  counted as skipped ("challenge page"), with a warning naming the vendor, so a
  "not found" says that a data request was challenged.
- The report and the terminal also show the page load's tunnel-measured total
  (the `meter:` line), which is the figure to compare with a bill; the ranking
  uses DevTools sizes. The line's failed count leaves out tunnels the browser
  closed before they opened (`failed:client_closed`; Chromium drops
  speculative connections) and names them separately. The report's tunnel
  counts, hosts table and Diagnostics still count them as failed
  (`client_closed`): for en.wikipedia.org/wiki/Mount_Everest on 2026-09-24
  the line read `in 16 tunnel(s) (0 failed; 6 closed by the browser before
  the tunnel opened)` and the report `16 (6 failed, 0 denied)`.

The ratio between a small matching response and the full page load compares
different things: one response against a page load that includes images,
scripts, fonts and background traffic. It shows the scale of the difference for
that page, not a saving you will get on every site.

## Sizing mode

Sizing mode (`--direct`) reproduces the transport: TCP and TLS through a proxy
hop, with one connection per client connection. It does not reproduce your
provider's exit location, the target's response to that location, blocks,
challenges, retries or slower pages. For protected targets it is a lower
bound. Re-measure a small sample through your provider before buying.

Its "with CONNECT" figure adds an estimate for each CONNECT tunnel (your
client's own CONNECT head without credentials, and a typical reply). Plain
`http://` requests get no such estimate: in sizing mode they go to the target
in origin form without `Proxy-Authorization`, while a provider would receive
the absolute-form target and your credentials line on every request (see
"Plain `http://` requests in sizing mode" above).

## What-if figures

- Each what-if reads "would remove about X (Y% of this run, modelled)". The
  `unreported` type never counts.
- **Blocking images, media and fonts** reports those types' allocated bytes. It
  does not model the page behaving differently when they are missing (lazy
  loading, layout-triggered requests, anti-bot reactions), or cache effects. It
  says "cache loss not modelled" when a context loaded more than one page.
- **Denying background hosts** reports the catalogued background buckets. Some
  of that traffic may recur later in a longer run, or stop by itself.
- Each what-if says "compare a second run". The second run is the measurement;
  the what-if is a prediction.

## Blind spots

- **Hosted browsers** (cloud browser services): their proxy traffic leaves
  from the service's cloud, so a local meter cannot see it. scrapescope makes
  no claims about them.
- **Clients not pointed at scrapescope**: counted by your provider, not here.
- **UDP, QUIC and WebRTC**: scrapescope carries TCP only. That Chromium does
  not use QUIC (HTTP/3) through an HTTP proxy, so its traffic stays inside the
  metered tunnels, was checked for Playwright's headless shell on 2026-09-23
  (two en.wikipedia.org loads: HTTP/2 only, no UDP sockets in the job's
  processes); headful Chromium was not checked. WebRTC is different: a
  page's `RTCPeerConnection` can send STUN and media over UDP straight from
  your machine, past the meter and your provider, and neither sees or bills
  those bytes (a local test saw STUN packets leave a `find` browser before the
  fix). `find` launches Chromium with
  `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, so its browser
  sends none. Browsers in your own jobs keep their WebRTC behaviour unless you
  pass that switch (the Playwright helper's `launch(...,
  webrtc_proxied_only=True)` does); their WebRTC UDP is then missing from
  every figure here.
- **DNS**: with a provider configured, target names are resolved by the
  provider and that traffic is not visible. The exception is direct.json hosts
  under `run --env-all`, which scrapescope resolves and connects to from your
  own IP address. In sizing mode, scrapescope resolves names with the system
  resolver and refuses non-global addresses unless `--allow-private-targets`;
  DNS traffic is not counted.
- **Firefox and WebKit** (Playwright without DevTools network data): with the
  helper, per-type figures come from Playwright's own sizes, and cache hits
  are recognised by a missing server address. They are unverified: a warning
  says so ("per-type figures for Firefox are unverified: ...", naming WebKit
  when it was launched), and
  their request events are kept out of the bypass volume check (hooks still
  count). Other browsers without the helper: totals only.
- **Windows**: untested in v1.

## Costs

Costs are `bytes / unit × your rate`, shown with and without CONNECT, per run,
per 1,000 units and, when success is known, per 1,000 successes. They leave out
plan tiers, minimum commitments, per-request fees, taxes, rounding and
everything listed above. They are labelled "estimated billable transfer" and
appear only when you pass `--rate`. scrapescope has no default rate.
