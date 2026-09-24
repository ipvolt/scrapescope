# Method: how scrapescope measures

This document explains what scrapescope counts, where it counts it, how it
assigns bytes to hosts, resource types and buckets, how the budget works and
how `find` searches and ranks responses. [accuracy.md](accuracy.md) covers what
the resulting figures mean and how they can differ from a provider's bill.

> **Status.** Checked against the implementation on 2026-09-24. Every behaviour
> claim made in the documentation is listed in
> [Claims to verify](#claims-to-verify) at the end, with the test that covers
> it. A claim without a test is unverified.

## 1. Where the meter sits

```text
your job (browser, HTTP client or agent)
   │  proxy URL http://127.0.0.1:<random port>; the client's own credentials pass through
   ▼
scrapescope forwarder ── counts bytes per tunnel ── enforces the budget
   ├──► your provider: HTTP CONNECT or SOCKS5 (hostname passed on unresolved) ──► target
   ├──► direct, in sizing mode (--direct) ──► target
   └──► direct from this machine's own IP, reported "non-target" (direct.json LLM API hosts, only with run --env-all)

helpers and hooks in your job's process ── metadata only ──► private events file
forwarder + events ──► terminal summary · report.json · report.html
```

The forwarder is a loopback proxy written with Python's asyncio and `h11`. It
accepts two kinds of request from your job:

- `CONNECT host:port`, which opens a tunnel. Everything after that (usually
  TLS) is relayed as opaque bytes. scrapescope never terminates or inspects
  TLS.
- Absolute-form `http://` requests (`GET http://host/path HTTP/1.1`), which are
  relayed with HTTP/1.1 framing and keep-alive on both sides (section 3).

Everything else is refused before any contact with the provider; see
[security.md](security.md) for the responses.

## 2. Tunnels

A **tunnel** (a tunnel record in the report) is one client connection's
traffic to one authority (`host:port`) over one upstream connection.
scrapescope never pools or shares upstream connections, and it never changes
hostnames or usernames. It opens no connections of its own: every upstream
connection belongs to one client connection. The extra hop does add a little
latency, and a browser schedules its HTTP/1.1 connections by timing, so a
browser can open a different number of connections through the meter than
without it. On loopback in the test world,
Chromium opened one extra connection in five of eight three-page runs through
the meter; with a 20 ms delay in front of the test provider (a stand-in for a
real provider's round trip) the counts were identical in every run.

If a keep-alive plain-HTTP client connection switches to a different host,
scrapescope starts a new tunnel record at the request boundary, so per-host
counts stay exact. Through an HTTP CONNECT provider the upstream connection is
to the provider, and clients such as Requests, urllib3 and Chromium keep one
proxy connection for plain `http://` requests to any host; so the connection
is kept, as the client itself would keep it, and the new record names the
previous one (`continued_from`). Providers that rotate the exit IP or bind a
sticky session per connection therefore see the job's own pattern. On SOCKS5,
direct and non-target routes the upstream connection goes to the target
itself, so a host switch closes it and opens a new one. Report "tunnels" count
records; on the HTTP CONNECT route with such clients there can be more records
than provider connections (the session-reuse fix counts connections).

Each tunnel records:

| Field | Meaning |
|---|---|
| authority | the target `host:port` as the client asked for it (an IP literal in canonical form, section 4) |
| kind | `connect` (a CONNECT tunnel) or `http` (absolute-form plain HTTP) |
| route | how it left: `http-connect`, `socks5`, `direct`, `non-target` or `refused` |
| opened / closed | wall-clock timestamps |
| upstream bytes sent / received | bytes written to and read from the socket to the provider (or to the target in direct mode) |
| negotiation bytes | the part of those bytes that was the CONNECT or SOCKS5 exchange |
| status | `ok`, `failed:<reason>`, `denied`, `budget` or `tunnel_cap` |
| upstream status | the provider's reply to CONNECT, or the last relayed HTTP status |
| CONNECT and `Proxy-Authorization` size | the size of the CONNECT head sent upstream and of its `Proxy-Authorization` line |
| auth | whether credentials were injected, passed through, mapped from the token username, or absent |

Failure reasons include `upstream_status` (the provider answered CONNECT with a
non-2xx status, which scrapescope relays to your client unchanged; and, on the
HTTP CONNECT route, a plain-HTTP record whose final responses were all 407,
which is the provider's answer: it is relayed verbatim and the record ends
`failed:upstream_status` with status 407, while a 407 followed by another
status on the same record stays `ok`, and a 407 on the direct or SOCKS5 routes
comes from the origin and is not converted),
`upstream_unreachable`, `upstream_timeout`, `upstream_closed`,
`upstream_reset` (the provider reset the connection during a relay; your client
then gets a TCP reset, not a clean close. While a plain-HTTP request body is
being forwarded, a reset gives your client `502 upstream-closed` if no
response byte had reached it, otherwise a reset; if the whole response had
already arrived, for example a 413 before the rest of an upload, the response
is relayed, the tunnel is `ok` and the client connection ends with a
lingering close), `socks_auth`, `socks_method`,
`socks_reply_<n>`, `socks_auth_unsupported` (non-Basic or over-long credentials
on a SOCKS5 route), `upstream_protocol` (the provider's reply was not valid
HTTP), `dns` (direct routes only), `private_address` (a direct route to a
non-global address, to this machine or to a host on its own IPv6 link,
section 4), `self_loop` (a name that resolves to the meter
itself, or a provider name that does), `connect_refused`, `connect_timeout`,
`local_limit` (the meter ran out of file descriptors on this machine; the
client gets `503 local-limit`), `client_closed` and `internal`. A client that
resets its connection has the reset passed on to the upstream; that tunnel
stays `ok`. The report counts failed tunnels by reason in its Diagnostics
(`upstream_status` with the provider's status appended, such as
`upstream_status_407`), and warns when every tunnel, or at least half of four
or more, failed: `every tunnel failed (<reason> xN): <hint naming $VAR>`.

## 3. Counting at the upstream socket

Every byte scrapescope writes to the upstream socket is added to "bytes sent"
when it is handed to the socket's transport. Every byte it reads is added to
"bytes received" as soon as it is read, before it is relayed to your client.
When scrapescope aborts a connection (budget, tunnel cap, stop or idle
timeout), whatever was still queued in the transport never reaches the kernel
and is uncounted again, so "bytes sent" means bytes handed to the kernel.
These counts are exact for that socket: they are the application-layer bytes
of the connection to your provider, including TLS records, HTTP/2 frames and
WebSocket frames inside the tunnel. They exclude TCP/IP headers and
retransmissions, which the operating system handles. Bytes between your client
and scrapescope are recorded only for diagnostics and never enter totals.

**Negotiation.** For an HTTP CONNECT provider, the negotiation bytes are the
CONNECT request head scrapescope sent and the reply head it read, plus the body
of a relayed non-2xx reply. For a SOCKS5 provider, they are the greeting, the
method choice, the RFC 1929 username/password exchange and the CONNECT request
and reply. Bytes read after a 2xx reply head, even in the same read, are
payload.

**Two totals.** Reports show both:

- **with CONNECT**: every upstream socket byte, negotiation included;
- **without CONNECT**: the same minus the negotiation bytes.

Which of the two a given provider bills is not known in general; see
[accuracy.md](accuracy.md).

**Direct (sizing) mode** has no negotiation. Its "with CONNECT" figure adds, for
each CONNECT tunnel, an estimate of the CONNECT exchange scrapescope would have
had with a provider:

- the request: the CONNECT head your client actually sent, as scrapescope
  would forward it to an HTTP CONNECT provider, without any
  `Proxy-Authorization` line. Chromium's is about 236 bytes (`Host`,
  `Proxy-Connection: keep-alive` and its `User-Agent`); a minimal head
  (`CONNECT host:port HTTP/1.1`, `Host` and a blank line) is 63 bytes for
  `origin-a.test:443`;
- the reply `HTTP/1.1 200 Connection established` with a blank line (39
  bytes).

Not included: your provider credentials, which a provider receives as
`Proxy-Authorization: Basic <base64 of username:password>` on every CONNECT
(often 50 to 150 bytes more per tunnel), and any headers a provider adds to
its reply. The report marks this total as estimated. These synthetic bytes
never count towards the budget. Plain `http://` requests get no estimate at
all: in sizing mode they go to the target in origin form without
`Proxy-Authorization`, while a provider would receive the absolute-form target
(`http://host[:port]` more per request) and the credentials line on every
request; the "estimated" mark reflects CONNECT tunnels only
([accuracy.md](accuracy.md#sizing-mode)).

**Plain HTTP.** For absolute-form `http://` requests, on every route:

- the `Host` header is set to the target's authority from the request line (a
  different `Host` is replaced);
- hop-by-hop request headers are removed: `Keep-Alive`, `Proxy-Connection` and
  every header that `Connection` names, except the framing headers, `Host`,
  `Proxy-Authorization`, `Upgrade` and `TE`; `Connection` itself is rewritten
  to the options that still apply (`close`, `upgrade`, `te`);
- a request with both `Content-Length` and `Transfer-Encoding` is refused with
  400 `bad-request` (request smuggling defence);
- chunked trailers are relayed in both directions, except to HTTP/1.0 clients,
  which get a close-delimited body;
- when a final response arrives while the client is still waiting for
  `100 Continue`, or either side closes after the response, scrapescope relays
  the response and then closes the client connection (with a lingering close)
  instead of waiting for the request body;
- interim `1xx` responses other than `101` are not relayed to HTTP/1.0 clients
  (RFC 9110, section 15.2);
- in a response head, whitespace between a field name and its colon is
  removed before parsing (RFC 9112, section 5.1, has a proxy remove it); a
  response with `Transfer-Encoding: <codings>, chunked` (such as `gzip,
  chunked`) reaches HTTP/1.1 clients with that header value and its
  chunk-framed body, although the chunk sizes may differ, as for any
  plain-HTTP body scrapescope relays. HTTP/1.0 clients get `502
  upstream-protocol-error` for such a response, since scrapescope does not
  decode transfer codings, and other malformed response heads still get
  `502 upstream-protocol-error`.

Through an HTTP CONNECT provider, the absolute-form request target is rebuilt
as `http://<authority as routed><path and query>`, with any fragment dropped,
instead of passing on the client's raw request target. Through a SOCKS5
provider, which carries no HTTP proxy semantics, the request is rewritten to
origin form without `Proxy-Authorization`. The counted bytes are the
rewritten bytes actually sent. CONNECT request heads are forwarded unchanged
(apart from `Proxy-Authorization`, section 4).

If a reused keep-alive upstream connection closes or resets after a request
was forwarded but before any byte of its reply, scrapescope closes (or resets)
your client's connection without a reply, so that your client's own retry of
an idempotent request applies, as it would with a direct connection; that
tunnel is `ok`. A first request on a fresh upstream connection still gets
`502 upstream-closed`.

**Totals** in the report are computed in one place from the tunnel records of
target routes (`http-connect`, `socks5`, `direct`). Non-target tunnels
(direct.json hosts under `run --env-all`) are excluded from totals, hosts and
the budget and are listed only under "non-target". Refused requests appear as
counts by reason, and denied tunnels are listed with the rule that denied them.
`tunnels` counts records; `connections` counts the upstream connections
opened (or attempted) for them, which is fewer when a kept provider
connection carried several records (section 2). The report shows a
`connections` row only when the two differ.

**Memory.** The forwarder keeps a record for every tunnel until it stops,
requests refused by a deny rule included. Measured with tracemalloc, a record
costs about 0.4 kB in the meter and about 0.8 kB once the snapshot cache holds
its copy (`serve` snapshots every 60 seconds), and about 1.1 kB while a
snapshot is alive. A snapshot holds the counting lock only while it copies
open and changed records; the per-record copies are made outside the lock, so
reports and the budget poll do not stall the relay. There is no cap on
retained records yet, so a very long `serve` session grows by about 0.8 kB per
tunnel ([security.md](security.md#resource-use)). The byte timeline (section 7) holds at most 16,384 slots: beyond
that, adjacent slots merge and the resolution doubles, and the report gives
the step in use. `serve` keeps no timeline, since its report never uses one.

**File descriptors.** Each tunnel costs the meter two descriptors. `run`,
`serve` and `find` raise their own soft open-files limit to the hard limit
(at most 65,536); `run` does it after starting the job, so the job keeps its
original limit. When descriptors run out, tunnels fail as `local_limit`, a
listener that cannot accept pauses for about a second (counted in the
report's Diagnostics), and a report warning says the failures came from this
machine. With a low hard limit, `run`, `serve` and `find` print a note at
start; raise it with `ulimit -Hn`.

## 4. Routing and credentials

For each request, in order:

1. **Deny rules** (`--deny-host`, `--deny-catalog background`): refused with
   403 and recorded as denied.
2. **Non-target hosts** (only with `run --env-all`): hosts in
   [direct.json](../src/scrapescope/catalog/direct.json) (LLM APIs only) are
   connected directly, never through your provider. **The meter resolves those
   names itself and connects from this machine's own IP address, even when a
   provider is configured, for every client of the meter (a browser
   included).** `run` prints a note saying so at start (unless `--quiet`), and
   the report carries a warning when such tunnels occurred. Cloud-storage hosts
   are deliberately not in direct.json: buckets are often scrape targets, and
   carrying them direct would expose your IP address to the bucket owner.
3. **Provider configured**: the request goes to the provider, with the target
   hostname passed on unresolved (HTTP CONNECT authority, or SOCKS5 address
   type "domain name", which means the provider resolves it). scrapescope
   never resolves target names locally on these routes; the only local lookup
   is of the provider's own hostname.
4. **Otherwise** (sizing mode): scrapescope connects directly. It resolves the
   name once, refuses destinations that are not globally routable (loopback,
   RFC 1918 private, link-local including `169.254.169.254`, CGNAT
   `100.64.0.0/10`, unique-local IPv6, unspecified, reserved and multicast;
   IPv4-mapped IPv6 addresses are checked as IPv4) with 403
   `X-Scrapescope-Error: private-address` (tunnel status
   `failed:private_address`), and connects only to the addresses it checked,
   so a second DNS answer cannot redirect it (DNS pinning). After connecting
   and before writing a byte, it also refuses a connection that reached this
   machine itself (the peer is the socket's own source address; a globally
   routable address can be this machine's own) and, for IPv6, a peer in the
   same /64 as the source address (hosts on this machine's own link), with
   the same 403. IPv4 netmasks are not visible, so IPv4 hosts on the local
   network that have public addresses are not caught. `--allow-private-targets`
   (on `run`, `serve` and `find`) turns these checks off. Non-target routes
   are exempt, because cloud private endpoints can legitimately resolve there;
   so are test connect-map entries.

IP-literal hosts are canonicalised before the self-loop, deny, direct-rule and
routing checks and in tunnel records and reports: `1.2.3.04`, `0x01020304`,
`16909060`, `1.2.772` and `::ffff:1.2.3.4` all become `1.2.3.4` (legacy
spellings follow `inet_aton`, so a leading zero means octal), and a deny glob
naming an address without `*` is canonicalised the same way. What an HTTP
CONNECT provider receives keeps your client's spelling (the CONNECT line, and
the plain-HTTP target and `Host`); over SOCKS5 a legacy IPv4 spelling is sent
as the canonical address (address type IPv4) instead of as a name.

On the two routes where scrapescope connects by itself (direct and
non-target), a name with several addresses is tried Happy-Eyeballs style (RFC
8305): address families interleaved, a new attempt every 250 ms or as soon as
one fails, within one overall connect deadline. A blackholed first address
(for example a broken IPv6 path) therefore costs about 250 ms instead of the
whole timeout.

**Deadlines.** The 30-second connect timeout bounds only name resolution and
the TCP connect (to the provider, or to the target on the direct routes).
Once connected, scrapescope waits up to the idle timeout (600 seconds) for the
provider's HTTP CONNECT reply head or its SOCKS5 negotiation replies, because
a provider may hold a CONNECT while it finds an exit or retries the target;
no reply in that time gives your client `504 upstream-timeout`. The body of a
non-2xx CONNECT reply is still read within 30 seconds. While scrapescope
waits, a client that resets its connection, or closes it without having sent
anything, ends the wait at once: the provider connection is closed and the
tunnel is `failed:client_closed`. Bytes a client sends before the 200 (a TLS
ClientHello sent early) are kept and relayed first once the tunnel is up, and
a half-close after such bytes is passed on after the 200.

Credentials follow the table in [security.md](security.md#credentials): your
client's own `Proxy-Authorization` is passed through unchanged; in `serve`, a
username of the form `ss-<token>~<provider-user>` is mapped to
`<provider-user>`; and when the client sends no credentials (or, in `serve`,
the bare `ss-<token>`), the credentials from the upstream environment variable
are injected. `run` and `find` have no token. For SOCKS5 providers,
Basic credentials become an RFC 1929 username/password. The provider's reply
to CONNECT, including 407 and 502 responses and vendor error headers, reaches
your client verbatim.

**Self-loops.** A target that is the meter itself is refused with 403
`self-loop` (`refused["self_loop"]`): `localhost` or a loopback literal on one
of the meter's ports. Loopback literals are parsed the way `getaddrinfo` parses
them, so legacy spellings (`127.1`, `0x7f.0.0.1`, `2130706433`,
`127.000.000.001`, `0177.0.0.1`) and `::ffff:127.0.0.1` are caught too. Two
more self-loops are caught when connecting, as a tunnel with status
`failed:self_loop` and a 403 `self-loop` reply: a hostname that resolves to the
meter's own port, and a provider hostname that resolves to the meter. An
upstream URL that points at the meter, in any of these spellings, is refused
at start.

## 5. Budget, tunnel cap and deny rules

**Budget** (`--budget SIZE`). The counted figure is the sum of upstream socket
bytes in both directions over all target tunnels, failed ones included,
negotiation included, synthetic estimates excluded. It is checked as bytes are
read and written, so the read that crosses the limit is counted in full: your
provider has already carried those bytes. A unit is required: `2GB`
(2 × 10^9 bytes), `500MB`, `1.5GiB` (1.5 × 2^30 bytes), or `2B` for bytes. A
bare number is a usage error (exit 2). Units mean what they say, independent
of `--gib`.

- At 80% scrapescope prints one warning, unless the same read also trips the
  budget; the report's budget events still list both.
- At 100% it records a budget event naming the (up to ten) heaviest hosts by
  upstream bytes in the final 60 seconds, closes every open tunnel (status
  `budget`), and answers every later request with 403 and
  `X-Scrapescope-Budget: tripped`.
- In `run`, it then sends SIGTERM to the job's whole process group, and SIGKILL
  five seconds later if anything is still running. The job runs in its own
  process group, so its child processes (for example browser processes) are
  stopped too. `run` exits with 86.
- In `serve`, it keeps refusing until it is restarted and exits with 86.

The meter stops at its own count. Bytes already in flight at your provider
when the budget trips can add roughly a few MB per open tunnel to what the
provider counts. In the local budget test, the test provider had handed over
about 80 KB more than scrapescope read before it closed the tunnel. Because an
abort uncounts sent bytes that were still queued (section 3), the final
counted total can end slightly below the figure in the trip event, which is
the count the meter decided on; the trip stays in force.

**Tunnel cap** (`--max-tunnel-mb N`): when one upstream connection's counted
bytes reach N × 10^6, only that connection is closed (status `tunnel_cap`).
The cap is per upstream connection. One HTTP/2 tunnel can carry many
responses, so it is not a per-response limit; and on the HTTP CONNECT route
a kept plain-HTTP provider connection carries every record that continues it
(section 2), so its count includes all of them. The budget event names the
record that reached the cap and gives the connection's count.

**Deny rules**: `--deny-host GLOB` (repeatable; `*` matches any characters
including dots, and `*.example.com` does not match `example.com`) and
`--deny-catalog background` (every host glob of every background catalog entry,
including `*.gvt1.com` and `dl.google.com`) refuse matching requests with 403
and record them as denied. The background catalog entries state their
security trade-off: component updates also deliver certificate-revocation and
Safe Browsing data.

## 6. Helper events

The helpers and hooks run inside your job's process. They append one JSON
object per line to a private events file whose path `run` passes in
`SCRAPESCOPE_EVENTS`. There is no network channel between them and the
forwarder in v1. Event kinds:

- `attach`: a helper started watching a browser context or HTTP client;
- `launch`: a browser was launched. `launch()` records it, and so does
  `instrument(context)` for the context's browser (once per browser).
  `record_launch(obj)` is idempotent per underlying browser: a context counts
  as `context.browser` when Playwright exposes one, which Playwright 1.63 does
  for persistent contexts too, so `record_launch(context)` plus
  `instrument(context)` write one launch in either order; on releases whose
  persistent context has no Browser, `record_launch(context)` is what counts
  it;
- `request`: one finished or failed request, with host, port, scheme, method,
  resource type, status, whether it failed, whether it came from the HTTP cache
  or a service worker, the kind of frame that issued it, whether it was a
  navigation, and four sizes (encoded body, response headers, request headers,
  request body). It also records whether a `Cookie` or `Authorization` header
  was sent (presence only). A path is included only with `--keep-urls`, and
  never a query string; it is cleaned like report paths (`;` parameters
  dropped, token-like segments replaced by `{token}`; [privacy.md](privacy.md)).
  A request line may also carry `"no_network": "fulfilled"`, `"aborted"` or
  `"blocked"` for a request answered or stopped before the network
  (`route.fulfill`, `route.abort`, a browser block such as mixed content);
  such events count as not hitting the network, like cache hits. Hosts that
  are IP literals are written in the meter's canonical spelling (`1.2.3.04`
  becomes `1.2.3.4`, `[2001:db8:0:0::1]` becomes `2001:db8::1`, and
  Chromium's `::ffff:102:304` becomes `1.2.3.4`), and attribution
  canonicalises request and tunnel hosts again before matching them, so the
  bypass check and its host list use the same spelling as the tunnel records.

The Playwright helper listens at the browser-context level (`request`,
`requestfinished`, `requestfailed`), not per page, so requests from
out-of-process iframes and, where Playwright exposes them, workers and service
workers are included. A request that a service worker answers is counted once:
the page's request is marked as served by the service worker, and the worker's
own network fetch is a separate event.

Sizes are what the client reports, with these rules:

- **HTTP/2 and HTTP/3** (a pseudo-header such as `:authority` among the request
  headers actually sent, or a zero response-header size on a network
  response): Playwright rebuilds the request-header size as HTTP/1.1 text and
  has no response-header size, so the helper writes both header sizes as
  unknown (null); `encoded_body_bytes` then includes the response header
  frames.
- **Failed requests** have `encoded_body_bytes` null, because Playwright's
  figure there is the declared `Content-Length`, not what was transferred.
- **Unfinished requests.** Requests still in flight when a page navigates or
  closes get no Playwright event. The helper writes them as failed with
  unknown sizes when their context or browser closes, or at interpreter exit
  for contexts that were never closed. WebSockets still open at close are
  written too. The bytes they used then appear as the `unreported` type
  (section 7).
- **HTTP cache.** Playwright has no cache flag. A memory-cache hit is
  recognised by `responseBodySize < 0`. A disk-cache hit reports its full size
  and is recognised by carrying only the provisional request headers (no
  `Host`/`:authority` or other headers the network stack adds). That second
  test is used only while no route or HTTP/proxy credentials are active,
  because request interception makes network requests look the same. A
  candidate is held until the context has shown wire-level headers; it is
  decided at once when its response came from a proxy other than the current
  meter (an entry cached during an earlier run), and otherwise when the
  context closes (a cache hit for Chromium and for unknown browsers). This
  heuristic and the holding apply only to Chromium and unknown browsers. In
  Firefox and WebKit contexts a cacheable response whose
  `response.server_addr()` is empty is a cache hit, written at once (checked
  with Firefox 155 and WebKit 26.6; one extra Playwright round trip per
  cacheable request). Service-worker script fetches are never cache
  candidates, and DevTools reports the bodies of worker and service-worker
  scripts as 0. Redirects and failed requests are never cache hits. Cache hits
  are written with sizes 0.
- **Service workers.** A request Playwright marks as served by a service
  worker is written as a network request when it shows wire-level request
  headers, or, under request interception, has a server address: with a warm
  profile the worker may not be running yet and the network answers. It gets
  an unknown body size (DevTools reports 0) and the header sizes as reported.
  Answers the worker built or fetched itself (no wire headers, no server
  address) keep sizes 0.

Hooks for Requests and HTTPX report the sizes the library exposes (see
[accuracy.md](accuracy.md#hook-reported-sizes)). The Requests hook writes its
event when the body has been read to the end or the response closed, or when
the response is garbage-collected or the interpreter exits; its body size is
the raw bytes urllib3 read, null for chunked bodies and never the declared
`Content-Length`. Both hooks write the header sizes as null on HTTP/2 and
HTTP/3.

The file is read after the job exits. Each line is validated strictly; lines
that are malformed, longer than 4,096 bytes or of another protocol version are
dropped and counted in the report.

## 7. Attribution

All attribution works on the "with CONNECT" figures, so the buckets add up to
the with-CONNECT total.

1. **First observation**: the time of the earliest `attach` event (or, without
   attach events, the earliest request event).
2. **Network requests**: request events that were not served from the HTTP
   cache, not answered by a service worker, and not answered or stopped before
   the network (`no_network`, section 6).
3. **Hosts with requests.** If any network request has host H, every tunnel of
   H is attributed. H's with-CONNECT bytes are shared over its requests in
   proportion to their reported sizes (by count when all sizes are unknown),
   scaled down or up, with largest-remainder rounding so the per-type figures
   add up to H's tunnel bytes exactly. These per-request and per-type figures
   are **allocated**.
   - Scaling down is unlimited (reported sizes above the tunnel bytes, for
     example hook sizes or WebSocket payloads).
   - Scaling up is capped at the reported sizes plus an overhead allowance:
     per tunnel, its negotiation bytes plus 16,448 bytes (twice the TLS
     handshake estimate plus 2 KiB; only for a record that opened its own
     upstream connection, not one that continues a kept provider
     connection); 25% of the reported sizes; and 512 bytes
     per request whose header sizes are unknown (HTTP/2, HTTP/3, failed
     requests). Tunnel bytes beyond that go to the type **`unreported`**:
     requests the helpers never saw (in flight when a page navigated away, a
     WebSocket still open, a client without helpers on the same host).
     What-if figures and fixes ignore `unreported`, and a warning names hosts
     with at least 64 KB of it. Hosts with a successful response of unknown
     size (a Requests hook on a chunked body) are not capped, because nothing
     limits what that response carried.
4. **Hosts without requests.** Each tunnel goes into the first bucket that
   matches:
   - `background:<catalog id>`, only when the host matches an entry in
     [background.json](../src/scrapescope/catalog/background.json);
   - `before_attach`, when it opened before the first observation;
   - `preconnect_idle`, when helpers were active, the tunnel did not fail, and
     it carried at most 3,072 payload bytes up and 6,144 down (a connection
     opened in advance and never used; Chromium's post-quantum TLS ClientHello
     alone is about 2 KB). A refused CONNECT (a provider's 402, 407 or 502, or
     any `failed:*` status) goes to `before_attach` when it opened before the
     first observation, otherwise to `unattributed`;
   - `unattributed`, otherwise.

   An uncatalogued host is never called background, however much it looks like
   browser housekeeping. Without any helper events, every uncatalogued tunnel is
   `unattributed` and the report says per-type figures are unavailable.
5. **Units** are the denominator for per-1,000 figures, in this order: `--units
   N`; else main-frame navigations seen by the Playwright helper, excluding 3xx
   redirect hops; else requests seen by the hooks, excluding 3xx; else none.
   Fewer than 20 units carries a warning.
6. **Success** (only with helpers or hooks): unit events with status 200-299 or
   304 that did not fail, and their rate.
7. **Per-unit bytes**: using the forwarder's timeline of bytes at 0.25-second
   resolution, the bytes before the first navigation, the bytes of the first
   unit (from the first unit to the second) and the mean of the rest. A
   navigation unit starts at the start of its redirect chain: the first 3xx
   main-frame navigation in the same context since that context's previous
   non-3xx navigation, each hop within 30 seconds. A timeline step that
   straddles the first unit's start belongs to the first unit, and one that
   straddles the second unit's start belongs to the rest (steps ending at or
   before the second unit's start are the first unit's). These are
   approximate to one timeline step. When the first two units
   started less than one timeline step apart, the first-unit/rest split is
   withheld (`per_unit` is null, with a warning), because the first unit would
   absorb the others; the bytes before the first navigation are still given.
8. **Status histogram** ("status (network requests; failed = no response)"):
   network requests by status, with `failed` for failures without a status.
   The other request events are counted on their own line, "not network
   requests: N request event(s): HTTP-cache hits, service-worker answers, and
   requests answered or stopped before the network (route.fulfill,
   route.abort, browser blocks such as mixed content)", and a warning counts
   them by kind. They stay out of the status line, allocation and the bypass
   check.
9. **Bypass detector.** The run is marked **incomplete** when a helper or hook
   reported a network request (scheme http, https, ws or wss; not served from
   cache or a service worker; not to a loopback host; not a failure without a
   status) and:
   - (a) its host appears in no tunnel record at all; or
   - (b) it started more than 2 seconds after every tunnel to its host had
     closed; or
   - (c) its host's helper- or hook-reported bytes exceed 1.5 × that host's
     tunnel bytes + 64 KiB (WebSocket payloads excluded): one request through
     the meter, the bulk around it. When a Firefox or WebKit launch was
     recorded, Playwright request events are left out of this volume check
     (their sizes are Playwright's own, not DevTools'; hook events still
     count), and a warning says that per-type figures for those browsers are
     unverified.

   A `403` to a request that started after the budget tripped is the meter's
   own refusal, which records no tunnel, and is not bypass. `data:` and `blob:`
   URLs are never recorded. The detector cannot see clients without helpers or
   hooks that skip scrapescope; the report says so. With
   `--fail-on bypass`, an incomplete run exits with 87, and the banner reads
   "helpers or hooks reported traffic that the meter did not carry".
10. **Multi-page contexts**: when one browser context loaded two or more pages,
    the what-if for blocking says "cache loss not modelled".

## 8. find

`scrapescope find URL --value V [--value V ...]` works as follows.

1. **Load and classify.** Headless Chromium (through Playwright, with its OS
   sandbox where available, and with WebRTC restricted to proxied connections
   by `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`) loads the
   URL once through the forwarder, with Chromium's default user agent and no
   spoofing, then waits a bounded time for the network to go quiet. A fast
   navigation error gets one retry, except errors a retry cannot fix
   (`ERR_UNSAFE_PORT`, `ERR_NAME_NOT_RESOLVED`, `ERR_INVALID_URL`, URL-scheme
   errors, `ERR_BLOCKED_BY_*`, SSL cipher mismatch, client-certificate errors,
   too many or invalid redirects, and every `ERR_CERT_*`); a timeout is not
   retried either. scrapescope ends the load early, with the reason, when the
   provider answers 407, rejects SOCKS5 credentials or cannot be reached
   (Chromium itself would wait for credentials until the timeout), when the
   budget trips, and, for an `https://` target, when the meter refused the
   CONNECT to the target itself: a private address or this machine's own in
   sizing mode ("the meter refused a private address (or this machine's own,
   or a host on its own IPv6 link); pass --allow-private-targets"), a deny
   rule, or
   a name resolving to the meter. After a failed navigation this check is
   asked again; its reason replaces the network error (shown in parentheses)
   and there is no retry. A tunnel failure to a loopback or private literal or
   to `localhost` is not retried either and adds a hint naming
   `--allow-private-targets`. For an `http://` target the meter's refusal is
   itself the main document: a reply with `X-Scrapescope-Error` and a
   `scrapescope:` body gives status `error` (exit 5), "page load failed: the
   main document is the meter's own reply (status N, X-Scrapescope-Error:
   code), not the site's: <reason>; cannot search", never "not found". An
   `http://` site could imitate such a reply, so `find` treats one as the
   meter's own only when the meter's records hold that refusal or failure
   (`find.meter_reply_check_from_snapshot`); otherwise it is searched as the
   site's response and a warning says the site sent the header itself. An
   `https://` response never counts as a meter reply, because the meter never
   terminates TLS. The main document is checked first against
   [challenges.json](../src/scrapescope/catalog/challenges.json): response
   headers (for example Cloudflare's `cf-mitigated: challenge`), cookie names,
   status codes and markers in the first 64 KiB of the body. If a challenge
   signal fires, the result is "blocked; cannot search (challenge: <vendor>)"
   and nothing is searched. Hard block pages count too: Cloudflare's 1xxx
   "Access denied" pages and Akamai's "Access Denied" page with its edge
   reference number, both on a 403 only. CAPTCHA-widget and markup rules that
   also appear on ordinary pages (a contact form with `id="captcha-form"` and
   a reCAPTCHA widget, a tutorial quoting HUMAN's `window._pxAppId` and
   `px-captcha`) need an error status (403 or 429). When the main document's
   status is 400 or more and no challenge rule fired, the page is searched,
   and a value that is not found is explained by that status (naming a vendor
   whose signals are present) instead of by scrolling or clicking. The
   classifier only recognises challenge pages; it never tries to get past
   them.
2. **Read.** Text bodies (`text/*`, JSON, JavaScript, XML) from the whole
   browser context, frames and workers included, are read into memory up to a
   size cap (5 MB per body by default, `--body-cap-mb`). Sub-responses are
   classified with challenges.json too: XHR, fetch, iframe documents and any
   non-2xx or 202 response. A challenged sub-response is not searched; it is
   counted as skipped (`challenge page`) and a warning names the vendor, so a
   "not found" says that a data request was challenged. Everything not read is
   counted by reason: over the cap, evicted before it could be read, in a frame
   or worker without a session, WebSocket, binary, failed, no body, challenge
   page, other. Sub-requests the meter answered itself (refused or failed
   upstream) are not searched: they count as skipped `failed`, and a warning
   says how many and why.
3. **Match.** Each value is searched as given and in variants: JSON and
   JavaScript escapes (`\uXXXX`, `\xNN`, `\'`, `\u{X}`, surrogate pairs,
   HTML-safe escapes such as `&` and `<` from Next.js, Rails or PHP's
   `JSON_HEX_*`, double-escaped strings such as Next.js RSC payloads, and HTML
   entities inside JSON strings), decoded in HTML documents, inline scripts,
   JavaScript and JSON bodies; HTML entities, also in JSON and JavaScript
   bodies without any backslash escape (a JSON leaf holding `&amp;` still gets
   its `json-key:` location); number formats; a value with one currency
   symbol (£ $ € ¥, US$ ...) or ISO 4217 code before or after the number also
   matches the bare number (`variant:number-format`); U+00A0 and U+202F spaces
   normalised; the visible text of HTML with tags stripped (so a price split
   across tags still matches); and a case-insensitive form. Number formats
   cover thousands separators, a decimal comma or point and trailing zeros,
   with rules that keep a match to the same number: `1,000` is a thousand,
   never 1; decimal zeros never form a three-digit group (`4.5` is not
   `4,500`, and `1000` is not in `1,000,000`); a space- or apostrophe-grouped
   number is not continued (`12345` is not in `12 345 678`); leading zeros are
   kept (`007` is not `7`). Round 4: a number uses one kind of thousands
   separator, and its decimal separator must differ from it (`1,234.567` is
   not 1234567); a value without a sign is not found right after a minus sign
   (`42` is not in `-42`, `−42` or `1e-42`, while `ABC-42` and `2020-2024` are
   hyphens and still match), and a value with a leading `-` is not found
   where the `-` follows a letter, digit or underscore (`-42` is not in
   `ABC-42`, `v2-42` or `1e-42`; U+2212 is always a minus sign). A leading
   `+` as typed is not found there either, but the number formats read `+`
   as no sign, so `+42` matches wherever `42` does (in `ABC+42` as
   `number-format`); for a whole-number value (`1994`, `1 994`,
   `5,000`, `1994.00`) a single thousands dot such as `1.994` counts only next
   to a currency (`1.994 EUR`, `EUR 1.994`, `kr 1.994`, `1.299,-`), while two
   dot groups or a following decimal comma need none; in a parsed JSON body,
   number tokens are compared as numbers (`.` is a decimal point, `,`
   separates array elements), for the exact test too: `1,299` is not in the
   list `[1,299]`, nor `12,5` in `[12,5]`, while a token equal to the value as
   typed is exact. Limits: in JavaScript, CSS and JSON embedded in
   HTML, `[1,994]` still reads as 1994, and a German `1.994` without a
   currency is not matched for 1994 (a deliberate false negative). Any value whose first or last
   character is a digit needs digit boundaries on that side to be `exact`:
   `51.77` is not exact inside `151.77` or `51.775`, and `22 available` is not
   exact inside `122 available`. Such a hit is the weakest kind,
   `variant:substring`; it is shown, but never counts as found: it is left out
   of the values matched, "all values", the status, the exit code and
   `--verify`'s "yes", and a response with only such hits is not listed.
   Space, no-break, narrow no-break and thin space and apostrophe group
   separators are number boundaries only when no three-digit group continues
   the number; commas between the elements of an array or list are element
   boundaries (so `42` is found in `[41,42,43]`); a parsed JSON leaf equal to
   the value counts; and letter currencies (`zł`, `kr`, `Kč`, `Ft`, `lei`,
   `руб.`, `R`, `Rs` and others on a closed list) are currency affixes like
   symbols. Location labels use the same boundaries. Each
   match records, per value, whether it was exact or which variant matched and
   where: document, XHR, fetch, script, an embedded block (`__NEXT_DATA__`,
   JSON-LD), a JSON key path (`json-key:offers.price`), HTML text, or the text
   of a script, stylesheet, XML, SVG, plain-text or JSON body (`script-text`,
   `css-text`, `xml-text`, `svg-text`, `plain-text`, `json-text` for a JSON
   match outside every leaf, such as in a key). Variant matching covers the
   whole JSON body; the 200,000-node limit (`MAX_JSON_NODES`) applies only to
   listing JSON key paths. Bodies are discarded after the search.
4. **Rank.** Responses containing all the values come first, then more values
   matched before fewer, then fewer `variant:substring` hits, then network
   responses before copies served by a service worker or the HTTP cache, then
   the **billed basis**: encoded body bytes + response header bytes + request
   header bytes + one new TLS handshake estimate (7,200 bytes for `https`).
   This approximates what a standalone fetch of that one response would move
   through a proxy, by a client that accepts the same compression. On HTTP/2
   and HTTP/3 there are no separate header sizes: the encoded body already
   includes the response header frames, and the request-header size (rebuilt
   HTTP/1.1 text, not the compressed bytes sent) is left out; such matches are
   marked `multiplexed`. Responses served from Chromium's HTTP cache (body +
   headers ≤ 0) get the location label `served-from-cache` and sizes 0, and are
   dropped when a network copy of the same URL matched; warnings report both
   cases. At most 20 matches are kept. A value shorter than five characters or
   made only of digits, spaces and `.,` (after removing a currency symbol or
   code) triggers a warning naming that value ("value 2 is short or
   numeric-only"), because a match for it alone is often a beacon or an ID.
   The warning is left out when nothing was searched (blocked, page load
   failed) and when the top match also holds, as itself, one of the other
   values that is not short.
5. **Coverage.** The output always carries a coverage line, for example
   `not found in 41 inspected responses; skipped: 2 binary`. When a value is in
   no inspected response, a warning printed under the coverage line (and kept
   in report.json) reads `not found: value N; only responses of the initial
   page load were inspected; content loaded later by scrolling, clicking or
   timers is not covered`. A value that is not found may still be computed by
   scripts; scrapescope never claims that the page computed it.
6. **Flags.** Each match shows whether the request actually sent cookies or an
   `Authorization` header (presence, not whether they were needed), whether it
   carries a random-looking token, whether the host is third-party (the last
   two host labels differ from the page's; a heuristic without a public-suffix
   list) and whether the method was not GET. Random-looking query values: JWTs
   and UUIDs in any case, 16 or more hex characters, 20 or more base64url
   characters with both cases, 20 or more id characters in either case with at
   least five letter/digit alternations, and 16 or more mixed letters and
   digits. A token embedded in a compound value counts too: a JWT anywhere, a
   run of 16 or more hex characters, or a random part after splitting on
   `~ = : , . ; | !`. So does any parameter whose name looks like a session or
   signature (matched per word: `token`, `session`, `sid`, `sig`, `auth`,
   `csrf`, `xsrf`, `hmac` and similar, plus `__token__`, `hdnts`, `policy`,
   `key-pair-id`, `cfid`, `cftoken`, `jsessionid`, `phpsessid`,
   `aspsessionid*` and `api_key`), with any non-empty value. A sent request
   header that looks like a credential or session token also withholds code,
   with its own reason, "sent a token header", and the flag `token-header`
   (`sent_token_header` in report.json, kept when a `--verify` replay without
   it said yes and shown next to `sent-cookies` when both were sent):
   a name with the word `key`, `token`, `session` and similar (`x-api-key`,
   `x-csrf-token`, `x-session-id`), or an `x-` header whose value holds a
   random-looking token; only presence is recorded, and headers browsers add
   themselves (`x-client-data`) are ignored. Path segments count when
   reports would show them as `{token}` (a JWT, a UUID, 24 or more hex
   characters, or 32 or more base64url characters mixing cases and digits; one
   heuristic shared with the report's path cleaning), and so do `;name=value`
   path parameters such as `;jsessionid=`; the reason is then "random-looking
   token in the path" (so UUID product ids and git-hash build ids in paths
   withhold code).
7. **Starter code.** `curl --compressed` and `httpx` snippets are printed only
   for GET matches with a 2xx status that sent no cookies, no `Authorization`
   header, no token header and no random-looking token. While some response
   holds every value, only such a response gets starter code; eligible
   responses that lack a value are listed with their count (`rank 2 (holds 1
   of 2 values)`). When no response holds every value, the heading of the
   starter code says what it lacks: `holds 1 of 2 values (value 2 is not in
   it)`. The curl command gets
   `--globoff` when the URL holds `[`, `]`, `{` or `}`, so it sends exactly
   that one request. Other matches print why, by reason: cookies,
   `Authorization`, a token header or a random-looking token give "not
   emitted: this response depends on session or anti-bot state; use the page
   or the site's official API, and check its terms"; a request that is not a
   GET gives "not emitted: starter code covers GET only; the request body and
   headers are not reproduced"; a non-2xx status "not emitted: the response
   had status N" (or "the response status is unknown"); and a service
   worker's answer "not emitted: the page's service worker answered; the
   network response may differ". The snippets take your proxy from the
   environment by scheme: `HTTPS_PROXY` for `https://` URLs; for `http://` URLs
   httpx reads `HTTP_PROXY` and curl reads lowercase `http_proxy`. When the
   browser received `br` or `zstd`, the httpx snippet says to install
   `httpx[brotli,zstd]` and a warning says that clients without those decoders
   receive a larger body. Starter code appears only in the terminal, never in
   the report file.
8. **Verify.** With `--verify`, scrapescope sends exactly one GET through the
   same forwarder and provider, with no cookies, no captured headers or
   tokens, redirects not followed, the user agent
   `scrapescope/<version> (+https://github.com/ipvolt/scrapescope)` and
   `Accept-Encoding: gzip, deflate`. It replays the top eligible match, or a
   higher-ranked match that is ineligible only because of the cookies or a
   token header the browser sent (a replay candidate) when no eligible match
   holding the same values is within twice its size (body and headers). A
   candidate gets starter code only when its replay says yes (and, while
   some response holds every value, only when it holds every value too). The
   replay can go to a match that lacks a value: when every response with all
   values is neither eligible nor a candidate (a POST, say), the top eligible
   match is replayed although it lacks one, and its verify line says which. It decodes the
   body itself with a bounded zlib decoder and applies the size cap to the
   received bytes and to the decoded bytes. The result is `yes` when the
   status is 2xx and the body still contains, each as itself, every value the
   match contained as itself, `no` otherwise (with the reason), or `not
   tested` (not requested, nothing matched, no eligible match, blocked, page load failed,
   response over the size cap, `unsupported content encoding (<codings>)` for
   several codings or a coding it did not ask for such as `br` or `zstd`,
   `(<coding>, corrupt)` for a broken stream, `request failed (<Class>)`
   for a transport or client error such as an over-long URL, `not sent:
   <reason>` when the budget tripped or the upstream failed before the replay,
   `the meter answered itself (<code>)` for a confirmed meter refusal, `the
   proxy asked for credentials (status 407)`, `gateway error (status 502)` or
   `(status 504)`, since a provider's relayed gateway error looks like the
   site's own, and `replay exceeded N s` past the replay's one overall
   deadline). Content-Encoding text in reasons and warnings is reduced to
   validated coding tokens. The verify line names the replayed rank and, for a
   response that lacks a value, `holds N of M values (value K is not in it)`;
   it
   reads `N body bytes received` and the replay's billed basis (body bytes
   received + its header bytes + the same TLS estimate); a warning compares it
   with the browser's figure, naming what the replay accepted, when it is more
   than 1.2 times larger.
9. **Privacy.** The values you search for never enter the report. Paths and
   JSON-key locations are dropped when they contain a value in any searched
   form: other number formats, a bare digit run or array index equal to the
   number, repeated percent-encoding and HTML entities. Full URLs appear only
   in the terminal.
10. **Charsets.** A body's declared charset never stops the search: labels
    that are undefined, or that are not web encodings (`idna`, `punycode`,
    `unicode-escape`, `utf-7`), are read as UTF-8. An unexpected error after
    the arguments were checked is `find`'s own internal error (exit 88, report
    written), never a usage error.

**Terminal layout.** The result starts with a header, `scrapescope find:
<host/path>  (N values)`, then the coverage line, any `not found: value N`
line, and a summary line, `smallest with all values: rank N, X B
billed-basis`. When it applies, a share line follows: `share: P% of this page
load (Y B body and headers against Z B DevTools-reported, TLS left out of
both); <qualifier>`. It is shown only when that response gets starter code
and is a network response whose figures fit; the page load leaves out
responses served by a service worker or the HTTP cache. The qualifier is `a
saving: --verify replayed it without a browser` only when the replay of that
response said yes; otherwise `not a saving until --verify replays it`, `not a
saving: the --verify replay failed (...)`, `not a saving yet: the --verify
replay was not tested (...)` or `... was not sent: <reason>`, and `no saving:
this one response is the whole page load`. Round 4: the replay is compared
like for like as well (its body and headers, TLS left out), and it is called a
saving only when the replay itself moved less than the page load. When it
moved more than 1.2 times the browser's copy, the qualifier reads `a saving:
--verify replayed it without a browser, moving about X B body and headers (P%
of this page load; see warnings)`; when it moved at least as much as the page
load, `no saving for a client that accepts only gzip or deflate: the --verify
replay moved about X B body and headers, more than this page load` (or `as
much as`), followed by ` (see warnings)` when the replay warning exists. An ineligible top match gets
`share of this page load: not shown for rank N (<why>)` instead. Each match is a
table row (rank, billed basis, values, status, type, method, flags, match
kind, or `mixed` when the values matched differently), followed by the host
and path (shortened in the middle, so the file name stays; rows that share
host and path add `?<query>`, shortened, or `?(query <hash>)` for a row with a
random-looking token), one line per value with its match kind and where it
matched (a weak hit reads "(only inside a longer number; not counted)"), and
the response's own labels (iframe, service worker, served from cache) and
Content-Encoding. After the starter code and a blank line, "also eligible
(other responses that would get starter code):" lists one URL line per other
eligible rank at the outer indentation, so it is not copied with the code,
with `(holds N of M values)` for a response that lacks a value. When no
response with every value is eligible, the eligible ones that lack a value
are listed under "eligible but missing a value (no starter code while a
response holds every value):". The
verify line is left out when nothing was found and `--verify` was not
requested. With `--quiet`, `find` drops only its progress notes on stderr; the
result and the `meter:` line still go to stdout.

`find` writes a report like `run`, with the page load's tunnels and a `find`
section, and prints one `meter:` line after its result with the tunnel-measured
totals of the page load and, separately, of the `--verify` replay. Its failed
count leaves out tunnels the browser closed before they opened
(`failed:client_closed`: Chromium drops speculative connections), which it
names separately (`N closed by the browser before the tunnel opened`). The
report's totals include both, and its tunnel counts, hosts table and
Diagnostics still count those tunnels as failed (`client_closed`), so a
report can read `6 failed` where the `meter:` line read `0 failed; 6 closed
by the browser before the tunnel opened`. Its text rendering has a "Page load (find)"
section instead of units: `browser_launches` is 1 per find result,
`units.low_sample_warning` is false, the page load's tunnels are labelled
"find page load" instead of "unattributed", and it prints the terminal's own
share line (`find.render.share_line` on the find entry rebuilt from the
report) and verify line (`find.render.verify_line`, naming the replayed
rank). Its match table shows values as `all 2/2` or `some 1/2` and the match
kind as the one kind all values share or `mixed: 1 number-format, 2 exact`.
The hosts table names the `--verify` replay
only on the host of the match actually replayed (`find.render.replayed_match`,
the same choice as find's, so a replayed cookie-sending match that said no
counts, not the eligible match below it). A known limit: the labels
(`labels.unattributed`, the buckets and the hosts table) name the replay only when it
said `yes` or `no` (`report._fmt.verify_replayed`). A replay that was sent
but came back `not tested` (a gateway error, over the size cap, an
unsupported encoding, past its deadline) still moved tunnel bytes, which
are in the totals and in the `meter:` line's replay figure, yet the labels
read "find page load"; the find section's verify line still names the
replayed rank. `find` exits 0 when every value was found,
6 when some responses matched but a value was in none of them, 1 when nothing
matched, 4 when the page was a challenge page, 5 when the page did not load
(including a target the meter refused), 3 when Playwright or Chromium is
missing, 130 on Ctrl-C (without a report) and 88 on an internal error (the
meter report is still written).

## 9. What-if, fixes and costs

**What-if** figures use allocated bytes (the `unreported` type never counts):

- *Block images, media and fonts*: the allocated bytes of those resource types.
- *Deny catalogued background hosts*: the bytes in the `background:*` buckets.

Each reads "would remove about X (Y% of this run, modelled)". The blocking
what-if carries the caveat "blocking can break extraction or attract anti-bot
scrutiny; compare a second run", and adds "cache loss not modelled" when a
context loaded more than one page, since blocking methods that disable the
cache can increase transfer on later pages. The background what-if carries
the security trade-off of each catalog entry involved (component updates also
deliver certificate-revocation and Safe Browsing data) and "compare a second
run".

**Fixes** are generated only when their detection fired in your run:

| Fix (id) | Shown when |
|---|---|
| Playwright Python, cache-preserving blocking (`playwright-cdp-block`): CDP `Network.setBlockedURLs` per page for font and media URL patterns, and `--blink-settings=imagesEnabled=false` for images | the Playwright helper was used and images, media and fonts were at least 10% of the with-CONNECT total |
| Playwright `route()` blocking, as an alternative (`playwright-route-block`), with the warning that Playwright documents "Enabling routing disables http cache" and with `service_workers="block"` because routes miss service-worker requests | same |
| Refuse catalogued background hosts at the meter (`chromium-background-flags`; the id is kept for compatibility): `scrapescope run --deny-catalog background` (or `--deny-host optimizationguide-pa.googleapis.com`). For runs with Playwright helper events it adds Playwright Python code for a persistent profile launched with `proxy=proxy_settings()`, `record_launch` and `instrument`; other stacks get a stack-independent shell snippet (refuse at the meter, keep your launcher's own profile). It says that Playwright already passes `--disable-background-networking` and `--disable-component-update` and that NodeMaven saw the optimization-guide fetch with both in force, and states the security trade-off | catalogued background bytes were seen |
| Playwright MCP (`playwright-mcp-flags`), titled "If you use Playwright MCP: ...": the MCP client's server command `scrapescope run --budget 2GB --deny-catalog background --quiet -- sh -c 'exec npx -y @playwright/mcp@X.Y.Z --proxy-server "$SCRAPESCOPE_PROXY_URL" --user-data-dir ./mcp-profile'`. Its caveats say that the meter's tokenless listener (random port) exists for the life of the server with that budget, and to pin the reviewed `@playwright/mcp` release in place of `X.Y.Z`; its code comment says to give `run` the same `--upstream-from-env VAR` or `--direct` as your other runs, since MCP clients often start servers with a minimal environment and `run` exits 89 without an upstream. It does not suggest `--blocked-origins`, which is `route()`-based: it intercepts page and worker requests only and disables the cache | same (shown on background bytes whatever the stack, and labelled conditional) |
| Reuse one `requests.Session` or one `httpx.Client` (keep-alive) | hook units ≥ 10 and at least one new upstream connection per two units (tunnel records that continue a kept provider connection, section 2, do not count) |

Every fix says to verify it with a compared second run. Fix code contains no
data from your job other than catalogued hosts and the meter's port, and never
credentials.

**Costs** appear only when you pass `--rate`. They are the total bytes
(with and without CONNECT) divided by 10^9 (or 2^30 with `--gib`) times your
rate, plus per 1,000 units and, when success is known, per 1,000 successes. The
label is "estimated billable transfer".

## 10. Outputs

- **Terminal summary**: plain-text tables with labelled figures. `run` and
  `serve` print it to stderr, so your job's stdout stays clean; `find` prints
  its result to stdout.
- **report.json**: schema version 1, described by
  [schema.json](../src/scrapescope/report/schema.json) (JSON Schema draft
  2020-12, no unlisted fields allowed). [privacy.md](privacy.md) lists what it
  contains.
- **report.html** (with `--html`): one self-contained file with tables only, no
  scripts and no external resources, under a Content Security Policy that
  allows only its own inline style by hash.
- **Reports read from a file** (`scrapescope report`): fixes are never shown as
  stored, in any format (`--format json` included). Their title, detection,
  code and caveats are rebuilt by this scrapescope from the fix id and the
  file's own figures; the stored detection text is never shown, and missing
  figures give a pointer such as "see the report's buckets". The text and
  HTML renderers say so: "titles, detections, code and caveats are rebuilt by
  this scrapescope from each fix id and the file's own figures. Code and text
  stored in fixes are never shown." The schema allows only the six fix
  ids scrapescope generates, so a file with another id fails validation (exit
  2).
- **Diagnostics** in every report: requests refused before a tunnel, by
  reason; failed tunnels by failure reason (`tunnel_failures`, for example
  `upstream_unreachable 1`); how many times a listener paused for lack of file
  descriptors (`accept_limit_errors`); and helper events by kind. The two
  middle fields are optional in the schema, so older reports still validate.
- **Costs** use cents from one dollar up (`$12.35`) and three significant
  digits below (`$0.120`, `$0.00235`), at most six decimals.

---

## Claims to verify

Each row is a behaviour claim made in the README or in `docs/`, with the test
that demonstrates it. The table was walked against the implementation on
2026-09-24, after the fourth review round and its find fixes (find-r4-1 to
find-r4-8): the full suite (`python -m pytest`)
passed on macOS with Python 3.12, Playwright 1.63 and Chromium 153, browser
tests included, three times in a row (1,537 passed; 2 skipped: the two
release steps that need network or the release gate; the HTTP/2 hook test now
runs, since the development environment has the `dev` extra's `h2`), and the
tests not marked `browser` also passed with Playwright made unimportable (O16).
Linux has not been run yet. Rows marked "live" also cite a page load against
the books.toscrape.com sandbox or en.wikipedia.org on the date given. Of the
144 rows, 135 are verified or changed (two of them on one platform or browser
build only), 4 are partial (F17, R13, R15 and O1) and 5 are open (O4
reconciliation, O10 release gate, O12 CI, O13 authorship review and O14
security mailbox; none of them is a unit-test matter).

Status values: `verified` (the named tests pass), `changed` (the documentation
was corrected to match the behaviour, and the named tests pass), `partial` (a
test or the code covers part of the claim), `open` (a measurement or manual
check, not a unit-test matter), `unverified` (no test yet).

### Forwarder and routing

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| F1 | Binds 127.0.0.1 only, on a random port by default | README, security.md | `tests/test_forwarder_thread.py::test_fixed_port_and_loopback_only_binding` | verified |
| F2 | Accepts only `CONNECT` and absolute-form `http://`; absolute-form `https://` gets 400 `X-Scrapescope-Error: https-absolute-form` | method.md §1, security.md | `tests/test_forwarder_errors.py::test_absolute_https_gets_400` | verified |
| F3 | Origin-form and other request forms get a bare 403 (`Content-Length: 0`, no body, no scrapescope headers) before any upstream contact | security.md | `tests/test_forwarder_errors.py::test_origin_form_gets_bare_403`; `tests/test_e2e_serve.py::test_serve_sigterm_and_origin_form_403` | verified |
| F4 | A target that is the meter's own listener is refused with 403 `self-loop`, including legacy loopback spellings and `::ffff:127.0.0.1`; a name or provider name that resolves to the meter is refused at connect time (`failed:self_loop`); an upstream URL pointing at the meter is refused at start | security.md, method.md §4 | `tests/test_forwarder_errors.py::test_self_loop_refused`; `tests/test_forwarder_errors.py::test_ip_literal_parses_like_getaddrinfo`; `tests/test_forwarder_errors.py::test_upstream_url_with_legacy_loopback_spelling_is_refused_at_start`; `tests/test_forwarder_errors.py::test_upstream_name_resolving_to_the_meter_does_not_recurse`; `tests/test_forwarder_thread.py::test_upstream_pointing_at_the_meter_itself_is_refused` | changed |
| F5 | Never terminates TLS; CONNECT payload is relayed as opaque bytes (clients verify the origin's certificate through the tunnel) | README, method.md | `tests/test_forwarder_counts.py::test_counts_equal_fixture_upstream`; `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts` | verified |
| F6 | With a provider configured, target names are never resolved locally on http-connect or socks5 routes (SOCKS5 uses address type "domain name"); the one exception is direct.json hosts under `run --env-all`, which the meter resolves and connects to from this machine's own IP, announced at start and in the report | method.md §4, security.md | `tests/test_forwarder_errors.py::test_upstream_route_never_resolves_target_names`; `tests/test_forwarder_errors.py::test_env_all_direct_rules_resolve_locally_as_documented`; `tests/test_forwarder_upstream_replies.py::test_socks_address_types`; `tests/test_e2e_run.py::test_env_all_carries_llm_hosts_direct_as_non_target`; `tests/test_e2e_run.py::test_env_all_without_upstream_prints_no_exposure_note` | changed |
| F7 | One upstream connection per client connection, never pooled; the meter opens no connections of its own and changes no hostnames or usernames. A browser's connection scheduling can shift with the added latency: with a 20 ms provider-like delay, Chromium's upstream connections and origin handshakes through the meter are within two of a run without it (identical in the recorded runs) | method.md §2 | `tests/test_e2e_forwarder_parity.py::test_origin_connections_and_tls_handshakes_are_equal_with_and_without_the_meter` (sequential HTTP clients); `tests/test_forwarder_browser.py::test_full_page_counts_equal_fixture` (meter 1:1); `tests/test_forwarder_browser.py::test_connection_pattern_with_and_without_the_meter_under_provider_latency` | changed |
| F8 | A keep-alive plain-HTTP connection that switches host starts a new tunnel record; through an HTTP CONNECT provider the provider connection is kept, as the client kept it (`continued_from`), while SOCKS5, direct and non-target routes open a new upstream connection | method.md §2 | `tests/test_forwarder_http.py::test_authority_switch_opens_new_tunnel`; `tests/test_forwarder_http.py::test_plain_http_connection_reuse_matches_the_client_without_the_meter`; `tests/test_forwarder_http.py::test_plain_http_same_host_after_switch_keeps_one_record_per_run`; `tests/test_snippets.py::test_reuse_fix_counts_upstream_connections_not_continued_records` | changed |
| F9 | No idle timeout below 600 s once a request arrived; a connection without one complete request head 60 s after accept is closed (`FIRST_REQUEST_TIMEOUT_S`); half-close propagates | security.md, contracts §3.8 | `tests/test_forwarder_thread.py::test_idle_timeout_closes_quiet_tunnels`; `tests/test_forwarder_thread.py::test_connections_without_a_first_request_head_are_closed_early`; `tests/test_forwarder_http.py::test_half_close_propagates` | changed |
| F23 | The 30 s connect timeout bounds only name resolution and the TCP connect; the HTTP CONNECT reply head and the SOCKS5 negotiation may take up to the idle timeout (600 s; no reply gives 504 `upstream-timeout`), a non-2xx CONNECT reply's body is read within 30 s; a client that resets or closes without having sent anything ends the wait at once (`failed:client_closed`, provider connection closed); bytes sent before the 200 are relayed first and a half-close after them is passed on after the 200 | method.md §4, accuracy.md, contracts §3.8 | `tests/test_forwarder_upstream_replies.py::test_upstream_reply_timeout`; `tests/test_forwarder_upstream_replies.py::test_slow_connect_reply_is_not_cut_at_the_connect_timeout`; `tests/test_forwarder_upstream_replies.py::test_slow_socks5_connect_reply_is_not_cut_at_the_connect_timeout`; `tests/test_forwarder_upstream_replies.py::test_early_client_bytes_during_a_slow_connect_are_relayed_in_order`; `tests/test_forwarder_upstream_replies.py::test_half_close_after_early_bytes_during_a_slow_connect_still_gets_the_tunnel`; `tests/test_forwarder_upstream_replies.py::test_client_that_gives_up_during_a_slow_connect_closes_the_provider_connection` | verified |
| F10 | The provider's CONNECT reply (407, 502, vendor headers, body) reaches the client verbatim, then both connections close | method.md §4, security.md | `tests/test_forwarder_errors.py::test_upstream_407_relayed_verbatim`; `tests/test_forwarder_errors.py::test_unknown_host_502_relayed_with_vendor_header`; `tests/test_forwarder_upstream_replies.py::test_chunked_error_body_relayed_verbatim` | verified |
| F11 | Failure statuses and client-visible codes match method.md §2 and security.md, including `upstream_protocol`, `socks_auth_unsupported`, `private_address`, `self_loop`, `local_limit` and `upstream_reset` (a provider reset reaches the client as a reset; a client reset is passed upstream and the tunnel stays `ok`); on the HTTP CONNECT route a plain-HTTP record whose final responses were all 407 ends `failed:upstream_status` (a 407 then another status stays `ok`; an origin's 407 on other routes is not converted); a reset while a request body is forwarded is `failed:upstream_reset` (502 before any response byte), unless the whole response had arrived | method.md §2, security.md | `tests/test_forwarder_errors.py`; `tests/test_forwarder_upstream_replies.py::test_garbage_reply_is_a_protocol_error`; `tests/test_forwarder_auth.py::test_non_basic_proxy_authorization`; `tests/test_forwarder_http.py::test_upstream_reset_in_tunnel_reaches_client_as_reset`; `tests/test_forwarder_http.py::test_upstream_reset_mid_close_delimited_body_is_not_a_complete_response`; `tests/test_forwarder_http.py::test_client_reset_in_tunnel_is_passed_to_the_upstream`; `tests/test_forwarder_errors.py::test_out_of_descriptors_is_local_limit_not_the_target_refusing`; `tests/test_forwarder_upstream_replies.py::test_plain_http_407_from_the_provider_is_a_credential_failure`; `tests/test_forwarder_upstream_replies.py::test_plain_http_407_then_success_on_one_record_stays_ok`; `tests/test_forwarder_upstream_replies.py::test_plain_http_407_from_an_origin_on_a_direct_route_is_not_a_proxy_failure`; `tests/test_forwarder_http.py::test_upstream_reset_during_the_request_body_is_a_failure`; `tests/test_forwarder_http.py::test_reset_after_a_complete_response_does_not_fail_the_exchange` | changed |
| F12 | Deny rules return 403 `denied` and are recorded as denied tunnels; `--deny-catalog background` expands to every background host glob (including `*.gvt1.com` and `dl.google.com`); a rule on an IPv4 address or glob also matches the IPv6 forms that embed it (NAT64 `64:ff9b::/96`, IPv4-translated, IPv4-compatible) | method.md §5 | `tests/test_forwarder_budget.py::test_deny_host_refuses_and_records`; `tests/test_catalog.py::test_rule_helpers_cover_every_glob_with_contract_labels`; `tests/test_e2e_run.py::test_deny_catalog_background_refuses_catalogued_hosts`; `tests/test_forwarder_budget.py::test_deny_rule_on_an_ipv4_address_covers_ipv6_forms_that_carry_it` | changed |
| F13 | Under `--env-all`, direct.json hosts (LLM APIs only; no cloud storage) go direct, never to the upstream, and appear only under non-target | README, method.md §4 | `tests/test_forwarder_budget.py::test_direct_rules_carry_llm_hosts_direct_as_non_target`; `tests/test_e2e_run.py::test_env_all_carries_llm_hosts_direct_as_non_target`; `tests/test_catalog.py::test_direct_catalog_never_carries_cloud_storage_hosts` | changed |
| F14 | Plain HTTP: `Host` is the target authority, hop-by-hop request headers are removed on every route, `Content-Length` with `Transfer-Encoding` gets 400, trailers are relayed both ways, SOCKS5 gets origin form without `Proxy-Authorization`/`Proxy-Connection`, and an HTTP CONNECT provider gets the target rebuilt as `http://<routed authority><path and query>` without the fragment | method.md §3 | `tests/test_forwarder_http.py::test_absolute_form_host_header_is_the_target_authority`; `tests/test_forwarder_http.py::test_hop_by_hop_request_headers_are_not_forwarded`; `tests/test_forwarder_http.py::test_content_length_with_transfer_encoding_is_refused`; `tests/test_forwarder_http.py::test_chunked_trailers_are_relayed_both_ways`; `tests/test_e2e_forwarder_parity.py::test_socks5_plain_http_reaches_the_origin_in_origin_form`; `tests/test_forwarder_http.py::test_http_upstream_gets_the_routed_authority_not_the_raw_target` | changed |
| F15 | h11 handling of chunked, close-delimited, HEAD, 1xx/`Expect: 100-continue` (a final response before `100 Continue` ends the connection; 1xx other than 101 never reach HTTP/1.0 clients), 204/304 and `Upgrade` | method.md §3 | `tests/test_forwarder_http.py::test_chunked_request_body`; `tests/test_forwarder_http.py::test_close_delimited_and_chunked_responses`; `tests/test_forwarder_http.py::test_head_204_304_keep_connection_usable`; `tests/test_forwarder_http.py::test_expect_100_continue_passthrough`; `tests/test_forwarder_http.py::test_final_response_before_100_continue_ends_the_connection`; `tests/test_forwarder_http.py::test_upgrade_switches_to_raw_relay`; `tests/test_forwarder_http.py::test_informational_responses_never_reach_http10_clients` | changed |
| F24 | Response heads: whitespace between a field name and its colon is removed before parsing (RFC 9112 §5.1); `Transfer-Encoding: <codings>, chunked` reaches HTTP/1.1 clients with that value and the chunk-framed body; HTTP/1.0 clients get 502 `upstream-protocol-error` for it, as for other malformed heads | method.md §3, accuracy.md, contracts §3.5 | `tests/test_forwarder_http.py::test_whitespace_before_a_response_colon_is_removed_not_refused`; `tests/test_forwarder_http.py::test_gzip_then_chunked_transfer_coding_is_relayed_with_its_coding`; `tests/test_forwarder_http.py::test_binary_reply_to_plain_http_still_fails_at_once`; `tests/test_forwarder_upstream_replies.py::test_garbage_reply_is_a_protocol_error` | verified |
| F16 | Sizing mode refuses non-global destinations (loopback, private, link-local, CGNAT, ULA, unspecified, reserved, multicast; IPv4-mapped unmapped; IPv6 forms that embed an IPv4 address (NAT64 `64:ff9b::/96`, IPv4-translated, IPv4-compatible) judged by that address; site-local `fec0::/10`, 6to4 `2002::/16` and local-use NAT64 `64:ff9b:1::/48` always refused) and, after connecting and before any byte, this machine's own address and IPv6 peers in the same /64 as the source address, with 403 `private-address`; it connects only to the checked address, and `--allow-private-targets` opts out on `run`, `serve` and `find`; non-target routes and test connect-map entries are exempt; IPv4 LAN hosts with public addresses and a network's own NAT64 prefix are documented limits | method.md §4, security.md, exit-codes.md | `tests/test_forwarder_errors.py::test_direct_mode_refuses_private_destinations`; `tests/test_forwarder_errors.py::test_allow_private_targets_opt_in`; `tests/test_forwarder_errors.py::test_direct_connects_only_to_the_checked_addresses`; `tests/test_cli.py::test_allow_private_targets_flag_reaches_every_command`; for `find`, a refused target is "page load failed" naming the option, never "not found": `tests/test_find_regressions.py::test_meter_refusal_of_an_http_target_is_a_load_error_not_not_found`; `tests/test_find_regressions.py::test_meter_refusal_of_an_https_target_names_the_cause_without_a_retry`; `tests/test_forwarder_errors.py::test_direct_mode_refuses_this_machines_own_global_address` (uses this machine's own non-loopback address; skipped when there is none); `tests/test_forwarder_errors.py::test_direct_mode_refuses_a_routable_address_that_is_this_machine`; `tests/test_forwarder_errors.py::test_private_destination_sees_ipv4_embedded_in_ipv6`; `tests/test_forwarder_errors.py::test_direct_mode_refuses_private_ipv4_behind_ipv6_spellings`; `tests/test_types.py::test_embedded_ipv4_forms` | changed |
| F17 | A snapshot holds the counting lock only for open and changed records; retained records cost about 0.4 kB each in the meter and about 0.8 kB with the snapshot cache's copy (about 1.1 kB while a snapshot is alive), deny-rule refusals included, with no cap yet | method.md §3, privacy.md, security.md | `tests/test_forwarder_meter.py::test_snapshot_holds_the_lock_only_for_open_and_changed_records`; the per-record sizes are a tracemalloc measurement of 100,000 `Meter.record_denied` calls in the round-3 review (2026-09-23), not a test | partial |
| F18 | Direct and non-target routes try several resolved addresses Happy-Eyeballs style (families interleaved, a new attempt every 250 ms or when one fails, one deadline) | method.md §4, security.md | `tests/test_forwarder_errors.py::test_direct_route_falls_back_to_the_next_address_quickly`; `tests/test_forwarder_errors.py::test_direct_route_times_out_at_the_deadline_when_no_address_answers`; `tests/test_forwarder_errors.py::test_interleave_families_alternates_starting_with_the_first`; `tests/test_forwarder_errors.py::test_direct_connects_only_to_the_checked_addresses` | verified |
| F19 | The timeline holds at most 16,384 slots (adjacent slots merge, the step doubles and is reported); `serve` keeps none | method.md §3 | `tests/test_forwarder_meter.py::test_timeline_is_bounded_by_merging_slots_and_doubling_the_step`; `tests/test_forwarder_meter.py::test_default_timeline_stays_bounded_for_a_long_session`; `tests/test_forwarder_meter.py::test_record_timeline_off_keeps_no_slots`; `tests/test_cli.py::test_serve_keeps_no_timeline_and_run_find_do` | verified |
| F20 | A reused keep-alive upstream connection that closes before any byte of a reply makes the meter close the client connection without a reply (the tunnel is `ok`); a fresh connection still gets `502 upstream-closed` | method.md §3 | `tests/test_forwarder_http.py::test_keep_alive_race_passes_the_close_on_instead_of_a_502` | verified |
| F21 | Each tunnel costs two descriptors: `run`, `serve` and `find` raise their soft open-files limit to min(hard, 65,536) (`run` after starting the job); a low limit gets a start note; running out gives `failed:local_limit` (503 `local-limit`), counted accept pauses and a warning that blames this machine | README, security.md, method.md §3 | `tests/test_forwarder_errors.py::test_raise_open_file_limit_raises_toward_the_hard_limit_and_never_lowers`; `tests/test_forwarder_errors.py::test_out_of_descriptors_is_local_limit_not_the_target_refusing`; `tests/test_cli.py::test_accept_failures_for_lack_of_descriptors_are_recognised`; `tests/test_cli.py::test_low_open_file_limit_is_mentioned_at_start`; `tests/test_cli.py::test_descriptor_limit_warning_blames_this_machine` (that `run` raises the limit after starting the job is code review: `runner.run_command`); round-4 manual check (2026-09-24): under `run` with soft limit 256 and an unlimited hard limit the job still saw 256, and with a hard limit of 300 the start note read "at most 300 files ... about 134 tunnels" | verified |
| F22 | IP-literal hosts are canonicalised (`1.2.3.04`, `0x01020304`, `16909060`, `1.2.772`, `::ffff:1.2.3.4` → `1.2.3.4`) before the self-loop, deny, direct-rule and routing checks and in records and reports; an HTTP CONNECT provider receives the client's spelling; over SOCKS5 a legacy IPv4 spelling goes as the canonical address (ATYP IPv4); helper and hook events carry the canonical spelling too (Chromium's `::ffff:102:304` is `1.2.3.4`) | method.md §4, security.md | `tests/test_types.py::test_ip_literal_globs_and_hosts_are_canonical`; `tests/test_forwarder_budget.py::test_deny_rule_on_an_address_covers_every_spelling`; `tests/test_forwarder_upstream_replies.py::test_socks_address_types`; round 4: helper and hook events write IP-literal hosts the same way and attribution canonicalises both sides before matching: `tests/test_helpers_events.py::test_url_parts_writes_ip_literals_the_way_the_meter_records_them`; `tests/test_attribution.py::test_ip_literal_hosts_match_their_tunnels_in_any_spelling` | changed |

### Credentials and tokens

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| A1 | Upstream URL is read only from an environment variable, never argv | README, security.md | `tests/test_cli.py::test_upstream_url_is_never_accepted_on_argv` | verified |
| A2 | Credential table (none → inject; `ss-<token>` → strip and inject; `ss-<token>~user` → forward `user:password`; other → pass through; wrong token → 407 where a token exists, i.e. in `serve`) | security.md, README | `tests/test_forwarder_auth.py::test_token_username_is_stripped_and_credentials_injected`; `tests/test_forwarder_auth.py::test_token_mapped_upstream_user`; `tests/test_forwarder_auth.py::test_passthrough_without_configured_credentials`; `tests/test_forwarder_auth.py::test_bad_token_prefix_refused_even_when_tokenless`; `tests/test_e2e_serve.py::test_serve_requires_the_token` | verified |
| A3 | `serve` always requires the token (407 with `Proxy-Authenticate: Basic realm="scrapescope"`); it has no tokenless mode (round 4 removed `--allow-tokenless`); other credentials without the prefix get 407 in `serve` | README, security.md | `tests/test_forwarder_auth.py::test_token_required_refusals`; `tests/test_e2e_serve.py::test_serve_requires_the_token`; `tests/test_e2e_serve.py::test_serve_has_no_tokenless_mode`; `tests/test_e2e_serve.py::test_serve_sigterm_and_origin_form_403` | changed |
| A4 | `run` and `find` accept tokenless loopback connections on the main listener and inject the configured credentials | security.md | `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_e2e_browser.py::test_find_through_upstream_finds_verifies_and_keeps_the_value_private` | verified |
| A5 | The auth listener answers 407 without credentials, so Chromium presents per-context credentials, which are then passed through unchanged | README, security.md | `tests/test_forwarder_auth.py::test_auth_listener_challenges_then_passes_through`; `tests/test_forwarder_browser.py::test_per_context_proxy_credentials`; `tests/test_helpers_playwright.py::test_per_context_credentials_pass_through_unchanged` | verified |
| A6 | Two contexts with different session usernames reach the upstream with those usernames unchanged | README | `tests/test_forwarder_auth.py::test_session_usernames_pass_through_unchanged`; `tests/test_helpers_playwright.py::test_per_context_credentials_pass_through_unchanged` | verified |
| A7 | SOCKS5: Basic credentials map to RFC 1929; SOCKS auth failure gives 502 `socks-auth-failed`; non-Basic credentials give 502 `socks-auth-unsupported` | security.md | `tests/test_forwarder_errors.py::test_socks_auth_failure`; `tests/test_forwarder_auth.py::test_non_basic_proxy_authorization`; `tests/test_e2e_run.py::test_credentials_never_leak_on_error_paths` | verified |
| A8 | Direct mode drops client credentials; they are never sent anywhere | security.md | `tests/test_forwarder_auth.py::test_direct_mode_drops_client_credentials` | verified |
| A9 | Credential sentinels never appear in stdout, stderr, logs, report.json, report.html or the events file, on success and on the error paths (upstream unreachable, 407, upstream DNS failure, TLS error, SOCKS auth failure), including the Basic base64 form | security.md | `tests/test_e2e_run.py::test_credentials_never_leak_on_error_paths`; `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_forwarder_errors.py::test_credentials_never_logged_or_stored`; `tests/test_e2e_browser.py::test_find_stops_early_when_the_upstream_rejects_credentials` | verified |
| A10 | `ConfigError` messages name the variable, never its value; exit 89. With only `https_proxy`, `all_proxy`, `ALL_PROXY`, `HTTP_PROXY` or `http_proxy` set, the message names that variable | security.md, exit-codes.md | `tests/test_config.py::test_parse_upstream_rejects_without_echoing_secrets`; `tests/test_cli.py::test_upstream_config_errors_exit_89_and_never_echo_the_value`; `tests/test_cli.py::test_lowercase_proxy_variable_is_named_in_the_error`; `tests/test_e2e_run.py::test_upstream_configuration_errors_exit_89_without_echoing_the_url`; `tests/test_config.py::test_missing_upstream_names_http_proxy_too` | changed |
| A11 | The child environment: upstream variable replaced by the meter URL without credentials; proxy variables naming the same upstream semantically (host case, scheme-less form, explicit default port, socks5/socks5h) replaced too, and any other variable only when its value is exactly the upstream URL; a proxy variable that still names the provider's host with other credentials, another port or scheme, or its credentials on another host, is left alone and gets a start note and a report warning (name only; for a loopback upstream only the same port counts; values parsed leniently, so `https://`, `socks4://` and URLs with paths count); `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` (either case) set to another proxy gets its own note and warning with a reason, the metered variable's case twin first, without setting `incomplete`; `SCRAPESCOPE_PROXY_URL`, `SCRAPESCOPE_AUTH_PROXY_URL`, `SCRAPESCOPE_EVENTS`, `SCRAPESCOPE_UPSTREAM_ID` and (with `--keep-urls`) `SCRAPESCOPE_KEEP_URLS` added, nothing else changed; `--env-all` variables and `NO_PROXY` merge as documented | README, security.md | `tests/test_config.py::test_child_env_topology_preserving_default`; `tests/test_config.py::test_child_env_replaces_semantic_duplicates_of_the_upstream`; `tests/test_config.py::test_child_env_socks5_and_socks5h_are_the_same_endpoint`; `tests/test_config.py::test_child_env_other_credentials_stay_and_are_named_for_a_warning`; `tests/test_e2e_run.py::test_default_mode_leaves_an_unproxied_llm_call_alone`; `tests/test_e2e_run.py::test_env_all_carries_llm_hosts_direct_as_non_target`; `tests/test_e2e_run.py::test_run_direct_without_env_all_changes_no_proxy_variables`; `tests/test_config.py::test_child_env_names_the_provider_gateway_on_another_port_or_scheme`; `tests/test_config.py::test_unmetered_variables_parse_other_schemes_and_paths_leniently`; `tests/test_config.py::test_case_twin_of_the_metered_variable_is_named_as_another_proxy`; `tests/test_cli.py::test_run_names_a_case_twin_that_shadows_the_metered_variable` | changed |
| A12 | Only `serve` has a token: 24 URL-safe characters from `secrets`, never containing `~` or `:`, never in reports; printed once, only when stderr is a terminal, with a banner example that keeps it out of argv (`HTTPS_PROXY=http://ss-<token>:x@... curl`); otherwise written as the proxy URL to a 0600 file in a fresh 0700 temporary directory, or to `--token-file PATH` (must not exist; `O_EXCL`/`O_NOFOLLOW`, 0600; exit 2 if it exists), whose path alone is printed; the file is removed when `serve` stops; the `ss-` prefix never reaches the provider. `run` and `find` have no token | README, security.md, SECURITY.md | `tests/test_config.py::test_token_helpers`; `tests/test_e2e_serve.py::test_serve_requires_the_token`; `tests/test_e2e_serve.py::test_serve_writes_the_token_to_a_private_file_when_stderr_is_not_a_terminal`; `tests/test_e2e_serve.py::test_serve_token_file_must_be_new`; `tests/test_e2e_serve.py::test_serve_prints_the_token_to_a_terminal`; `tests/test_forwarder_auth.py::test_ss_prefix_passes_through_when_no_token_configured`; `tests/test_cli.py::test_serve_banner_example_uses_compressed` | changed |
| A13 | With an upstream, `run` gives the job `SCRAPESCOPE_UPSTREAM_ID` (a salted HMAC of the upstream host:port, never the host) and removes an inherited one otherwise; the helper reroutes only `proxy=` servers matching it | README, security.md | `tests/test_e2e_run.py::test_run_gives_the_job_an_upstream_id_the_helper_can_match`; `tests/test_helpers_playwright.py::test_rewrite_proxy_reroutes_only_the_runs_upstream_when_its_fingerprint_is_given` | verified |

### Counting, budget and totals

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| M1 | Upstream bytes counted on write and on read, before relaying; they equal the fixture upstream's own counts | method.md §3 | `tests/test_forwarder_counts.py::test_counts_equal_fixture_upstream`; `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_e2e_run.py::test_run_through_socks5_upstream_matches_fixture_counts`; `tests/test_e2e_browser.py::test_playwright_helper_run_attribution` | verified |
| M2 | Negotiation bytes are recorded separately; "without CONNECT" = upstream bytes − negotiation | method.md §3 | `tests/test_forwarder_meter.py::test_counts_negotiation_and_totals`; `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts` | verified |
| M3 | Direct mode adds an estimated CONNECT exchange to "with CONNECT" only: the client's own CONNECT head without `Proxy-Authorization` (Chromium about 236 bytes; minimal 63 for `origin-a.test:443`) and a 39-byte reply; provider credentials are not included; labelled estimated, excluded from the budget. Plain `http://` requests get no estimate (origin form, no `Proxy-Authorization`), and the estimated mark reflects CONNECT tunnels only | method.md §3, accuracy.md | `tests/test_forwarder_counts.py::test_direct_mode_estimates_connect_from_the_clients_own_head`; `tests/test_forwarder_counts.py::test_direct_mode_counts_equal_origin`; `tests/test_config.py::test_synthetic_connect_sizes_match_bytes`; `tests/test_forwarder_meter.py::test_direct_mode_synthetic_sizes`; `tests/test_e2e_run.py::test_run_direct_mode_uses_connect_map_and_estimates_connect`; live: `find --verify` on books.toscrape.com, 410 B between the two totals for the page load's and the replay's CONNECT tunnels (2026-09-23); `tests/test_forwarder_counts.py::test_direct_mode_adds_no_estimate_for_plain_http`; the gap was measured in the round-3 review: ten identical small requests, 87 B up per request in sizing mode against 196 B through the fixture provider | changed |
| M4 | Non-target tunnels are excluded from totals, hosts, timeline and budget | method.md §3 | `tests/test_forwarder_meter.py::test_non_target_tunnels_are_excluded`; `tests/test_e2e_run.py::test_env_all_carries_llm_hosts_direct_as_non_target` | verified |
| M5 | Budget counts upstream bytes both ways including negotiation and failed tunnels; the tripping read counts in full | method.md §5 | `tests/test_forwarder_meter.py::test_warn_then_trip_counts_the_tripping_slice`; `tests/test_forwarder_meter.py::test_sent_bytes_count_toward_budget`; `tests/test_forwarder_budget.py::test_budget_trip_mid_download` | verified |
| M6 | One warning at 80% (not printed when the same read also tripped the budget; the report still lists both events); at 100% every tunnel closes, new requests get 403 `X-Scrapescope-Budget: tripped`, and the event names up to 10 heaviest hosts of the final 60 s | README, method.md §5 | `tests/test_forwarder_budget.py::test_budget_trip_mid_download`; `tests/test_forwarder_meter.py::test_top_hosts_limited_to_ten`; `tests/test_e2e_run.py::test_budget_trip_stops_the_whole_process_group`; `tests/test_e2e_serve.py::test_serve_budget_trip_refuses_and_exits_86`; `tests/test_cli.py::test_budget_announcer_skips_the_80_percent_line_when_the_same_read_tripped` | changed |
| M7 | `run` stops the child's whole process group (SIGTERM, SIGKILL after 5 s), grandchildren included, on Linux and macOS | README, method.md §5 | `tests/test_e2e_run.py::test_budget_trip_stops_the_whole_process_group` (a grandchild that ignores SIGTERM) | verified on macOS; Linux open |
| M8 | Budget trip with 50 concurrent tunnels | method.md §5 | `tests/test_forwarder_budget.py::test_budget_trip_closes_50_concurrent_tunnels` | verified |
| M9 | `--max-tunnel-mb N` closes only that upstream connection at N × 10^6 bytes, regardless of `--gib`; on the HTTP CONNECT route a kept provider connection's count includes every continued record, and the `tunnel_cap` event names the record that reached the cap with the connection's count | README, method.md §5, contracts §3.7 | `tests/test_forwarder_budget.py::test_max_tunnel_bytes_closes_only_that_tunnel`; `tests/test_forwarder_budget.py::test_max_tunnel_bytes_follows_a_kept_provider_connection_across_authorities`; `tests/test_cli.py::test_max_tunnel_mb_is_decimal_megabytes_regardless_of_gib` | changed |
| M10 | Sizes like `2GB`/`1.5GiB` parse as decimal/binary regardless of `--gib`; `--budget` requires a unit (a bare number exits 2) | method.md §5, README | `tests/test_config.py::test_parse_size`; `tests/test_config.py::test_parse_size_rejects`; `tests/test_cli.py::test_budget_accepts_sizes_with_units`; `tests/test_cli.py::test_budget_without_a_unit_is_a_usage_error` | changed |
| M11 | The meter stops at its own count: after a trip the provider may have handed over more than scrapescope counted (bounded by socket buffers) | README, method.md §5, accuracy.md | `tests/test_e2e_run.py::test_budget_trip_stops_the_whole_process_group` | verified |
| M12 | Sent bytes count when handed to the transport; an abort uncounts what was still queued, so the final count can end below the trip event's, and the trip stays in force | method.md §3, §5 | `tests/test_forwarder_meter.py::test_discard_sent_uncounts_tunnel_budget_and_timeline`; `tests/test_forwarder_meter.py::test_discard_sent_keeps_a_trip_in_force`; `tests/test_forwarder_budget.py::test_sent_bytes_at_an_upload_trip_equal_what_left_the_meter` | verified |
| M13 | `totals.tunnels` counts records and `totals.connections` the upstream connections opened for them; the report shows a `connections` row only when they differ | method.md §3, contracts §11.1 | `tests/test_attribution.py::test_a_record_that_continues_a_kept_connection_gets_no_setup_allowance` (`Totals.connections`); `tests/test_report.py::test_totals_show_connections_only_when_fewer_than_tunnel_records` | verified |

### Helpers, events and attribution

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| H1 | `launch()` sets a browser-wide proxy to the meter, records a launch and instruments every new context; `instrument(context)` records the context's browser once; `record_launch(obj)` is idempotent per underlying browser, and a context counts as `context.browser` (Playwright 1.63 exposes it for persistent contexts), so `record_launch(context)` plus `instrument(context)` write one launch in either order | README, method.md §6, accuracy.md | `tests/test_helpers_playwright.py::test_launch_sets_proxy_records_launch_and_wraps`; `tests/test_helpers_playwright.py::test_instrument_records_the_context_browser_once`; `tests/test_helpers_playwright.py::test_record_launch_variants_and_idempotence`; `tests/test_helpers_playwright.py::test_a_persistent_context_with_a_browser_counts_one_launch_in_either_order`; `tests/test_helpers_playwright.py::test_the_generated_persistent_profile_fix_records_one_launch`; `tests/test_e2e_browser.py::test_playwright_helper_run_attribution`; live (2026-09-24): `browser launches: 1` on a three-page books.toscrape.com run with `launch(proxy=proxy_settings())` + `instrument()` | changed |
| H2 | `wrap_new_context` (and `launch(proxy=...)`) replace the proxy server with the meter's auth URL and keep username/password; with `SCRAPESCOPE_UPSTREAM_ID` set, only a server that is the run's upstream is rerouted and others are left alone with a warning | README | `tests/test_helpers_playwright.py::test_wrap_new_context_sync`; `tests/test_helpers_playwright.py::test_rewrite_proxy`; `tests/test_helpers_playwright.py::test_rewrite_proxy_reroutes_only_the_runs_upstream_when_its_fingerprint_is_given`; `tests/test_e2e_run.py::test_run_gives_the_job_an_upstream_id_the_helper_can_match` | changed |
| H3 | Helpers are no-ops with one warning when `SCRAPESCOPE_EVENTS` is unset | README | `tests/test_helpers_playwright.py::test_helpers_inactive_without_events`; `tests/test_helpers_events.py::test_inactive_warning_is_issued_once_per_process` | verified |
| H4 | Context-level listeners capture cross-site iframe, dedicated worker and service-worker requests; a service-worker-answered request is counted once; a request marked as served by a service worker that shows wire-level headers (or, under interception, a server address) is a network request (the warm-profile race), with an unknown body size | method.md §6 | `tests/test_helpers_playwright.py::test_sync_browser_events_cover_frames_workers_and_service_worker`; `tests/test_helpers_playwright.py::test_cache_and_service_worker_sizes`; `tests/test_helpers_playwright.py::test_a_navigation_the_network_answered_while_the_worker_started_is_a_network_request`; `tests/test_helpers_playwright.py::test_a_warm_profile_with_a_service_worker_keeps_its_network_navigations` | changed |
| H5 | Events never contain bodies, cookies, header values, credentials or query strings; paths only with `--keep-urls`, cleaned (`;` parameters dropped, token-like segments as `{token}`) | privacy.md | `tests/test_helpers_events.py::test_non_network_schemes_and_invalid_events_are_not_written`; `tests/test_helpers_events.py::test_paths_only_with_keep_urls_and_never_queries`; `tests/test_helpers_hooks.py::test_requests_presence_flags_without_values`; `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_types.py::test_clean_path_drops_path_parameters_and_token_segments`; `tests/test_report.py::test_keep_urls_keeps_clean_paths_only` | changed |
| H6 | Invalid, oversized (> 4,096 bytes) or wrong-version event lines are dropped and counted | method.md §6 | `tests/test_types.py::test_parse_event_rejects`; `tests/test_helpers_events.py::test_read_events_drops_and_counts_bad_lines`; `tests/test_helpers_events.py::test_read_events_handles_huge_lines_without_reading_them_whole` | verified |
| H7 | Hooks never read bodies for themselves; the Requests hook writes its event when the body is read to the end, the response is closed, garbage-collected or the interpreter exits, with the raw bytes urllib3 read (null for chunked, never `Content-Length`); HTTPX reports `num_bytes_downloaded` | README, accuracy.md | `tests/test_helpers_hooks.py::test_httpx_client_records_downloaded_bytes`; `tests/test_helpers_hooks.py::test_requests_session_records_each_response`; `tests/test_helpers_hooks.py::test_requests_body_sizes_are_written_when_read_closed_or_collected`; `tests/test_helpers_hooks.py::test_requests_stream_read_in_part_reports_the_bytes_read_not_the_content_length` | changed |
| H8 | HTTP/2 and HTTP/3 events carry unknown (null) header sizes and the body includes the header frames, so reported sizes stay below tunnel bytes; failed requests have an unknown body size | method.md §6, accuracy.md, README | `tests/test_helpers_playwright_h2.py::test_http2_sizes_redirect_host_and_disk_cache_hits` (needs `node`); `tests/test_helpers_playwright.py::test_http2_header_sizes_are_unknown_and_the_body_keeps_the_header_frames`; `tests/test_helpers_playwright.py::test_h2_redirects_and_failures_after_headers_are_not_cache_hits`; hooks: `tests/test_helpers_hooks.py::test_httpx_http2_and_http3_header_sizes_are_unknown`, `tests/test_helpers_hooks.py::test_requests_http2_responses_have_unknown_header_sizes` (mock transports); `tests/test_helpers_hooks_h2.py::test_httpx_http2_through_the_meter_writes_unknown_header_sizes` (real HTTP/2; needs `h2` and `node`: passes since the round-4 verifier installed `.[dev]`, which lists `h2`, in the development environment; also passed from the sdist in a fresh `.[dev]` environment with h2 4.4.1 and Node 26.8.1) | verified |
| H9 | Cache hits: memory cache by `responseBodySize < 0`; for Chromium and unknown browsers, disk cache by provisional-only request headers, used only without routes or HTTP/proxy credentials, with candidates held until wire-level headers were seen, decided at once for a response from another proxy (an earlier run's cache entry), else at context close; for Firefox and WebKit, a cacheable response without a server address, written at once; service-worker scripts never; redirects and failures never | method.md §6, accuracy.md | `tests/test_helpers_playwright.py::test_second_load_cache_hits_are_flagged`; `tests/test_helpers_playwright.py::test_disk_cache_hits_are_recognised_by_their_provisional_headers`; `tests/test_helpers_playwright.py::test_disk_cache_heuristic_is_off_when_interception_hides_the_wire_headers`; `tests/test_helpers_playwright.py::test_navigation_response_gives_wire_evidence_before_cached_subresources_finish`; `tests/test_helpers_playwright.py::test_held_candidates_are_decided_when_the_context_closes`; `tests/test_helpers_playwright.py::test_service_worker_scripts_are_never_cache_hits`; `tests/test_helpers_playwright.py::test_firefox_and_webkit_cache_hits_are_recognised_by_their_missing_server_address`; `tests/test_helpers_playwright.py::test_firefox_and_webkit_cache_hits_match_what_the_origin_served` (real Firefox and WebKit; skipped where not installed) | changed |
| H10 | Requests in flight at navigation or close are written as failed with unknown sizes when the context closes, or at exit for contexts never closed; their bytes stay `unreported` | method.md §6, accuracy.md | `tests/test_helpers_playwright.py::test_unfinished_requests_are_written_as_failed_when_the_context_closes`; `tests/test_helpers_playwright.py::test_unfinished_requests_of_a_context_never_closed_are_written_at_exit`; `tests/test_helpers_playwright.py::test_fetch_aborted_by_navigation_is_written_at_close_and_its_bytes_stay_unreported` | verified |
| H11 | Requests answered or stopped before the network (`route.fulfill`, `route.abort`, browser blocks) carry `no_network`, count as not network requests, and stay out of the status line, allocation and bypass, with a warning counting them by kind | method.md §6-7, accuracy.md | `tests/test_helpers_playwright.py::test_fulfilled_aborted_and_blocked_requests_are_not_network_requests_in_chromium`; `tests/test_helpers_playwright.py::test_fulfilled_responses_are_recognised_by_their_missing_server_address_without_the_route_wrappers`; `tests/test_attribution.py::test_requests_that_never_reached_the_network_are_not_network_requests`; live: 93 events = 72 network (status line) + 18 cache hits + 3 blocked on a 3-page books.toscrape.com run (2026-09-23) | verified |
| H12 | `launch(..., webrtc_proxied_only=True)` adds `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` (the switch `find` always uses); off by default | README, security.md | `tests/test_helpers_playwright.py::test_launch_offers_the_webrtc_switch_find_uses` (the switch's effect is measured for `find`: D22) | verified |
| H13 | For plain `http://` requests, `request_header_bytes` leaves out the proxy-hop headers Chromium sends to the meter (`Proxy-Connection`; `Proxy-Authorization` after a 407), which the meter removes; `find`'s billed basis does the same; Playwright's rebuilt size has no query and no final CRLF, so reported heads sit slightly below the wire | accuracy.md, contracts §4 | `tests/test_helpers_playwright.py::test_proxy_hop_headers_are_left_out_of_plain_http_request_sizes`; `tests/test_helpers_playwright.py::test_plain_http_request_headers_leave_out_the_proxy_hop` (real Chromium); `tests/test_find_round4.py::test_find_leaves_the_proxy_hop_out_of_plain_http_request_heads` (real Chromium; without the subtraction the head was 427 B against 399 B the origin received) | verified |
| B1 | Allocations per host sum exactly to the host's with-CONNECT bytes; buckets sum to the with-CONNECT total | method.md §7 | `tests/test_attribution.py::test_host_allocation_shares_tunnel_overhead_in_proportion`; `tests/test_attribution.py::test_largest_remainder_is_exact_and_proportional`; `tests/test_e2e_browser.py::test_playwright_helper_run_attribution` | verified |
| B2 | An uncatalogued host is never labelled background; iframe, worker, service-worker and idle-preconnect traffic never lands in background | README, method.md §7 | `tests/test_attribution.py::test_uncatalogued_host_is_never_background`; `tests/test_catalog.py::test_uncatalogued_hosts_are_never_background`; `tests/test_e2e_browser.py::test_playwright_helper_run_attribution`; `tests/test_e2e_browser.py::test_full_chromium_preconnect_and_background_buckets`; `tests/test_helpers_playwright.py::test_full_chromium_preconnect_and_background_buckets` | verified |
| B3 | Bucket order: background, before_attach, preconnect_idle (tunnels that did not fail, ≤ 3,072 up / ≤ 6,144 down payload), unattributed; a refused CONNECT of a host without requests is never an idle preconnect | method.md §7 | `tests/test_attribution.py::test_every_bucket_and_first_match_order`; `tests/test_attribution.py::test_idle_limits_are_inclusive`; `tests/test_attribution.py::test_refused_tunnels_of_hosts_without_requests_are_not_idle_preconnects` | changed |
| B4 | Units exclude 3xx; < 20 units warns; `--units N` overrides | method.md §7 | `tests/test_attribution.py::test_units_from_navigations_exclude_redirects_and_subframes`; `tests/test_attribution.py::test_units_from_hooks_and_low_sample_warning`; `tests/test_attribution.py::test_units_override_keeps_success_from_events` | verified |
| B5 | Bypass detector marks the run incomplete for a host no tunnel carried, a request more than 2 s after every tunnel of its host closed, or reported bytes above 1.5 × tunnel bytes + 64 KiB; it excludes cache, service-worker, no-network, loopback, `data:`/`blob:` and failed-without-status requests, and 403s to requests started after the budget tripped; with a Firefox or WebKit launch, Playwright events stay out of the volume check (hooks still count) and a warning calls those per-type figures unverified; request and tunnel hosts are compared canonically, so `bypass.hosts` uses the meter's spelling | method.md §7, README | `tests/test_attribution.py::test_bypass_exclusions`; `tests/test_attribution.py::test_bypass_detected_for_uncarried_host`; `tests/test_attribution.py::test_bypass_by_time_after_every_tunnel_closed`; `tests/test_attribution.py::test_bypass_by_volume_one_request_through_the_meter_the_bulk_around_it`; `tests/test_attribution.py::test_no_volume_bypass_for_a_modest_scale_down`; `tests/test_e2e_run.py::test_bypass_is_detected_and_gated`; `tests/test_attribution.py::test_budget_refusals_after_the_trip_are_not_bypass`; `tests/test_attribution.py::test_firefox_and_webkit_sizes_are_flagged_unverified_and_kept_out_of_the_volume_check`; `tests/test_attribution.py::test_ip_literal_hosts_match_their_tunnels_in_any_spelling` | changed |
| B6 | "cache loss not modelled" appears when a context loaded more than one page | method.md §9 | `tests/test_attribution.py::test_multi_page_context`; `tests/test_model.py::test_cache_caveat_only_for_multi_page_contexts`; `tests/test_e2e_browser.py::test_playwright_helper_run_attribution` | verified |
| B7 | A timeline step that straddles the first unit's start counts for the first unit, and one that straddles the second unit's start for the rest; a navigation unit starts with its redirect chain (3xx hops in the same context, each within 30 s); the first-unit/rest split is withheld (null, with a warning) when the first two units started within one step | method.md §7, accuracy.md | `tests/test_attribution.py::test_timeline_bucket_straddling_the_first_unit_goes_to_that_unit`; `tests/test_attribution.py::test_timeline_figures`; `tests/test_attribution.py::test_per_unit_withheld_when_units_start_within_one_timeline_step`; `tests/test_report.py::test_per_unit_withheld_is_explained`; `tests/test_attribution.py::test_timeline_bucket_straddling_the_second_unit_goes_to_the_rest`; `tests/test_attribution.py::test_a_navigation_unit_starts_with_its_redirect_hops` | changed |
| B8 | Scale-down is unlimited; scale-up is capped at reported + 16,448 B per tunnel that opened its own upstream connection (none for a record that continues a kept provider connection) + negotiation per tunnel + 25% + 512 B per request with unknown headers, the rest is `unreported` (never in what-if or fixes; a warning at ≥ 64 KB per host); hosts with an unknown successful response size are not capped | method.md §7, accuracy.md, README | `tests/test_attribution.py::test_allocation_scales_down_when_reported_exceeds_tunnel_bytes`; `tests/test_attribution.py::test_scale_up_is_bounded_and_the_rest_is_unreported`; `tests/test_attribution.py::test_unknown_headers_and_negotiation_extend_the_allowance`; `tests/test_attribution.py::test_scale_up_unbounded_when_a_successful_response_size_is_unknown`; `tests/test_attribution.py::test_a_record_that_continues_a_kept_connection_gets_no_setup_allowance`; `tests/test_model.py::test_unreported_bytes_never_count_as_savings` | changed |
| B9 | The report shows "status (network requests; failed = no response)" and "not network requests: N request event(s): HTTP-cache hits, service-worker answers, and requests answered or stopped before the network (...)"; "browser launches: not recorded" when browser request types exist without a launch event | method.md §7, accuracy.md, README | `tests/test_report.py::test_cache_served_events_are_counted_in_the_units_section`; `tests/test_report.py::test_launches_not_recorded_when_a_browser_ran`; `tests/test_report.py::test_render_text_labels_and_sections`; live: launches 1 on a 3-page run with `proxy_settings()` + `instrument()` (2026-09-23) | changed |
| B10 | The events reader keeps at most 1,000,000 events (about 0.5 kB each, about 0.5 GB at the cap); lines past it are not read, and `run` passes their count so the report says they were skipped at the cap, not invalid | security.md, contracts §6 | `tests/test_attribution.py::test_events_past_the_reader_cap_are_named_in_a_warning`; `tests/test_attribution.py::test_read_events_shares_repeated_strings`; `tests/test_cli.py::test_run_passes_the_events_cap_count_to_attribution` | verified |

### find

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| D1 | Challenge pages (Cloudflare `cf-mitigated: challenge`, "Just a moment...", AWS WAF 202 challenge / 405 captcha) and hard block pages on a 403 (Cloudflare 1xxx "Access denied", Akamai "Access Denied" with its edge reference) give "blocked; cannot search" and exit 4, never "not found"; an ordinary 200 form with a Turnstile or hCaptcha widget labelled "Verify you are human", a 200 contact form with `id="captcha-form"` and a reCAPTCHA widget, a 200 tutorial quoting HUMAN's markup, and a 503 maintenance page with only DataDome, HUMAN, Akamai or Imperva cookies or headers, are not blocked | README, method.md §8 | `tests/test_find_browser.py::test_challenge_pages_are_blocked_not_not_found`; `tests/test_find_classifier.py::test_shipped_catalog_classifies_fixture_challenges`; `tests/test_e2e_browser.py::test_find_reports_a_challenge_page_as_blocked`; `tests/test_find_classifier.py::test_shipped_catalog_still_blocks_sourced_challenge_pages`; `tests/test_find_classifier.py::test_shipped_catalog_does_not_block_forms_or_maintenance_pages`; `tests/test_find_classifier.py::test_shipped_catalog_does_not_block_pages_that_only_mention_or_embed_vendors`; `tests/test_catalog.py::test_challenge_signals_classify`; `tests/test_catalog.py::test_every_challenge_signal_cites_its_own_sources` | changed |
| D2 | Values are found in XHR JSON, `__NEXT_DATA__`, JSON-LD, split tags, narrow-NBSP text, number variants and JS/JSON escapes (HTML-safe, `\xNN`, `\u{X}`, surrogate pairs, double-escaped) | README, method.md §8 | `tests/test_find_browser.py::test_price_found_in_product_json_and_ranked_above_the_html`; `tests/test_find_browser.py::test_embedded_next_data_and_ld_json`; `tests/test_find_browser.py::test_narrow_nbsp_price_matched_as_variant`; `tests/test_find_search.py::test_tag_stripped_variant_for_split_price`; `tests/test_find_search.py::test_number_format_variants`; `tests/test_find_regressions.py::test_escaped_next_data_and_ld_json_values_are_found`; `tests/test_find_search.py::test_escaped_embedded_values_are_never_not_found` | changed |
| D3 | Ranking: all values first, then values matched, then fewer `variant:substring` hits, then network before service-worker or HTTP-cache copies, then billed basis (encoded body + response headers + request headers + 7,200 for https; request headers left out on HTTP/2 and HTTP/3); at most 20 matches | method.md §8 | `tests/test_find_browser.py::test_name_and_price_rank_responses_with_all_values_first`; `tests/test_find_search.py::test_ranking_puts_substring_hits_after_boundary_matches_and_more_values_first`; `tests/test_find_browser.py::test_plain_http_target_has_no_tls_estimate`; `tests/test_helpers_playwright_h2.py::test_find_on_http2_keeps_rebuilt_header_sizes_out_of_the_billed_basis` (needs `node`; the 20-match cap is `find.core.MAX_MATCHES`) | changed |
| D4 | Short or digits-only values warn (coincidental beacon match), currency symbols and codes included; the warning names the value, and is left out when nothing was searched or the top match also holds a non-short value | README, method.md §8 | `tests/test_find_search.py::test_short_value_rule`; `tests/test_find_search.py::test_currency_values_count_as_numeric_only`; `tests/test_find_search.py::test_short_value_warning_names_the_value_and_is_left_out_when_it_cannot_mislead`; `tests/test_find_browser.py::test_coincidental_beacon_match_is_flagged`; live: no warning for `51.77` next to "A Light in the Attic" in the same top match (2026-09-23) | changed |
| D5 | Coverage line on every result; skipped reasons counted, a challenged sub-response as `challenge page` with a warning naming the vendor; values in no response are named under the coverage line with the initial-load note | README, method.md §8 | `tests/test_find_browser.py::test_coverage_counts_every_response`; `tests/test_find_browser.py::test_value_nowhere_reports_not_found_with_coverage`; `tests/test_types.py::test_coverage_summary`; `tests/test_find_regressions.py::test_challenged_xhr_is_not_counted_as_inspected`; `tests/test_find_search.py::test_sub_response_classification_scope`; `tests/test_find_search.py::test_render_names_missing_values_under_the_coverage_line` | changed |
| D6 | Starter code only for 2xx GETs without cookies, Authorization, a token-like request header ("sent a token header", flag `token-header`) or random-looking tokens (query values, session- or signature-like parameter names, tokens inside compound values, `;name=value` path parameters, and path segments on the same heuristic as report path cleaning); otherwise a not-emitted line that names session or anti-bot state only for those reasons (a non-GET, a status and a service worker's answer each say what they are); the curl command gets `--globoff` for URLs with `[ ] { }` | README, method.md §8 | `tests/test_find_search.py::test_code_eligibility_reasons`; `tests/test_find_search.py::test_looks_random_uuids_and_lowercase_ids`; `tests/test_find_search.py::test_random_path_token_detection`; `tests/test_find_regressions.py::test_uuid_request_id_withholds_code_and_verify`; `tests/test_find_browser.py::test_session_product_flagged_sent_cookies_and_not_code_eligible`; `tests/test_find_browser.py::test_signed_offer_flagged_random_token`; `tests/test_find_search.py::test_signed_and_session_query_values_withhold_code`; `tests/test_find_search.py::test_session_path_parameters_withhold_code`; `tests/test_find_search.py::test_find_and_reports_share_one_path_token_heuristic`; `tests/test_find_round3.py::test_token_header_withholds_code_with_its_own_reason`; `tests/test_find_regressions.py::test_api_key_header_withholds_code_and_verify_says_no`; `tests/test_find_round3.py::test_persisted_query_hashes_and_jsonp_callbacks_are_not_tokens`; `tests/test_find_round3.py::test_curl_starter_turns_globbing_off_for_brackets_and_braces`; `tests/test_find_round3.py::test_curl_starter_command_sends_exactly_one_request`; `tests/test_find_round4_find.py::test_not_emitted_text_matches_the_reason`; `tests/test_find_round4_find.py::test_a_cookieless_post_and_a_404_are_not_called_session_state` | changed |
| D7 | `--verify` sends exactly one cookie-less GET with the scrapescope user agent and `Accept-Encoding: gzip, deflate`, no redirects, through the same forwarder/upstream, to the top eligible match or to a higher-ranked replay candidate (ineligible only for cookies or a token header) when no eligible match with the same values is within 2x its size; it decodes the body with a bounded decoder (the cap holds for received and decoded bytes; stacked or unrequested codings are `not tested`); "yes" needs every value as itself; client errors, a replay not sent after a budget trip or upstream failure, the meter's own reply, a proxy 407, a 502/504 and a replay past its one deadline are `not tested`, never a crash; coding text in reasons is reduced to tokens | README, method.md §8 | `tests/test_find_browser.py::test_verify_replays_product_json_through_the_same_proxy`; `tests/test_e2e_browser.py::test_find_through_upstream_finds_verifies_and_keeps_the_value_private`; `tests/test_find_search.py::test_verify_replay_rejects_overlong_urls_as_not_tested`; `tests/test_find_search.py::test_verify_top_turns_unexpected_errors_into_not_tested`; `tests/test_find_search.py::test_bounded_decoder_stops_at_the_cap_and_refuses_stacked_codings`; `tests/test_find_search.py::test_verify_survives_a_compression_bomb`; `tests/test_find_search.py::test_verify_needs_a_non_weak_match_in_the_replay`; `tests/test_find_round3.py::test_verify_target_prefers_a_much_smaller_candidate_over_the_page`; `tests/test_find_round3.py::test_a_cookie_only_match_is_replayed_and_gets_code_when_it_replays`; `tests/test_find_regressions.py::test_analytics_cookie_does_not_keep_the_json_from_verify`; `tests/test_find_round3.py::test_no_replay_after_the_budget_tripped`; `tests/test_find_regressions.py::test_no_replay_once_the_budget_tripped`; `tests/test_find_round3.py::test_replay_answered_by_the_meter_or_a_proxy_is_not_tested`; `tests/test_find_round3.py::test_replay_has_one_overall_deadline`; `tests/test_find_round3.py::test_replay_reason_never_carries_the_sites_content_encoding`; `tests/test_find_round3.py::test_replay_warning_shows_coding_tokens_only` | changed |
| D8 | Find values never appear in report.json or report.html; paths and JSON-key locations holding any searched form are dropped | privacy.md | `tests/test_find_browser.py::test_value_in_the_url_path_is_kept_out_of_the_report`; `tests/test_report.py::test_reports_never_contain_credentials_queries_cookies_or_find_values`; `tests/test_e2e_browser.py::test_find_through_upstream_finds_verifies_and_keeps_the_value_private`; `tests/test_find_search.py::test_no_searched_form_reaches_locations_or_paths_d8`; `tests/test_find_search.py::test_safe_path_drops_number_format_and_multiply_encoded_forms`; `tests/test_find_search.py::test_json_key_paths_drop_number_format_and_digit_run_forms` | changed |
| D9 | Browser tests skip cleanly without Chromium; missing Playwright gives exit 3 before the meter starts, with uv, pipx and pip advice; a Chromium that fails to start gets its own message | exit-codes.md, README | `tests/conftest.py::_skip_browser_tests_without_chromium`; `tests/test_find_browser.py::test_missing_playwright_raises_browser_unavailable`; `tests/test_cli.py::test_find_without_a_browser_exits_3`; `tests/test_cli.py::test_find_checks_for_playwright_before_starting_the_meter`; `tests/test_cli.py::test_find_with_chromium_missing_gets_browser_advice_not_pip` | changed |
| D10 | Default body cap 5 MB, adjustable with `--body-cap-mb` | method.md §8 | `tests/test_cli.py::test_find_passes_options_and_maps_outcomes`; `tests/test_find_browser.py::test_body_cap_skips_large_bodies` | verified |
| D11 | `find` uses a fresh browser context without the user's cookies or profile | security.md | by construction: `find/browser.py` `load_page` launches a new, non-persistent browser and context for every `find`; round-4 manual check (2026-09-24): two consecutive `find` runs against a local server that sets `sess=abc123` sent no `Cookie` either time | verified |
| D12 | `find` asks for Chromium's OS sandbox and, where it cannot start, runs without it and warns | security.md, method.md §8 | `tests/test_find_browser.py::test_find_asks_for_the_sandbox_and_falls_back_with_a_warning` | verified |
| D13 | `find` ends the page load early, without a retry, when the provider answers 407 (Chromium alone waits for the timeout), and when the meter refused the `https://` target itself (private address or this machine's own, deny rule, self-loop), naming the reason, and the option only for the first connection to the target itself (a DNS-name target adds the rebinding caution; a refusal after the page loaded from the target is named as DNS rebinding or split DNS; hosts compared canonically, so `[::ffff:a.b.c.d]` targets match; the whole reason is kept, up to 300 characters); a refused sub-request or a redirect of the target to a private address never gets "pass --allow-private-targets"; an `http://` target's meter reply is a load error only when the meter's records hold it (an imitation by the site is searched as the site's response, with a warning); all exit 5 | method.md §8, accuracy.md, exit-codes.md | `tests/test_e2e_browser.py::test_find_stops_early_when_the_upstream_rejects_credentials`; `tests/test_find_browser.py::test_wrong_proxy_credentials_end_early_through_abort_check`; `tests/test_cli.py::test_find_abort_check_names_meter_refusals_of_the_https_target`; `tests/test_find_regressions.py::test_meter_refusal_of_an_https_target_names_the_cause_without_a_retry`; `tests/test_find_regressions.py::test_meter_refusal_of_an_http_target_is_a_load_error_not_not_found`; `tests/test_find_regressions.py::test_meter_refused_sub_request_is_skipped_and_named`; `tests/test_find_round3.py::test_imitated_meter_reply_on_the_main_document_is_the_sites`; `tests/test_find_round3.py::test_imitated_meter_reply_of_a_sub_response_is_named`; `tests/test_find_round3.py::test_meter_reply_check_matches_the_code_to_the_meters_records`; `tests/test_find_round3.py::test_meter_reply_check_against_a_real_meter`; `tests/test_find_regressions.py::test_forged_meter_reply_is_the_sites_when_the_meter_did_not_send_it`; `tests/test_find_regressions.py::test_forged_meter_reply_through_the_real_meter_and_its_records`; the CLI passes the check: `runner.find_command` (`meter_reply_check_from_snapshot(fw.snapshot)`, wired in round 3); round 4: `tests/test_cli.py::test_find_abort_check_compares_canonical_hosts_and_advises_the_flag_only_for_the_first_connection`; `tests/test_cli.py::test_find_reports_the_whole_abort_reason`; `tests/test_find_round4.py::test_a_sub_request_refused_as_private_never_recommends_the_flag`; `tests/test_find_round4.py::test_the_targets_own_name_refused_later_is_named_as_rebinding`; `tests/test_find_round4.py::test_a_redirect_of_the_target_to_a_private_address_does_not_recommend_the_flag`; `tests/test_find_round4.py::test_meter_warning_unit`; `tests/test_find_round4.py::test_meter_reply_check_matches_ipv4_mapped_spellings`; `tests/test_find_round4.py::test_a_real_refusal_of_an_ipv4_mapped_url_is_confirmed`; `tests/test_find_round4.py::test_an_iframe_to_an_ipv4_mapped_literal_is_the_meters_refusal`; `tests/test_find_round4.py::test_a_forged_main_document_is_warned_about_once`; `tests/test_find_round4.py::test_a_forged_main_document_in_chromium_is_warned_about_once`; live (2026-09-24): `find https://127.0.0.1:8443/ --direct` and `find 'https://[::ffff:127.0.0.1]:8443/' --direct` both print the whole reason ending "pass --allow-private-targets to load it" (before round 4 the first was cut at 80 characters and the second fell back to Chromium's net error) | changed |
| D14 | A currency symbol or ISO code around a number also matches the bare number; any value whose first or last character is a digit needs digit boundaries for `exact`, else `variant:substring`, which is shown but never counts as found (values matched, all values, status, exit code, verify) | README, method.md §8 | `tests/test_find_search.py::test_currency_values_match_bare_numbers`; `tests/test_find_search.py::test_strip_currency`; `tests/test_find_regressions.py::test_currency_value_finds_the_bare_number_in_the_api`; `tests/test_find_search.py::test_numeric_exact_respects_digit_boundaries`; `tests/test_find_search.py::test_values_with_digit_edges_are_not_exact_inside_longer_numbers`; `tests/test_find_search.py::test_values_with_digit_edges_still_match_on_their_own`; `tests/test_find_search.py::test_weak_hits_do_not_count_as_matched`; `tests/test_find_search.py::test_weak_only_responses_are_not_ranked_and_the_result_says_why`; `tests/test_find_regressions.py::test_value_only_inside_a_longer_number_is_not_found`; letter currencies and group separators: `tests/test_find_search.py::test_letter_currency_affixes_allow_number_matching`; `tests/test_find_search.py::test_letter_affixes_are_a_closed_list`; `tests/test_find_search.py::test_space_and_apostrophe_grouped_numbers_are_not_exact_for_a_part`; `tests/test_find_search.py::test_space_grouped_values_are_still_found_as_a_whole_and_next_to_words`; array and list elements: `tests/test_find_search.py::test_numbers_in_compact_json_arrays_are_found_as_themselves`; `tests/test_find_search.py::test_numbers_in_script_arrays_and_text_lists_are_found`; `tests/test_find_regressions.py::test_time_series_array_values_are_found`; `tests/test_find_search.py::test_leaf_locations_use_the_match_boundaries` | changed |
| D15 | HTTP-cache copies are labelled `served-from-cache` with sizes 0 and dropped when a network copy matched | method.md §8, accuracy.md | `tests/test_find_search.py::test_http_cache_hits_are_recognised_from_sizes`; `tests/test_find_search.py::test_cached_copy_is_dropped_when_the_network_copy_matched`; `tests/test_find_regressions.py::test_http_cache_hit_is_not_ranked_as_its_own_smaller_response` | verified |
| D16 | br/zstd matches get a warning and an httpx snippet note; `--verify` reports body bytes received and the replay's billed basis, with a warning above 1.2 × the browser's; starter code routes by scheme (`HTTP_PROXY`/`http_proxy` for `http://`) | README, accuracy.md, method.md §8 | `tests/test_find_search.py::test_encoding_and_replay_warnings`; `tests/test_find_search.py::test_starter_code_mentions_brotli_when_the_browser_got_br`; `tests/test_find_search.py::test_starter_code_proxy_comment_follows_the_scheme` | verified |
| D17 | Deterministic navigation errors are not retried | method.md §8 | `tests/test_find_search.py::test_navigation_retry_rule`; `tests/test_find_regressions.py::test_unsafe_port_is_not_retried` | verified |
| D18 | Terminal layout: header, coverage line, summary line and a separate share line, table rows, middle-shortened paths, one line per value with its kind and locations, no verify line when nothing was found and none was asked for; rows sharing host and path add their query (or its hash for a token row); "also eligible" lists URLs after a blank line at the outer indentation; weak hits read "not counted"; `find --quiet` drops only the progress notes | README, method.md §8 | `tests/test_find_search.py::test_render_is_narrow_lists_kinds_per_value_and_summarises`; `tests/test_find_search.py::test_render_middle_truncation_keeps_the_file_name`; `tests/test_find_search.py::test_render_prints_locations_per_value_and_response_labels`; `tests/test_find_search.py::test_locations_are_recorded_per_value`; `tests/test_find_search.py::test_render_not_found_without_verify_has_no_verify_line`; `tests/test_find_search.py::test_render_tells_apart_rows_with_the_same_path_and_lists_eligible_urls`; `tests/test_find_search.py::test_render_marks_weak_hits_as_not_counted`; `tests/test_cli.py::test_quiet_help_says_what_each_command_keeps` | changed |
| D19 | `find` exit codes: 0 every value found, 6 partly found, 1 not found, 4 blocked, 5 load failed (target refusals included), 3 browser missing, 130 Ctrl-C without a report, 88 internal error with the report still written | exit-codes.md, README | `tests/test_cli.py::test_find_outcomes_have_distinct_exit_codes`; `tests/test_cli.py::test_find_partial_result_exits_6`; `tests/test_cli.py::test_find_help_and_exit_130`; `tests/test_cli.py::test_find_internal_error_still_writes_the_meter_report` | changed |
| D20 | find reports: "Page load (find)" section, one browser launch per find, no low-sample warning, the page load labelled "find page load" (`labels.unattributed`: "find page load" or "find page load and --verify replay"), `-` for helper-reported requests in the hosts table, a closing line that names only the figures the report holds, and the terminal's own share line (`find.render.share_line`), so terminal and report never disagree; the hosts table names the `--verify` replay only on its host; a known limit: a replay that was sent but came back `not tested` (gateway error, size cap, unsupported encoding, deadline) is not named in the labels, although its bytes are in the totals | method.md §8, README | `tests/test_report.py::test_find_reports_label_the_page_load_and_the_top_match_share`; `tests/test_report.py::test_find_reports_drop_unit_warnings_and_duplicate_short_value_notes`; `tests/test_report.py::test_find_share_uses_the_top_complete_network_match_like_the_terminal`; `tests/test_report.py::test_find_share_ignores_the_verify_replay_and_background_tunnels`; `tests/test_report.py::test_find_hosts_table_names_the_verify_replay_only_for_its_host`; `tests/test_find_round3.py::test_share_line_is_the_same_for_a_result_rebuilt_from_its_report_entry`; `tests/test_report.py::test_find_reports_do_not_read_like_run_reports`; the known limit is by construction (`report._fmt.verify_replayed` counts only `yes` and `no`); round-4 verification repro (2026-09-24): a sent replay stubbed as `gateway error (status 502)` left `labels.unattributed` at "find page load" while the find section's verify line named rank 1 | changed |
| D21 | Variant matching covers the whole JSON body; the node limit applies only to key paths | method.md §8 | `tests/test_find_search.py::test_large_json_is_searched_to_the_end` | verified |
| D22 | `find` launches Chromium with WebRTC restricted to proxied connections: no STUN or UDP from this machine around the proxy | security.md, accuracy.md, method.md §8 | `tests/test_find_regressions.py::test_webrtc_sends_no_udp_around_the_proxy` (a local STUN listener) | verified |
| D23 | Number formats keep a match to the same number: `1,000` is not 1, `4.5` not `4,500`, `1000` not inside `1,000,000`, `12345` not inside `12 345 678`, `007` not `7`; one kind of thousands separator per number and a different decimal separator (`1,234.567` is not 1234567); a value without a sign is not found right after a minus sign (`42` not in `-42`, `−42`, `1e-42`; `ABC-42` and `2020-2024` still match); for a whole-number value a single thousands dot counts only next to a currency (`1.994 EUR`, `kr 1.994`, `1.299,-`), two dot groups or a following decimal comma need none; JSON number tokens compare as numbers. Limits: `[1,994]` in JavaScript, CSS or JSON embedded in HTML still reads as 1994; a German `1.994` without a currency is not matched for 1994 | README, method.md §8, contracts §7 | `tests/test_find_search.py::test_number_format_has_no_round_thousands_false_positives`; `tests/test_find_search.py::test_number_format_still_matches_real_reformattings`; `tests/test_find_search.py::test_number_pattern_keeps_sign_and_leading_zeros`; `tests/test_find_search.py::test_number_format_variants`; `tests/test_find_round4.py::test_number_format_never_reads_a_different_number`; `tests/test_find_round4.py::test_number_format_still_matches_the_same_number`; `tests/test_find_round4.py::test_json_numbers_are_read_from_the_whole_body`; `tests/test_find_round4.py::test_json_number_leaves_are_decimal_numbers` | changed |
| D24 | HTML entities are decoded in JSON and JavaScript bodies without backslashes (with `json-key:` locations); bodies without finer locations get `script-text`, `css-text`, `xml-text`, `svg-text`, `plain-text` or `json-text` | method.md §8 | `tests/test_find_search.py::test_entities_in_json_without_backslashes_are_found_with_a_location`; `tests/test_find_search.py::test_bodies_without_finer_locations_get_a_text_label` | verified |
| D25 | The `meter:` line gives the page load's and the `--verify` replay's tunnel-measured bytes separately | README, method.md §8 | `tests/test_cli.py::test_find_meter_line_splits_the_page_load_from_the_verify_replay`; live: 196.76 kB page load and 16.52 kB replay on books.toscrape.com (round 3, 2026-09-23); 196.73 kB and 16.52 kB for the README demo (round-4 verification, 2026-09-24) | verified |
| D26 | The share line compares like with like (body and headers against the DevTools-reported page load, TLS left out of both; responses served by a service worker or the HTTP cache left out of the page load), appears only for a code-eligible network top match (else "not shown for rank N (<why>)"), and is called a saving only after a `--verify` yes whose replay itself moved less than the page load (the replay's body and headers, TLS left out), never for a response that is the whole page load; a replay that moved more than 1.2 × the browser's copy shows its own share, and one that moved at least the page load reads "no saving for a client that accepts only gzip or deflate: ..." | README, method.md §8, accuracy.md | `tests/test_find_round3.py::test_share_compares_body_and_headers_with_devtools_bytes`; `tests/test_find_round3.py::test_share_is_called_a_saving_only_when_verify_replayed_it`; `tests/test_find_round3.py::test_no_share_for_a_top_match_that_needs_the_browser`; `tests/test_find_round3.py::test_share_is_left_out_when_it_cannot_be_like_for_like`; `tests/test_find_round3.py::test_a_saving_that_moved_more_on_replay_says_so_inline`; `tests/test_find_round3.py::test_page_load_bytes_leave_out_service_worker_and_cache_copies`; `tests/test_find_round4.py::test_a_replay_that_moved_more_than_the_page_load_is_no_saving`; `tests/test_find_round4.py::test_a_replay_that_moved_more_than_the_browser_copy_shows_its_own_share`; live (2026-09-24): `share: 1.4% of this page load (2,592 B body and headers against 184,102 B DevTools-reported, TLS left out of both); a saving: --verify replayed it without a browser, moving about 9,753 B body and headers (5.3% of this page load; see warnings)` on books.toscrape.com | changed |
| D27 | A site-chosen charset never stops the search (undefined, `idna`, `punycode`, `unicode-escape` and `utf-7` labels are read as UTF-8), and an unexpected error after argument checks is `find`'s internal error (exit 88, report written), never a usage error | method.md §8 | `tests/test_find_round3.py::test_decode_body_never_raises_for_a_site_chosen_charset`; `tests/test_find_round3.py::test_utf7_is_not_a_web_encoding`; `tests/test_find_regressions.py::test_undefined_charset_on_the_main_document_is_searched`; `tests/test_find_round3.py::test_a_late_value_error_is_never_reported_as_a_usage_error` | verified |
| D28 | When the main document's status is 400 or more (and no challenge rule fired), the not-found note names the status and any vendor whose signals are present, instead of the scrolling/clicking hint | method.md §8, exit-codes.md | `tests/test_find_round3.py::test_not_found_on_an_error_document_names_the_status_not_scrolling`; `tests/test_find_round3.py::test_error_document_not_found_names_the_vendor` | verified |
| D29 | While some response holds every value, only such a response gets starter code; eligible responses lacking a value are listed with `(holds N of M values)`; with no response holding every value, the starter-code heading and the verify line say `holds N of M values (value K is not in it)` | README, method.md §8 | `tests/test_find_round4_find.py::test_no_starter_code_for_a_partial_match_while_a_match_with_every_value_exists`; `tests/test_find_round4_find.py::test_the_all_values_match_gets_the_code_and_partial_ones_are_listed_with_their_count`; `tests/test_find_round4_find.py::test_a_partial_top_match_says_which_value_it_lacks`; `tests/test_find_round4_find.py::test_a_partial_candidate_that_replays_gets_no_code_while_a_full_match_exists` | verified |
| D30 | The token-header flag is recorded in `FindFlags.sent_token_header` and report.json, survives a `--verify` yes and shows next to `sent-cookies` | README, method.md §8 | `tests/test_find_round4_find.py::test_the_token_header_flag_survives_a_yes_replay_and_reaches_the_report`; `tests/test_find_round4_find.py::test_the_token_header_flag_shows_next_to_sent_cookies`; `tests/test_find_round4_find.py::test_report_flags_name_the_token_header` | verified |
| D31 | find reports show values as `all 2/2`/`some 1/2`, mixed match kinds per value (`mixed: 1 number-format, 2 exact`), the terminal's verify line with the replayed rank, and name the `--verify` replay on the host of the match actually replayed | method.md §8, accuracy.md | `tests/test_find_round4_find.py::test_verify_hosts_names_the_host_actually_replayed`; `tests/test_find_round4_find.py::test_report_find_table_counts_values_and_names_the_replayed_rank`; `tests/test_find_round4_find.py::test_report_match_column_keeps_exact_in_mixed_kinds` | verified |
| D32 | In a parsed JSON body a list is not a formatted number for the exact test either (`1,299` not in `[1,299]`); a value's leading ASCII `-` must not follow a letter, digit or underscore (`-42` not in `ABC-42` or `1e-42`); a leading `+` is not exact there either, but the number formats read it as no sign, so `+42` matches wherever `42` does | README, method.md §8 | `tests/test_find_round4_find.py::test_a_json_list_is_not_a_formatted_number`; `tests/test_find_round4_find.py::test_json_numbers_and_strings_still_match`; `tests/test_find_round4_find.py::test_a_signed_value_does_not_match_a_hyphen`; `tests/test_find_round4_find.py::test_a_signed_value_still_matches_a_sign`; `tests/test_find_round4_find.py::test_signed_number_format_does_not_match_a_hyphen_either`; `tests/test_find_round4_find.py::test_a_leading_plus_is_no_sign_to_the_number_formats` | changed |
| D33 | The `meter:` line does not count tunnels the browser closed before they opened (`failed:client_closed`) as failed and names them separately (the report's tunnel counts, hosts table and Diagnostics still count them as failed); `--verify` with nothing matched reads `not tested (nothing matched)`; the `--verify` help names the replay candidate | method.md §8, accuracy.md | `tests/test_find_round4_find.py::test_meter_line_does_not_count_tunnels_the_browser_closed_as_failed`; `tests/test_find_round4_find.py::test_verify_with_nothing_matched_says_so`; `tests/test_find_round4_find.py::test_verify_help_names_the_candidate`; `tests/test_find_browser.py::test_value_nowhere_reports_not_found_with_coverage`; live: en.wikipedia.org/wiki/Mount_Everest (2026-09-24): `in 16 tunnel(s) (0 failed; 6 closed by the browser before the tunnel opened)`, report `16 (6 failed, 0 denied)` with Diagnostics `client_closed 6` | changed |

### Reports, CLI and exit codes

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| R1 | Generated reports validate against schema.json; the golden examples are the builders' own output | method.md §10 | `tests/test_report.py::test_run_report_validates_and_carries_the_contract_fields`; `tests/test_report.py::test_golden_examples_validate_and_render`; `tests/test_report.py::test_golden_examples_are_generator_output`; every e2e test validates its report (`tests/e2e_support.py::load_report`) | changed (regenerated in round 2 for the diagnostics fields and in round 4 for `labels.unattributed`, `totals.connections` and the fix texts) |
| R2 | Reports never contain bodies, query strings, cookies, header values, credentials, the upstream host or port, the command line, environment values or find values | README, privacy.md | `tests/test_report.py::test_reports_never_contain_credentials_queries_cookies_or_find_values`; `tests/test_report.py::test_without_keep_urls_no_paths_anywhere`; `tests/test_e2e_run.py::test_credentials_never_leak_on_error_paths` | verified |
| R3 | `--redact-hosts` uses `catalog:<id>` or `redacted:<12 hex>` from a per-report random HMAC key that is never stored, and drops paths | privacy.md | `tests/test_report.py::test_redact_hosts_uses_catalog_ids_and_keyed_hashes`; `tests/test_report.py::test_redaction_is_unlinkable_across_reports`; `tests/test_report.py::test_redaction_merges_hosts_sharing_a_catalog_label` | verified |
| R4 | report.html has no scripts or external resources and a CSP with a style hash; hostile strings (`<script>`, `javascript:`, Markdown image syntax) are escaped | security.md | `tests/test_report.py::test_html_has_no_scripts_links_or_external_resources`; `tests/test_report.py::test_html_has_a_strict_csp_matching_the_single_style`; `tests/test_report.py::test_html_escapes_hostile_strings_everywhere` | verified |
| R5 | Terminal summary on stderr for `run`/`serve`; `find` result on stdout | method.md §10 | `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_e2e_browser.py::test_find_through_upstream_finds_verifies_and_keeps_the_value_private` | verified |
| R6 | Costs only with `--rate`; no default rate anywhere | README | `tests/test_report.py::test_no_rate_means_no_cost`; `tests/test_model.py::test_zero_rate_and_zero_bytes` | verified |
| R7 | Fixes appear only when their detection fired; every fix carries "verify with a compared second run"; the background fixes refuse hosts at the meter and never offer `--blocked-origins`; Playwright Python code only for runs with helper events, a stack-independent shell snippet otherwise; the MCP fix is a budgeted `scrapescope run` server command with a pinned release, never `serve --allow-tokenless`, and its comment asks for the same upstream flag as other runs; the session-reuse fix counts upstream connections, not tunnel records | method.md §9 | `tests/test_snippets.py::test_nothing_fires_on_an_empty_run`; `tests/test_snippets.py::test_every_fix_asks_for_a_compared_second_run`; `tests/test_snippets.py::test_blocking_fixes_do_not_fire_below_ten_percent`; `tests/test_snippets.py::test_background_fix_leads_with_meter_side_refusal_and_stays_metered`; `tests/test_snippets.py::test_mcp_fix_refuses_background_hosts_at_a_meter_not_with_blocked_origins`; `tests/test_snippets.py::test_mcp_fix_keeps_the_tokenless_listener_per_run_budgeted_and_pinned`; `tests/test_snippets.py::test_background_code_is_playwright_python_only_for_playwright_runs`; `tests/test_snippets.py::test_mcp_shell_snippet_parses`; `tests/test_snippets.py::test_reuse_fix_counts_upstream_connections_not_continued_records` | changed |
| R8 | Exit codes and precedence as in exit-codes.md, including 126/127 and 128+N | exit-codes.md | `tests/test_e2e_run.py::test_run_passes_the_job_exit_code_through`; `tests/test_e2e_run.py::test_run_missing_or_non_executable_command`; `tests/test_e2e_run.py::test_budget_trip_stops_the_whole_process_group`; `tests/test_e2e_run.py::test_bypass_is_detected_and_gated`; `tests/test_cli.py::test_port_in_use_exits_88` (88-over-86 precedence is not exercised) | verified |
| R9 | `report --fail-on` accepts `budget` and `bypass` (repeatable) and returns 86 before 87 | README, exit-codes.md | `tests/test_cli.py::test_report_fail_on_gates` | verified |
| R10 | Events file is 0600 in a 0700 directory and deleted after the run unless `--keep-events` | privacy.md, security.md | `tests/test_config.py::test_private_events_file_permissions_and_cleanup`; `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_e2e_run.py::test_run_direct_without_env_all_changes_no_proxy_variables` | verified |
| R11 | `serve` prints the address and `ss-<token>` once to a terminal (with a `curl --compressed` example that passes the token in the environment, not argv), otherwise only the path of the 0600 token file with a `HTTPS_PROXY="$(cat PATH)" curl --compressed` example; rewrites the report every 60 s and on exit | README, security.md | `tests/test_e2e_serve.py::test_serve_requires_the_token`; `tests/test_e2e_serve.py::test_serve_prints_the_token_to_a_terminal`; `tests/test_e2e_serve.py::test_serve_writes_the_token_to_a_private_file_when_stderr_is_not_a_terminal`; `tests/test_cli.py::test_serve_rewrites_its_report_while_running` (with a shortened interval); `tests/test_cli.py::test_serve_banner_example_uses_compressed` | changed |
| R12 | Without `--upstream-from-env`/`--direct`, `HTTPS_PROXY` is used if set, else exit 89 with a message suggesting `--direct`; the two flags together are a usage error (2) | README, exit-codes.md | `tests/test_config.py::test_resolve_upstream_missing_suggests_direct`; `tests/test_cli.py::test_usage_errors_exit_2`; `tests/test_cli.py::test_upstream_config_errors_exit_89_and_never_echo_the_value` | verified |
| R13 | No network access except the job, find's page load and the one verify request; no telemetry or update checks | README, NOTICE, privacy.md | code review; the whole suite runs without internet access (the fixture world refuses unmapped names); the round-3 live runs (`find --verify` and a three-page `run`, books.toscrape.com, 2026-09-23) made no connections other than the page loads and the replay, which the meter's tunnel records list; not checked with a packet capture | partial |
| R14 | `report` validates a file against the schema before rendering; unreadable or invalid files exit 2; fixes in a file are rebuilt from their id and the file's own figures (title, detection, code, caveats) in every format, `--format json` included, the stored detection text is never shown, and an unknown id fails validation; a file with a newer `schema_version` says "this report uses schema version N; this scrapescope reads version 1, so upgrade scrapescope to read it" | security.md, exit-codes.md | `tests/test_cli.py::test_report_rejects_unreadable_or_invalid_files`; `tests/test_report.py::test_load_report_errors_never_echo_content`; `tests/test_report.py::test_report_file_code_is_never_shown_and_fixes_are_rebuilt`; `tests/test_report.py::test_report_file_with_an_unknown_fix_id_is_rejected`; `tests/test_report.py::test_report_file_json_output_never_echoes_the_stored_fix_code`; `tests/test_report.py::test_report_file_detections_are_rebuilt_from_the_reports_figures`; `tests/test_snippets.py::test_regenerated_detections_come_from_the_report_not_the_stored_text` | changed |
| R15 | scrapescope writes no log files, caches, history or configuration files; reports are written atomically (temporary file, then rename) | privacy.md | `tests/test_report.py::test_write_and_load_round_trip`; no files beyond the report are code review; round-4 manual check (2026-09-24): with `HOME` and `TMPDIR` pointed at empty temporary directories, `find --verify`, `run` and `report` left only the report file in the working directory and nothing in either directory | partial |
| R16 | report.json and report.html are created with mode 0600 | privacy.md | `tests/test_e2e_run.py::test_run_through_http_upstream_matches_fixture_counts`; `tests/test_cli.py::test_report_text_json_and_html` | verified |
| R17 | `--out`/`--html` locations are checked before the job starts (exit 2) | exit-codes.md | `tests/test_cli.py::test_report_paths_are_checked_before_the_job_runs` | verified |
| R18 | Text in reports cannot carry Cc, Cf, Zl, Zp or Cs characters (bidi marks, separators, zero-width characters): `safe_text` escapes them and the schema rejects them | security.md | `tests/test_types.py::test_safe_text_escapes_every_control_format_and_separator_character`; `tests/test_report.py::test_schema_text_rejects_every_character_safe_text_escapes`; `tests/test_report.py::test_schema_code_allows_newlines_and_tabs_like_safe_code` | verified |
| R19 | The CLI help lists every exit code inline (the docs are not in the wheel) | README | `tests/test_cli.py::test_help_lists_every_exit_code_without_uninstalled_docs` | verified |
| R20 | Reports count failed tunnels by reason (`tunnel_failures`) and descriptor-limit accept pauses (`accept_limit_errors`) and show both under Diagnostics; both fields are optional in the schema; a warning names the cause when every tunnel (or most, with four or more) failed | method.md §2, §10, contracts §11 | `tests/test_report.py::test_diagnostics_name_tunnel_failure_reasons_and_accept_pauses`; `tests/test_cli.py::test_failure_warning_names_the_reason_and_the_variable_only`; `tests/test_types.py::test_schema_top_level_is_closed_and_complete` | verified |
| R21 | Costs read in cents from $1 up and with three significant digits below, at most six decimals | method.md §10 | `tests/test_report.py::test_cost_lines_use_cents_or_three_significant_digits` | verified |

### Documentation facts, packaging and open questions

| ID | Claim | Where | Test | Status |
|---|---|---|---|---|
| O1 | Install commands (`uv tool install`, `uvx --from`, `pipx install` with any Python 3.11 or newer and `pip install`, each with the `scrapescope @ git+https://github.com/ipvolt/scrapescope` direct reference, plus `--with-executables-from playwright` and `pipx inject --include-apps`) work | README | manual: round 2 installed the wheel into fresh uv environments on Python 3.11 and 3.14 and with pipx on 3.13 (`--python python3.13`) and ran `report`; the round-3 review (2026-09-23) built the wheel and on Python 3.13 installed it with `uv venv` + `uv pip`, with `uv tool install '[browser]' --with-executables-from playwright` and with `uvx --from <wheel>`, and saw the clear exit-3 messages for a missing Playwright and a missing Chromium. Round 4 (2026-09-24): pipx 1.17.2 on Python 3.13 installed the wheel, then `pipx inject --include-apps scrapescope playwright`; both states gave the documented exit-3 messages. Release preparation (2026-09-24): the README's recipes were run against this tree with `file:///` in place of the git URL, in scratch tool directories: uv 0.12.9 (`uv tool install 'scrapescope[browser] @ file://...' --with-executables-from playwright` on Python 3.12 exposed both `scrapescope` and `playwright`, and `uvx --from 'scrapescope @ file://...' scrapescope --version` ran), pipx 1.17.2 on Python 3.13 (`pipx install 'scrapescope @ file://...'` then `pipx inject --include-apps scrapescope playwright` exposed both commands; installing with the `[browser]` extra first makes `inject` refuse to expose `playwright` without `--force`, which is why the README's pipx recipe installs without the extra) and pip in a fresh Python 3.13 venv. The `git+https` form itself needs the public repository and is not tested yet. Nothing is on PyPI. `.github/workflows/ci.yml` installs the built wheel as a uv tool but has not run | partial |
| O2 | The README `find` demo values (`£51.77` and "A Light in the Attic" on the books.toscrape.com product page) are still correct | README | live, 2026-09-24 (round 4): the demo command (`--value 51.77`) found both values in the product page's HTML document (rank 1, 9,792 B billed-basis; share 1.4% of 184,102 B DevTools-reported, TLS left out; `--verify` yes, about 9,753 B body and headers, 5.3%). Re-check before release | verified |
| O3 | Chromium does not use QUIC/HTTP3 through the meter and sends no UDP to port 443 (spike question) | accuracy.md | live, 2026-09-23 (round-3 review): two en.wikipedia.org loads through the helper under `run --direct` showed request protocols `h2` (64) and `data` (6) and no UDP sockets in the job's process tree (chrome-headless-shell, node). Headful Chromium was not tested | verified for chrome-headless-shell; headful open |
| O4 | Which of "with CONNECT" / "without CONNECT" providers bill, and whether TLS handshakes are billed, per workload class (reconciliation) | accuracy.md | reconciliation protocol | open |
| O5 | Prior-work descriptions in the README match each project's own pages (NetScope's store listing, Firefox's "Search in requests", Bright Data's domain-consumption API, the Skyvern postmortem, NodeMaven's NOTEBOOK section measured 2026-08-19 in a repository created 2026-08-25, Puppeteer #7042's "Chromium") | README | round-3 review (2026-09-23): every prior-work page was fetched and matches, apart from the Skyvern wording, now corrected to Skyvern's own attribution ("did not persist browser state between sessions"); Bright Data's "SSL analyzing" is described in the luminati-proxy README, which the README now names as the source. Round 4 (2026-09-24): fetched again; three nits fixed: NodeMaven's own section calls the fetch intermittent (the README, the catalog credit and the fix comment now say so), Scrapfly's TLS termination is cited from its certificates page, and Bright Data's note on statistics versus billing is attributed to its configuration documentation. Re-check before release | verified |
| O6 | Node: `fetch` honours `NODE_USE_ENV_PROXY` from 24.0.0 and 22.21.0, the `node:http` global agent from 24.5.0 and 22.21.0 (Node's own docs); Node 26.8.1 `fetch` was metered under `--env-all`. aiohttp `trust_env=True` as stated | README | Node checked against Node's own docs (24.5.0 and 22.21.0 for the global agent) and Node 26.8.1 `fetch` metered under `--env-all`; the round-3 review (2026-09-23) metered aiohttp with `trust_env=True` under `run --direct --env-all` (1 tunnel) and saw no tunnel with `trust_env=False` | verified |
| O7 | Playwright launches Chromium without its OS-level sandbox unless `chromium_sandbox=True`; `find` therefore asks for it | security.md | `tests/test_find_browser.py::test_find_asks_for_the_sandbox_and_falls_back_with_a_warning` (the Playwright default itself is from its documentation) | changed |
| O8 | The h11 dependency floor excludes versions affected by GHSA-vqfr-h8mv-ghfj (CVE-2025-43859) | security.md | `tests/test_packaging.py::test_h11_floor_excludes_the_chunked_encoding_advisory` | verified |
| O9 | No shipped file names a URL under an unreserved namespace (the PyPI project name, `pypi.org/project/scrapescope`, until the planned publication; the GitHub namespace left the list on 2026-09-24 when `github.com/ipvolt/scrapescope` was created); the report schema's `$id` is `urn:scrapescope:report:v1`; the User-Agent names the tool, its version and the repository's URL as contact, nothing else | security.md, SECURITY.md, release checklist | `tests/test_packaging.py::test_no_project_url_points_at_an_unreserved_namespace` (every file of the wheel and sdist per pyproject.toml's build targets, plus any archive in `dist/`); `tests/test_packaging.py::test_namespace_scan_finds_urls_in_files_and_built_archives`; `tests/test_config.py::test_user_agent_is_honest`. The wheel and sdist were built with `uv build` in round 3 (2026-09-23; the integrating verifier rebuilt them after the last changes) and the packaging tests passed with them in `dist/`, with no home path in either archive; the CI workflow repeats this with fresh archives | verified |
| O10 | The release check finds placeholders, relative README links and missing project/contact URLs; the tree is not release-ready while the maintainer-name placeholder remains; the check reads every file the wheel and sdist ship, and its own documentation of the placeholder does not trip it | CONTRIBUTING, docs/dev/release-checklist.md | `tests/test_packaging.py::test_release_check_finds_placeholders_relative_links_and_missing_urls`; `tests/test_packaging.py::test_release_check_reads_every_shipped_file_and_not_its_own_documentation`; `tests/test_packaging.py::test_tree_is_ready_for_a_public_release` (runs with `SCRAPESCOPE_RELEASE_CHECK=1`; fails today by design) | open |
| O11 | The is-antibot copyright line and MIT permission notice are reproduced verbatim in NOTICE | NOTICE | `tests/test_catalog.py::test_is_antibot_copyright_and_permission_notice_are_verbatim` | verified |
| O12 | CI builds, installs and tests on Linux and macOS with Python 3.11-3.14, plus a Chromium job; classifiers list only what has run (macOS, 3.12) | README, CONTRIBUTING, pyproject.toml | `.github/workflows/ci.yml` has every action pinned to a commit SHA (2026-09-24: actions/checkout v4.4.0, astral-sh/setup-uv v6.8.0, actions/setup-node v4.4.0) and needs no secrets, but has not run yet: it runs on the first push to the public repository. Locally, round 4 (2026-09-24): the tests not marked `browser` passed from the sdist on macOS with Python 3.12 and 3.14 (1,302 passed, 5 skipped), which is what the CI job "without a browser" runs | open |
| O14 | SECURITY.md says who reads the reporting mailbox (ipvolt's shared inbox, read by staff and AI mail assistants) until a dedicated address exists | SECURITY.md | release checklist item 3 (blocker) | open |
| O15 | Every direct.json docs URL and background.json `host_evidence` URL still names its host | CONTRIBUTING, contracts §8 | `tests/test_catalog.py::test_catalog_urls_still_name_their_hosts` (network; runs only with `SCRAPESCOPE_CHECK_CATALOG_URLS=1`): passed in the round-3 review (2026-09-23) and again in the round-4 review (2026-09-24, 346 s; 45 URLs swept, all 200 except ai.google.dev (302) and the NodeMaven blob (429), as in round 3); a status sweep of every catalog, README and NOTICE URL returned 200 (ai.google.dev needs a cookie jar; NodeMaven's blob URL was rate-limited, its raw file loads). The challenge sources added in round 3 (Cloudflare's Error 1020 page, Akamai's error-string page) were fetched and contain their patterns | verified |
| O16 | The test suite needs no Playwright outside the tests marked `browser` (the CI job "without a browser" installs only `.[dev]`) | CONTRIBUTING, .github/workflows/ci.yml | `tests/test_packaging.py::test_the_suite_without_the_browser_extra_needs_no_playwright` (collects the whole suite and runs the find CLI and route-wrapper tests with Playwright made unimportable); the whole non-browser suite also passed that way in round 3 (`-p tests._no_playwright -m 'not browser'`) and again after the round-4 find fixes (2026-09-24: 1,459 passed, 5 skipped) | verified |
| O17 | No shipped file holds a developer's absolute home path or agent-only build directives, and no Python source holds a literal control, bidi or line-separator character (escapes only) | pyproject.toml, contracts §1 | `tests/test_packaging.py::test_shipped_files_name_no_local_home_directory`; `tests/test_packaging.py::test_python_sources_hold_no_invisible_or_bidi_characters` (round 3 found and escaped a literal U+202E and U+2028/U+2029 in `tests/test_find_search.py`) | verified |
