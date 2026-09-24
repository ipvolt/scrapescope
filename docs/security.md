# Security

This is scrapescope's threat model: what it protects, what it trusts, how its
listeners and tokens work, how it handles your provider credentials, and what
it does to stay safe with untrusted input. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

> **Status.** Checked against the implementation on 2026-09-24. Each behaviour
> claim is tracked, with the test that covers it, in
> [method.md](method.md#claims-to-verify). Treat a claim without a passing test
> as unverified.

## What scrapescope protects

- **Your provider credentials**: the upstream proxy URL with its username and
  password, and any credentials your job passes through scrapescope.
- **Your provider balance**: bytes sent through your provider are billed to you.
- **Your traffic**: scrapescope never decrypts it and stores only metadata.
- **Your reports**: they name the hosts your job contacted.

It trusts your user account and the job you run under it. It treats as
untrusted: other users and processes on the same machine, web pages open in
your desktop browser, the content of the sites you load (hostnames, paths,
headers and bodies), report files you receive from someone else, and the lines
in its own events file (which the job writes).

Out of scope: an attacker with root or administrator rights on your machine,
and your provider itself, which sees your traffic whether or not scrapescope is
in the path.

## Listeners

- scrapescope binds `127.0.0.1` only, never `0.0.0.0` or `::`. Other machines
  cannot reach it. It does not listen on IPv6 loopback, so clients must use
  `http://127.0.0.1:<port>`, not `localhost` (which may resolve to `::1`).
- The port is random unless you pass `--port`.
- `run` opens a second loopback listener, the **auth listener**
  (`SCRAPESCOPE_AUTH_PROXY_URL`), which answers 407 to a request without
  credentials. Chromium sends proxy credentials only after a 407 challenge, so
  this listener is what lets per-context credentials (such as provider session
  usernames) reach scrapescope and pass through. scrapescope's own 407 replies
  carry `Connection: close`; Chromium retries on a new connection with the
  credentials, which tests confirm for both launch-level and per-context
  credentials.
- Listeners exist only while the command runs.

### What the listeners accept

| Client request | Response |
|---|---|
| `CONNECT host:port` | a tunnel, subject to the checks below |
| absolute-form `http://...` (any method) | relayed with HTTP/1.1 framing |
| absolute-form `https://...` | `400`, `X-Scrapescope-Error: https-absolute-form` (scrapescope never originates TLS) |
| origin-form (`GET /path`), asterisk-form or anything else | `403` with `Content-Length: 0`, no body and no scrapescope headers |
| malformed request or authority, or a plain-HTTP request with both `Content-Length` and `Transfer-Encoding` | `400`, `X-Scrapescope-Error: bad-request` |
| a target that is scrapescope itself: `localhost` or a loopback literal on one of its ports, in any spelling `getaddrinfo` accepts (`127.1`, `0x7f.0.0.1`, `2130706433`, `::ffff:127.0.0.1` ...) | `403`, `X-Scrapescope-Error: self-loop` |
| token required but missing, or an `ss-` username with the wrong token | `407`, `Proxy-Authenticate: Basic realm="scrapescope"` |
| budget already tripped | `403`, `X-Scrapescope-Budget: tripped` |
| host matches `--deny-host` or `--deny-catalog` | `403`, `X-Scrapescope-Error: denied` |

Checks run in that order, and all of them before any connection to your
provider. Two more refusals happen while connecting, as a tunnel record: a
hostname or provider hostname that resolves to the meter itself (`403
self-loop`, status `failed:self_loop`), and in sizing mode a non-global
destination, this machine's own address or a host on its own IPv6 link
(`403 private-address`, see
[Sizing mode and private addresses](#sizing-mode-and-private-addresses)).
scrapescope's own responses carry `Connection: close`, a fixed one-line body
and never echo request content. After sending one, scrapescope keeps reading
the client's connection for up to a second before closing it, so the reply is
not lost to a TCP reset. When your provider resets a connection during a relay,
your client gets a TCP reset too (tunnel status `failed:upstream_reset`), so a
truncated response is never passed off as complete.

### Error codes

scrapescope's own error replies carry `X-Scrapescope-Error: <code>` (except the
bare origin-form 403). The codes are: `bad-request`, `https-absolute-form`,
`self-loop`, `token-required`, `bad-token`, `auth-challenge`, `budget`,
`denied`, `upstream-unreachable`, `upstream-timeout`, `upstream-closed`,
`upstream-protocol-error`, `socks-auth-failed`, `socks-no-method`,
`socks-auth-unsupported`, `socks-reply-<n>`, `dns-failed`, `private-address`,
`connect-refused`, `connect-timeout`, `local-limit` (503: the meter ran out of
file descriptors on this machine; see [Resource use](#resource-use)) and
`internal-error`. A non-2xx reply from your provider is relayed as it is,
without a scrapescope header.

## Tokens

Each `serve` creates a fresh token of 24 URL-safe characters from Python's
`secrets` module (about 144 bits). Clients present it as the proxy username
`ss-<token>`, or `ss-<token>~<provider-username>` to pass their own provider
username through. scrapescope strips the prefix; the token never reaches your
provider.

| Command | Tokenless connections | Why |
|---|---|---|
| `serve` | always refused with 407; `serve` has no tokenless mode | a long-running listener must not be usable by every local process |
| `run`, `find` | accepted on the main listener for the command's lifetime; these commands have no token at all | browsers' own background fetches cannot answer a 407, so a token would break the traffic being measured |

The token is never written to reports. Where `serve` puts it depends on
where its stderr goes:

- **stderr is a terminal**: `serve` prints the address and the username
  `ss-<token>` once, in its start banner.
- **stderr is not a terminal**: `serve` prints no token. It writes the proxy
  URL `http://ss-<token>:x@127.0.0.1:<port>` to a file of mode 0600 in a
  fresh temporary directory of mode 0700 and prints only that file's path.
  stderr that is not a terminal usually ends up somewhere other users can
  read: the systemd journal (readable by the `adm` and `systemd-journal`
  groups), `docker logs` (anyone in the `docker` group), `nohup.out`, and CI
  logs, which are often world-readable (mode 0644) or visible to everyone
  with access to the pipeline.
- **`--token-file PATH`** picks the file in either case. PATH must not exist
  yet: it is created with `O_EXCL` and `O_NOFOLLOW` and mode 0600, so an
  existing file or a symbolic link planted there makes `serve` exit 2
  instead of writing through it. Recommended for CI.

Either file is removed when `serve` stops. The token is valid only until
then. Because `run` and `find` have no token, a provider username that happens
to start with `ss-` passes through them unchanged.

Keep the token out of command-line arguments. Other local users can read a
process's arguments (`ps`, `/proc/<pid>/cmdline`), and an interactive command
line also lands in shell history. The banner's example therefore passes it in
the environment of one command:

```sh
HTTPS_PROXY=http://ss-<token>:x@127.0.0.1:<port> curl --compressed https://example.com/
HTTPS_PROXY="$(cat PATH)" curl --compressed https://example.com/   # the token file
```

A client configuration file works too, for example a curl config file with
`proxy = "http://ss-<token>:x@127.0.0.1:<port>"` read with `curl -K FILE`.
Typed at an interactive prompt, even the environment form is saved in shell
history; most shells skip lines that start with a space when configured to
(`HISTCONTROL=ignorespace` in bash, `setopt histignorespace` in zsh).

### The risk of the tokenless listener in `run` and `find`

While `run` or `find` is running, any process on the machine that can reach
`127.0.0.1` and finds the port (by scanning, for example) can send traffic
through scrapescope. For a request without credentials, scrapescope injects
the credentials from your upstream environment variable, so that traffic goes
through your provider **and is billed to you**. On a single-user laptop the
other local processes are your own; on a shared machine they may not be.

The Playwright MCP fix that scrapescope suggests runs the MCP server under
`scrapescope run` (`scrapescope run --budget 2GB --deny-catalog background
--quiet -- sh -c 'exec npx -y @playwright/mcp@X.Y.Z --proxy-server
"$SCRAPESCOPE_PROXY_URL" ...'`, with your usual `--upstream-from-env VAR` or
`--direct` added), so this tokenless listener, on a random port, exists for as
long as the MCP server runs, and the fix sets a budget for that reason. It
never suggests `serve` for this: `serve` always requires its token, which
Chromium's own background fetches cannot present. Pin the `@playwright/mcp`
version you reviewed instead of `X.Y.Z`.

Mitigations:

- Set `--budget`. The budget counts all traffic through scrapescope, so it caps
  what another local process could spend. Without a budget, nothing caps it.
  The meter stops at its own count: bytes already in flight when it trips can
  add up to a few MB per open tunnel at your provider.
- The port is random and the listener lasts only as long as the command.
- The auth listener never injects credentials for a request without them; it
  answers 407.
- On shared machines, prefer `serve` with its token, or run the job in a
  container or VM of its own.

Not in v1: checking which local user owns a connecting socket (possible on
Linux; considered for a later version).

## Web pages and DNS rebinding

A web page open in your desktop browser can send requests to
`127.0.0.1:<port>`, either directly or through DNS rebinding. Browsers send
such page requests in origin form (`GET /path` with a `Host` header); a page
cannot issue `CONNECT` or an absolute-form proxy request with `fetch` or XHR.
scrapescope refuses every origin-form request with a bare 403 before contacting
anything, serves no readable pages and has no HTTP API (the helpers use a
private file, not a network channel). A page therefore can neither read from
scrapescope nor use it as a proxy.

## Sizing mode and private addresses

In sizing mode (`--direct`), scrapescope connects to targets itself, so a page
loaded through it (by `find`, or by your job's browser) could otherwise reach
services on your machine or network: a router's admin page, a local database's
HTTP port, or a cloud metadata service at `169.254.169.254`. Browsers protect
against this with Private Network Access and Local Network Access, but those
protections do not apply here: a browser treats a proxied request as coming
from the proxy, which is on loopback, so it allows it.

So on the direct route scrapescope resolves the name once, refuses destinations
that are not globally routable, and connects only to the addresses it checked
(DNS pinning, so a second DNS answer cannot redirect it). When a name has
several addresses, every one is checked, and they are tried Happy-Eyeballs
style (address families interleaved, a new attempt every 250 ms or as soon as
one fails, one overall deadline):

- refused: loopback, RFC 1918 private ranges, link-local (including
  `169.254.169.254`), CGNAT (`100.64.0.0/10`), unique-local IPv6, unspecified,
  reserved and documentation ranges, and multicast. Site-local IPv6
  (`fec0::/10`), 6to4 (`2002::/16`) and the local-use NAT64 prefix
  (`64:ff9b:1::/48`) are always refused;
- IPv6 forms that embed an IPv4 address are judged by that IPv4 address:
  IPv4-mapped (`::ffff:a.b.c.d`), the NAT64 well-known prefix
  (`64:ff9b::/96`, so `64:ff9b::a00:5` is refused like `10.0.0.5`),
  IPv4-translated (`::ffff:0:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`).
  Limit: a NAT64 prefix that a particular network chooses for itself cannot
  be recognised. Deny rules (`--deny-host`, `--deny-catalog`) on an IPv4
  address or glob also match these IPv6 forms. Records keep the IPv6
  address (except IPv4-mapped ones, which are the IPv4 address in canonical
  form, below), and a provider still receives the client's own spelling;
- also refused: a connection that reached this machine itself. A globally
  routable address can be this machine's own (most IPv6-enabled machines, and
  servers with a public IPv4 address on an interface, have one), and a
  service bound to all interfaces answers there. So after the TCP connection
  is made and before any byte is written, scrapescope compares the peer with
  the socket's own source address and refuses a match; for IPv6 it also
  refuses a peer in the same /64 as the source address (hosts on this
  machine's own link, such as a router or NAS). Limit: IPv4 netmasks are not
  visible to it, so IPv4 hosts on your network that have public addresses are
  not caught;
- IP literals are canonicalised before any of these checks, the deny and
  direct rules and routing, and in reports: `1.2.3.04`, `0x01020304`,
  `16909060`, `1.2.772` and `::ffff:1.2.3.4` all become `1.2.3.4`. Legacy
  spellings follow `inet_aton` (a leading zero means octal). What an HTTP
  CONNECT provider receives keeps your client's spelling (the CONNECT line and
  a plain-HTTP target and `Host`), so a provider that parses such a spelling
  differently could reach another address; over SOCKS5 a legacy IPv4 spelling
  is sent as the canonical address (address type IPv4);
- the client gets `403` with `X-Scrapescope-Error: private-address`, and the
  tunnel is recorded with status `failed:private_address`. `find` reports
  such a refusal of its target's own address (the host and port you typed,
  in any spelling of the same address) as "page load failed" with the reason
  and `--allow-private-targets` (exit 5), never as "not found";
- `--allow-private-targets` (on `run`, `serve` and `find`) turns these checks
  off, for example to measure a staging server on your own network;
- non-target routes (direct.json hosts under `run --env-all`) are exempt,
  because cloud private endpoints can legitimately resolve there.

For an `http://` target, the meter's refusal is the page's main document.
`find` accepts a reply carrying `X-Scrapescope-Error` as the meter's own only
when the meter's records hold that refusal; an `http://` site that sends the
header itself (a forged header) is searched as the site's response, with a
warning.

A page can still cause real refusals: an iframe to a router's address, or a
DNS-rebinding name that moves to a private address after the page loaded.
Passing `--allow-private-targets` would then let that page reach the address
and read it through the meter, so `find` advises the option only in these
cases:

- **The refused address is the target's own host and port as you typed them**
  (any spelling of the same address): the reason and the option, as above.
  When the target is a DNS name, the advice adds "only if you expect this
  name on your own network: a public name that resolves to a private address
  can be a DNS-rebinding attack".
- **A sub-request was refused**: `find` reports that the page asked for a
  private or local address and the meter refused it to protect this
  machine's network; `--allow-private-targets` would let the page reach it,
  so use it only for a page you trust.
- **A later request to the target's own name was refused after the page
  loaded from it**: reported as DNS rebinding or split DNS, without advising
  the option, apart from "use `--allow-private-targets` only for a site you
  trust". This holds both for the page's own requests and for a refusal
  that stops the page load or the `--verify` replay.
- **The target redirected to a private address**: "the target redirected to
  a private or local address ...; use `--allow-private-targets` only for a
  site you trust".

With a provider configured, the provider connects to targets, so this check
does not apply; what the provider can reach is its concern.

## TLS

- scrapescope never terminates TLS. CONNECT tunnels are relayed as opaque
  bytes, so there is no certificate to install and your client's TLS
  fingerprint is unchanged.
- It never originates TLS: absolute-form `https://` requests are refused.
- v1 does not support TLS to the proxy (`https://` proxy URLs are rejected with
  exit code 89). With an `http://` provider URL, the CONNECT request and its
  `Proxy-Authorization` header travel to your provider unencrypted, exactly as
  they would without scrapescope.
- Plain `http://` target traffic passes through scrapescope unencrypted, as it
  does through any HTTP proxy. scrapescope parses the HTTP framing to relay it
  and keeps nothing but metadata.

## Credentials

### Where the upstream URL comes from

The upstream proxy URL, which usually contains your provider username and
password, is read only from an environment variable (`--upstream-from-env
VAR`, or `HTTPS_PROXY`). scrapescope never accepts it as a command-line
argument, because other users can often read a process's arguments (for
example with `ps`), while its environment is readable only by the same user and
root.

Setting the variable with `export` on an interactive command line can leave the
URL in your shell history. Prefer loading it from a file with restricted
permissions or from a secret manager.

### What your job receives

In the default mode, the upstream variable in your job's environment is
replaced by scrapescope's address (`http://127.0.0.1:<port>`, no credentials),
and so is any other proxy variable (a `*_proxy` name in any case, `NO_PROXY`
excepted) that names the same upstream: the same host, port and credentials,
whatever the host's case, with or without the scheme (`user:pass@host:port`),
with an explicit default port, and `socks5` versus `socks5h`. Other variables
are replaced only when they hold exactly the same URL, whatever their name.
Your job never sees the upstream URL through those variables. If your job
passes its proxy URL to something that does not run on this machine (a cloud
browser session, a remote worker, a configuration file it writes out), keep
that URL in a variable scrapescope does not touch, since the replaced ones
now point at `127.0.0.1`. When a proxy variable still names your provider's
host on another port or scheme, or with other credentials, or carries its
username and password on another host, `run` prints a note at start and the
report warns ("still names your upstream proxy" at start, "still named the
upstream proxy" in the report), naming the variable, never its value: traffic
that uses it reaches the provider without the meter. Such a variable is not
replaced, because providers often select sessions or countries by port; for
a loopback upstream only the same port counts. This check parses values
leniently, so an `https://` URL (a provider's TLS proxy port), a `socks4://`
URL and URLs with a path count too.

A standard proxy variable (`HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`, in
either case) set to a proxy other than the meter is left alone as well, and
`run` names it too, with the metered variable's case twin first: "note:
$NAME names another proxy and was left unchanged; <reason>, and that traffic
goes around the meter" at start, and "$NAME named another proxy (<reason>);
any traffic that used it went around the meter (and is missing from these
totals)" in the report. The reason says why the variable matters: "curl,
Python (urllib, Requests, HTTPX) and Node read $https_proxy before
$HTTPS_PROXY" or "Go reads $HTTPS_PROXY before $https_proxy" for the case
twin of the metered variable, otherwise "clients use it for http:// URLs",
"clients use it for https:// URLs" or "clients without a scheme-specific
proxy variable use it". Neither warning sets the report's `incomplete` flag,
which only the bypass check sets.
scrapescope cannot know about credentials your job keeps elsewhere (for
example a `PROVIDER_PASSWORD` variable or a config file); those are left
untouched.

With a provider configured, `run` also gives your job
`SCRAPESCOPE_UPSTREAM_ID`: a random key and an HMAC-SHA256 of the provider's
host and port under that key. The Playwright helper uses it to reroute only
`proxy=` servers that are that provider. It does not contain the host, but
anyone with the job's environment can test a guessed host and port against
it; it is a salted fingerprint, not a secret.

### What is forwarded

| Client sends | scrapescope does | Recorded as |
|---|---|---|
| no credentials | `serve` with a token, or the auth listener: 407. Otherwise injects the credentials from the upstream variable, if any | `injected` or `none` |
| username exactly `ss-<token>` | strips it and injects the upstream variable's credentials | `injected` or `none` |
| username `ss-<token>~<user>` and a password | forwards `<user>:<password>` | `token-mapped` |
| a username starting with `ss-` with the wrong token (only when a token exists, that is in `serve`) | 407; never forwarded | refused |
| other Basic credentials | `serve` with a token: 407. Otherwise passes them through unchanged | `passthrough` |
| a non-Basic `Proxy-Authorization` | `serve` with a token: 407. HTTP provider: passes it through. SOCKS5 provider: `502 socks-auth-unsupported` | `passthrough` |

- For an HTTP CONNECT provider, the client's CONNECT request line and headers
  are forwarded unchanged apart from `Proxy-Authorization`, because providers
  use custom CONNECT headers. Plain-HTTP requests are normalised instead: the
  `Host` header is set to the target's authority, and hop-by-hop headers
  (`Keep-Alive`, `Proxy-Connection` and any header `Connection` names, except
  the framing headers, `Host`, `Proxy-Authorization`, `Upgrade` and `TE`) are
  removed on every route.
- For a SOCKS5 provider, Basic credentials become an RFC 1929
  username/password (each up to 255 bytes). A SOCKS5 authentication failure is
  answered with `502 socks-auth-failed`, not 407, so that browsers do not loop
  re-prompting for credentials they cannot fix.
- In direct (sizing) mode, client credentials are dropped and never sent
  anywhere.
- Your provider's reply to CONNECT (including 407, 502 and vendor error
  headers) is relayed to your client unchanged. scrapescope does not print or
  store it.

### Never logged, printed or stored

The upstream URL, its host, port, username and password, and every
`Proxy-Authorization` value are never written to stdout, stderr, logs,
report.json, report.html or the events file. Error messages about the upstream
name the environment variable, never its value. Reports record the mode
(`direct`, `http-connect` or `socks5`), never the provider's host.

The test suite checks this with **credential sentinels**: distinctive
usernames and passwords (and their Basic base64 form) are searched for in every
output, on success and on these error paths: upstream unreachable, a 407 from
the upstream, a DNS failure at the upstream, a TLS error at the client, and a
SOCKS5 authentication failure. See claim A9 in
[method.md](method.md#claims-to-verify) for its status.

## The events file

`run` creates the events file with mode 0600 inside a new directory with mode
0700, and passes its path to your job in `SCRAPESCOPE_EVENTS`. The helpers
open it for appending only; they never create it or follow a missing path. It
holds metadata only (see [privacy.md](privacy.md)) and is deleted after the
run unless you pass `--keep-events`.

Your job can write anything to that file. scrapescope parses every line
strictly: fixed field types, charsets and lengths, at most 4,096 bytes per
line, and invalid lines dropped and counted. A hostile line therefore cannot
inject markup into a report. A job can still deliberately distort its own
attribution; that is outside the threat model.

## Untrusted strings in output

Hostnames, paths, statuses and catalog text reach the terminal and the reports.
Every such string is sanitised before output:

- hosts are normalised to lowercase `[a-z0-9_.:-]` (IDNA-encoded);
- paths drop the query and fragment, percent-encode non-printable and non-ASCII
  characters and are capped at 512 characters;
- every character of the Unicode categories Cc, Cf, Zl, Zp and Cs is shown as
  a visible escape: controls and C1, format characters (bidi marks such as
  U+200E, U+200F and U+061C, overrides and isolates, zero-width characters, the
  byte-order mark, the tag block), line and paragraph separators (U+2028,
  U+2029) and lone surrogates. Lengths are capped. The report schema's text
  patterns reject the same characters, so a report file carrying them fails
  validation.

report.html additionally escapes every string for HTML, contains no scripts and
no external resources, and carries the Content Security Policy
`default-src 'none'; style-src 'sha256-<hash>'; img-src 'none'; base-uri 'none'; form-action 'none'`.
Test fixtures include paths with `<script>`, `javascript:` and Markdown image
syntax.

`scrapescope report` validates a report file against the schema before
rendering it and exits with code 2 if it is unreadable or invalid, so report
files from other people are handled as untrusted input. Fixes in a report read
from a file are never shown as stored, in any output format (`--format json`
included): their title, code and caveats are rebuilt from the fix id and the
catalogs, the detection is shown as report data, and the text and HTML
renderers say so. The schema allows only the six fix ids
scrapescope generates, so a file with any other id fails validation.

## find

- `find` loads the page in headless Chromium in a fresh browser context,
  without your cookies or profile. The site's JavaScript runs as it would in a
  browser. Playwright starts Chromium without its OS-level sandbox by default
  (`chromium_sandbox=False`), so `find` asks for the sandbox explicitly. Where
  the sandbox cannot start, which on Linux means no unprivileged user
  namespaces (containers, Ubuntu 24.04's AppArmor default, GitHub's
  `ubuntu-24.04` runners), `find` launches Chromium a second time without the
  sandbox, loads the page anyway and says so: the result's warnings, printed
  under `warnings:` and stored in the report, carry "Chromium's OS sandbox
  could not start on this machine ..., so the page was loaded in Chromium
  without it; load only pages you trust". The fallback is automatic; there is
  no option to fail instead. Load only pages you would open in a normal
  browser, and on such a machine treat the page's JavaScript as running with
  no more isolation than any other process of your user.
- `find` launches Chromium with
  `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, so WebRTC may
  use proxied connections only: a page cannot send STUN or other UDP from this
  machine's interfaces, past the meter and your provider, or learn this
  machine's local or public addresses that way. This covers `find`'s own
  browser only. Browsers in your own `run` jobs keep their WebRTC behaviour;
  `launch(..., webrtc_proxied_only=True)` in the Playwright helper, or the same
  Chromium switch in your launcher, applies it there. UDP is never carried or
  counted by scrapescope.
- Starter code contains the full URL of the match. Read it before running it.
- `--verify` sends one GET with no cookies, captured headers or tokens, and
  identifies itself with the user agent
  `scrapescope/<version> (+https://github.com/ipvolt/scrapescope)`: the tool,
  its version and the project's contact URL, so that a site operator can reach
  whoever runs it. Nothing else is sent in it.
- `--verify` asks only for `Accept-Encoding: gzip, deflate` and decodes the
  body itself with a bounded zlib decoder, checking the size cap
  (`--body-cap-mb`, 5 MB by default) against the bytes received and against
  the decoded bytes as it goes. A compression bomb (a small body that inflates
  to gigabytes) therefore stops at the cap. A response with more than one
  content coding (`gzip, gzip`), or with `br`, `zstd` or another coding the
  replay did not ask for, is not decoded: the result is `not tested` with the
  reason `unsupported content encoding (<codings>)`, and a corrupt stream gives
  `(<coding>, corrupt)`.

## Test-only settings

`SCRAPESCOPE_TEST_CONNECT_MAP` (redirects scrapescope's own direct connections)
and `SCRAPESCOPE_TEST_CA` (a CA bundle; also makes `find`'s browser ignore
certificate errors) are honoured only when `SCRAPESCOPE_TESTING=1`. Never set
these outside the test suite.

## No telemetry

scrapescope has no telemetry, analytics, crash reporting or update checks, and
never contacts ipvolt. It makes network connections only for your job's
traffic, for the page `find` loads (and everything that page loads), and for the
single `--verify` request. In sizing mode it resolves your job's hostnames with
the system resolver. With a provider configured, target hostnames go to the
provider unresolved on HTTP CONNECT and SOCKS5 routes, and the only lookup it
makes for them is of the provider's own hostname. The one exception is
direct.json hosts under `run --env-all` (LLM APIs): scrapescope resolves those
names itself and connects to them from this machine's own IP address, for
every client of the meter, a browser included. `run` prints a note saying so at
start (unless `--quiet`), and the report carries a warning when such tunnels
occurred. Cloud-storage hosts are deliberately not in direct.json, because
buckets are often scrape targets and carrying them direct would expose your IP
address to the bucket owner.

## Resource use

scrapescope does not rate-limit local clients. Response bodies are relayed as
they arrive through bounded buffers and never accumulated in memory; `find`
reads text bodies into memory up to its size cap, and `--verify` bounds both
the received and the decoded bytes. The budget bounds bytes, not connections.

- **File descriptors.** Each tunnel costs the meter two descriptors (the
  client's socket and the upstream socket). `run`, `serve` and `find` raise
  their own soft open-files limit (`RLIMIT_NOFILE`) to the hard limit, at most
  65,536; `run` does it after starting your job, so the job keeps its original
  limit. With a hard limit below 1,024, scrapescope prints a note at start.
  When descriptors run out, a tunnel that cannot be opened fails as
  `failed:local_limit` (the client gets `503` with `X-Scrapescope-Error:
  local-limit`), a listener that cannot accept pauses for about a second
  (counted as `accept_limit_errors` in the report), and the report warns that
  these failures came from this machine, not from the target or the provider.
  Raise the hard limit with `ulimit -Hn` (which can need administrator rights).
- **Connections that send nothing.** A connection that has not sent one
  complete request head 60 seconds after it was accepted is closed, however
  slowly it keeps sending. After its first request, a connection or tunnel
  that moves no bytes in either direction is closed after 600 seconds.
  Exhausting the meter's descriptors from another local process therefore
  takes tens of thousands of open connections, renewed every minute; nothing
  in v1 limits connections per local client.
- **Tunnel records.** The meter keeps a record of every tunnel until it stops,
  with no cap: measured, about 0.4 kB per record in the meter and about
  0.8 kB once a report snapshot holds its copy (`serve` takes one every
  60 seconds), about 1.1 kB while a snapshot is being built. Requests refused
  by a deny rule create records too, before any contact with your provider,
  and count no bytes, so `--budget` does not bound them. A local process can
  therefore grow the memory of a long-running tokenless listener (`run` with
  a long-lived job such as an MCP server) by repeating a denied `CONNECT`, at
  no cost to your provider balance: about 0.8 GB per million requests. On a
  shared machine, prefer `serve` with its token for long sessions.
- **Helper events.** `run` reads the helper events file into memory after
  your job exits, at about 0.5 kB per event (measured with CPython 3.12:
  about 470 bytes for an ordinary request event, with repeated strings such
  as hosts shared). It stops after 1,000,000 events, about 0.5 GB, more with
  `--keep-urls` paths that differ per request. Any process that knows the
  file's path can append to it, so a runaway or hostile writer costs at most
  that. Lines past the cap are not read; the report says how many and that
  its figures cover only the events read.

## Supply chain

- **Dependencies.** The core depends on `h11` and `httpx[socks]` (plus their own
  dependencies). The `h11` floor is 0.16, because earlier versions accept some
  malformed chunked bodies (GHSA-vqfr-h8mv-ghfj, CVE-2025-43859) and the
  forwarder parses untrusted HTTP/1.1 from clients and origins with it. The
  optional `[browser]` extra adds Playwright, whose `playwright install
  chromium` downloads a Chromium build from Playwright's servers.
- **Releases.** scrapescope is installed from its GitHub repository
  (`git+https://github.com/ipvolt/scrapescope`); pin a tag or commit with
  `@<ref>` when you need a fixed revision. PyPI publication is planned, not
  yet in place: packages are to be published from CI with PyPI Trusted
  Publishing and attestations, from a protected default branch to which only
  the ipvolt team merges. Until the first PyPI release exists, none of that
  applies. Before any public build, `scripts/release_check.py` must pass: no
  placeholders, no relative README links, and project and contact URLs that
  exist ([release checklist](dev/release-checklist.md)).
- **Catalogs.** The JSON catalogs are data, reviewed by the maintainer. They can
  label hosts, deny hosts you ask to deny, and classify responses; they cannot
  make scrapescope contact anything.
- **Your side.** Pin the version you use in CI, and install with hashes
  (`pip install --require-hashes`) where you can.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
