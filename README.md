# scrapescope

Find the smallest response that already contains the data your scraper needs.
See every host the job talked to, including traffic the browser started by
itself, and how many bytes each part used. scrapescope runs locally and works
with any proxy provider or none. It is open source under the MIT licence.

scrapescope is built and maintained at ipvolt, a proxy provider. It works with
any provider or none and never contacts ipvolt.

**It stays free.** ipvolt commits that scrapescope stays free and MIT-licensed.
There is no paid tier, licence key, usage limit or feature held back for ipvolt
customers. It has no default provider, rate or account, no telemetry and no
update checks. The full commitment is in [NOTICE](NOTICE). If a release breaks
it, report that as a bug ([SECURITY.md](SECURITY.md)).

> **Status: 0.1.0, pre-release.** Installed from GitHub; not yet published on
> PyPI (publication there is planned). The docs were checked against the
> implementation on 2026-09-24, after the fourth review round;
> [docs/method.md](docs/method.md#claims-to-verify) lists each behaviour claim
> with the test that covers it and the ones that are still open. The test
> suite has run on macOS with Python 3.12. A CI workflow for Linux and macOS
> with Python 3.11 to 3.14 is in `.github/workflows/` and runs on every push
> and pull request; until its first run has passed, Linux is expected to work
> but is untested. Windows is untested.

---

## What it shows

**The smallest response that carries your value.** `scrapescope find URL
--value V` loads the page once in headless Chromium. It searches every text
response the page received for the values you name: the document, XHR and
fetch, scripts, embedded JSON such as `__NEXT_DATA__` and JSON-LD, and frames
and workers. It also matches common encodings of each value: JSON and
JavaScript escapes (including the HTML-safe `\u0026` forms and double-escaped
strings that Next.js and Rails pages embed), HTML entities, number formats, a
price with a currency symbol or code against the bare number, non-breaking
spaces, text split across HTML tags, and case. Matches are ranked by the bytes
a standalone fetch of that response would move, by a client that accepts the
same compression, which can be a small fraction of the full page load. Each
match says whether the browser sent cookies, an `Authorization` header, a
token-like request header or a random-looking token for it. Starter code
(`curl` and `httpx`) is printed only for plain GET requests that sent none of
those and, while some response holds every value, only for such a response; a
response that lacks a value says which one. With `--verify`, scrapescope fetches the top eligible match once more
without a browser, without cookies or captured headers, and reports whether it
still works: `yes`, `no` or `not tested`. When a higher-ranked match is
ineligible only because of the cookies or a token header the browser sent,
and no eligible match holds the same values within twice its size, the replay
tests that match instead; it gets starter code only if the replay says yes. If the page turns out to
be a challenge page, the result reads "blocked; cannot search" instead of "not
found", and a data request that was itself challenged is named in a warning.

**What your provider's dashboard cannot show.** A provider sees the host in
each CONNECT request and a stream of encrypted bytes. It cannot see inside TLS,
so it cannot tell you which resource type or request used the bytes, which
component of the browser fetched something the job never asked for, or what
blocking would change. scrapescope sits on your machine in front of your
provider. It counts the bytes of every tunnel at the socket to the provider and
joins those counts to what the browser helper reports. From that it produces:

- every host, with tunnel counts and bytes with and without the CONNECT
  exchange;
- bytes per resource type (document, script, image, font, media, XHR and so
  on), allocated from the tunnel totals;
- traffic the browser started by itself, labelled with a catalogued component
  such as Chromium's optimisation-guide model downloads, but only when the host
  is in the evidence-backed [background catalog](src/scrapescope/catalog/background.json);
- idle preconnects, bytes before the helper attached, and bytes it cannot
  attribute, each shown separately rather than guessed;
- a what-if for blocking images, media and fonts or denying catalogued
  background hosts, with fixes for your stack that appear only when the
  matching problem was measured in your run: Playwright Python code for runs
  with the Playwright helper, a stack-independent `scrapescope run
  --deny-catalog background` command for any other browser launcher, a
  Playwright MCP server command (shown whenever background bytes were seen,
  and labelled "If you use Playwright MCP"), and session reuse for Requests
  and HTTPX;
- per-1,000-unit figures (a unit is a page load by default) and, when you give
  your own `--rate`, an estimated cost per run, per 1,000 units and per 1,000
  successful units.

**A byte budget.** `--budget 2GB` stops a runaway job. scrapescope warns at 80%.
At 100% it closes every tunnel, refuses new ones, stops your job's whole
process group and names the heaviest hosts of the final minute. The meter stops
at its own count; your provider may count up to a few MB more per open tunnel.

**What it does not do.** It never terminates or intercepts TLS, so your
client's TLS fingerprint is unchanged. It has no stealth features, does not
solve or get past challenges, and ranks no vendors. Its figures are
measurements on your machine, not your provider's bill (see
[Honest limits](#honest-limits)).

## Install

scrapescope is not on PyPI yet (publication there is planned), so install it
from GitHub. It needs Python 3.11 or newer and `git` on your `PATH`. `uv`
downloads a suitable Python for you if needed; pipx uses its default Python
unless you name one.

```sh
uv tool install 'scrapescope @ git+https://github.com/ipvolt/scrapescope'    # install the command
pipx install 'scrapescope @ git+https://github.com/ipvolt/scrapescope'       # alternative; its Python must be 3.11 or newer
uvx --from 'scrapescope @ git+https://github.com/ipvolt/scrapescope' scrapescope --help   # run without installing
```

With pipx, `--python python3.13` (any `python3.11` or newer on your `PATH`)
picks the interpreter, and pipx 1.5 or later can fetch one with
`--fetch-missing-python --python 3.12`. To install a particular tag or commit,
append `@<tag-or-commit>` to the URL.

`find` and the Playwright helper need the optional browser extra and
Playwright's Chromium. Install Chromium with the Playwright from the same
environment, so the browser build matches:

```sh
uv tool install 'scrapescope[browser] @ git+https://github.com/ipvolt/scrapescope' --with-executables-from playwright
playwright install chromium

# or with pipx: install without the extra, then inject Playwright with its command
# (add --python python3.13, or any python3.11 or newer, if pipx's default is older)
pipx install 'scrapescope @ git+https://github.com/ipvolt/scrapescope'
pipx inject --include-apps scrapescope playwright
playwright install chromium

# or in your project's own virtual environment
pip install 'scrapescope[browser] @ git+https://github.com/ipvolt/scrapescope' && python -m playwright install chromium
```

If you use the Playwright helper or the hooks inside your own job, install
`scrapescope` in the job's environment too, so that `import scrapescope.helpers`
works there.

From a clone of this repository, `pip install -e '.[browser]'` installs it
editable; [CONTRIBUTING.md](CONTRIBUTING.md) has the development setup.

The test suite has run on macOS with Python 3.12. Linux is expected to work but
has not been tested yet (the CI workflow runs the suite there on every push).
Windows is untested in v1. Stopping a job's process group is implemented for
POSIX systems only.

Each tunnel costs the meter two file descriptors. `run`, `serve` and `find`
raise their own soft open-files limit to the hard limit (at most 65,536); `run`
does it after starting your job, so the job keeps its usual limit. When the
hard limit is low, scrapescope prints a note at start, and tunnels it cannot
open fail as `failed:local_limit` with a report warning saying the failures
came from this machine. If you see it, raise the hard limit (`ulimit -Hn`,
which can need administrator rights).

## Quick start

### find: which response already has the value

```sh
scrapescope find 'https://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html' \
    --value '£51.77' --value 'A Light in the Attic' --direct --verify
```

- `--value` is repeatable. `find` ranks the responses that contain any of the
  values: those holding every value first, then those with more values. A
  value with a currency symbol or code, such as `£51.77` or `51,77 EUR`, also
  matches the bare number `51.77` in JSON, and other number formats match too
  (`1,299.00` and `1.299,00`). The rules keep a match to the same number:
  `1` is not found in `1,000`, nor `4.5` in `4,500`; a number uses one kind of
  thousands separator and a different decimal separator (`1,234.567` is not
  1234567); a value without a sign is not found right after a minus sign
  (`42` is not in `-42`, `−42` or `1e-42`, while `ABC-42` and `2020-2024` are
  hyphens and still match), nor is a value's leading minus after a letter or
  digit (`-42` is not in `ABC-42`; a leading `+` counts as no sign, so `+42`
  matches wherever `42` does); and for a whole-number value (`1994`, `1 994`,
  `5,000`, `1994.00`) a single thousands dot such as `1.994` counts only next
  to a currency (`1.994 EUR`, `EUR 1.994`, `kr 1.994`, `1.299,-`), while two dot
  groups (`1.234.567`) or a following decimal comma (`1.994,00`) need none. In
  a JSON response, number tokens are compared as numbers (`1,299` is not in
  the list `[1,299]`). Limits: inside
  JavaScript, CSS or JSON embedded in an HTML page, `[1,994]` still reads as
  1994, and a German `1.994` without a currency is not matched for `1994` (a
  deliberate miss). A value that starts or ends with a digit needs digit
  boundaries on that side: `51.77` inside `151.77`, or `22 available` inside
  `122 available`, is only a `substring` hit. Such hits are shown ("only
  inside a longer number; not counted") but never count as found.
- `--direct` loads the page from your own connection ("sizing mode"). To go
  through your provider instead, leave it out and set `HTTPS_PROXY` (see
  `run` below). In sizing mode scrapescope refuses loopback, private and
  link-local addresses, this machine's own addresses and hosts on its own
  IPv6 link (/64) unless you pass `--allow-private-targets`. When the
  refused address is the target you typed, `find` reports a page load that
  failed because the meter refused the address, names that option (with a
  DNS-rebinding caution when the target is a name) and exits 5, never "not
  found". When a page's own sub-request, a redirect, or a later request to a
  name that moved is refused, `find` says so and mentions the option only
  with a warning to use it for a page or site you trust
  ([docs/security.md](docs/security.md#sizing-mode-and-private-addresses)).
- The result starts with a header (`scrapescope find: <host/path>  (N
  values)`), then the coverage line (`searched N inspected responses; skipped:
  ...`, or `not found in N inspected responses; skipped: ...`), a summary line
  and, when it applies, a share line. For the command above on 2026-09-24 they
  read `smallest with all values: rank 1, 9,792 B billed-basis` and `share:
  1.4% of this page load (2,592 B body and headers against 184,102 B
  DevTools-reported, TLS left out of both); a saving: --verify replayed it
  without a browser, moving about 9,753 B body and headers (5.3% of this page
  load; see warnings)`: the product page's own HTML document, served over
  HTTP/2 with `br`, already carries both values, and the replay, which
  accepts only gzip and deflate, received it uncompressed. Both sides of the
  comparison are body and headers, with TLS left out. The share is shown only
  for a response that gets starter code, and it is called a saving only when
  the `--verify` replay of that response returned its values and itself moved
  less than the page load; a replay that moved more reads `no saving for a
  client that accepts only gzip or deflate: the --verify replay moved about X
  B body and headers, more than this page load`. Otherwise the line says why
  not. Each
  match is a table row (rank, billed-basis bytes, values, status, type,
  method, flags, match kind), then its host and path, then one line per value
  saying how and where it matched. Rows that share a host and path add their
  query (or a short hash of it when it holds a random-looking token). After
  that come starter code or the reason it was not emitted, the other eligible
  responses under "also eligible" (separated from the code), the `--verify`
  result, and a `meter:` line with the tunnel-measured bytes of the page load
  and, separately, of the `--verify` replay. The report file keeps hosts,
  types and sizes, never the value you searched for or query strings. Its text
  rendering (`scrapescope report`) has a "Page load (find)" section with one
  browser launch, labels the page load's tunnels "find page load", and prints
  the terminal's own share and verify lines.
- The starter code reads your proxy from the environment by scheme:
  `HTTPS_PROXY` for `https://` URLs; for `http://` URLs, httpx reads
  `HTTP_PROXY` and curl reads lowercase `http_proxy`. When the browser received
  `br` or `zstd`, a client without those decoders (stock macOS curl, httpx
  without `httpx[brotli,zstd]`) receives a larger body; `find` warns about it.
- A short or digits-only value triggers a warning naming it by position
  (`value 1 is short or numeric-only: ...`), because a match for it alone is
  often a tracking beacon or an ID. The warning is left out when the top match
  also holds one of your other, longer values.
- When a value is in no response, a `not found: value N` line under the
  coverage line says so, and adds that only responses of the initial page load
  were inspected: content loaded later by scrolling, clicking or timers is not
  covered.
- `find` exits 0 when every value was found, 6 when some responses matched but
  at least one value was in none of them, 1 when nothing matched, 4 when the
  page was a challenge or block page, 5 when the page did not load (including
  a target the meter refused), 3 when Playwright or its Chromium is missing,
  and 130 on Ctrl-C, without a report ([docs/exit-codes.md](docs/exit-codes.md)).
  With `--quiet`, `find` drops only its progress notes on stderr; the result
  and the `meter:` line still go to stdout.

Only use `find` on pages you are allowed to access, and check the site's terms
before automating anything it shows you.

### run: meter an existing job through your provider

Put your provider's proxy URL in an environment variable, never on the command
line:

```sh
export HTTPS_PROXY='http://USERNAME:PASSWORD@proxy.example.net:8000'   # your provider's endpoint
scrapescope run --upstream-from-env HTTPS_PROXY --budget 2GB --rate 3.00 -- python my_scraper.py
```

`--rate` is your own price per GB in USD; 3.00 here is only an example. There is
no default rate, so without `--rate` there are no costs in the report.

`--upstream-from-env HTTPS_PROXY` keeps the job's routing as it was. The job
gets `HTTPS_PROXY=http://127.0.0.1:<port>`, which points at scrapescope and
carries no credentials, and scrapescope forwards each connection to the real
proxy with your credentials. Other proxy variables (`*_proxy` in any case,
`NO_PROXY` excepted) that name the same upstream, whatever the host's case,
with or without the scheme, are replaced the same way, and so is any other
variable whose value is exactly the upstream URL. scrapescope also adds
`SCRAPESCOPE_PROXY_URL`, `SCRAPESCOPE_AUTH_PROXY_URL`, `SCRAPESCOPE_EVENTS`,
`SCRAPESCOPE_UPSTREAM_ID` (a salted fingerprint of the upstream's host and
port; see below) and, with `--keep-urls`, `SCRAPESCOPE_KEEP_URLS`. Nothing
else changes. If your job hands its proxy URL to something that does not run
on this machine (a cloud browser session, a remote worker, a configuration
file it writes out), keep that URL in a variable scrapescope does not touch:
in the replaced variables it now reads `http://127.0.0.1:<port>`, which is
useless elsewhere. A proxy variable that names your provider's host on
another port or scheme, or its credentials on another host, is left alone
(providers often select sessions or countries by port), and `run` names it at
start and in the report, because its traffic skips the meter. The same goes
for `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` (either case) set to any other
proxy, with a reason: for example, curl, Python and Node read
`$https_proxy` before `$HTTPS_PROXY`, so a lowercase twin that points
elsewhere takes their traffic around the meter. If you give neither
`--upstream-from-env` nor `--direct`, scrapescope uses `HTTPS_PROXY` when it
is set and otherwise stops with a message suggesting `--direct` (or naming
`https_proxy`, `all_proxy`, `ALL_PROXY`, `HTTP_PROXY` or `http_proxy` when
one of those is set instead).

When the job exits, scrapescope prints a summary to stderr, writes
`scrapescope-report.json` (`--out PATH` to change it, `--html PATH` for an
offline HTML table) and exits with the job's own exit code, or with one of the
codes in [docs/exit-codes.md](docs/exit-codes.md).

### Sizing mode: measure before you buy

```sh
scrapescope run --direct --env-all -- python my_scraper.py
```

`--direct` sends traffic from your own connection, so you need no proxy
account. `--env-all` points every proxy-aware client in the job at scrapescope:
it sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase forms,
`NODE_USE_ENV_PROXY=1`, and adds `127.0.0.1,localhost,::1` to `NO_PROXY`.
Under `--env-all`, the LLM API hosts listed in
[direct.json](src/scrapescope/catalog/direct.json) (for example
`api.openai.com`) always go direct, never to a paid proxy, and are reported
separately as "non-target". **They go direct even when you use `--env-all` with
a provider: scrapescope resolves those names and connects from your own IP
address, for every client of the meter, a browser included.** `run` prints a
note saying so, and the report warns when it happened. Cloud-storage hosts are
not in the list, because buckets are often scrape targets. Without
`--env-all`, `--direct` changes no proxy variables, and only clients that use
the helpers or `$SCRAPESCOPE_PROXY_URL` are measured.

Sizing mode reproduces the transport (TCP and TLS through a proxy hop), not
your provider's exit location, block rate or retries. For protected sites it is
a lower bound. Re-measure a small sample through your provider before buying.

### Attribution for Playwright (Python)

Totals work for any client. For per-type figures, units (pages), success counts
and the bypass check, use the helper:

```python
from playwright.sync_api import sync_playwright
from scrapescope.helpers.playwright import launch

with sync_playwright() as p:
    browser = launch(p.chromium)       # browser-wide proxy -> scrapescope; records the launch
    context = browser.new_context()    # every new context is instrumented
    page = context.new_page()
    page.goto("https://books.toscrape.com/")
    browser.close()
```

The async API has `async_launch`. The lower-level pieces are
`proxy_settings()` (for `launch(proxy=...)`), `instrument(context)` and
`wrap_new_context(browser)`. `instrument(context)` also records the context's
browser launch, once per browser. For a persistent context
(`launch_persistent_context`), call `record_launch(context)` too: Playwright
1.63 gives such a context its Browser (`context.browser`), which
`instrument(context)` records, but older releases may not. Both count the
same browser once, in either order. When a report shows browser traffic but no
recorded launch, it prints "browser launches: not recorded" instead of 0. If
your job passes per-context provider credentials, for example a session
username, keep passing them:

```python
context = browser.new_context(proxy={
    "server": "http://proxy.example.net:8000",
    "username": "customer-x-session-1",
    "password": PROVIDER_PASSWORD,
})
```

The wrapped `new_context` replaces `server` with scrapescope's address and
leaves the username and password unchanged; scrapescope forwards them to the
provider it was started with. `launch(p.chromium, proxy={...})` rewrites a
proxy you pass in the same way. So start scrapescope with the upstream variable
pointing at that same provider endpoint; the URL in the variable can omit
credentials if every context brings its own. Only a `server` with that
provider's host and port is rerouted: `run` gives the job
`SCRAPESCOPE_UPSTREAM_ID`, a salted fingerprint of the upstream's host and
port (not the host itself), and a `proxy=` naming any other server is left
alone with one warning, so its traffic shows up as bypassing the meter
instead of being sent to the wrong provider. In sizing mode there is no
upstream, so every `proxy=` server is rerouted, with a warning when a process
names two different ones. Outside `scrapescope run` the helpers do nothing
except print one warning, so the same script still runs.

`launch(p.chromium, webrtc_proxied_only=True)` adds Chromium's
`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, so WebRTC cannot
send UDP (STUN) from your machine around the meter and your provider, which
would also show pages your real address. It is off by default because it
changes what pages can do with WebRTC; `find` always sets it.

Playwright turns off Chromium's HTTP cache whenever a browser or context has
proxy credentials. Without them (plain `launch(p.chromium)`), scrapescope adds
your provider credentials itself and the cache stays on.

### Hooks for Requests and HTTPX

```python
import requests
from scrapescope.helpers.hooks import instrument_requests
session = instrument_requests(requests.Session())

import httpx
from scrapescope.helpers.hooks import instrument_httpx
client = instrument_httpx(httpx.Client())   # or httpx.Client(event_hooks=httpx_event_hooks())
```

Hooks record metadata about each response (host, method, status and sizes) and
never read bodies for themselves. The Requests hook writes its event when your
code has read the body to the end or closed the response (or when the response
is garbage-collected or the interpreter exits), with the raw body bytes urllib3
read; the size is unknown for chunked bodies and is never just the declared
`Content-Length`. On HTTP/2 and HTTP/3 both hooks write the header sizes as
unknown, because those headers are compressed on the wire.
`instrument_requests()` and `instrument_httpx()` also record requests that
fail before any response; the plain `httpx_event_hooks()` dictionary cannot
see those. Routing still comes from `HTTPS_PROXY`, which both libraries read by
default. HTTPX 0.28 cannot send a plain `http://` request to an IPv6 literal
through an HTTP proxy: it writes the target without brackets
(`GET http://::1:8080/x`), which scrapescope refuses with `400 bad-request`.
It also rejects legacy IPv4 spellings such as `1.2.3.04` before sending.

### serve: a standing meter for hand-configured clients and CI

```sh
scrapescope serve --upstream-from-env HTTPS_PROXY --budget 5GB
scrapescope serve --upstream-from-env HTTPS_PROXY --budget 5GB --token-file ./proxy-url   # CI, logs
```

`serve` creates a per-run username `ss-<token>`, then runs until Ctrl-C or
SIGTERM. Clients must use that username; `serve` has no tokenless mode. When
stderr is a terminal, `serve` prints the address and the username once.
Otherwise (a log file, journald, `docker logs`, a CI log, which other users
can often read) it prints no token: it writes the proxy URL
`http://ss-<token>:x@127.0.0.1:<port>` to a file of mode 0600 in a fresh
private temporary directory and prints only that file's path.
`--token-file PATH` picks the file instead: PATH must not exist yet
(otherwise `serve` exits 2), and it is created with mode 0600. Either file is
removed when `serve` stops, since the token dies with it. Use
`--token-file` in CI.

Keep the token out of command-line arguments, which `ps` and `/proc` show to
other local users: pass it in the environment, as the banner's example does,
or in a client configuration file. Typed at a prompt, the environment form
still lands in your shell history unless the line starts with a space and
your shell skips such lines (`HISTCONTROL=ignorespace` in bash, `setopt
histignorespace` in zsh); for repeated use, the curl configuration file is
the better choice:

```sh
HTTPS_PROXY=http://ss-<token>:x@127.0.0.1:<port> curl --compressed https://books.toscrape.com/
HTTPS_PROXY="$(cat ./proxy-url)" curl --compressed https://books.toscrape.com/   # with --token-file
# or put  proxy = "http://ss-<token>:x@127.0.0.1:<port>"  in a curl config file and run  curl -K FILE ...
# keep your own provider username and password:
#   username ss-<token>~<provider-username>, password <provider-password>
```

With `ss-<token>` alone, scrapescope uses the credentials from
`--upstream-from-env`. With `ss-<token>~<provider-username>`, it strips its own
prefix and sends your username and password to the provider. The report is
rewritten every 60 seconds and on exit; it keeps no byte timeline, which only
`run`'s per-unit figures use. See [docs/security.md](docs/security.md) for
the token and the listener.

### report: re-render or gate a saved report

```sh
scrapescope report scrapescope-report.json                             # text summary
scrapescope report scrapescope-report.json --format html --html out.html
scrapescope report scrapescope-report.json --fail-on budget            # exit 86 if the budget tripped
```

A report file is treated as untrusted input: it is validated against the
schema first (an invalid file exits 2), and suggested fixes are rebuilt by
this scrapescope from their id and the file's own figures (title, detection,
code and caveats) rather than shown as stored, in every format (`--format
json` included), so a report from someone else cannot present its own code
or text as scrapescope's.

### Common options

| Option | Meaning |
|---|---|
| `--rate USD` | your price per GB (per GiB with `--gib`); no default, costs only when given |
| `--gib` | report in GiB (2^30 bytes) instead of GB (10^9 bytes, the default) |
| `--budget SIZE` | stop at this many bytes to and from the provider; a unit is required, e.g. `2GB`, `500MB`, `1.5GiB` (`2B` for bytes). The provider may count up to a few MB more per open tunnel |
| `--max-tunnel-mb N` | close any single upstream connection after N × 10^6 bytes. It is per connection, not per response: one HTTP/2 tunnel carries many responses (often a host's whole page load), and a kept plain-HTTP provider connection can carry several hosts' requests, so the cap can close all of that traffic |
| `--deny-host GLOB` | refuse matching hosts (repeatable); `*` matches any characters, dots included |
| `--deny-catalog background` | refuse every host in the background catalog (read the trade-off below) |
| `--units N` | (`run`, `serve`) the number of units (pages, items) the run produced, for per-1,000 figures |
| `--out PATH`, `--html PATH` | report locations; default `./scrapescope-report.json`, HTML only when asked |
| `--keep-urls` | keep URL paths (never query strings) in reports; default is hosts only. `;` path parameters are dropped and token-like segments (JWT, UUID, long hex or base64) become `{token}`; this is a heuristic, so a kept path can still hold an identifier it does not recognise |
| `--redact-hosts` | replace hosts with catalog ids or per-report keyed hashes |
| `--keep-events` | (`run`) keep the private helper events file after the run and print its path |
| `--fail-on bypass` | (`run`) exit 87 when helpers or hooks reported traffic the meter did not carry: a request to a host no tunnel carried, a request more than 2 s after every tunnel to its host had closed, or a host whose reported bytes exceed 1.5 × its tunnel bytes + 64 KiB (WebSocket payloads excluded). Clients without helpers or hooks stay invisible |
| `--allow-private-targets` | (sizing mode) let scrapescope connect to loopback, private and link-local addresses, this machine's own addresses and hosts on its own IPv6 link, which it refuses by default |
| `--quiet` | `run`, `serve`: no summary; errors and budget messages still go to stderr. `find`: no progress notes; the result still goes to stdout |
| `--port N` | listening port; default random |

Denying catalogued background hosts has a security cost: Chromium's component
updates also deliver certificate-revocation lists and Safe Browsing data. Each
catalog entry states its trade-off.

## Which clients it covers

| Client | How it reaches scrapescope | Totals | Attribution | `find` | Hooks |
|---|---|---|---|---|---|
| Playwright Python, Chromium | the helper (`launch()` or `proxy_settings()`) | yes | yes (helper) | yes | — |
| Playwright JS, Puppeteer | a launch option: `proxy: {server: process.env.SCRAPESCOPE_PROXY_URL}` or `--proxy-server=$SCRAPESCOPE_PROXY_URL` | yes | planned for v1.1 | via the CLI | — |
| Requests, HTTPX | `HTTPS_PROXY`, read by default | yes | hook-reported | via the CLI | yes (a code change) |
| Scrapy, curl | `HTTPS_PROXY` (Scrapy's proxy middleware; curl's `https_proxy`/`HTTPS_PROXY`) | yes | totals only | via the CLI | no |
| Node `fetch` and the global agent | `NODE_USE_ENV_PROXY=1` (set by `--env-all`): `fetch` from Node 24.0 or 22.21, the `node:http` global agent from Node 24.5 or 22.21; got and many undici dispatchers ignore it | yes | totals only | — | — |
| aiohttp | only with `trust_env=True` | yes | totals only | — | — |
| Selenium (Chrome) | one `--proxy-server` argument | yes | totals only | — | — |
| Firefox, Camoufox | the browser's proxy setting | yes | with the Playwright helper, per-type figures from Playwright's own sizes (cache hits recognised by a missing server address), marked unverified and kept out of the bypass volume check; otherwise totals only | — | — |
| Containerised jobs | planned for v1.1 (Docker image) | — | — | — | — |

"Totals" means tunnel-measured bytes per host. "Attribution" adds per-type
allocation, units, success counts and the bypass check. A client that builds
its own proxy URL can point at `$SCRAPESCOPE_PROXY_URL` and keep its own
username and password; scrapescope passes them through to the provider it was
started with. Hosted browsers (Browserbase, Steel and similar) are invisible to
a local meter, because their proxy traffic leaves from the cloud.

## Honest limits

- **Not a bill.** Totals are the bytes scrapescope wrote to and read from the
  socket to your provider (tunnel-measured). Providers may count differently:
  with or without the CONNECT exchange, GB or GiB, with minimums or rounding,
  including or excluding failed requests. Costs are labelled "estimated
  billable transfer". No reconciliation against a provider's billing has been
  published yet; until one exists for a kind of workload, nothing here is
  billing-grade. See [docs/accuracy.md](docs/accuracy.md).
- **Tunnel-measured versus allocated.** Per-host totals are measured.
  Per-request and per-type bytes are allocated: each host's tunnel bytes shared
  in proportion to the reported sizes, scaled down or up. Scaling up is capped
  at an overhead allowance; tunnel bytes beyond it are shown as the type
  `unreported` (requests the helpers never saw), which what-if figures and
  fixes ignore. On HTTP/2 and HTTP/3 the browser reports no header sizes, so
  those are left unknown rather than guessed. A request cannot be tied to a
  particular tunnel.
- **Blocking can break extraction or attract anti-bot scrutiny.** The blocking
  what-if and the blocking fixes say so; the background what-if and fixes state
  their security trade-off instead. Every what-if and fix says to compare a
  second run before relying on it. Playwright's `route()` disables the HTTP
  cache, so the suggested fixes prefer blocking methods that keep it.
- **Launch flags do not stop Chromium's model downloads.** Playwright already
  passes `--disable-background-networking` and `--disable-component-update`,
  and NodeMaven saw the optimisation-guide fetch with both. The suggested fix
  refuses the catalogued background hosts at the meter
  (`--deny-catalog background`) and keeps one profile. For Playwright MCP it
  gives a server command for your MCP client:
  `scrapescope run --budget 2GB --deny-catalog background --quiet -- sh -c
  'exec npx -y @playwright/mcp@X.Y.Z --proxy-server "$SCRAPESCOPE_PROXY_URL"
  --user-data-dir ./mcp-profile'`, with the release you reviewed in place of
  `X.Y.Z` and your usual `--upstream-from-env VAR` or `--direct` added (the
  fix's comment says so). MCP clients often start servers with a minimal
  environment: without the upstream variable set in the server's
  configuration, or `--direct`, `run` exits 89 and the server does not start.
  MCP's `--blocked-origins` is no substitute, because it is `route()`-based:
  it sees only page and worker requests and disables the cache. While that server runs, the meter's tokenless listener (random port,
  as in every `run`) is open to local processes, and the budget bounds what
  they could spend.
- **The meter stops at its own count, not your provider's.** Bytes already in
  flight when the budget trips can reach your provider, roughly up to a few MB
  per open tunnel.
- **Sizing mode is a lower bound for protected sites,** and its "with CONNECT"
  figure is an estimate. For plain `http://` requests it adds nothing: a
  provider would also receive each request's absolute-form target and your
  credentials line ([accuracy.md](docs/accuracy.md#sizing-mode)).
- **The bypass check sees only instrumented clients.** It catches requests to
  hosts no tunnel carried, requests after a host's tunnels had closed, and
  hosts whose reported bytes far exceed what their tunnels carried. Traffic
  from a client without the helper or hooks that skips scrapescope cannot be
  detected.
- **`--env-all` with a provider sends LLM API calls from your own IP.** That is
  its purpose (those calls should not go through a paid proxy), and scrapescope
  says so at start and in the report.
- **`find` looks at one page load.** It reports what it inspected and what it
  skipped (over the size cap, evicted, a worker without a session, WebSocket,
  binary, a challenged sub-request). It never says the page computed the value;
  a value not found may still be built by scripts. Its billed basis assumes a
  client that accepts the same compression as the browser.
- **UDP is not metered.** scrapescope carries TCP only. A page's WebRTC can
  send STUN over UDP straight from your machine, past the meter and your
  provider, and learn your addresses that way. `find` launches Chromium with
  WebRTC restricted to proxied connections; for your own jobs,
  `launch(..., webrtc_proxied_only=True)` or the Chromium switch
  `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` does the same.
- **Not supported in v1:** Windows (untested), TLS to the proxy (`https://`
  proxy URLs), SOCKS4, UDP, and absolute-form `https://` requests to
  scrapescope. `http://` proxies with CONNECT and `socks5://`/`socks5h://`
  proxies (hostnames resolved by the provider) are supported.

## Prior work

scrapescope combines ideas that other tools already implement well. Each
description below is from the project's own documentation as read on
2026-09-23 and re-checked on 2026-09-24; they are checked again before each
release.

- **Chrome DevTools** can search request headers, payloads and response bodies
  in the Network panel, with plain-text or regular-expression search, shows
  each response's transferred bytes in its Size column, and copies any request
  as a cURL command ("Copy as cURL")
  ([Chrome reference](https://developer.chrome.com/docs/devtools/network/reference));
  Firefox's network monitor has an equivalent "Search in requests"
  ([Firefox documentation](https://firefox-source-docs.mozilla.org/devtools-user/network_monitor/request_list/index.html#search-in-requests)).
  **NetScope** ([Chrome Web Store](https://chromewebstore.google.com/detail/dalnhbofgpgeaoecpndnehfonjfpjnmo),
  version 1.2.0, updated 2026-07-26), a Chrome DevTools panel, searches response
  bodies and WebSocket frames for a value you type, as plain text or a regular
  expression, and also offers copy as cURL. Both find *which* request carries
  a value, and a regular expression can cover some encodings by hand.
  scrapescope adds, automatically: a ranking of the responses that hold your
  values (those with all of them first) by what a standalone fetch would move,
  including a TLS handshake; the common encoded variants of each value tried for you; flags
  for cookies, authorisation and tokens; and a cookie-less replay check
  without a browser.
- **mitmproxy2swagger** ([github.com/alufers/mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger))
  turns captured traffic into an OpenAPI description of a site's REST API, and
  **Integuru** ([github.com/Integuru-AI/Integuru](https://github.com/Integuru-AI/Integuru))
  uses an LLM agent to write integration code from a HAR file and a described
  action. They document whole APIs. scrapescope answers a narrower question:
  which single response already contains the values you name, and how large it
  is. It is deterministic and local, and needs no API key or model.
- **apify/proxy-chain** ([github.com/apify/proxy-chain](https://github.com/apify/proxy-chain))
  is a Node.js proxy server library that chains to HTTP and SOCKS upstreams and
  exposes per-connection traffic statistics. scrapescope's per-tunnel counting
  is the same kind of plumbing, packaged as a command that wraps your job and
  adds attribution, a budget and reports.
- **Bright Data Proxy Manager** ([github.com/luminati-io/luminati-proxy](https://github.com/luminati-io/luminati-proxy))
  is a local forward proxy with traffic statistics, request logs and rules. It
  requires a Bright Data account, and it can also route other vendors'
  proxies ("Add External Proxies" in its
  [configuration documentation](https://docs.brightdata.com/products/proxy-manager/configuration)).
  Its README describes request-level detail through its "SSL analyzing"
  (TLS interception) option. Its configuration documentation notes that its
  statistics can differ from billing, and Bright Data also offers per-domain usage statistics for its
  network
  ([domain consumption API](https://docs.brightdata.com/api-reference/account-management-api/domain-consumption)).
  scrapescope needs no account, adds attribution, a budget and `find`, and
  never intercepts TLS.
- **Scrapfly Proxy Saver** ([docs](https://scrapfly.io/docs/proxy-saver/getting-started))
  is a hosted, paid layer between your client and any proxy provider. It blocks
  and stubs unneeded resources, caches, enforces budgets and shows per-domain
  metrics; it terminates TLS (clients trust its certificate:
  [certificates](https://scrapfly.io/docs/proxy-saver/certificates)).
  scrapescope measures and explains on your own
  machine and leaves optimisation to you.
- **NodeMaven** measured on 2026-08-19 (published by 2026-08-25, when the
  repository was created) that a fresh Chrome profile spent about 43 MB on
  `optimizationguide-pa.googleapis.com`, even with
  `--disable-background-networking` and `--disable-component-update`. The
  fetch is intermittent: NodeMaven saw it in some idle windows, not all
  ([NOTEBOOK.md, "Chrome pays its vendor 43 MB per profile"](https://github.com/nodemaven/proxy-benchmark/blob/main/NOTEBOOK.md#chrome-pays-its-vendor-43-mb-per-profile-and-the-pool-was-billed-for-it)).
  **Skyvern's** postmortem described about 200 GB of proxy traffic in six hours,
  with repeated 70 MB calls to `optimizationguide-pa.googleapis.com`, which
  Skyvern attributed to Chrome re-downloading the model because it did not
  persist browser state between sessions
  ([postmortem](https://blog.skyvern.com/how-we-accidentally-burned-through-200gb-of-proxy-bandwidth-in-6-hours/),
  [HN discussion](https://news.ycombinator.com/item?id=41593410)), and
  [Puppeteer issue #7042](https://github.com/puppeteer/puppeteer/issues/7042)
  reported that about 90% of one user's proxy traffic went to Chromium `.crx`
  package downloads. scrapescope's background catalog builds on these findings and
  credits them in each entry.
- Some challenge-page patterns are adapted from **is-antibot**
  ([github.com/microlinkhq/is-antibot](https://github.com/microlinkhq/is-antibot),
  MIT, Copyright © 2025 Microlink). They are used only to recognise a challenge
  page, never to get past one; [NOTICE](NOTICE) lists them and reproduces
  is-antibot's licence notice.

## Documentation

- [docs/method.md](docs/method.md): how counting, attribution, the budget and
  `find` work, with the list of behaviour claims and their test status
- [docs/accuracy.md](docs/accuracy.md): what each figure means and how it can
  differ from a bill
- [docs/security.md](docs/security.md): threat model, listeners, tokens and
  credential handling
- [docs/privacy.md](docs/privacy.md): exactly what is and is not stored
- [docs/exit-codes.md](docs/exit-codes.md): exit codes for scripts and CI
- [CONTRIBUTING.md](CONTRIBUTING.md): development, tests and catalog entries
  with evidence
- [SECURITY.md](SECURITY.md): reporting a vulnerability

## Licence

MIT; see [LICENSE](LICENSE). [NOTICE](NOTICE) holds ipvolt's stays-free
commitment and third-party attributions.
