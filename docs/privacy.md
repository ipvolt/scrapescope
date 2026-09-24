# Privacy: what scrapescope stores

scrapescope runs on your machine and sends nothing to ipvolt or anyone else. It
has no telemetry, analytics, crash reporting or update checks. This page lists
every place it writes data, what each one contains, and what it never keeps.

> **Status.** Checked against the implementation and the report schema
> ([schema.json](../src/scrapescope/report/schema.json)) on 2026-09-23. The
> claims below are tracked as R2, R3, R10, R13, R15, H5 and D8 in
> [method.md](method.md#claims-to-verify).

## Where data goes

| Output | When | Where | Lifetime |
|---|---|---|---|
| report.json | at the end of `run` and `find`; `serve` also rewrites it every 60 s | `./scrapescope-report.json`, or `--out PATH` | until you delete it |
| report.html | only with `--html PATH` (or `scrapescope report ... --html PATH`) | that path | until you delete it |
| events file | during `run` | `events.jsonl` in a new private temporary directory | deleted after the run, unless `--keep-events` |
| serve token file | `serve` with `--token-file PATH`, or when its stderr is not a terminal | that path, or `proxy-url` in a new private (0700) temporary directory; mode 0600 | deleted when `serve` stops |
| terminal output | always, unless `--quiet` | stderr (`run`, `serve`), stdout (`find` result) | not stored by scrapescope; your terminal or CI may keep it |

scrapescope writes no log files, caches, history or configuration files.
Reports are written atomically (a temporary file, then a rename) and are
created with mode 0600, readable only by you, because they name the hosts your
job contacted. Use `chmod` if you want to share one on the same machine.

## What report.json contains

report.json follows [schema.json](../src/scrapescope/report/schema.json),
which rejects any field it does not list. By group:

- **About the run**: schema and tool versions, which subcommand produced it
  (`run`, `serve` or `find`, not your job's command line), the catalog
  versions, start and end times in UTC, the mode (`direct`, `http-connect` or
  `socks5`, never the provider's address), the GB or GiB unit and the fixed
  labels.
- **Totals**: bytes with and without CONNECT, bytes sent and received, and
  counts of tunnels, failed tunnels and denied tunnels.
- **Budget**: the limit, the per-tunnel cap, the counted bytes, whether it
  tripped, and budget events (time, bytes, and the hosts involved).
- **Units and pages**: the unit count and its source, browser launches, bytes
  before the first navigation, bytes of the first unit and the mean of the
  rest, the status histogram and the success count and rate.
- **Hosts**: for each host your job contacted through scrapescope, its name,
  ports, tunnel counts, bytes, request count, buckets, bytes allocated per
  resource type and, when it is catalogued, the background catalog id. With
  `--keep-urls` only, its top URL paths with request counts and sizes; never
  query strings.
- **Resource types** and **buckets**: totals per type and per bucket.
- **Non-target hosts**: with `--env-all`, the names of the LLM API hosts from
  direct.json that your job used, with bytes. This shows which of those
  services your job called.
- **Bypass**: hostnames the helpers or hooks saw that did not pass through
  scrapescope, and a count.
- **find**: the target host (and path with `--keep-urls`); the result status;
  the number of values searched (not the values); challenge vendor and signal
  names; for each match its host, port, scheme, resource type, MIME type,
  method, status, sizes, whether it was HTTP/2 or HTTP/3, its Content-Encoding
  token (such as `br`), flags, how many of the values it contained, per value
  whether the match was `exact` or which variant matched and where it was found
  (for example a JSON key path such as `offers.price`, referring to values as
  "value 1", "value 2"); coverage counts; the `--verify` outcome, status, body
  bytes received and the replay's billed basis; warnings.
- **What-if, fixes and cost**: estimated savings with caveats, fix snippets
  (which contain only catalogued hosts and the meter's port) and, with
  `--rate`, your rate and the resulting estimates.
- **Diagnostics**: warnings (sanitised text that can name hosts), counts of
  refused requests by reason, counts of failed tunnels by failure reason (for
  example `upstream_unreachable` or `upstream_status_407`), how many times the
  meter paused accepting connections for lack of file descriptors, and counts
  of helper events by kind.

## What is never stored

In report.json, report.html and the events file, scrapescope never stores:

- request or response bodies;
- cookies, or the value of any header (only whether a `Cookie` or
  `Authorization` header was sent, and header sizes);
- credentials: the upstream URL, provider usernames and passwords, the
  scrapescope token, or any `Proxy-Authorization` value;
- your provider's host or port;
- the command line or arguments of your job, or environment variable values;
- the values you search for with `find`. A match's path, and a JSON-key
  location, is dropped when it contains a value in any searched form: the value
  as given, other number formats, a bare digit run or array index equal to the
  number, repeated percent-encoding and HTML entities;
- query strings or fragments;
- URL paths, unless you pass `--keep-urls`.

### Paths kept with `--keep-urls`

Kept paths (in the report, in the events file, and the paths `find` shows in
the terminal next to each match) are cleaned first: `;` path parameters such
as `;jsessionid=...` are dropped, and segments that look like tokens are
replaced by `{token}`, keeping a file extension: a JWT, a UUID anywhere in the
segment, 24 or more hex characters, or 32 or more base64url characters mixing
upper case, lower case and digits (not word-like titles such as
`Galaxy_S24_Ultra_512GB`). This is a heuristic: a kept path can still contain
an identifier it does not recognise, such as a short account number or an
email address. `find`'s starter code and match URLs in the terminal stay
complete, because you need them to fetch the response.

## The events file

During `run`, the helpers and hooks in your job append one JSON line per event
to a file with mode 0600, inside a new directory with mode 0700. Each line has
a version and kind; `attach` and `launch` lines add a timestamp, the helper
name, the process id and an opaque context id or browser name. `request` lines
add the host, port, scheme, method, resource type, status, whether the request
failed or came from the cache or a service worker, the kind of frame, whether it
was a navigation, four sizes, and whether a `Cookie` or `Authorization` header
was sent, plus a timestamp and the opaque context id. A path is included only
with `--keep-urls`. `data:`, `blob:`, `about:`, `chrome:` and extension URLs
are never written.

scrapescope reads the file after your job exits and deletes the directory,
unless you pass `--keep-events`, in which case it prints the path and leaves the
file for you.

## Terminal output

The terminal summary shows the same kind of information as report.json. `find`
also prints, in the terminal only, the full URLs of the target and the matches
and the starter code, which contain query strings and may contain the value you
searched for or site tokens. `serve` prints its `ss-<token>` username once, to
stderr, only when stderr is a terminal; otherwise it prints only the path of
its token file. With `--keep-events`, `run` prints the events file's path. If your
terminal output is captured (for example in CI logs), treat it accordingly.

## In memory only

- The forwarder relays traffic as it arrives and keeps only per-tunnel counters
  and a byte timeline in memory. It keeps a record for every tunnel until it
  stops, with no cap yet: about 0.8 kB per tunnel once a report snapshot holds
  its copy (about 0.4 kB in the meter alone), so a very long `serve` session
  grows by about 0.8 kB per tunnel. Requests refused by a deny rule get a
  record too. Reports and the budget poll copy only open
  and changed records while holding the counting lock, so they do not stall
  the relay.
- `find` reads text response bodies into memory, up to its size cap, searches
  them and discards them.

## Sharing reports

A report names the hosts your job contacted, which can reveal your targets or
internal hostnames. Before sharing one, re-run with `--redact-hosts`:

- catalogued hosts become `catalog:<id>`;
- every other host becomes `redacted:<12 hex characters>`, a keyed hash
  (HMAC-SHA256) using a random key created for that report and never stored.
  The same host gets the same label within one report, but labels cannot be
  compared across reports or reversed with a dictionary of hostnames;
- paths are dropped;
- hosts inside warning text are replaced the same way, and rows that share a
  catalog label are merged (for example `update.googleapis.com` and
  `edgedl.me.gvt1.com` both become `catalog:component-updater`).

Independently of `--redact-hosts`, every free-text field (warnings, reasons) is
scrubbed of URL credentials, query strings, and Basic, Bearer, Cookie and
Authorization values before it is written.

`scrapescope report` cannot redact an existing report; re-run the job with
`--redact-hosts`.

Sizes, counts, resource types and timing still describe the shape of your
traffic, which can be enough to recognise a well-known site.

## Network connections

scrapescope connects only on behalf of your job, for the page `find` loads
(and what that page loads), and for the single `--verify` request. With a
provider configured, target hostnames go to the provider unresolved. The one
exception is direct.json hosts (LLM APIs) under `run --env-all`: scrapescope
resolves them and connects from your own IP address, which those services
then see; `run` says so at start and the report warns. In sizing mode
scrapescope resolves names with your system resolver and refuses loopback,
private and link-local destinations unless you pass `--allow-private-targets`.
It never contacts ipvolt.
