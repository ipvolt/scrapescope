# Exit codes

scrapescope's exit codes are part of its command-line interface, for scripts
and CI. Its own codes, 86-89, do not overlap with the codes shells use for "not
executable" (126), "not found" (127) and "killed by signal N" (128 + N).
`find` has no job, so its outcomes use small codes (0, 1, 3, 4, 5, 6). The same
list is in `scrapescope --help`, because this file is not installed with the
package.

> **Status.** Checked against the implementation on 2026-09-24. Tracked as R8,
> R9, R12 and R17 in [method.md](method.md#claims-to-verify).

## Table

| Code | Commands | Meaning |
|---|---|---|
| the job's own code | `run` | The job exited and no scrapescope condition below applies. A job killed by signal N gives 128 + N, as in a shell. |
| 0 | `serve`, `find`, `report` | `serve` stopped normally; `find` found every value (each in at least one inspected response); `report` rendered and passed its `--fail-on` gates. |
| 1 | `find` | Not found: no inspected response contained any of the values. The coverage line says what was inspected and skipped. A value seen only inside a longer number (`variant:substring`) does not count as found. |
| 2 | all | Usage error (for example an unknown option, `--direct` together with `--upstream-from-env`, or `--budget` without a unit such as `2GB` or `2B`). For `run`, `serve` and `find`, also an `--out` or `--html` path whose directory does not exist or is not writable; this is checked before the job starts. For `serve`, also a `--token-file` path that already exists or cannot be created. For `report`, also an unreadable file or one that is not a valid report (including a fix id scrapescope does not generate, or a report from a newer scrapescope, which the message names by its schema version). |
| 3 | `find` | Playwright or its Chromium is not available. A missing Playwright package is detected before the meter starts; the message gives the `uv tool`, `pipx` and `pip` commands. A Chromium that fails to start gets its own message (`playwright install chromium`; on Linux also `playwright install-deps chromium`). |
| 4 | `find` | Blocked: the page was a challenge or block page ("blocked; cannot search"), such as a Cloudflare challenge or 1xxx "Access denied" page or an Akamai "Access Denied" page with its reference number. Nothing was searched; this is never "not found". A main document with status 400 or more that matched no challenge rule is searched, and a "not found" then names the status (and any vendor the page's signals name). |
| 5 | `find` | The page did not load (navigation error, timeout, or the provider answered 407, rejected SOCKS5 credentials or was unreachable), or the meter refused the target itself: a loopback, private or link-local address, this machine's own address or a host on its own IPv6 link in sizing mode without `--allow-private-targets`, a host matching `--deny-host` or `--deny-catalog`, or a name resolving to the meter. The warning names the reason and the option; such a refusal is never retried and never reported as "not found". Nothing was searched. |
| 6 | `find` | Partly found: some responses matched, but at least one value was in no inspected response (as itself). The report's status is still `found`; its warnings, and a line under the coverage line, name the missing values (`not found: value N`) and say that only responses of the initial page load were inspected. |
| 86 | `run`, `serve`, `find`, `report` | The byte budget tripped. For `report --fail-on budget`: the saved report records a tripped budget. |
| 87 | `run`, `report` | `run --fail-on bypass`: helpers or hooks reported traffic that the meter did not carry, so the run is incomplete: a request to a host no tunnel carried, a request that started more than 2 s after every tunnel to its host had closed, or a host whose reported bytes exceed 1.5 × its tunnel bytes + 64 KiB. Clients without helpers or hooks are invisible to this check. `report --fail-on bypass`: the saved report is marked incomplete. |
| 88 | `run`, `serve`, `find` | scrapescope failed internally: the meter could not start (for example `--port` already in use), stopped unexpectedly, the report could not be written, or `find` itself hit an unexpected error (the meter report is still written, with the find result marked as an error). |
| 89 | `run`, `serve`, `find` | Upstream configuration error before start: the variable is missing or empty, the URL has an unsupported scheme (`https://`, `socks4://`, others), a path or query, a bad host or port, or over-long SOCKS5 credentials. The message names the variable, never its value. When `HTTPS_PROXY` is not set but `https_proxy`, `all_proxy`, `ALL_PROXY`, `HTTP_PROXY` or `http_proxy` is, the message names that variable and suggests `--upstream-from-env`. |
| 126 | `run` | The job's command was found but is not executable. |
| 127 | `run` | The job's command was not found. |
| 130 | `find` | Interrupted with Ctrl-C (SIGINT). No report is written. (`run` passes the job's own code through instead, usually 130 too.) |

## Precedence in `run`

When several conditions apply, `run` exits with the first that matches:

1. **88**, meter internal error;
2. **86**, budget tripped (the job was stopped by scrapescope, so its own code
   says little);
3. **87**, bypass detected, only with `--fail-on bypass`;
4. the job's own exit code.

Codes 89, 126, 127 and 2 occur before the job runs, so no precedence question
arises.

## Precedence in `find`

1. **88**, meter internal error or an unexpected error inside `find`;
2. **86**, budget tripped;
3. the outcome: **0** found, **6** partly found, **1** not found, **4** blocked,
   **5** page load failed.

A Ctrl-C during `find` exits 130 at once, without a report.

Scripts that need more detail can read `find[0].status` from the report
(`found`, `not_found`, `blocked` or `error`), for example
`jq -r '.find[0].status' scrapescope-report.json`. A partly found result has
the status `found`; exit code 6 and the `not found: value N` warning tell it
apart, so `find ... && next-step` does not treat a missing value as found.

## Signals

If scrapescope itself receives SIGINT, SIGTERM or SIGHUP during `run`, it
forwards the signal to the job's process group; a second SIGINT sends SIGKILL.
It then writes the report and exits with the job's code, which is usually 130
(SIGINT) or 143 (SIGTERM). The job runs in its own session, so pressing Ctrl-C
reaches it only through scrapescope. `serve` stops on SIGINT or SIGTERM, writes its
report and exits with 0, or 86 if its budget tripped.

## `report --fail-on`

`scrapescope report REPORT.json --fail-on budget` exits with 86 if the report
records a tripped budget. `--fail-on bypass` exits with 87 if the report is
marked incomplete. The option can be given for both; if both conditions hold,
86 wins. Without `--fail-on`, `report` exits 0 after rendering a valid report.

## Examples

Stop a CI job when a scraper exceeds a byte budget or bypasses the meter:

```sh
scrapescope run --budget 500MB --fail-on bypass --quiet -- python scrape.py
status=$?
case $status in
  0)  echo "ok" ;;
  86) echo "byte budget exceeded; see scrapescope-report.json" ; exit 1 ;;
  87) echo "some traffic bypassed the meter" ; exit 1 ;;
  88|89) echo "scrapescope could not run (code $status)" ; exit 1 ;;
  *)  echo "scraper failed with code $status" ; exit "$status" ;;
esac
```

Tell a blocked page from a missing value (`--quiet` drops only the progress
notes on stderr; the result and the `meter:` line still go to stdout):

```sh
scrapescope find "$URL" --value "$PRICE" --quiet > find.txt
case $? in
  0) echo "found" ;;
  6) echo "some values found, at least one missing" ;;
  1) echo "not found in the inspected responses" ;;
  4) echo "challenge page: cannot search" ;;
  5) echo "the page did not load" ;;
  *) echo "scrapescope could not run" ;;
esac
```

Gate on a report produced earlier:

```sh
scrapescope report scrapescope-report.json --fail-on budget --fail-on bypass
```
