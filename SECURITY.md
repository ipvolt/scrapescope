# Security policy

scrapescope handles proxy credentials and sits in the path of your traffic, so
security reports are welcome and taken seriously. The threat model, listener
rules and credential handling are described in
[docs/security.md](docs/security.md).

## Reporting a vulnerability

Please report privately, not in a public issue:

- by email to **hello@ipvolt.com**, with "scrapescope security" in the
  subject. This is not a dedicated security address. It is ipvolt's shared
  contact mailbox: ipvolt staff with mailbox access read it, and so do the AI
  assistants ipvolt uses to sort and draft mail. Send a short first message
  without exploit details, and ask for a private channel; the ipvolt team will
  reply with one. A dedicated security address is planned;
- or through GitHub's private vulnerability reporting on
  <https://github.com/ipvolt/scrapescope> (the **Security** tab, then
  **Report a vulnerability**).

Include what you found, the scrapescope version (`scrapescope --version`), your
operating system and Python version, and steps to reproduce. Please do not
include real provider credentials; the test suite's fixture credentials, or
any distinctive made-up value, are enough to show a leak.

The ipvolt team handles every report, aims to acknowledge it within 7 days,
and will agree a disclosure date with you. Reporters are credited in the
release notes unless they prefer not to be.

## What counts

Examples of issues we want to hear about:

- provider credentials, the upstream URL or `Proxy-Authorization` values
  appearing in any output (stdout, stderr, logs, report.json, report.html or
  the events file), or the scrapescope token appearing anywhere other than the
  one startup message `serve` prints to a terminal or the private token file
  it writes instead (mode 0600, removed when `serve` stops);
- a listener reachable from anything other than `127.0.0.1`, or a way for a
  web page (for example through DNS rebinding) to read from scrapescope or use
  it as a proxy;
- `serve` accepting traffic without the token, or credentials being sent
  somewhere other than the configured provider;
- target hostnames resolved or connected to locally while a provider is
  configured, other than the documented exception (direct.json LLM API hosts
  under `run --env-all`, which scrapescope announces at start and in the
  report);
- in sizing mode, a connection to a loopback, private or link-local address,
  to this machine's own address or to a host on its own IPv6 link (/64)
  without `--allow-private-targets`, or a way around the self-loop checks
  (IPv4 hosts on your network that have public addresses, and NAT64
  prefixes a network chooses for itself, are documented limits: the meter
  cannot see IPv4 netmasks or a network's own NAT64 prefix);
- script injection or markup injection through report.html or the terminal
  output;
- weaker permissions than documented on the events file or its directory;
- any network connection other than your job's traffic, `find`'s page load and
  the single `--verify` request, including UDP (WebRTC) from `find`'s own
  browser, which it launches with WebRTC restricted to proxied connections;
- the serve token or provider credentials placed in a process's command line
  by scrapescope itself, or a `--verify` response exhausting memory despite
  the size cap.

## Breaches of the NOTICE commitments

[NOTICE](NOTICE) records ipvolt's commitments: scrapescope stays free and
MIT-licensed, works with any provider or none, and never contacts ipvolt. A
release that breaks one of them is a bug. Report it the same way; if it does
not put users at risk, a public issue is fine too.

## Known and documented behaviour

These are design decisions documented in [docs/security.md](docs/security.md),
not vulnerabilities in themselves:

- `run` and `find` accept tokenless connections on their loopback listener for
  the life of the command, because browsers' own background fetches cannot
  answer a proxy authentication challenge. Set `--budget` to cap what another
  local process could spend. A way to use that listener beyond what the
  document describes is still worth reporting.
- The meter keeps a record of every tunnel, including requests refused by a
  deny rule, for as long as it runs, with no cap (docs/security.md, "Resource
  use").
- With an `http://` provider URL, the CONNECT request and its
  `Proxy-Authorization` header travel to the provider unencrypted, as they do
  without scrapescope. TLS to the proxy is not supported in v1.
- Plain `http://` target traffic passes through scrapescope unencrypted, as
  through any HTTP proxy.
- `run --env-all` carries the LLM API hosts in direct.json directly, from your
  own IP address, even when a provider is configured; that is what the option
  is for, and scrapescope says so at start and in the report.
- scrapescope carries TCP only. WebRTC in the browsers of your own jobs can
  send UDP from your machine, past the meter and your provider, unless you
  launch them with WebRTC restricted to proxied connections (the Playwright
  helper's `launch(..., webrtc_proxied_only=True)`).

Out of scope: attackers with root or administrator rights on your machine, and
the behaviour of your proxy provider or the sites you load.

## Supported versions

scrapescope is pre-release. Until 1.0, fixes go into the latest release only.
