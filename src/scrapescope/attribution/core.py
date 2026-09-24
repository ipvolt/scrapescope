"""Attribution: combine the meter's tunnel counters with helper/hook events.

Contract: docs/dev/contracts.md section 6. Labels and limits, stated honestly:

- Tunnel totals (per host, per bucket) are *tunnel-measured*: bytes on the
  meter's side of the upstream socket, CONNECT/SOCKS negotiation and TLS
  included (plus the synthesised CONNECT estimate in direct mode). All byte
  figures here use that "with CONNECT" basis, so the buckets add up exactly to
  ``snapshot.totals().with_connect``.
- Per-request and per-type figures are *allocated*: a request cannot be tied
  to a tunnel (DevTools does not expose the proxied connection), so each host's
  tunnel bytes are shared over the network requests helpers reported for that
  host, in proportion to their client-reported sizes (largest-remainder
  rounding, exact integer sums). When the reported sizes exceed the tunnel
  bytes (HTTP/2 header estimates, hook sizes, decompressed WebSocket payloads)
  every share is scaled down.
- Scaling up is bounded. A host's reported sizes may grow by a known overhead
  allowance (per tunnel: its negotiation bytes plus, when the record opened
  an upstream connection of its own, :data:`OVERHEAD_PER_TUNNEL_BYTES` for the
  TLS handshake and connection setup; a record that continues a kept provider
  connection gets none, round 4 meas4-6;
  :data:`OVERHEAD_SHARE` of the reported bytes; :data:`UNKNOWN_HEADERS_BYTES`
  per request whose header sizes are unknown). Tunnel bytes beyond that go to
  the type :data:`UNREPORTED_TYPE`, which what-if figures and fixes ignore:
  they belong to requests the helpers never reported (a request still in flight
  when its page navigated away or the browser closed, a WebSocket still open, a
  client without helpers on the same host). Hosts where a successful response
  has an unknown body size (a Requests hook on a chunked response) are not
  bounded, because nothing limits what that response carried.
- Tunnel bytes of hosts with no reported network request go into exactly one
  bucket per tunnel, first match wins: ``background:<catalog id>`` ONLY when the
  host matches background.json (an uncatalogued host is never called
  background); ``before_attach`` when the tunnel opened before the first helper
  observation; ``preconnect_idle`` when, with helpers active, the tunnel
  established and carried at most about 3 KB up and 6 KB down after
  negotiation; otherwise ``unattributed`` (a tunnel the upstream refused is
  never called a preconnect).
- The bypass detector only sees requests that an instrumented client reported.
  It flags a request whose host no tunnel carried, a request that started after
  every tunnel of its host had closed, and a host whose reported bytes exceed
  its tunnel bytes by more than :data:`BYPASS_VOLUME_FACTOR` times plus
  :data:`BYPASS_VOLUME_SLACK_BYTES` (one request through the meter, the bulk
  around it). Uninstrumented clients that bypass the meter are invisible to it.
  A ``403`` to a request that started after the budget tripped is the meter's
  own refusal (no tunnel is recorded for it) and is not called bypass. When a
  Firefox or WebKit launch was recorded, Playwright's request sizes are
  unverified (no DevTools data): a warning says so, and Playwright events are
  left out of the volume check.
- Hosts are matched in the meter's spelling: an IP-literal host of a tunnel or
  a request event is compared in its canonical form (``types.canonical_host``),
  so ``1.2.3.04``, ``2001:db8:0:0::1`` or Chromium's ``::ffff:102:304`` in an
  event still matches the tunnel recorded as ``1.2.3.4`` or ``2001:db8::1``.
- Request events the helpers marked as never reaching the network (answered by
  ``route.fulfill``, aborted by ``route.abort``, or blocked by the browser
  before sending; see :mod:`scrapescope.attribution.intake`) are not network
  requests: they are left out of the status histogram, the allocation and the
  bypass check, and a warning counts them.
- Timeline-derived figures (bytes before the first unit, first unit versus the
  rest) are approximate to one timeline bucket (``timeline_resolution_s``). A
  navigation unit starts with the first redirect hop that led to it. A bucket
  that straddles a unit's start belongs to that unit (the first unit at the
  first start, the rest at the second). The first-unit/rest split is withheld
  when the first two units started closer together than one bucket, because
  the first unit would absorb the others.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable, Sequence

from ..config import (
    LOW_UNITS_THRESHOLD,
    PRECONNECT_IDLE_MAX_RECEIVED,
    PRECONNECT_IDLE_MAX_SENT,
    TLS_HANDSHAKE_ESTIMATE_BYTES,
)
from ..types import (
    BUCKET_ATTRIBUTED,
    BUCKET_BACKGROUND_PREFIX,
    BUCKET_BEFORE_ATTACH,
    BUCKET_PRECONNECT_IDLE,
    BUCKET_UNATTRIBUTED,
    AttachEvent,
    AttributionResult,
    BucketTally,
    Buckets,
    BypassInfo,
    Catalogs,
    EventCounts,
    HelperEvent,
    HostAttribution,
    LaunchEvent,
    MeterSnapshot,
    NonTargetHost,
    PathBytes,
    PerUnitBytes,
    RequestEvent,
    SuccessInfo,
    TimelinePoint,
    TunnelRecord,
    TypeAllocation,
    UnitsInfo,
    canonical_host,
    is_catalog_id,
    safe_text,
)
from .allocate import largest_remainder
from .intake import MAX_EVENTS

#: Maximum hosts listed in ``bypass.hosts`` (the schema's limit).
MAX_BYPASS_HOSTS = 100
#: Maximum paths per host (``--keep-urls``).
MAX_PATHS_PER_HOST = 20
#: Maximum rows in ``types`` (the schema's limit); the smallest extra types fold into "other".
MAX_TYPES = 64
#: Resource type that absorbs folded types.
OTHER_TYPE = "other"
#: catalog id used for a non-target tunnel whose rule is not a direct.json id.
UNCATALOGUED_ID = "uncatalogued"
#: Type that holds a host's tunnel bytes beyond its reported sizes plus the allowance below.
#: What-if figures and fixes never count it. A request event claiming this type is filed as "other".
UNREPORTED_TYPE = "unreported"
#: Allowance per tunnel on top of its real and synthetic negotiation bytes: twice the TLS handshake
#: estimate (config.TLS_HANDSHAKE_ESTIMATE_BYTES), which covers long certificate chains, session
#: tickets, HTTP/2 connection setup and a CONNECT retried after a 407. An allowance, not an estimate.
OVERHEAD_PER_TUNNEL_BYTES = 2 * TLS_HANDSHAKE_ESTIMATE_BYTES + 2 * 1024
#: Allowance proportional to the reported bytes (TLS records, framing, header estimates).
OVERHEAD_SHARE = 0.25
#: Allowance per request whose request header size is unknown (HTTP/2 and HTTP/3 send compressed
#: headers the helpers cannot see; failed requests and WebSocket handshakes have no sizes).
UNKNOWN_HEADERS_BYTES = 512
#: Warn about unreported bytes when a host has at least this many.
UNREPORTED_WARN_BYTES = 64_000
#: Bypass by volume: reported bytes above FACTOR x tunnel bytes + SLACK mean traffic went around the meter.
BYPASS_VOLUME_FACTOR = 1.5
BYPASS_VOLUME_SLACK_BYTES = 65_536
#: Bypass by time: a request that started this long after its host's last tunnel closed.
BYPASS_TIME_SLACK_S = 2.0
#: A 3xx navigation hop further than this before the next navigation event of its context does not
#: move that unit's start (a chain whose end was never reported must not stretch a later page).
REDIRECT_CHAIN_MAX_GAP_S = 30.0

_HOOK_SOURCES = frozenset({"requests", "httpx"})
#: Browsers Playwright drives without DevTools (CDP) network data; their launch events trigger
#: NON_CDP_WARNING and keep their request events out of the bypass volume check.
_NON_CDP_BROWSERS = frozenset({"firefox", "webkit"})
_NETWORK_SCHEMES = frozenset({"http", "https", "ws", "wss"})

NO_EVENTS_WARNING = "no helper events: per-type figures unavailable; buckets only"
NO_UNITS_WARNING = (
    "no units counted: no main-frame navigations or HTTP-client requests were reported; "
    "per-1,000 figures unavailable (use the helpers or hooks, or --units N)"
)
#: How the warning names the helpers' no-network kinds (helpers.events.NO_NETWORK_KINDS), in order.
NO_NETWORK_LABELS = (
    ("fulfilled", "answered by request interception (route.fulfill, route_from_har)"),
    ("aborted", "aborted by route.abort"),
    ("blocked", "blocked by the browser before sending (mixed content, CSP, a block list)"),
)
#: Warning prefix when a Firefox or WebKit launch was recorded (see _warnings).
NON_CDP_WARNING_PREFIX = "per-type figures for"
#: Prefix of the warning given when the first-unit/rest split is withheld (renderers look for it).
PER_UNIT_WITHHELD_PREFIX = "first unit vs the rest not shown"


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def is_redirect(status: int | None) -> bool:
    """3xx other than 304: a redirect hop, which is not a page (unit) of its own."""
    return status is not None and 300 <= status <= 399 and status != 304


def is_success(event: RequestEvent) -> bool:
    """2xx or 304 and not failed."""
    status = event.status
    return not event.failed and status is not None and (200 <= status <= 299 or status == 304)


def is_loopback_host(host: str) -> bool:
    """``localhost`` (and ``*.localhost``), 127.0.0.0/8, ``::1`` and IPv4-mapped loopback."""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_loopback)


class _HostKeys:
    """Hosts in the meter's spelling (``types.canonical_host``), memoised: one parse per distinct host."""

    __slots__ = ("_seen",)

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def __call__(self, host: str) -> str:
        key = self._seen.get(host)
        if key is None:
            key = self._seen[host] = canonical_host(host)
        return key


def _timeline_sum(points: Iterable[TimelinePoint]) -> int:
    return sum(p.sent + p.received for p in points)


class _TypeRow:
    __slots__ = ("allocated", "reported", "requests")

    def __init__(self) -> None:
        self.requests = 0
        self.reported = 0
        self.allocated = 0


def _classify_idle_tunnel(tunnel: TunnelRecord, background_id: str | None, first_observation: float | None) -> str:
    """Bucket for a tunnel of a host no reported request went to (first match wins).

    A failed tunnel (the upstream refused the CONNECT, answered 407 or 502, or the
    connection never completed) is never called an idle preconnect: it was not a
    connection opened in advance, and its small size is only the refusal.
    """
    if background_id is not None:
        return BUCKET_BACKGROUND_PREFIX + background_id
    if first_observation is not None and tunnel.opened_at < first_observation:
        return BUCKET_BEFORE_ATTACH
    if (
        first_observation is not None
        and not tunnel.failed
        and tunnel.payload_bytes_sent <= PRECONNECT_IDLE_MAX_SENT
        and tunnel.payload_bytes_received <= PRECONNECT_IDLE_MAX_RECEIVED
    ):
        return BUCKET_PRECONNECT_IDLE
    return BUCKET_UNATTRIBUTED


def _redirect_chain_starts(requests: Sequence[RequestEvent]) -> dict[int, float]:
    """``id(unit event) -> start of its redirect chain`` for Playwright main-frame navigations.

    A navigation unit's own event is the final (non-3xx) hop; the 3xx hops that led
    to it are separate events of the same context, written just before it. The
    unit starts with the first of them, so a redirect's handshake and 3xx exchange
    count for the page it led to, not as "before the first navigation" or as the
    previous page. Hops are matched by order within a context (every main-frame
    navigation of the context, sorted by start): the 3xx events since the context's
    previous non-3xx navigation, each within :data:`REDIRECT_CHAIN_MAX_GAP_S` of the
    next. Units without redirects keep their own start. Two
    pages of one context navigating at the same moment can swap hops; a start then
    moves by that hop's lead, which stays within the timeline figures' approximation.
    """
    by_context: dict[str | None, list[RequestEvent]] = defaultdict(list)
    for request in requests:
        if request.source == "playwright" and request.frame == "main" and request.is_navigation:
            by_context[request.context].append(request)
    starts: dict[int, float] = {}
    for rows in by_context.values():
        chain_start: float | None = None
        previous: float | None = None
        for request in sorted(rows, key=lambda r: r.ts):
            if previous is not None and request.ts - previous > REDIRECT_CHAIN_MAX_GAP_S:
                chain_start = None  # too far from the hops before it: not their chain
            previous = request.ts
            if is_redirect(request.status):
                if chain_start is None:
                    chain_start = request.ts
                continue
            if chain_start is not None:
                starts[id(request)] = min(chain_start, request.ts)
            chain_start = None
    return starts


def _fmt_bytes(n: int) -> str:
    return f"{n:,} B"


def _budget_trip_time(snapshot: MeterSnapshot) -> float | None:
    """When the meter's budget tripped (its first ``tripped`` event), else None."""
    if not snapshot.budget_tripped:
        return None
    return min((e.ts for e in snapshot.budget_events if e.kind == "tripped"), default=None)


def _refused_after_trip(request: RequestEvent, tripped_at: float | None) -> bool:
    """A 403 to a request started after the budget tripped: the meter's own refusal, no tunnel carried it.

    After a trip the meter answers plain-HTTP requests with ``403`` (``X-Scrapescope-Budget:
    tripped``) and records no tunnel; a refused CONNECT reaches the client as a failure without a
    status, which the bypass check skips anyway. Such a response went nowhere, so it is not bypass.
    """
    return (
        tripped_at is not None
        and request.status == 403
        and request.ts >= tripped_at - BYPASS_TIME_SLACK_S
    )


def _no_network_kinds(requests: Iterable[RequestEvent]) -> dict[str, int]:
    """Request events the helpers marked as never reaching the network, by kind (see attribution.intake)."""
    kinds: dict[str, int] = defaultdict(int)
    for request in requests:
        kind = getattr(request, "no_network", None)
        if isinstance(kind, str) and not request.hit_network:
            kinds[kind] += 1
    return dict(kinds)


def _overhead_allowance(tunnels: Sequence[TunnelRecord], requests: Sequence[RequestEvent], reported: int) -> int:
    """How far a host's reported bytes may be scaled up before the rest is called unreported."""
    # meas4-6: a record that continues a kept provider connection (continued_from) set up nothing
    per_tunnel = sum(
        (OVERHEAD_PER_TUNNEL_BYTES if t.opened_connection else 0)
        + t.negotiation_bytes_sent
        + t.negotiation_bytes_received
        + t.synthetic_negotiation_bytes_sent
        + t.synthetic_negotiation_bytes_received
        for t in tunnels
    )
    unknown_headers = UNKNOWN_HEADERS_BYTES * sum(1 for r in requests if r.request_header_bytes is None)
    return per_tunnel + unknown_headers + int(reported * OVERHEAD_SHARE)


def _unbounded(requests: Sequence[RequestEvent]) -> bool:
    """A successful response of unknown body size: nothing limits what the host's tunnels carried for it."""
    return any(r.encoded_body_bytes is None and r.status is not None and not r.failed for r in requests)


def allocate_host(total: int, tunnels: Sequence[TunnelRecord], requests: Sequence[RequestEvent]) -> tuple[list[int], int]:
    """Share one host's tunnel bytes over its reported requests; returns (shares, unreported).

    ``sum(shares) + unreported == total``. Shares follow the reported sizes (by
    count when all are zero). Scaling down is unlimited; scaling up stops at the
    reported bytes plus :func:`_overhead_allowance`, and the remainder is
    returned as ``unreported`` (see the module docstring).
    """
    weights = [r.reported_bytes for r in requests]
    reported = sum(weights)
    attributable = total
    if not _unbounded(requests):
        attributable = min(total, reported + _overhead_allowance(tunnels, requests, reported))
    return largest_remainder(attributable, weights), total - attributable


def _add_to_run_buckets(buckets: Buckets, name: str, n_bytes: int) -> None:
    if name == BUCKET_ATTRIBUTED:
        buckets.attributed += n_bytes
    elif name == BUCKET_PRECONNECT_IDLE:
        buckets.preconnect_idle += n_bytes
    elif name == BUCKET_BEFORE_ATTACH:
        buckets.before_attach += n_bytes
    elif name == BUCKET_UNATTRIBUTED:
        buckets.unattributed += n_bytes
    elif name.startswith(BUCKET_BACKGROUND_PREFIX):
        catalog_id = name[len(BUCKET_BACKGROUND_PREFIX) :]
        buckets.background[catalog_id] = buckets.background.get(catalog_id, 0) + n_bytes


def _top_paths(requests: Sequence[RequestEvent]) -> list[PathBytes]:
    by_path: dict[str, list[int]] = {}
    for request in requests:
        if request.path is None:
            continue
        row = by_path.setdefault(request.path, [0, 0])
        row[0] += 1
        row[1] += request.reported_bytes
    rows = [PathBytes(path=p, requests=r[0], reported_bytes=r[1]) for p, r in by_path.items()]
    rows.sort(key=lambda row: (-row.reported_bytes, row.path))
    return rows[:MAX_PATHS_PER_HOST]


def _fold_types(rows: dict[str, _TypeRow]) -> list[TypeAllocation]:
    ordered = sorted(rows.items(), key=lambda item: (-item[1].allocated, item[0]))
    if len(ordered) > MAX_TYPES:
        # "unreported" is never folded: it must stay visible and out of what-if figures.
        pinned = [item for item in ordered if item[0] == UNREPORTED_TYPE]
        foldable = [item for item in ordered if item[0] not in (OTHER_TYPE, UNREPORTED_TYPE)]
        keep = pinned + foldable[: MAX_TYPES - 1 - len(pinned)]
        kept_names = {name for name, _ in keep}
        other = _TypeRow()
        for name, row in ordered:
            if name not in kept_names:
                other.requests += row.requests
                other.reported += row.reported
                other.allocated += row.allocated
        ordered = sorted([*keep, (OTHER_TYPE, other)], key=lambda item: (-item[1].allocated, item[0]))
    return [
        TypeAllocation(type=name, requests=row.requests, reported_bytes=row.reported, allocated_bytes=row.allocated)
        for name, row in ordered
    ]


def attribute(
    snapshot: MeterSnapshot,
    events: Sequence[HelperEvent],
    catalogs: Catalogs,
    *,
    units_override: int | None = None,
    events_dropped: int = 0,
    events_capped: int | None = None,
) -> AttributionResult:
    """Combine tunnel counters with helper events into hosts, types, buckets and units.

    See the module docstring and docs/dev/contracts.md section 6 for the
    algorithm. Pure function: no I/O, deterministic for a given input order.
    ``events_dropped`` and ``events_capped`` are ``EventsLog.dropped`` and
    ``EventsLog.capped`` (the lines past the reader's cap, which are part of
    ``dropped``). Without ``events_capped`` the cap counts as reached when
    ``events`` holds :data:`~scrapescope.attribution.intake.MAX_EVENTS` events.
    """
    attaches = [e for e in events if isinstance(e, AttachEvent)]
    launches = [e for e in events if isinstance(e, LaunchEvent)]
    requests = [e for e in events if isinstance(e, RequestEvent)]
    non_cdp = sorted({launch.browser for launch in launches if launch.browser in _NON_CDP_BROWSERS})

    # 1. First observation: the first attach, else the first request event.
    if attaches:
        first_observation: float | None = min(a.ts for a in attaches)
    elif requests:
        first_observation = min(r.ts for r in requests)
    else:
        first_observation = None

    # 2. Network requests: cache hits, service-worker-answered page requests (the worker's own
    #    fetch is its own event, so each is counted once) and requests answered or stopped before
    #    the network (route.fulfill/abort, browser blocks) excluded.
    #    Hosts are compared in the meter's spelling (see the module docstring).
    host_key = _HostKeys()
    network = [r for r in requests if r.hit_network]
    network_by_host: dict[str, list[RequestEvent]] = defaultdict(list)
    for request in network:
        network_by_host[host_key(request.host)].append(request)

    # 3-6. Hosts, allocation, buckets, types.
    target_by_host: dict[str, list[TunnelRecord]] = defaultdict(list)
    for tunnel in snapshot.target_tunnels():
        target_by_host[host_key(tunnel.host)].append(tunnel)
    denied_by_host: dict[str, list[TunnelRecord]] = defaultdict(list)
    for tunnel in snapshot.denied_tunnels():
        denied_by_host[host_key(tunnel.host)].append(tunnel)

    buckets = Buckets()
    type_rows: dict[str, _TypeRow] = {}
    hosts: list[HostAttribution] = []
    background_tunnels: dict[str, int] = {}
    #: (host, unreported, reported, tunnel bytes) for hosts whose tunnels carried more than reported.
    unreported_hosts: list[tuple[str, int, int, int]] = []
    for host in sorted(set(target_by_host) | set(denied_by_host)):
        tunnels = target_by_host.get(host, [])
        denied = denied_by_host.get(host, [])
        host_requests = network_by_host.get(host, [])
        background_id = catalogs.background_id_for(host)
        row = HostAttribution(
            host=host,
            ports=sorted({t.port for t in (*tunnels, *denied)}),
            tunnels=len(tunnels),
            failed_tunnels=sum(1 for t in tunnels if t.failed),
            denied_tunnels=len(denied),
            bytes_sent=sum(t.upstream_bytes_sent for t in tunnels),
            bytes_received=sum(t.upstream_bytes_received for t in tunnels),
            bytes_with_connect=sum(t.bytes_with_connect for t in tunnels),
            bytes_without_connect=sum(t.bytes_without_connect for t in tunnels),
            requests=len(host_requests),
            background_id=background_id,
            paths=_top_paths(host_requests),
        )
        if tunnels and host_requests:
            total = row.bytes_with_connect
            shares, unreported = allocate_host(total, tunnels, host_requests)
            per_type: dict[str, int] = defaultdict(int)
            for request, share in zip(host_requests, shares):
                rtype = OTHER_TYPE if request.resource_type == UNREPORTED_TYPE else request.resource_type
                per_type[rtype] += share
                type_row = type_rows.setdefault(rtype, _TypeRow())
                type_row.requests += 1
                type_row.reported += request.reported_bytes
                type_row.allocated += share
            if unreported > 0:
                per_type[UNREPORTED_TYPE] += unreported
                type_rows.setdefault(UNREPORTED_TYPE, _TypeRow()).allocated += unreported
                unreported_hosts.append((host, unreported, sum(r.reported_bytes for r in host_requests), total))
            row.allocated_by_type = dict(sorted(per_type.items()))
            row.buckets = {BUCKET_ATTRIBUTED: BucketTally(tunnels=len(tunnels), bytes=total)}
            buckets.attributed += total
        elif tunnels:
            tallies: dict[str, BucketTally] = {}
            for tunnel in tunnels:
                name = _classify_idle_tunnel(tunnel, background_id, first_observation)
                tally = tallies.setdefault(name, BucketTally())
                tally.tunnels += 1
                tally.bytes += tunnel.bytes_with_connect
                _add_to_run_buckets(buckets, name, tunnel.bytes_with_connect)
                if background_id is not None:
                    background_tunnels[background_id] = background_tunnels.get(background_id, 0) + 1
            row.buckets = dict(sorted(tallies.items()))
        hosts.append(row)
    hosts.sort(key=lambda h: (-h.bytes_with_connect, h.host))
    buckets.background = dict(sorted(buckets.background.items()))

    # 7. Non-target hosts (direct.json, --env-all): never sent to the upstream.
    non_target_rows: dict[str, NonTargetHost] = {}
    for tunnel in snapshot.non_target_tunnels():
        nt_host = host_key(tunnel.host)
        entry = non_target_rows.get(nt_host)
        if entry is None:
            catalog_id = tunnel.rule if is_catalog_id(tunnel.rule) else catalogs.direct_id_for(nt_host)
            entry = NonTargetHost(
                host=nt_host,
                catalog_id=catalog_id or UNCATALOGUED_ID,
                tunnels=0,
                bytes_sent=0,
                bytes_received=0,
            )
            non_target_rows[nt_host] = entry
        entry.tunnels += 1
        entry.bytes_sent += tunnel.upstream_bytes_sent
        entry.bytes_received += tunnel.upstream_bytes_received
    non_target = sorted(non_target_rows.values(), key=lambda r: (-(r.bytes_sent + r.bytes_received), r.host))

    # 8. Units.
    navigation_units = [
        r
        for r in requests
        if r.source == "playwright" and r.frame == "main" and r.is_navigation and not is_redirect(r.status)
    ]
    hook_units = [r for r in requests if r.source in _HOOK_SOURCES and not is_redirect(r.status)]
    if navigation_units:
        unit_events, basis = navigation_units, "navigations"
    elif hook_units:
        unit_events, basis = hook_units, "requests"
    else:
        unit_events, basis = [], None
    if units_override is not None:
        count = max(0, int(units_override))
        units = UnitsInfo(count=count, source="override", low_sample_warning=count < LOW_UNITS_THRESHOLD)
    elif basis is not None:
        units = UnitsInfo(
            count=len(unit_events),
            source=basis,  # type: ignore[arg-type]
            low_sample_warning=len(unit_events) < LOW_UNITS_THRESHOLD,
        )
    else:
        units = UnitsInfo(count=0, source="none", low_sample_warning=True)

    # 9. Success, only when unit events exist.
    success = None
    if unit_events and basis is not None:
        succeeded = sum(1 for r in unit_events if is_success(r))
        success = SuccessInfo(count=succeeded, basis=basis, rate=round(succeeded / len(unit_events), 6))  # type: ignore[arg-type]

    # 10. Launches and timeline figures.
    timeline = snapshot.timeline
    bytes_before_first = None
    per_unit = None
    per_unit_gap: float | None = None
    if unit_events:
        if basis == "navigations":
            chain_starts = _redirect_chain_starts(requests)
            stamps = sorted(chain_starts.get(id(r), r.ts) for r in unit_events)
        else:
            stamps = sorted(r.ts for r in unit_events)
        first = stamps[0]
        resolution = max(0.0, snapshot.timeline_resolution_s)
        # A bucket counts as "before" only when it ENDS at or before the first unit;
        # the bucket that straddles the first unit's start goes to that unit, so a
        # load that fits inside one bucket is not reported as "before the first page".
        before = [p for p in timeline if p.t + resolution <= first]
        bytes_before_first = _timeline_sum(before)
        after = [p for p in timeline if p.t + resolution > first]
        if len(stamps) > 1 and stamps[1] - stamps[0] < resolution:
            # The first unit would absorb the buckets of the units that started with it
            # (concurrent pages, or loads faster than one timeline step): withhold the split.
            per_unit_gap = stamps[1] - stamps[0]
        elif len(stamps) > 1:
            second = stamps[1]
            # The same rule at the second unit's start: the bucket that straddles it holds that
            # unit's first bytes (new handshakes, its document), so it belongs to the rest.
            first_unit = _timeline_sum(p for p in after if p.t + resolution <= second)
            rest = _timeline_sum(p for p in after if p.t + resolution > second)
            rest_units = len(stamps) - 1
            rest_mean: int | None = rest // rest_units
        else:
            first_unit = _timeline_sum(after)
            rest, rest_units, rest_mean = 0, 0, None
        if per_unit_gap is None:
            per_unit = PerUnitBytes(
                first_unit_bytes=first_unit,
                rest_units=rest_units,
                rest_bytes=rest,
                rest_mean_bytes=rest_mean,
                resolution_s=snapshot.timeline_resolution_s,
            )

    # 11. Status histogram over network requests.
    histogram: dict[str, int] = defaultdict(int)
    for request in network:
        histogram[str(request.status) if request.status is not None else "failed"] += 1
    status_histogram = dict(
        sorted(histogram.items(), key=lambda item: (item[0] == "failed", len(item[0]), item[0]))
    )

    # 12. Bypass. (a) A network request whose host no tunnel of any route or status carried,
    #     or that started after every tunnel of its host had closed. (b) A host whose
    #     reported bytes clearly exceed what its tunnels carried: one request through the
    #     meter, the bulk around it (a client with its own proxies= setting, for example).
    tunnels_by_host: dict[str, list[TunnelRecord]] = defaultdict(list)
    for tunnel in snapshot.tunnels:
        tunnels_by_host[host_key(tunnel.host)].append(tunnel)
    last_close = {
        host: max((t.closed_at if t.closed_at is not None else snapshot.taken_at) for t in rows)
        for host, rows in tunnels_by_host.items()
    }
    request_bypass_hosts: set[str] = set()
    bypass_requests = 0
    volume_reported: dict[str, int] = defaultdict(int)
    tripped_at = _budget_trip_time(snapshot)
    for request in network:
        host = host_key(request.host)
        if request.scheme not in _NETWORK_SCHEMES or is_loopback_host(host):
            continue
        if request.failed and request.status is None:
            continue
        if _refused_after_trip(request, tripped_at):
            continue
        closed = last_close.get(host)
        if closed is None or request.ts > closed + BYPASS_TIME_SLACK_S:
            bypass_requests += 1
            request_bypass_hosts.add(host)
        elif request.resource_type == "websocket":
            continue  # frame payloads may be decompressed: not wire bytes
        elif non_cdp and request.source == "playwright":
            continue  # Firefox/WebKit sizes are unverified (no CDP): not evidence of bypass by volume
        else:
            volume_reported[host] += request.reported_bytes
    bypass_hosts = set(request_bypass_hosts)
    volume_hosts: list[tuple[str, int, int]] = []
    for host, reported in sorted(volume_reported.items()):
        carried_bytes = sum(t.bytes_with_connect for t in tunnels_by_host.get(host, []))
        if reported > BYPASS_VOLUME_FACTOR * carried_bytes + BYPASS_VOLUME_SLACK_BYTES:
            volume_hosts.append((host, reported, carried_bytes))
            bypass_hosts.add(host)
    bypass = BypassInfo(
        incomplete=bool(bypass_hosts),
        hosts=sorted(bypass_hosts)[:MAX_BYPASS_HOSTS],
        requests=bypass_requests,
    )

    # 13. More than one page per context (what-if "cache loss not modelled").
    pages_per_context: dict[str | None, int] = defaultdict(int)
    for request in navigation_units:
        pages_per_context[request.context] += 1
    multi_page_context = any(n >= 2 for n in pages_per_context.values())

    # 14. Sources, event counts and warnings.
    sources = sorted({r.source for r in requests})
    counts = EventCounts(
        attach=len(attaches), launch=len(launches), request=len(requests), dropped=max(0, int(events_dropped))
    )
    if events_capped is None:
        capped: int | None = None
        cap_reached = len(events) >= MAX_EVENTS
    else:
        capped = max(0, int(events_capped))
        cap_reached = capped > 0
    warnings = _warnings(
        snapshot=snapshot,
        have_events=bool(attaches or launches or requests),
        dropped=counts.dropped,
        cap=(len(events), capped) if cap_reached and counts.dropped > 0 else None,
        units=units,
        bypass=bypass,
        bypass_host_count=len(request_bypass_hosts),
        volume_hosts=volume_hosts,
        background_tunnels=background_tunnels,
        unreported_hosts=unreported_hosts,
        per_unit_gap=per_unit_gap,
        resolution=snapshot.timeline_resolution_s,
        no_network=_no_network_kinds(requests),
        non_cdp=non_cdp,
    )

    return AttributionResult(
        hosts=hosts,
        types=_fold_types(type_rows),
        buckets=buckets,
        non_target=non_target,
        units=units,
        browser_launches=len(launches),
        bytes_before_first_navigation=bytes_before_first,
        per_unit=per_unit,
        status_histogram=status_histogram,
        success=success,
        bypass=bypass,
        multi_page_context=multi_page_context,
        sources=sources,
        events=counts,
        warnings=warnings,
    )


def _warnings(
    *,
    snapshot: MeterSnapshot,
    have_events: bool,
    dropped: int,
    cap: tuple[int, int | None] | None = None,
    units: UnitsInfo,
    bypass: BypassInfo,
    bypass_host_count: int,
    volume_hosts: Sequence[tuple[str, int, int]] = (),
    background_tunnels: dict[str, int],
    unreported_hosts: Sequence[tuple[str, int, int, int]] = (),
    per_unit_gap: float | None = None,
    resolution: float = 0.25,
    no_network: dict[str, int] | None = None,
    non_cdp: Sequence[str] = (),
) -> list[str]:
    out: list[str] = []
    invalid = dropped
    if cap is not None:
        kept, capped = cap
        scope = (
            "per-type figures, units, success and the bypass check cover only the events read; "
            "tunnel totals are complete"
        )
        if capped is None:
            were = "was" if dropped == 1 else "were"
            out.append(
                f"{_plural(dropped, 'helper event line')} {were} not read or {were} invalid: the reader keeps "
                f"at most {kept:,} events and skips the lines past that limit; {scope}"
            )
            invalid = 0
        else:
            out.append(
                f"{_plural(capped, 'helper event line')} {'was' if capped == 1 else 'were'} not read: the "
                f"reader keeps at most {kept:,} events and skips the lines past that limit; {scope}"
            )
            invalid = max(0, dropped - capped)
    if invalid > 0:
        out.append(
            f"{_plural(invalid, 'helper event line')} dropped (invalid, oversized or another events version)"
        )
    if not have_events:
        out.append(NO_EVENTS_WARNING)
    if units.source == "none":
        out.append(NO_UNITS_WARNING)
    elif units.count < LOW_UNITS_THRESHOLD:
        out.append(
            f"only {_plural(units.count, 'unit')} ({units.source}): per-1,000 figures from fewer than "
            f"{LOW_UNITS_THRESHOLD} units are unreliable"
        )
    if bypass.requests > 0:
        out.append(
            f"incomplete: helpers saw {_plural(bypass.requests, 'network request')} to "
            f"{_plural(bypass_host_count, 'host')} that no meter tunnel carried (no tunnel to the host, or "
            "every tunnel to it had closed); the totals miss that traffic (clients without helpers that "
            "bypass the meter cannot be detected)"
        )
    if no_network:
        parts = [
            f"{no_network[kind]} {label}"
            for kind, label in NO_NETWORK_LABELS
            if no_network.get(kind)
        ]
        out.append(
            f"{_plural(sum(no_network.values()), 'request event')} never reached the network: "
            + "; ".join(parts)
            + ". They are left out of the status line, the per-type figures and the bypass check"
        )
    if volume_hosts:
        host, reported, carried = max(volume_hosts, key=lambda row: (row[1] - row[2], row[0]))
        others = f" and {_plural(len(volume_hosts) - 1, 'other host')}" if len(volume_hosts) > 1 else ""
        out.append(
            f"incomplete: helpers and hooks reported {_fmt_bytes(reported)} for {host}{others}, but the meter's "
            f"tunnels to it carried only {_fmt_bytes(carried)}; most of that traffic went around the meter "
            "(for example a client with its own proxies= setting), so the totals miss it and its per-type "
            "figures were scaled down"
        )
    if unreported_hosts:
        heavy = [row for row in unreported_hosts if row[1] >= UNREPORTED_WARN_BYTES]
        if heavy:
            total_unreported = sum(row[1] for row in unreported_hosts)
            host, unreported, reported, carried = max(heavy, key=lambda row: (row[1], row[0]))
            out.append(
                f"{_fmt_bytes(total_unreported)} of tunnel bytes were beyond what helpers reported and are shown "
                f"as type '{UNREPORTED_TYPE}' (largest: {host}, {_fmt_bytes(carried)} carried for "
                f"{_fmt_bytes(reported)} reported); what-if and fixes leave them out. Usual causes: requests "
                "still in flight when a page navigated or the browser closed, WebSockets still open, or a "
                "client without helpers using the same host"
            )
    if non_cdp:
        names = " and ".join({"firefox": "Firefox", "webkit": "WebKit"}[name] for name in non_cdp)
        out.append(
            f"{NON_CDP_WARNING_PREFIX} {names} are unverified: Playwright gives no DevTools network data for "
            "them, so their request sizes are Playwright's own and their HTTP-cache hits are recognised only by a "
            "missing server address. Tunnel totals and buckets are measured as for any client; their reported "
            "sizes are left out of the bypass volume check"
        )
    if per_unit_gap is not None:
        out.append(
            f"{PER_UNIT_WITHHELD_PREFIX}: the first two units started {per_unit_gap:.3f} s apart, closer than "
            f"the meter's {resolution:g} s timeline step, so the first unit would absorb the others' bytes"
        )
    if background_tunnels:
        total = sum(background_tunnels.values())
        ids = ", ".join(sorted(background_tunnels))
        out.append(
            f"{_plural(total, 'tunnel')} matched the background catalog ({ids}): "
            "Chromium traffic the job did not request"
        )
    if snapshot.internal_errors > 0:
        out.append(
            f"the meter caught {_plural(snapshot.internal_errors, 'internal error')}; the affected tunnels were closed"
        )
    return [safe_text(w) for w in out]


__all__ = [
    "BYPASS_TIME_SLACK_S",
    "BYPASS_VOLUME_FACTOR",
    "BYPASS_VOLUME_SLACK_BYTES",
    "MAX_BYPASS_HOSTS",
    "NO_EVENTS_WARNING",
    "NO_NETWORK_LABELS",
    "NON_CDP_WARNING_PREFIX",
    "NO_UNITS_WARNING",
    "OVERHEAD_PER_TUNNEL_BYTES",
    "OVERHEAD_SHARE",
    "PER_UNIT_WITHHELD_PREFIX",
    "REDIRECT_CHAIN_MAX_GAP_S",
    "UNCATALOGUED_ID",
    "UNKNOWN_HEADERS_BYTES",
    "UNREPORTED_TYPE",
    "allocate_host",
    "attribute",
    "is_loopback_host",
    "is_redirect",
    "is_success",
]
