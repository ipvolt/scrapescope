"""Attribution: events intake, allocation, buckets, units and bypass detection.

Contract: docs/dev/contracts.md section 6.

- :func:`read_events` reads the helper events file (JSONL, v=1) with the
  strict parser in :mod:`scrapescope.types`, dropping and counting bad lines.
- :func:`attribute` combines a :class:`~scrapescope.types.MeterSnapshot` with
  those events into an :class:`~scrapescope.types.AttributionResult`: per-host
  tunnel-measured bytes, per-type *allocated* bytes (client-reported sizes plus
  a proportional share of the host's tunnel overhead, because a request cannot
  be tied to a tunnel), the four buckets for unmatched tunnel bytes, units,
  success, timeline figures and the bypass detector.
"""

from __future__ import annotations

from .allocate import largest_remainder
from .core import attribute, is_loopback_host, is_redirect, is_success
from .intake import MAX_EVENTS, EventsLog, NoNetworkRequestEvent, read_events

__all__ = [
    "MAX_EVENTS",
    "EventsLog",
    "NoNetworkRequestEvent",
    "attribute",
    "is_loopback_host",
    "is_redirect",
    "is_success",
    "largest_remainder",
    "read_events",
]
