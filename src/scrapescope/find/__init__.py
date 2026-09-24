"""find: the smallest response that already contains your value.

``run_find`` loads a page once in headless Chromium through the meter,
classifies the main document against ``challenges.json`` (a challenge page is
reported as "blocked; cannot search", never "not found"; challenged XHR,
fetch and frame responses are counted and named in a warning), reads text
bodies from the whole browser context under a size cap, searches each value
with variants (escapes in embedded JSON and scripts, entities, spaces, number
formats with or without a currency symbol), and ranks matching responses:
those containing all values first, then more values, then by billed-basis
bytes (encoded body + response headers + request headers + one TLS handshake
estimate), with cache or service-worker copies after the others. A value
seen only inside a longer number (``variant:substring``) is reported but
never counts as found. The meter's own replies (a refused private address or
denied host, an unreachable upstream) are never searched: the result is a
load error naming the cause. Starter code is emitted only for GET responses
that sent no cookies, no Authorization, no token-like header and no
random-looking token; while some listed response holds every value, only
such a response gets starter code. ``verify`` replays one match once,
cookie-less, with an honest User-Agent and a bounded decoder: the top
eligible match, or a higher-ranked one ineligible only because of the
cookies or token header the browser sent (it then gets starter code only if
that replay returned the values found in it). The page-load share is shown like for like (body and headers
against DevTools bytes) and called a saving only after such a replay, and
only when the replay itself moved less than the page load. Chromium runs with WebRTC restricted to
proxied connections, so a page cannot send UDP around the meter.

Classification of challenge pages only; scrapescope never tries to get past
one. Playwright is imported lazily, so importing this package is cheap.
Contract: docs/dev/contracts.md section 7.
"""

from __future__ import annotations

from .browser import BrowserUnavailableError, meter_reply_check_from_snapshot
from .challenge import classify_challenge
from .core import run_find
from .render import render_find_text

__all__ = [
    "BrowserUnavailableError",
    "classify_challenge",
    "meter_reply_check_from_snapshot",
    "render_find_text",
    "run_find",
]
