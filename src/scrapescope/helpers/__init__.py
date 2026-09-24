"""In-process helpers for jobs run under ``scrapescope run``.

Submodules (import the one you need; this package imports nothing heavy):

- ``scrapescope.helpers.playwright``: browser-wide proxy settings, context
  instrumentation and per-context proxy wrapping (sync and async Playwright).
- ``scrapescope.helpers.hooks``: Requests and HTTPX response hooks.
- ``scrapescope.helpers.events``: the events-file writer they share.

All helpers are no-ops (with one warning) when SCRAPESCOPE_EVENTS is unset.
Contract: docs/dev/contracts.md sections 4 and 5.
"""
