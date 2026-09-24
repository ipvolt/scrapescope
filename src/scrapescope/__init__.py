"""scrapescope: a local metering proxy that shows where a scraper's bytes go.

Importing the package is cheap and side-effect free: it does not import the
forwarder, Playwright, Requests or HTTPX. Public entry points:

- ``scrapescope`` console script / ``python -m scrapescope`` (``scrapescope.cli``)
- ``scrapescope.helpers.playwright`` and ``scrapescope.helpers.hooks`` for jobs
- ``scrapescope.types`` for the shared data model

See docs/dev/contracts.md for the module contracts.
"""

from ._version import __version__

__all__ = ["__version__"]
