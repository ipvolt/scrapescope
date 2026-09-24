"""Playwright settings for loading the fixture site in Chromium (tests only).

Findings that shaped these helpers (Playwright 1.63, Chromium 153, 2026-09-23):
- ``ignore_https_errors=True`` alone is not enough for the service worker:
  Chromium refuses to register it ("An SSL certificate error occurred when
  fetching the script"). Launching with
  ``--ignore-certificate-errors-spki-list=<fixture leaf SPKI>`` makes the
  certificate valid for Chromium, and the service worker then registers,
  claims the page and intercepts ``/api/sw.json``.
- ``<link rel=preconnect href="https://origin-c.test">`` produces an idle
  tunnel (CONNECT + TLS handshake, no request) only in the full Chromium build
  (``channel="chromium"``) with a persistent context; the default headless
  shell and non-persistent contexts do not preconnect.
- The full Chromium build also sends background traffic through the proxy
  (update.googleapis.com, clients2.google.com:80, www.google.com,
  accounts.google.com, android.clients.google.com). The fixture upstreams
  serve the documented background hosts locally and refuse the rest.
- With proxy credentials, Chromium first sends CONNECT without
  ``Proxy-Authorization``, receives 407 and retries on the same connection.
"""

from __future__ import annotations

import functools
import os
from typing import Any

from .world import free_port

#: Keyword arguments for ``browser.new_context()`` in tests.
CONTEXT_KWARGS: dict[str, Any] = {"ignore_https_errors": True}

#: JavaScript predicate that is true once app.js has finished every fetch.
PAGE_DONE_PREDICATE = "document.documentElement.getAttribute('data-fixture-state') === 'done'"


def chromium_launch_kwargs(
    world: Any,
    *,
    server: str | None = None,
    username: str | None = None,
    password: str | None = None,
    full_chromium: bool = False,
    extra_args: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Keyword arguments for ``chromium.launch()`` / ``launch_persistent_context()``.

    ``server`` is the proxy (e.g. ``world.http_upstream.server`` or a meter URL);
    ``full_chromium=True`` selects ``channel="chromium"`` instead of the headless shell.
    """
    kwargs: dict[str, Any] = {"args": [*world.chromium_args(), *extra_args]}
    if server is not None:
        proxy: dict[str, str] = {"server": server}
        if username is not None:
            proxy["username"] = username
        if password is not None:
            proxy["password"] = password
        kwargs["proxy"] = proxy
    if full_chromium:
        kwargs["channel"] = "chromium"
    return kwargs


@functools.lru_cache(maxsize=2)
def chromium_unavailable_reason(full_chromium: bool = False) -> str | None:
    """None when Playwright can launch Chromium here, else a skip reason.

    Launches the browser once (cached per build) behind a dead loopback proxy,
    so the probe cannot reach the network.
    """
    if os.environ.get("SCRAPESCOPE_SKIP_BROWSER_TESTS") == "1":
        return "SCRAPESCOPE_SKIP_BROWSER_TESTS=1"
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "playwright is not installed (install the [browser] extra)"
    # A proxy on a dead loopback port: whatever the browser tries to fetch
    # during this probe (the full build starts background requests at once)
    # fails locally instead of reaching the internet.
    dead_proxy = {"server": f"http://127.0.0.1:{free_port()}"}
    try:
        with sync_playwright() as p:
            kwargs: dict[str, Any] = {"proxy": dead_proxy}
            if full_chromium:
                kwargs["channel"] = "chromium"
            browser = p.chromium.launch(**kwargs)
            browser.close()
    except PlaywrightError as exc:
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        return f"Playwright Chromium unavailable: {first_line[:200]}"
    except Exception as exc:  # e.g. a running asyncio loop in this thread
        return f"Playwright could not start: {type(exc).__name__}"
    return None


@functools.lru_cache(maxsize=1)
def chromium_sandbox_unavailable_reason() -> str | None:
    """None when Chromium starts with its OS sandbox here, else why the sandboxed launch failed.

    ``find`` launches with ``chromium_sandbox=True`` and falls back to no
    sandbox, with a warning, only when that launch fails: on Linux without
    unprivileged user namespaces (containers, Ubuntu 24.04's AppArmor default,
    GitHub's ubuntu-24.04 runners) Chromium exits with "No usable sandbox!".
    This probe makes the same sandboxed launch once (cached), behind a dead
    loopback proxy, so tests can expect the fallback note exactly on machines
    where the sandbox is genuinely unavailable. Call it only where
    :func:`chromium_unavailable_reason` returned None.
    """
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    dead_proxy = {"server": f"http://127.0.0.1:{free_port()}"}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(chromium_sandbox=True, proxy=dead_proxy)
            browser.close()
    except PlaywrightError as exc:
        lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
        detail = next((line for line in lines if "sandbox" in line.lower()), lines[0] if lines else "")
        return f"Chromium could not start with its OS sandbox: {detail[:200]}"
    return None
