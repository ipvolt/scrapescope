"""Fix templates: fixed code text with a few safe substitutions.

The only values ever substituted into generated code are catalogued background
hosts (charset ``[a-z0-9_.:-]``, public catalog data), catalog ids and figures
computed by scrapescope. Never credentials, paths, query strings, target hosts
or anything from a page.

Python templates are complete modules: constants and functions at module level
plus an ``if __name__ == "__main__":`` example, so a test (or a user) can import
the functions without launching anything. Tests compile every Python snippet.
"""

from __future__ import annotations

PLAYWRIGHT_CDP_BLOCK = '''\
# Cache-preserving blocking for Playwright (Python, Chromium).
# Images: a Blink setting at launch. Fonts and media: CDP Network.setBlockedURLs
# on every page before it navigates. Neither disables the HTTP cache (route() does).
# CDP reference: https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-setBlockedURLs
# Limits: URL patterns miss fonts and media served without a file extension, and
# the CDP block applies to that page only (not to out-of-process iframes or workers).
from playwright.sync_api import sync_playwright

LAUNCH_ARGS = ["--blink-settings=imagesEnabled=false"]
BLOCKED_URL_PATTERNS = [
    "*.woff2", "*.woff", "*.ttf", "*.otf", "*.eot",
    "*.mp4", "*.webm", "*.m4s", "*.m3u8", "*.mp3", "*.m4a", "*.ogg", "*.wav",
]


def block_fonts_and_media(page):
    """Block font and media URLs for this page. Call it before page.goto()."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("Network.enable")
    cdp.send("Network.setBlockedURLs", {"urls": BLOCKED_URL_PATTERNS})
    return cdp


if __name__ == "__main__":
    with sync_playwright() as p:
        # Keep your own launch options (proxy=..., headless=...) and add LAUNCH_ARGS.
        browser = p.chromium.launch(args=LAUNCH_ARGS)
        context = browser.new_context()
        page = context.new_page()
        block_fonts_and_media(page)  # repeat for every page you open, before goto()
        page.goto("https://example.com/")
        browser.close()
'''

PLAYWRIGHT_ROUTE_BLOCK = '''\
# Alternative: block images, media and fonts with route().
# Playwright documents: "Enabling routing disables http cache." Stylesheets,
# scripts and fonts are then downloaded again for every page, which can cost more
# than blocking saves on multi-page runs. Routes also miss requests that a
# service worker makes, so service workers are blocked here.
from playwright.sync_api import sync_playwright

BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}
CONTEXT_OPTIONS = {"service_workers": "block"}


def block_heavy_resources(route):
    """Abort image, media and font requests; let everything else through."""
    if route.request.resource_type in BLOCKED_RESOURCE_TYPES:
        route.abort()
    else:
        route.continue_()


if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch()  # keep your own launch options (proxy=..., ...)
        context = browser.new_context(**CONTEXT_OPTIONS)
        context.route("**/*", block_heavy_resources)
        page = context.new_page()
        page.goto("https://example.com/")
        browser.close()
'''

CHROMIUM_BACKGROUND_FLAGS = '''\
# Stop paying proxy bytes for Chromium's own background downloads.
# Catalogued background hosts seen in this run: {hosts}
#
# 1. Refuse them at the meter. This works whatever launches the browser:
#      scrapescope run --deny-catalog background -- <your command>
#    or one host at a time:
#      scrapescope run --deny-host optimizationguide-pa.googleapis.com -- <your command>
#    NodeMaven measured about 43 MB of optimization-guide downloads in a fresh
#    profile (intermittent: they saw it in some idle windows, not all) and
#    removed them by refusing that host at their proxy relay; the Skyvern
#    postmortem added a proxy rule rejecting the same host.
# 2. Keep one browser profile between launches (below), so a component or model
#    downloaded once is not fetched again for every fresh profile (Skyvern's
#    other change).
#
# Launch switches are not the fix: Playwright already passes
# --disable-background-networking and --disable-component-update, and NodeMaven
# saw the optimization-guide fetch with both switches in force. Only launchers
# that do not set them (raw CDP, Selenium) gain anything from adding them.
#
# Security trade-off: refusing component-update and Safe Browsing hosts also
# stops certificate-revocation (CRLSet) and Safe Browsing data for the profile.
# Use it for short-lived automation profiles, not for a browser that signs in to
# real accounts. A persistent profile keeps cookies and site data between runs;
# clear it when runs must not share state.
from playwright.sync_api import sync_playwright

from scrapescope.helpers.playwright import instrument, proxy_settings, record_launch

USER_DATA_DIR = "./chromium-profile"


def launch_context(playwright, **options):
    """A persistent context that stays metered and attributed under scrapescope run."""
    options.setdefault("proxy", proxy_settings())
    context = playwright.chromium.launch_persistent_context(USER_DATA_DIR, **options)
    record_launch(context)  # counts this browser once, also where Playwright gives the context no Browser
    return instrument(context)


if __name__ == "__main__":
    with sync_playwright() as p:
        context = launch_context(p)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto("https://example.com/")
        context.close()
'''

PLAYWRIGHT_MCP_FLAGS = '''\
# If you use Playwright MCP: start its server under scrapescope run. Its browser
# then goes through a meter that refuses the catalogued background hosts and
# stops at a budget (2GB here: choose your own). Keep one profile between
# sessions so fresh-profile downloads are not repeated.
# Catalogued background hosts seen in this run: {hosts}
# Use this as the server command in your MCP client's configuration. run keeps
# the MCP protocol on stdin/stdout untouched (--quiet: no summary on stderr) and
# writes its report when the server exits.
# While the server runs, the meter's local listener (a random port, given to the
# server as $SCRAPESCOPE_PROXY_URL) accepts connections without a token from any
# local process, like every scrapescope run; --budget bounds what they can spend.
# Give run the same --upstream-from-env VAR or --direct as your other runs.
# Pin the Playwright MCP release you reviewed: replace X.Y.Z (npm view @playwright/mcp version).
# Refusing at the meter covers browser-process downloads such as the
# optimization guide. Playwright MCP's --blocked-origins does not replace it: it
# is implemented with Playwright routing, which intercepts page and worker
# requests only, and routing disables the HTTP cache.
# Security trade-off: refusing component-update and Safe Browsing hosts also
# stops certificate-revocation and Safe Browsing data for that profile.
scrapescope run --budget 2GB --deny-catalog background --quiet -- \\
  sh -c 'exec npx -y @playwright/mcp@X.Y.Z --proxy-server "$SCRAPESCOPE_PROXY_URL" --user-data-dir ./mcp-profile'
'''

CHROMIUM_BACKGROUND_REFUSE = '''\
# Stop paying proxy bytes for Chromium's own background downloads.
# Catalogued background hosts seen in this run: {hosts}
#
# 1. Refuse them at the meter. This works whatever launches the browser
#    (Selenium, Puppeteer, raw CDP, Playwright); put your usual command after --:
scrapescope run --deny-catalog background -- python job.py
#    or one host at a time:
#      scrapescope run --deny-host optimizationguide-pa.googleapis.com -- python job.py
#    NodeMaven measured about 43 MB of optimization-guide downloads in a fresh
#    profile (intermittent: they saw it in some idle windows, not all) and
#    removed them by refusing that host at their proxy relay; the Skyvern
#    postmortem added a proxy rule rejecting the same host.
# 2. Keep one browser profile between launches (your launcher's user-data-dir
#    option), so a component or model downloaded once is not fetched again for
#    every fresh profile (Skyvern's other change).
#
# Launchers that do not pass --disable-background-networking and
# --disable-component-update (raw CDP, Selenium) can add them too; Playwright
# already passes both, and NodeMaven saw the optimization-guide fetch with both
# in force, so they are not the fix on their own.
#
# Security trade-off: refusing component-update and Safe Browsing hosts also
# stops certificate-revocation (CRLSet) and Safe Browsing data for the profile.
# Use it for short-lived automation profiles, not for a browser that signs in to
# real accounts. A persistent profile keeps cookies and site data between runs;
# clear it when runs must not share state.
'''

REQUESTS_SESSION_REUSE = '''\
# Reuse one requests.Session: its connection pool keeps connections (and their
# CONNECT exchange and TLS handshake) alive between requests to the same host.
# Detected in this run: {detection}.
# Not where a new exit per request is the point: many providers rotate the exit
# per connection, so keeping a connection alive also keeps its exit.
import requests

session = requests.Session()  # create once and reuse it for every request
# Optional, under scrapescope run, to attribute these requests in the report:
# from scrapescope.helpers.hooks import instrument_requests
# instrument_requests(session)


def fetch(url, **kwargs):
    """GET through the shared session (proxies come from HTTPS_PROXY as before)."""
    kwargs.setdefault("timeout", 30)
    response = session.get(url, **kwargs)
    response.raise_for_status()
    return response
'''

HTTPX_CLIENT_REUSE = '''\
# Reuse one httpx.Client (or one httpx.AsyncClient under asyncio): its pool keeps
# connections (and their CONNECT exchange and TLS handshake) alive between requests.
# Detected in this run: {detection}.
# Not where a new exit per request is the point: many providers rotate the exit
# per connection, so keeping a connection alive also keeps its exit.
import httpx

client = httpx.Client(timeout=30.0)  # create once and reuse it; close it at the end
# Optional, under scrapescope run, to attribute these requests in the report:
# from scrapescope.helpers.hooks import instrument_httpx
# instrument_httpx(client)


def fetch(url, **kwargs):
    """GET through the shared client (proxies come from HTTPS_PROXY as before)."""
    response = client.get(url, **kwargs)
    response.raise_for_status()
    return response
'''

__all__ = [
    "CHROMIUM_BACKGROUND_FLAGS",
    "CHROMIUM_BACKGROUND_REFUSE",
    "HTTPX_CLIENT_REUSE",
    "PLAYWRIGHT_CDP_BLOCK",
    "PLAYWRIGHT_MCP_FLAGS",
    "PLAYWRIGHT_ROUTE_BLOCK",
    "REQUESTS_SESSION_REUSE",
]
