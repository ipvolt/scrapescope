"""Starter code for eligible ``find`` matches (terminal only, never in reports).

Emitted only for GET responses that sent no cookies, no Authorization header
and no random-looking token (see :mod:`.heuristics`). The code is a plain
request with the client's own User-Agent: no captured cookies, headers or
tokens are ever copied into it, and it does not impersonate a browser.

Both clients read the proxy from the environment, but by URL scheme:
for ``https://`` URLs HTTPX reads ``HTTPS_PROXY`` (or ``https_proxy``) and curl
reads ``https_proxy`` or ``HTTPS_PROXY``; for ``http://`` URLs HTTPX reads
``HTTP_PROXY`` (or ``http_proxy``) and curl reads only the lowercase
``http_proxy``. ``ALL_PROXY`` applies to both schemes in both clients. The
comment in the HTTPX snippet names the variable for the match's scheme, so a
plain-http match does not silently bypass a proxy set only in ``HTTPS_PROXY``.

When the browser received the match brotli- or zstd-compressed, the snippet
says so: a client without those decoders (stock curl builds, HTTPX without its
``brotli``/``zstd`` extras) is sent a larger gzip or uncompressed body.

curl expands ``[1-9]`` ranges and ``{a,b}`` sets in a URL into several
requests, and Chromium leaves ``[`` ``]`` ``{`` ``}`` unescaped in paths and
queries (JSON:API ``filter[category]=``, ``ids[]=``). A URL holding any of
them gets ``--globoff``, so the command sends exactly one request, as the
HTTPX snippet does; a hostile page cannot turn the copied command into a
burst of requests through the user's proxy.
"""

from __future__ import annotations

import urllib.parse

from ..types import StarterCode, safe_code

#: Content-Encoding values that common clients do not decode out of the box.
UNCOMMON_ENCODINGS = frozenset({"br", "zstd"})


def shell_single_quote(text: str) -> str:
    """POSIX single-quoted form of ``text`` (always quoted, ``'`` as ``'\\''``)."""
    return "'" + text.replace("'", "'\\''") + "'"


#: Characters curl's URL globbing interprets.
_CURL_GLOB_CHARS = frozenset("[]{}")


def curl_command(url: str) -> str:
    """``curl --compressed '<url>'`` with shell-safe quoting (``--globoff`` first when the URL has ``[]{}``)."""
    globoff = "--globoff " if any(c in _CURL_GLOB_CHARS for c in url) else ""
    return safe_code(f"curl {globoff}--compressed {shell_single_quote(url)}")


def proxy_env_comment(url: str) -> str:
    """Which proxy variables HTTPX and curl read for ``url``'s scheme (one comment line)."""
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        scheme = "https"
    if scheme == "http":
        return (
            "# For this http:// URL httpx reads HTTP_PROXY (not HTTPS_PROXY); curl reads only lowercase "
            "http_proxy."
        )
    return "# httpx reads HTTPS_PROXY from the environment for this https:// URL (curl: https_proxy)."


def encoding_comment(content_encoding: str | None) -> str | None:
    """A comment line when the browser got a br/zstd body that plain clients cannot request."""
    enc = (content_encoding or "").strip().lower()
    if enc not in UNCOMMON_ENCODINGS:
        return None
    return (
        f"# The browser received this response {enc}-compressed; install httpx[brotli,zstd] (and use a curl "
        f"built with {'brotli' if enc == 'br' else 'zstd'}) or expect a larger body than find's figure."
    )


def httpx_snippet(url: str, *, json_body: bool, content_encoding: str | None = None) -> str:
    """A minimal HTTPX GET of ``url`` (Python string literal via ``repr``)."""
    read = "data = response.json()" if json_body else "text = response.text"
    lines = [
        "import httpx",
        "",
        "# One plain GET: no cookies, no Authorization, httpx's own User-Agent.",
        proxy_env_comment(url) + " Check the site's terms first.",
    ]
    note = encoding_comment(content_encoding)
    if note is not None:
        lines.append(note)
    lines += [f"response = httpx.get({url!r}, timeout=30.0)", "response.raise_for_status()", read]
    return safe_code("\n".join(lines) + "\n")


def starter_code(rank: int, url: str, *, json_body: bool, content_encoding: str | None = None) -> StarterCode:
    """Starter code for one eligible match."""
    return StarterCode(
        rank=rank,
        curl=curl_command(url),
        httpx=httpx_snippet(url, json_body=json_body, content_encoding=content_encoding),
    )


__all__ = [
    "UNCOMMON_ENCODINGS",
    "curl_command",
    "encoding_comment",
    "httpx_snippet",
    "proxy_env_comment",
    "starter_code",
]
