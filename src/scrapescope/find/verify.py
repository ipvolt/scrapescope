"""``find --verify``: one cookie-less HTTPX GET of the top eligible match.

The replay is exactly one request through the same proxy ``find`` used (the
meter, and behind it the user's upstream), with a fresh client: no cookie jar,
no captured headers or tokens, redirects not followed, and the honest
User-Agent ``scrapescope/<version> (+https://github.com/ipvolt/scrapescope)``
(``config.USER_AGENT``: the tool, its version and the contact URL).
The body is read under the same size cap as the page load, searched with the
same variants, and discarded.

The size cap holds for the bytes received *and* for the decoded body: the
replay asks only for ``gzip, deflate`` and decodes the body itself, in bounded
steps (``zlib`` with ``max_length``), so a small compressed body that expands
to gigabytes (a compression bomb) stops at the cap instead of filling memory.
A response with more than one content coding (``gzip, gzip``) or one the
replay did not ask for (``br``, ``zstd``) is not decoded: ``not_tested`` with
reason ``unsupported content encoding``.

``replays`` is ``yes`` when the status is 2xx and the body still contains
every value the browser-side match contained, each as itself (a weak
``variant:substring`` hit, the value only inside a longer number, does not
count), ``no`` otherwise (reason ``status <n>`` or ``value missing``). A transport failure (proxy refused,
timeout, TLS error, a URL HTTPX refuses such as one over 65,536 characters,
or any other unexpected client error) is ``not_tested`` with reason ``request
failed (<error class>[, <errno name or SSL>])``, because it says nothing about
whether the endpoint replays. So is a reply that did not come from the site:
for an ``http://`` URL the meter's own refusal or upstream failure
(``X-Scrapescope-Error`` with a ``scrapescope:`` body; reason ``the meter
answered itself (<code>)``), confirmed with ``meter_reply_check`` when given,
and a proxy's 407 (``the proxy asked for credentials (status 407)``). A 502
or 504 is ``not_tested`` too (``gateway error (status <n>)``): a provider's
relayed gateway error looks the same as the site's own, and neither says
whether the endpoint replays. The
whole exchange has one deadline of ``timeout_s`` (HTTPX's timeout limits each
read, so a server trickling bytes could otherwise hold the replay for hours):
past it the reason is ``replay exceeded <N> s``. The request is not retried:
one GET is the contract.

:func:`verify_replay_detail` also returns what the replay moved
(:class:`ReplayDetail`): body bytes as received, estimated header bytes, the
Content-Encoding it got (as validated coding tokens, never the raw header:
``heuristics.encoding_tokens``) and the Accept-Encoding it sent (always
``gzip, deflate``), so a replay of a response the browser received with br
or zstd can move a much larger body than the browser did.

Accuracy limit: one request is a spot check. An endpoint can answer a single
cookie-less request and still rate-limit, fingerprint or block repeated ones.
Header byte counts are estimated from the parsed headers (HTTP/1.1 framing).
"""

from __future__ import annotations

import asyncio
import errno
import ssl
import zlib
from collections.abc import Sequence
from dataclasses import dataclass

from ..config import USER_AGENT
from ..types import VerifyResult, safe_text
from .browser import METER_ERROR_HEADER, MeterReplyCheck, confirm_meter_reply, meter_error_code
from .heuristics import body_kind, decode_body, encoding_tokens, looks_binary, mime_of
from .search import PreparedValue, counts_as_match, parse_json_text, search_body

#: The only codings the replay asks for; it decodes them itself with a bounded output.
REPLAY_ACCEPT_ENCODING = "gzip, deflate"
_ZLIB_WBITS = {"gzip": zlib.MAX_WBITS | 16, "x-gzip": zlib.MAX_WBITS | 16, "deflate": zlib.MAX_WBITS}
#: Body bytes of a non-2xx reply kept to recognise the meter's one-line ``scrapescope:`` body.
_METER_BODY_PEEK = 256
#: Gateway errors: from an upstream proxy (relayed on plain http) or the site's own gateway.
_GATEWAY_STATUSES = frozenset({502, 504})


class UnsupportedEncoding(Exception):
    """A Content-Encoding the replay does not decode (stacked codings, br, zstd...).

    Its message is the codings as validated tokens (``heuristics.encoding_tokens``).
    """


class OverCap(Exception):
    """The received or the decoded body went over the size cap."""


class BoundedDecoder:
    """Decode one gzip/deflate coding incrementally, never producing more than ``cap`` bytes.

    ``zlib.decompressobj().decompress(data, max_length)`` returns at most
    ``max_length`` bytes and keeps the rest of the input in
    ``unconsumed_tail``, so each step is bounded by what the cap still allows
    and a compression bomb raises :class:`OverCap` after at most ``cap + 1``
    decoded bytes. ``deflate`` falls back to a raw stream (no zlib header), as
    HTTPX does.
    """

    def __init__(self, content_encoding: str, cap: int) -> None:
        codings = [c.strip().lower() for c in content_encoding.split(",") if c.strip()]
        codings = [c for c in codings if c != "identity"]
        if len(codings) > 1 or (codings and codings[0] not in _ZLIB_WBITS):
            raise UnsupportedEncoding(encoding_tokens(", ".join(codings))[:40])
        self.coding = codings[0] if codings else ""
        self.cap = cap
        self.total = 0
        self._chunks: list[bytes] = []
        self._first = True
        self._z = zlib.decompressobj(_ZLIB_WBITS[self.coding]) if self.coding else None

    def _keep(self, out: bytes) -> None:
        self.total += len(out)
        if self.total > self.cap:
            raise OverCap()
        if out:
            self._chunks.append(out)

    def feed(self, data: bytes) -> None:
        if self._z is None:
            self._keep(data)
            return
        while data and not self._z.eof:
            try:
                out = self._z.decompress(data, self.cap - self.total + 1)
            except zlib.error:
                if self.coding == "deflate" and self._first:
                    self._first = False
                    self._z = zlib.decompressobj(-zlib.MAX_WBITS)
                    continue
                raise
            self._first = False
            self._keep(out)
            # a non-empty tail means the output limit was reached: _keep raised above
            data = self._z.unconsumed_tail

    def body(self) -> bytes:
        return b"".join(self._chunks)


def failure_detail(exc: BaseException) -> str:
    """``<ExceptionClass>`` plus the errno name or ``SSL`` of its cause, never a message or URL."""
    detail = type(exc).__name__
    seen = 0
    cause: BaseException | None = exc
    while cause is not None and seen < 6:
        if isinstance(cause, ssl.SSLError):
            return f"{detail}, SSL"
        if isinstance(cause, OSError) and isinstance(cause.errno, int) and cause.errno in errno.errorcode:
            return f"{detail}, {errno.errorcode[cause.errno]}"
        cause = cause.__cause__ or cause.__context__
        seen += 1
    return detail


@dataclass(frozen=True)
class ReplayDetail:
    """What the one replay moved (terminal and warnings only; no URL, no values)."""

    #: Body bytes as received (still compressed), as HTTPX counted them.
    received_body_bytes: int
    #: Estimated response header bytes (status line, headers, blank line).
    response_header_bytes: int
    #: Estimated request header bytes (request line, headers, blank line).
    request_header_bytes: int
    #: Content-Encoding of the replay's response as coding tokens ("" when none; see ``encoding_tokens``).
    content_encoding: str
    #: Accept-Encoding HTTPX sent.
    accept_encoding: str


def _header_bytes(first_line_len: int, headers: Sequence[tuple[bytes, bytes]]) -> int:
    """HTTP/1.1 size of a header block: first line + ``name: value`` lines + CRLFs."""
    return first_line_len + 2 + sum(len(n) + 2 + len(v) + 2 for n, v in headers) + 2


async def verify_replay(
    url: str,
    values: Sequence[PreparedValue],
    needed: Sequence[int],
    *,
    proxy_url: str,
    ca_file: str | None = None,
    timeout_s: float = 30.0,
    body_cap_bytes: int,
    resource_type: str = "fetch",
    meter_reply_check: MeterReplyCheck | None = None,
) -> VerifyResult:
    """Replay ``url`` once without cookies and check the ``needed`` value indices."""
    result, _detail = await verify_replay_detail(
        url,
        values,
        needed,
        proxy_url=proxy_url,
        ca_file=ca_file,
        timeout_s=timeout_s,
        body_cap_bytes=body_cap_bytes,
        resource_type=resource_type,
        meter_reply_check=meter_reply_check,
    )
    return result


async def verify_replay_detail(
    url: str,
    values: Sequence[PreparedValue],
    needed: Sequence[int],
    *,
    proxy_url: str,
    ca_file: str | None = None,
    timeout_s: float = 30.0,
    body_cap_bytes: int,
    resource_type: str = "fetch",
    meter_reply_check: MeterReplyCheck | None = None,
) -> tuple[VerifyResult, ReplayDetail | None]:
    """:func:`verify_replay` plus what the replay moved (None when no response arrived)."""
    import httpx

    timer = asyncio.timeout(timeout_s)
    try:
        async with timer:
            verify: ssl.SSLContext | bool = ssl.create_default_context(cafile=ca_file) if ca_file else True
            async with httpx.AsyncClient(
                proxy=proxy_url,
                verify=verify,
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(timeout_s),
                headers={"User-Agent": USER_AGENT, "Accept-Encoding": REPLAY_ACCEPT_ENCODING},
            ) as client:
                async with client.stream("GET", url) as response:
                    status = response.status_code
                    over_cap = False
                    unsupported: str | None = None
                    decoder: BoundedDecoder | None = None
                    if 200 <= status <= 299:
                        try:
                            decoder = BoundedDecoder(response.headers.get("content-encoding", ""), body_cap_bytes)
                        except UnsupportedEncoding as exc:
                            unsupported = str(exc) or "unknown"
                    # the meter's own replies (http:// only: it never terminates TLS) carry this header
                    peek: bytearray | None = (
                        bytearray()
                        if response.request.url.scheme == "http" and METER_ERROR_HEADER in response.headers
                        else None
                    )
                    raw_total = 0
                    try:
                        # raw bytes: HTTPX's own decoders have no output limit, so decoding happens here
                        async for chunk in response.aiter_raw():
                            raw_total += len(chunk)
                            if raw_total > body_cap_bytes:
                                raise OverCap()
                            if peek is not None and len(peek) < _METER_BODY_PEEK:
                                peek += chunk[: _METER_BODY_PEEK - len(peek)]
                            if decoder is not None:
                                decoder.feed(chunk)
                    except OverCap:
                        over_cap = True
                    except zlib.error:
                        unsupported = f"{decoder.coding if decoder else 'unknown'}, corrupt"
                        decoder = None
                    meter_code = (
                        meter_error_code(list(response.headers.items()), bytes(peek).decode("utf-8", "replace"))
                        if peek is not None
                        else None
                    )
                    plain_http = response.request.url.scheme == "http"
                    target = (response.request.url.host, response.request.url.port or 80)
                    received = response.num_bytes_downloaded
                    content_type = response.headers.get("content-type")
                    request = response.request
                    request_line = len(request.method) + 1 + len(request.url.raw_path) + len(" HTTP/1.1")
                    status_line = len("HTTP/1.1 ") + 3 + 1 + len(response.reason_phrase or "")
                    detail = ReplayDetail(
                        received_body_bytes=received,
                        response_header_bytes=_header_bytes(status_line, response.headers.raw),
                        request_header_bytes=_header_bytes(request_line, request.headers.raw),
                        content_encoding=encoding_tokens(response.headers.get("content-encoding")),
                        accept_encoding=request.headers.get("accept-encoding", ""),
                    )
    except (httpx.HTTPError, httpx.InvalidURL, ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
        if timer.expired():
            return VerifyResult(replays="not_tested", reason=f"replay exceeded {timeout_s:g} s"), None
        return VerifyResult(replays="not_tested", reason=f"request failed ({failure_detail(exc)})"), None
    except Exception as exc:  # noqa: BLE001 - any other client failure says nothing about replaying
        if timer.expired():
            return VerifyResult(replays="not_tested", reason=f"replay exceeded {timeout_s:g} s"), None
        return VerifyResult(replays="not_tested", reason=f"request failed ({failure_detail(exc)})"), None

    if meter_code is not None and confirm_meter_reply(meter_reply_check, meter_code, *target) is not False:
        # the meter refused the replay or its upstream failed: nothing reached the site
        reason = f"the meter answered itself ({safe_text(meter_code, 40)})"
        return VerifyResult(replays="not_tested", reason=reason), None
    if status == 407 and plain_http:
        # a plain-http 407 is the proxy's (the meter relays the upstream's): the replay never reached the site
        return VerifyResult(replays="not_tested", reason="the proxy asked for credentials (status 407)"), None
    if status in _GATEWAY_STATUSES:
        # a proxy's relayed 502/504 cannot be told from the site's own gateway error; neither says
        # whether the endpoint replays without a browser
        reason = f"gateway error (status {status})"
        return VerifyResult(replays="not_tested", status=status, received_bytes=received, reason=reason), detail
    if not 200 <= status <= 299:
        return VerifyResult(replays="no", status=status, received_bytes=received, reason=f"status {status}"), detail
    if over_cap:
        return (
            VerifyResult(
                replays="not_tested", status=status, received_bytes=received, reason="response over the size cap"
            ),
            detail,
        )
    if unsupported is not None or decoder is None:
        reason = f"unsupported content encoding ({safe_text(unsupported or 'unknown', 40)})"
        return VerifyResult(replays="not_tested", status=status, received_bytes=received, reason=reason), detail
    data = decoder.body()
    mime = mime_of(content_type)
    kind = body_kind(mime, resource_type) or "text"
    if mime is None and looks_binary(data):
        return VerifyResult(replays="no", status=status, received_bytes=received, reason="value missing"), detail
    text = decode_body(data, content_type, kind)
    del data, decoder
    if kind == "text" and parse_json_text(text) is not None:
        kind = "json"
    hits = await asyncio.to_thread(search_body, text, kind, list(values))
    del text
    # every needed value as itself: a weak hit (only inside a longer number) is "value missing"
    if all(0 <= i < len(hits.kinds) and counts_as_match(hits.kinds[i]) for i in needed):
        return VerifyResult(replays="yes", status=status, received_bytes=received, reason=None), detail
    return VerifyResult(replays="no", status=status, received_bytes=received, reason="value missing"), detail


__all__ = [
    "REPLAY_ACCEPT_ENCODING",
    "BoundedDecoder",
    "OverCap",
    "ReplayDetail",
    "UnsupportedEncoding",
    "failure_detail",
    "verify_replay",
    "verify_replay_detail",
]
