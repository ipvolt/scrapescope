"""What-if savings: what blocking or denying would have saved in this run.

Accuracy limits, stated honestly:

- Figures are on the *allocated* basis. Image, media and font bytes are their
  hosts' tunnel bytes shared in proportion to the DevTools-reported sizes (scaled
  down when the reported sizes exceed the tunnel, and up by at most a bounded
  overhead allowance); they are not measured on a separate tunnel. Tunnel bytes
  beyond that allowance are the ``unreported`` type, which no what-if counts.
- Blocking has second-order effects the model ignores: fewer connections and
  TLS handshakes to image CDNs (saving more), pages that fetch replacements or
  retry (saving less), and extraction that breaks or anti-bot systems that
  react. Hence the caveat "compare a second run".
- ``route()``-style blocking disables Playwright's HTTP cache, so on runs where
  a context loaded more than one page the saving can be smaller than shown, or
  negative. "cache loss not modelled" flags those runs.
- Denying catalogued background hosts saves their bucket bytes (tunnel-measured,
  with CONNECT); it has a security cost described by each catalog entry.
"""

from __future__ import annotations

from ..types import AttributionResult, Catalogs, Totals, WhatIf

BLOCKING_CAVEAT = "blocking can break extraction or attract anti-bot scrutiny; compare a second run"
CACHE_CAVEAT = "cache loss not modelled"
COMPARE_CAVEAT = "compare a second run"

#: Resource types the blocking what-if (and the blocking fixes) cover.
BLOCKABLE_TYPES: tuple[str, ...] = ("image", "media", "font")

BLOCK_ID = "block-images-media-fonts"
BLOCK_TITLE = "Block images, media and fonts"
DENY_BACKGROUND_ID = "deny-background-catalog"
DENY_BACKGROUND_TITLE = "Deny catalogued Chromium background hosts"


def blockable_bytes(attribution: AttributionResult) -> int:
    """Allocated bytes of image, media and font requests in the run."""
    return sum(max(0, t.allocated_bytes) for t in attribution.types if t.type in BLOCKABLE_TYPES)


def background_bytes(attribution: AttributionResult) -> int:
    """Bytes in the ``background:<catalog id>`` buckets."""
    return sum(max(0, b) for b in attribution.buckets.background.values())


def share_of(part: int, total: int) -> float:
    """``part / total`` clamped to [0, 1] and rounded to 6 decimals; 0 when the total is 0."""
    if total <= 0 or part <= 0:
        return 0.0
    return round(min(1.0, part / total), 6)


def compute_what_if(attribution: AttributionResult, totals: Totals, catalogs: Catalogs) -> list[WhatIf]:
    """Modelled savings, each emitted only when it would save something.

    - ``block-images-media-fonts``: allocated bytes of types image, media and
      font; caveats: the blocking caveat, plus "cache loss not modelled" when a
      context loaded more than one page.
    - ``deny-background-catalog``: bytes of every ``background:<id>`` bucket;
      caveats: each involved entry's security trade-off (heaviest first), then
      "compare a second run".

    ``share`` is bytes saved over ``totals.with_connect`` (0 when the total is 0).
    """
    out: list[WhatIf] = []
    total = totals.with_connect

    blocked = blockable_bytes(attribution)
    if blocked > 0:
        caveats = [BLOCKING_CAVEAT]
        if attribution.multi_page_context:
            caveats.append(CACHE_CAVEAT)
        out.append(
            WhatIf(
                id=BLOCK_ID,
                title=BLOCK_TITLE,
                bytes_saved=blocked,
                share=share_of(blocked, total),
                caveats=caveats,
            )
        )

    background = background_bytes(attribution)
    if background > 0:
        entries = {entry.id: entry for entry in catalogs.background}
        involved = sorted(
            ((cid, b) for cid, b in attribution.buckets.background.items() if b > 0),
            key=lambda item: (-item[1], item[0]),
        )
        caveats = []
        for cid, _ in involved:
            entry = entries.get(cid)
            tradeoff = entry.security_tradeoff if entry else "see this entry in the background catalog"
            caveats.append(f"{cid}: {tradeoff}")
        caveats.append(COMPARE_CAVEAT)
        out.append(
            WhatIf(
                id=DENY_BACKGROUND_ID,
                title=DENY_BACKGROUND_TITLE,
                bytes_saved=background,
                share=share_of(background, total),
                caveats=caveats,
            )
        )
    return out


__all__ = [
    "BLOCKABLE_TYPES",
    "BLOCKING_CAVEAT",
    "CACHE_CAVEAT",
    "COMPARE_CAVEAT",
    "background_bytes",
    "blockable_bytes",
    "compute_what_if",
    "share_of",
]
