"""The meter's open-file limit (RLIMIT_NOFILE).

Every tunnel costs the meter two file descriptors: the client's socket and the
upstream socket. A job that holds N connections open therefore needs about 2N
descriptors in the meter, and the common macOS shell default soft limit of 256
would fail tunnels beyond roughly 120, where the job on its own would not fail.
So ``run``, ``serve`` and ``find`` raise the soft limit of their own process
toward the hard limit (at most :data:`TARGET_OPEN_FILES`) with
:func:`raise_open_file_limit`. ``run`` does it after starting the job, so the
job keeps the limit it would have had without the meter. When the hard limit
is low, the meter reports ``failed:local_limit`` for tunnels it cannot open
(never "refused by the target" or "provider unreachable").
"""

from __future__ import annotations

#: Soft open-file limit the meter asks for (never above the hard limit).
TARGET_OPEN_FILES = 65536
#: Below this soft limit, the runner mentions the limit at start.
LOW_OPEN_FILES = 1024
#: Fallbacks tried when the system refuses the first value (macOS OPEN_MAX is 10240).
_FALLBACKS = (10240, 4096, 2048, 1024)


def raise_open_file_limit(target: int = TARGET_OPEN_FILES) -> tuple[int | None, int | None]:
    """Raise the soft RLIMIT_NOFILE toward ``min(hard, target)``; never lowers it.

    Returns ``(before, after)`` soft limits, None when unknown or unlimited.
    Never raises: a refusal leaves the limit as it was.
    """
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return None, None
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        return None, None
    infinity = resource.RLIM_INFINITY
    if soft == infinity or soft < 0:
        return None, None
    want = target if hard == infinity or hard < 0 else min(hard, target)
    if soft >= want:
        return int(soft), int(soft)
    for candidate in (want, *_FALLBACKS):
        if candidate <= soft or candidate > want:
            continue
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (candidate, hard))
        except (OSError, ValueError):
            continue
        return int(soft), int(candidate)
    return int(soft), int(soft)


__all__ = ["LOW_OPEN_FILES", "TARGET_OPEN_FILES", "raise_open_file_limit"]
