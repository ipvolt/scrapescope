"""Shared helpers for the end-to-end tests (tests/test_e2e_*.py).

The e2e tests run the real ``scrapescope`` CLI as a subprocess (``python -m
scrapescope``) against the local fixture world (tests/fixtures). Nothing here
touches the internet: child environments come from ``world.subprocess_env()``
(proxy variables removed, test connect map and CA set), and fake hostnames
resolve only through the fixture upstreams or the connect map.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any

from scrapescope.report import validate

PYTHON = sys.executable


def cli(
    args: list[str], *, env: dict[str, str], timeout: float = 90, cwd: str | os.PathLike[str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m scrapescope ARGS`` and capture its output."""
    return subprocess.run(
        [PYTHON, "-m", "scrapescope", *args],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def write_script(directory: Path, name: str, code: str) -> str:
    """Write a child job script and return its path."""
    path = Path(directory) / name
    path.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    return str(path)


def load_report(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read a report.json and assert that it validates against the schema."""
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    problems = validate(report)
    assert problems == [], problems[:5]
    return report


def read_text(path: str | os.PathLike[str]) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def secret_forms(username: str, password: str) -> list[str]:
    """Every form a leaked credential could take: raw parts, userinfo and Basic base64."""
    userinfo = f"{username}:{password}"
    return [username, password, userinfo, base64.b64encode(userinfo.encode()).decode()]


def assert_absent(secrets: list[str], **texts: str) -> None:
    """Assert that no secret appears in any of the named texts (without printing the secret)."""
    for name, text in texts.items():
        for index, secret in enumerate(secrets):
            assert secret not in text, f"credential form #{index} leaked into {name}"


def events_path_from(stderr: str) -> str | None:
    match = re.search(r"helper events kept at (\S+)", stderr)
    return match.group(1) if match else None


def bucket_sum(report: dict[str, Any]) -> int:
    b = report["buckets"]
    return b["attributed"] + b["preconnect_idle"] + b["before_attach"] + b["unattributed"] + sum(b["background"].values())


def host_rows(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["host"]: row for row in report["hosts"]}


class LineReader:
    """Collects a subprocess stream's lines in a background thread (for serve)."""

    def __init__(self, stream: Any) -> None:
        self.lines: list[str] = []
        self._queue: queue.Queue[str] = queue.Queue()
        self._thread = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        self._thread.start()

    def _pump(self, stream: Any) -> None:
        for line in stream:
            self.lines.append(line)
            self._queue.put(line)

    def wait_for(self, pattern: str, timeout: float = 20.0) -> re.Match[str]:
        regex = re.compile(pattern)
        for line in list(self.lines):
            if (m := regex.search(line)) is not None:
                return m
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self._queue.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            if (m := regex.search(line)) is not None:
                return m
        raise AssertionError(f"pattern {pattern!r} not seen; got {''.join(self.lines)[-2000:]}")

    def text(self) -> str:
        self._thread.join(timeout=10)
        return "".join(self.lines)


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_dead(pid: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.05)
    return not pid_alive(pid)
