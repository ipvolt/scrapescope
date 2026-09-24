"""Events-file writer (scrapescope.helpers.events) and reader (scrapescope.attribution.read_events)."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import warnings
from pathlib import Path

import pytest

from scrapescope.attribution import EventsLog, read_events
from scrapescope.config import ENV_EVENTS, ENV_KEEP_URLS, PrivateEventsFile
from scrapescope.helpers import events as ev
from scrapescope.types import MAX_EVENT_LINE_BYTES, AttachEvent, LaunchEvent, RequestEvent

T0 = 1_790_000_000.0


@pytest.fixture(autouse=True)
def _fresh_writer_state():
    ev._reset_for_tests()
    yield
    ev._reset_for_tests()


@pytest.fixture
def events_file(monkeypatch: pytest.MonkeyPatch):
    private = PrivateEventsFile.create()
    monkeypatch.setenv(ENV_EVENTS, str(private.path))
    monkeypatch.delenv(ENV_KEEP_URLS, raising=False)
    yield private.path
    ev._reset_for_tests()
    private.cleanup()


def _request(**kw) -> RequestEvent:
    base = dict(ts=T0, source="playwright", host="origin-a.test", port=443, scheme="https", status=200,
                resource_type="document", frame="main", is_navigation=True, encoded_body_bytes=10)
    base.update(kw)
    return RequestEvent(**base)  # type: ignore[arg-type]


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# ---------------------------------------------------------------------------- environment helpers


def test_environment_accessors(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert ev.events_path() == str(events_file)
    assert ev.enabled() is True
    assert ev.keep_urls() is False
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    assert ev.keep_urls() is True
    monkeypatch.setenv(ENV_KEEP_URLS, "yes")
    assert ev.keep_urls() is False
    monkeypatch.setenv(ENV_EVENTS, str(events_file) + ".missing")
    assert ev.enabled() is False
    monkeypatch.setenv(ENV_EVENTS, "")
    assert ev.events_path() is None and ev.enabled() is False


def test_new_context_ids_are_unique_and_valid() -> None:
    ids = {ev.new_context_id() for _ in range(100)}
    assert len(ids) == 100
    for value in ids:
        pid, _, n = value.partition("-")
        assert pid == str(os.getpid()) and n.isdigit()


# ---------------------------------------------------------------------------- writing


def test_emit_appends_valid_lines_and_keeps_permissions(events_file: Path) -> None:
    ev.emit(AttachEvent(ts=T0, source="playwright", pid=os.getpid(), context="1-1"))
    ev.emit(LaunchEvent(ts=T0, source="playwright", pid=os.getpid()))
    ev.emit(_request(path="/product/1"))
    rows = _lines(events_file)
    assert [r["kind"] for r in rows] == ["attach", "launch", "request"]
    assert all(r["v"] == 1 for r in rows)
    assert "path" not in rows[2]  # paths only with SCRAPESCOPE_KEEP_URLS=1
    assert stat.S_IMODE(events_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(events_file.parent.stat().st_mode) == 0o700
    log = read_events(events_file)
    assert log.dropped == 0 and len(log.events) == 3


def test_paths_only_with_keep_urls_and_never_queries(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    ev.emit(_request(path="/api/offer.json?sig=SECRET-TOKEN#frag"))
    rows = _lines(events_file)
    assert rows[0]["path"] == "/api/offer.json"
    assert "SECRET-TOKEN" not in events_file.read_text()


def test_non_network_schemes_and_invalid_events_are_not_written(events_file: Path) -> None:
    ev.emit(_request(scheme="data"))
    ev.emit(_request(scheme="blob"))
    ev.emit(_request(scheme="chrome-extension"))
    ev.emit(_request(host="bad host with spaces"))
    ev.emit(_request(method="get"))  # parse_event requires [A-Z]
    ev.emit(_request(encoded_body_bytes=-5))
    assert events_file.read_text() == ""


def test_emit_never_creates_a_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "nope" / "events.jsonl"
    monkeypatch.setenv(ENV_EVENTS, str(missing))
    with pytest.warns(RuntimeWarning, match="could not append"):
        ev.emit(_request())
        ev.emit(_request())
    assert not missing.exists() and not missing.parent.exists()


def test_emit_refuses_symlinks_and_non_regular_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    monkeypatch.setenv(ENV_EVENTS, str(link))
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        ev.emit(_request())
    assert target.read_text() == ""
    ev._reset_for_tests()
    monkeypatch.setenv(ENV_EVENTS, str(tmp_path))  # a directory
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ev.emit(_request())
    assert len(caught) == 1


def test_inactive_warning_is_issued_once_per_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_EVENTS, raising=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ev.emit(_request())
        ev.emit(_request())
        ev.warn_inactive()
    assert len(caught) == 1
    assert issubclass(caught[0].category, RuntimeWarning)
    assert "SCRAPESCOPE_EVENTS is not set" in str(caught[0].message)
    assert "scrapescope run" in str(caught[0].message)


def test_warnings_as_errors_never_raise_into_callers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ENV_EVENTS, raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        ev.emit(_request())  # inactive warning swallowed
        monkeypatch.setenv(ENV_EVENTS, str(tmp_path / "missing.jsonl"))
        ev.emit(_request())  # write-failure warning swallowed


def test_lines_respect_the_size_cap(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    ev.emit(_request(path="/" + "a" * 5000))
    data = events_file.read_bytes()
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    assert len(data) - 1 <= MAX_EVENT_LINE_BYTES
    assert json.loads(data)["path"].endswith("...")


def test_concurrent_writers_do_not_interleave(events_file: Path) -> None:
    def work(n: int) -> None:
        for i in range(250):
            ev.emit(_request(ts=T0 + i, host=f"h{n}.test", encoded_body_bytes=i))

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log = read_events(events_file)
    assert log.dropped == 0 and len(log.events) == 2000


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
# The session's fixture servers run threads; this test forks on purpose (the child only
# writes one event and exits), so Python's multi-threaded fork warning is expected here.
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
def test_forked_child_reopens_and_appends(events_file: Path) -> None:
    ev.emit(_request(host="parent.test"))
    pid = os.fork()
    if pid == 0:  # child
        try:
            ev.emit(_request(host="child.test"))
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    ev.emit(_request(host="parent2.test"))
    hosts = [e.host for e in read_events(events_file).events]
    assert sorted(hosts) == ["child.test", "parent.test", "parent2.test"]


def test_switching_paths_reopens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = PrivateEventsFile.create(), PrivateEventsFile.create()
    try:
        monkeypatch.setenv(ENV_EVENTS, str(first.path))
        ev.emit(_request(host="one.test"))
        monkeypatch.setenv(ENV_EVENTS, str(second.path))
        ev.emit(_request(host="two.test"))
        assert [e.host for e in read_events(first.path).events] == ["one.test"]
        assert [e.host for e in read_events(second.path).events] == ["two.test"]
    finally:
        first.cleanup()
        second.cleanup()


# ---------------------------------------------------------------------------- url parts


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Origin-A.test/x?y=1", ("https", "origin-a.test", 443)),
        ("http://origin-a.test:8080/", ("http", "origin-a.test", 8080)),
        ("wss://ws.test/socket", ("wss", "ws.test", 443)),
        ("ws://ws.test/socket", ("ws", "ws.test", 80)),
        ("https://[::1]:8443/", ("https", "::1", 8443)),
        ("https://b\u00fccher.example/", ("https", "xn--bcher-kva.example", 443)),
    ],
)
def test_url_parts(url: str, expected: tuple[str, str, int]) -> None:
    parts = ev.url_parts(url)
    assert parts is not None
    assert (parts.scheme, parts.host, parts.port) == expected
    assert parts.path is None


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://1.2.3.04/plain.html", ("1.2.3.4", 80)),  # legacy spelling: a leading zero is octal
        ("http://0x01020304/", ("1.2.3.4", 80)),
        ("http://16909060:8080/", ("1.2.3.4", 8080)),
        ("http://[2001:db8:0:0::1]/", ("2001:db8::1", 80)),  # uncompressed IPv6
        ("https://[2001:DB8::1]:8443/", ("2001:db8::1", 8443)),
        ("http://[::ffff:102:304]/", ("1.2.3.4", 80)),  # how Chromium writes [::ffff:1.2.3.4]
        ("http://[::ffff:1.2.3.4]/", ("1.2.3.4", 80)),
        ("http://1.2.3.08/", ("1.2.3.08", 80)),  # not an address (08 is no octal): a name, left as written
    ],
)
def test_url_parts_writes_ip_literals_the_way_the_meter_records_them(url: str, expected: tuple[str, int]) -> None:
    # meas4-1: the meter files every tunnel under types.canonical_host; an event host in another
    # spelling matched no tunnel, so its request was called bypass and its tunnel had no requests.
    parts = ev.url_parts(url)
    assert parts is not None
    assert (parts.host, parts.port) == expected


@pytest.mark.parametrize(
    "url",
    ["data:text/html,hi", "blob:https://a.test/uuid", "about:blank", "chrome://version",
     "chrome-extension://abc/x.js", "file:///etc/passwd", "", "https:///nohost", None],
)
def test_url_parts_rejects_non_network(url) -> None:
    assert ev.url_parts(url) is None


def test_url_parts_path_with_keep_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    parts = ev.url_parts("https://a.test/<script>/x?token=abc#f")
    assert parts is not None and parts.path == "/<script>/x"


def test_count() -> None:
    assert ev.count(5) == 5 and ev.count(5.9) == 5 and ev.count(0) == 0
    assert ev.count(-1) is None and ev.count(None) is None and ev.count(True) is None
    assert ev.count(float("nan")) is None and ev.count(2**60) == 2**53 - 1


# ---------------------------------------------------------------------------- reader


def test_read_events_missing_file(tmp_path: Path) -> None:
    log = read_events(tmp_path / "missing.jsonl")
    assert isinstance(log, EventsLog) and log.events == [] and log.dropped == 0 and log.error is None


def test_read_events_unreadable(tmp_path: Path) -> None:
    log = read_events(tmp_path)  # a directory
    assert log.events == [] and log.error is not None and str(tmp_path) not in log.error


def test_read_events_drops_and_counts_bad_lines(tmp_path: Path) -> None:
    good = json.dumps({"v": 1, "kind": "attach", "ts": T0, "source": "playwright", "extra": "ignored"})
    request = json.dumps({"v": 1, "kind": "request", "ts": T0, "source": "httpx", "host": "A.test",
                          "path": "/x?secret=1"})
    lines = [
        good,
        "",  # blank: ignored, not dropped
        "{not json",
        json.dumps({"v": 2, "kind": "attach", "ts": T0, "source": "playwright"}),
        json.dumps({"v": 1, "kind": "request", "ts": T0, "source": "playwright", "host": "x.test",
                    "scheme": "data"}),
        json.dumps([1, 2, 3]),
        "x" * (MAX_EVENT_LINE_BYTES + 100),
        request,
    ]
    path = tmp_path / "events.jsonl"
    path.write_bytes(("\n".join(lines) + "\n").encode() + b"\xff\xfe\n" + good.encode())  # bad UTF-8, no final \n
    log = read_events(path)
    assert log.dropped == 6
    assert [e.kind for e in log.events] == ["attach", "request", "attach"]
    assert log.events[1].host == "a.test" and log.events[1].path == "/x"


def test_read_events_caps_the_number_of_events(tmp_path: Path) -> None:
    line = json.dumps({"v": 1, "kind": "launch", "ts": T0, "source": "playwright"})
    path = tmp_path / "events.jsonl"
    path.write_text((line + "\n") * 25)
    log = read_events(path, max_events=10)
    assert len(log.events) == 10 and log.dropped == 15


def test_read_events_handles_huge_lines_without_reading_them_whole(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    good = json.dumps({"v": 1, "kind": "launch", "ts": T0, "source": "playwright"})
    with open(path, "wb") as fh:
        fh.write(b"y" * (3 * 1024 * 1024) + b"\n" + good.encode() + b"\n")
    log = read_events(path)
    assert log.dropped == 1 and len(log.events) == 1


def test_writer_output_round_trips_through_reader(events_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEEP_URLS, "1")
    original = _request(path="/p", sent_cookies=True, sent_authorization=True, context="9-9",
                        response_header_bytes=100, request_header_bytes=200, request_body_bytes=0)
    ev.emit(original)
    (parsed,) = read_events(events_file).events
    assert parsed == original


def test_module_import_is_light() -> None:
    code = ("import sys, scrapescope.helpers, scrapescope.helpers.events, scrapescope.helpers.hooks, "
            "scrapescope.helpers.playwright, scrapescope.attribution; "
            "print(sorted(m for m in ('playwright', 'requests', 'httpx') if m in sys.modules))")
    import subprocess

    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=30)
    assert out.stdout.strip() == "[]"


@pytest.mark.timeout(10)
def test_read_events_never_blocks_on_a_fifo(tmp_path: Path) -> None:
    # sec-9: the job can replace events.jsonl with a FIFO; a plain open() would block forever.
    import threading

    fifo = tmp_path / "events.jsonl"
    os.mkfifo(fifo)
    result: list[EventsLog] = []
    reader = threading.Thread(target=lambda: result.append(read_events(fifo)), daemon=True)
    reader.start()
    reader.join(3)
    assert not reader.is_alive(), "read_events blocked on a FIFO"
    (log,) = result
    assert log.events == [] and log.error == "events path is not a regular file"


def test_read_events_refuses_a_symlinked_events_file(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.jsonl"
    target.write_text('{"v":1,"kind":"attach","ts":1790000000,"source":"playwright"}\n')
    link = tmp_path / "events.jsonl"
    link.symlink_to(target)
    log = read_events(link)
    assert log.events == [] and log.error == "events path is not a regular file"
    assert len(read_events(target).events) == 1
