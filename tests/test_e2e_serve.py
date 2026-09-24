"""End-to-end tests of ``scrapescope serve`` (the real CLI in a subprocess).

``serve`` always requires the per-run ``ss-<token>`` username (round 4,
hon4-3: no ``--allow-tokenless``), prints the token once to stderr only when
that is a terminal and otherwise writes it to a private 0600 file (round 4,
sec4-7), stops on SIGINT or SIGTERM, writes its report on exit and exits 86
when its budget tripped.
"""

from __future__ import annotations

import base64
import os
import re
import signal
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

from tests.e2e_support import PYTHON, LineReader, assert_absent, cli, load_report, read_text, secret_forms
from tests.fixtures import UPSTREAM_PASSWORD, UPSTREAM_USERNAME, TestWorld

pytestmark = pytest.mark.timeout(90)


@contextmanager
def serve(world: TestWorld, tmp_path: Path, *args: str, env_extra: dict[str, str] | None = None
          ) -> Iterator[tuple[subprocess.Popen[str], LineReader, int, str]]:
    """Start ``scrapescope serve --token-file`` and yield (process, stderr reader, port, token username)."""
    token_file = tmp_path / "serve-token"
    proc = subprocess.Popen(
        [PYTHON, "-m", "scrapescope", "serve", "--out", str(tmp_path / "serve.json"), "--token-file", str(token_file),
         *args],
        env=world.subprocess_env(env_extra), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    assert proc.stderr is not None
    reader = LineReader(proc.stderr)
    try:
        port = int(reader.wait_for(r"listening on http://127\.0\.0\.1:(\d+)").group(1))
        reader.wait_for(r"proxy URL with username ss-<token>: in ")
        match = re.fullmatch(rf"http://(ss-[A-Za-z0-9_-]+):x@127\.0\.0\.1:{port}\n", token_file.read_text())
        assert match is not None
        yield proc, reader, port, match.group(1)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def _raw_request(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def _client(world: TestWorld, proxy: str) -> httpx.Client:
    return httpx.Client(proxy=proxy, verify=world.tls.client_context(), trust_env=False, timeout=20)


def test_serve_requires_the_token(world: TestWorld, tmp_path: Path) -> None:
    with serve(world, tmp_path, "--upstream-from-env", "HTTPS_PROXY",
               env_extra={"HTTPS_PROXY": world.http_upstream.url}) as (proc, reader, port, token):
        assert token is not None
        # No credentials: the meter's own 407 challenge.
        reply = _raw_request(port, b"GET http://origin-a.test/plain.html HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        assert reply.startswith(b"HTTP/1.1 407 ")
        assert b'Proxy-Authenticate: Basic realm="scrapescope"' in reply
        with _client(world, f"http://127.0.0.1:{port}") as client, pytest.raises(httpx.ProxyError):
            client.get("https://origin-a.test/api/product.json")
        # A wrong token is refused too, and never forwarded.
        with _client(world, f"http://ss-wrongtoken:x@127.0.0.1:{port}") as client, pytest.raises(httpx.ProxyError):
            client.get("https://origin-a.test/api/product.json")
        # The token works; the meter injects the upstream credentials from $HTTPS_PROXY.
        with _client(world, f"http://{token}:anything@127.0.0.1:{port}") as client:
            assert client.get("https://origin-a.test/api/product.json").status_code == 200
        # ss-<token>~<user> passes the client's own provider credentials through.
        with _client(world, f"http://{token}~{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}@127.0.0.1:{port}") as client:
            assert client.get("https://origin-b.test/embed").status_code == 200
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=30) == 0
        stderr = reader.text()
    assert token not in stderr and token[3:] not in stderr  # --token-file: the token is never printed
    assert not (tmp_path / "serve-token").exists()  # removed when serve stopped
    report = load_report(tmp_path / "serve.json")
    assert report["command"] == "serve"
    assert report["refused"].get("token_required", 0) >= 2 and report["refused"].get("bad_token", 0) >= 1
    assert {row["host"] for row in report["hosts"]} == {"origin-a.test", "origin-b.test"}
    report_text = read_text(tmp_path / "serve.json")
    assert token not in report_text and token[3:] not in report_text
    assert_absent(secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), stderr=stderr, report=report_text)


def test_serve_sigterm_and_origin_form_403(world: TestWorld, tmp_path: Path) -> None:
    with serve(world, tmp_path, "--direct", "--quiet") as (proc, reader, port, token):
        with _client(world, f"http://{token}:x@127.0.0.1:{port}") as client:
            assert client.get("https://origin-a.test/api/product.json").status_code == 200
        # Origin-form requests (DNS rebinding) get a bare 403, before any token check.
        reply = _raw_request(port, b"GET / HTTP/1.1\r\nHost: evil.example\r\nOrigin: http://evil.example\r\n\r\n")
        assert reply.startswith(b"HTTP/1.1 403 ") and b"X-Scrapescope" not in reply
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0
        stderr = reader.text()
    assert "Totals (tunnel-measured)" not in stderr  # --quiet
    report = load_report(tmp_path / "serve.json")
    assert report["mode"] == "direct" and report["totals"]["tunnels"] == 1


def test_serve_has_no_tokenless_mode(world: TestWorld, tmp_path: Path) -> None:
    """hon4-3: the plan says serve always requires the per-run token; --allow-tokenless is gone."""
    result = cli(["serve", "--direct", "--allow-tokenless", "--out", str(tmp_path / "s.json")], env=world.subprocess_env())
    assert result.returncode == 2 and "--allow-tokenless" in result.stderr
    assert not (tmp_path / "s.json").exists()


def test_serve_writes_the_token_to_a_private_file_when_stderr_is_not_a_terminal(world: TestWorld, tmp_path: Path) -> None:
    """sec4-7: stderr going to a log (a pipe here) never carries the token; a 0600 file does, until serve stops."""
    proc = subprocess.Popen(
        [PYTHON, "-m", "scrapescope", "serve", "--direct", "--out", str(tmp_path / "serve.json")],
        env=world.subprocess_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert proc.stderr is not None
    reader = LineReader(proc.stderr)
    try:
        port = int(reader.wait_for(r"listening on http://127\.0\.0\.1:(\d+)").group(1))
        path = Path(reader.wait_for(r"proxy URL with username ss-<token>: in (\S+) \(mode 0600").group(1))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        proxy_url = path.read_text().strip()
        token = re.fullmatch(rf"http://(ss-[A-Za-z0-9_-]+):x@127\.0\.0\.1:{port}", proxy_url).group(1)  # type: ignore[union-attr]
        with _client(world, proxy_url) as client:
            assert client.get("https://origin-a.test/api/product.json").status_code == 200
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
    stderr = reader.text()
    assert token not in stderr and token[3:] not in stderr
    assert "stderr is not a terminal" in stderr and "--token-file" in stderr
    assert not path.exists() and not path.parent.exists()


def test_serve_token_file_must_be_new(world: TestWorld, tmp_path: Path) -> None:
    existing = tmp_path / "token"
    existing.write_text("keep me")
    result = cli(["serve", "--direct", "--token-file", str(existing), "--out", str(tmp_path / "s.json")],
                 env=world.subprocess_env())
    assert result.returncode == 2 and "already exists" in result.stderr
    assert existing.read_text() == "keep me"


@pytest.mark.skipif(not hasattr(os, "openpty"), reason="needs a pseudo-terminal")
def test_serve_prints_the_token_to_a_terminal(world: TestWorld, tmp_path: Path) -> None:
    """sec4-7: an interactive stderr still shows the token once, as before; no file is written."""
    master, slave = os.openpty()
    proc = subprocess.Popen(
        [PYTHON, "-m", "scrapescope", "serve", "--direct", "--out", str(tmp_path / "serve.json")],
        env=world.subprocess_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=slave,
    )
    os.close(slave)
    chunks: list[bytes] = []

    def drain() -> None:  # a pty's buffer is small: keep reading or serve blocks writing its summary
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                return
            if not data:
                return
            chunks.append(data)

    pump = threading.Thread(target=drain, daemon=True)
    pump.start()
    try:
        deadline = time.monotonic() + 20
        while b"report: " not in b"".join(chunks) and time.monotonic() < deadline:
            time.sleep(0.05)
        text = b"".join(chunks).decode("utf-8", "replace")
        token = re.search(r"proxy username: (ss-[A-Za-z0-9_-]+)", text).group(1)  # type: ignore[union-attr]
        port = int(re.search(r"listening on http://127\.0\.0\.1:(\d+)", text).group(1))  # type: ignore[union-attr]
        with _client(world, f"http://{token}:x@127.0.0.1:{port}") as client:
            assert client.get("https://origin-a.test/api/product.json").status_code == 200
        assert "proxy URL with username" not in text
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        pump.join(timeout=5)
        os.close(master)
    text = b"".join(chunks).decode("utf-8", "replace")
    assert text.count(token) == 3  # the banner is the only place the token appears


def test_serve_budget_trip_refuses_and_exits_86(world: TestWorld, tmp_path: Path) -> None:
    with serve(world, tmp_path, "--direct", "--budget", "200kB") as (proc, reader, port, token):
        proxy = f"http://{token}:x@127.0.0.1:{port}"
        with _client(world, proxy) as client:
            with pytest.raises(httpx.HTTPError):
                client.get("https://origin-a.test/big.bin?size=2000000").read()
        reader.wait_for("byte budget tripped")
        reply = _raw_request(
            port,
            b"GET http://origin-a.test/plain.html HTTP/1.1\r\nHost: origin-a.test\r\n"
            + b"Proxy-Authorization: Basic " + base64.b64encode(f"{token}:x".encode()) + b"\r\n\r\n",
        )
        assert reply.startswith(b"HTTP/1.1 403 ") and b"X-Scrapescope-Budget: tripped" in reply
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=30) == 86
    report = load_report(tmp_path / "serve.json")
    assert report["budget"]["tripped"] is True
    assert "tripped" in [e["kind"] for e in report["budget_events"]]
