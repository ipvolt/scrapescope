"""Background asyncio loop and byte-pumping helpers shared by the fixture servers.

Every fixture server runs its asyncio code on a :class:`BackgroundLoop`, a
daemon thread that owns one event loop, so synchronous pytest code can start,
stop and inspect servers without an event loop of its own.

Counting note: the helpers count bytes when they are *consumed from* a
``StreamReader`` or *handed to* a ``StreamWriter``. Once a connection has been
drained to EOF this equals the bytes carried by the socket; while a connection
is still open a few kilobytes may sit unconsumed in the reader buffer.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import threading
import time
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

T = TypeVar("T")

PUMP_CHUNK = 64 * 1024


class BackgroundLoop:
    """An asyncio event loop running forever in a daemon thread."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._closed = False
        self._thread = threading.Thread(target=self._main, name=f"fixture-{name}", daemon=True)
        self._thread.start()
        self._ready.wait(10)

    def _main(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.call_soon(self._ready.set)
        self.loop.run_forever()

    def run(self, coro: Coroutine[Any, Any, T], timeout: float = 30.0) -> T:
        """Run ``coro`` on the loop and wait for its result from another thread."""
        if threading.current_thread() is self._thread:
            raise RuntimeError("BackgroundLoop.run() called from its own loop thread")
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout)

    def call(self, fn: Callable[[], T], timeout: float = 30.0) -> T:
        """Run a plain callable on the loop thread and return its result."""

        async def _wrapper() -> T:
            return fn()

        return self.run(_wrapper(), timeout)

    def stop(self) -> None:
        """Cancel every task on the loop, stop it and join the thread."""
        if self._closed:
            return
        self._closed = True

        async def _cancel_all() -> None:
            current = asyncio.current_task()
            tasks = [t for t in asyncio.all_tasks() if t is not current]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.wait(tasks, timeout=5)

        with contextlib.suppress(Exception):
            self.run(_cancel_all(), timeout=10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(10)
        if not self._thread.is_alive():
            self.loop.close()


async def pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_bytes: Callable[[int], None],
    chunk: int = PUMP_CHUNK,
) -> None:
    """Copy ``reader`` to ``writer`` until EOF, reporting each chunk, then half-close.

    ``on_bytes`` is called with the size of every chunk right after it is read
    (count on read) and before it is written onward.
    """
    try:
        while True:
            data = await reader.read(chunk)
            if not data:
                break
            on_bytes(len(data))
            writer.write(data)
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            if not writer.is_closing() and writer.can_write_eof():
                writer.write_eof()


async def splice(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    origin_reader: asyncio.StreamReader,
    origin_writer: asyncio.StreamWriter,
    on_client_bytes: Callable[[int], None],
    on_origin_bytes: Callable[[int], None],
) -> None:
    """Relay both directions with half-close propagation until both sides finish.

    ``on_client_bytes`` receives sizes of chunks read from the client (and
    written to the origin); ``on_origin_bytes`` receives sizes of chunks read
    from the origin (and written to the client). If either direction fails with
    a connection error the other direction is cancelled.
    """
    up = asyncio.ensure_future(pump(client_reader, origin_writer, on_client_bytes))
    down = asyncio.ensure_future(pump(origin_reader, client_writer, on_origin_bytes))
    try:
        pending = {up, down}
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if any(t.exception() is not None for t in done if not t.cancelled()):
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.wait(pending)
                break
    finally:
        for task in (up, down):
            if not task.done():
                task.cancel()
        await asyncio.gather(up, down, return_exceptions=True)


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Close a writer and wait briefly, ignoring errors from dead sockets."""
    if writer is None:
        return
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), timeout=2)


def wait_until(predicate: Callable[[], bool], timeout: float, interval: float = 0.02) -> bool:
    """Poll ``predicate`` until it is true or ``timeout`` seconds pass."""
    deadline = time.monotonic() + timeout
    if not predicate():
        # Some clients (requests + PySocks) keep sockets alive through reference
        # cycles until a collection runs; collect once so "idle" means idle.
        gc.collect()
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)
