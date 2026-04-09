"""Async memory streams replacing anyio memory object streams.

Provides StreamWriter/StreamReader pairs backed by asyncio.Queue
for bidirectional in-process communication.
"""

import asyncio
from typing import Generic, TypeVar

T = TypeVar("T")


class ClosedStreamError(Exception):
    """Raised when attempting to use a closed stream."""


_CLOSED = object()


class StreamWriter(Generic[T]):
    """Write end of a memory stream."""

    __slots__ = ("_closed", "_queue")

    def __init__(self, queue: asyncio.Queue[T | object]) -> None:
        self._queue = queue
        self._closed = False

    async def send(self, item: T) -> None:
        if self._closed:
            raise ClosedStreamError("Stream writer is closed")
        await self._queue.put(item)

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            # Drain one item to make room for the sentinel if the queue is full
            while True:
                try:
                    self._queue.put_nowait(_CLOSED)
                    break
                except asyncio.QueueFull:
                    try:
                        self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break


class StreamReader(Generic[T]):
    """Read end of a memory stream."""

    __slots__ = ("_closed", "_queue")

    def __init__(self, queue: asyncio.Queue[T | object]) -> None:
        self._queue = queue
        self._closed = False

    async def receive(self) -> T:
        if self._closed:
            raise ClosedStreamError("Stream reader is closed")
        item = await self._queue.get()
        if item is _CLOSED:
            self._closed = True
            raise ClosedStreamError("Stream was closed by writer")
        return item  # type: ignore[return-value]

    async def aclose(self) -> None:
        self._closed = True

    def __aiter__(self) -> "StreamReader[T]":
        return self

    async def __anext__(self) -> T:
        try:
            return await self.receive()
        except ClosedStreamError:
            raise StopAsyncIteration


def create_memory_stream(max_buffer_size: int = 0) -> tuple[StreamWriter[T], StreamReader[T]]:
    """Create a connected (writer, reader) stream pair.

    Args:
        max_buffer_size: Maximum items buffered. 0 means use a small buffer (1).
    """
    # asyncio.Queue(maxsize=0) means unlimited, but we want rendezvous-like behavior
    # Use maxsize=1 for bounded behavior similar to anyio's max_buffer_size=0
    maxsize = max(max_buffer_size, 1)
    queue: asyncio.Queue[T | object] = asyncio.Queue(maxsize=maxsize)
    return StreamWriter(queue), StreamReader(queue)
