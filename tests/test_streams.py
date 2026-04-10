"""Tests for aiohttp_mcp.protocol.streams — async memory stream primitives."""

import asyncio
from typing import Any

import pytest

from aiohttp_mcp.protocol.streams import (
    ClosedStreamError,
    StreamReader,
    StreamWriter,
    create_memory_stream,
)


async def test_send_and_receive() -> None:
    writer: StreamWriter[str]
    reader: StreamReader[str]
    writer, reader = create_memory_stream(0)
    await writer.send("hello")
    assert await reader.receive() == "hello"
    await writer.aclose()
    await reader.aclose()


async def test_multiple_items_in_order() -> None:
    writer: StreamWriter[int]
    reader: StreamReader[int]
    writer, reader = create_memory_stream(0)
    for i in range(5):
        await writer.send(i)
    for i in range(5):
        assert await reader.receive() == i
    await writer.aclose()
    await reader.aclose()


async def test_send_after_close_raises() -> None:
    writer: StreamWriter[Any]
    reader: StreamReader[Any]
    writer, reader = create_memory_stream(0)
    await writer.aclose()
    with pytest.raises(ClosedStreamError, match="Stream writer is closed"):
        await writer.send("x")
    await reader.aclose()


async def test_receive_after_close_raises() -> None:
    writer: StreamWriter[Any]
    reader: StreamReader[Any]
    writer, reader = create_memory_stream(0)
    await reader.aclose()
    with pytest.raises(ClosedStreamError, match="Stream reader is closed"):
        await reader.receive()
    await writer.aclose()


async def test_receive_closed_by_writer() -> None:
    writer: StreamWriter[Any]
    reader: StreamReader[Any]
    writer, reader = create_memory_stream(0)
    await writer.aclose()
    with pytest.raises(ClosedStreamError, match="Stream was closed by writer"):
        await reader.receive()


async def test_async_iteration() -> None:
    writer: StreamWriter[str]
    reader: StreamReader[str]
    writer, reader = create_memory_stream(0)
    await writer.send("a")
    await writer.send("b")
    await writer.aclose()

    items: list[str] = []
    async for item in reader:
        items.append(item)
    assert items == ["a", "b"]


async def test_async_iteration_stops_on_close() -> None:
    writer: StreamWriter[str]
    reader: StreamReader[str]
    writer, reader = create_memory_stream(0)
    await writer.aclose()
    items: list[str] = []
    async for item in reader:
        items.append(item)
    assert items == []


async def test_writer_aclose_timeout_on_full_queue() -> None:
    """Writer aclose handles TimeoutError when the queue is full and no reader drains it."""
    queue: asyncio.Queue[str | object] = asyncio.Queue(maxsize=1)
    writer: StreamWriter[str] = StreamWriter(queue)
    # Fill the queue so the sentinel can't be placed
    await queue.put("block")
    # aclose should not raise — it catches the TimeoutError internally
    await writer.aclose()
    assert writer._closed is True


async def test_create_memory_stream_with_buffer() -> None:
    writer: StreamWriter[str]
    reader: StreamReader[str]
    writer, reader = create_memory_stream(2)
    # Should be able to send 2 items without blocking
    await writer.send("a")
    await writer.send("b")
    assert await reader.receive() == "a"
    assert await reader.receive() == "b"
    await writer.aclose()
    await reader.aclose()


async def test_writer_double_close_is_safe() -> None:
    writer: StreamWriter[Any]
    reader: StreamReader[Any]
    writer, reader = create_memory_stream(0)
    await writer.aclose()
    # Second close should be a no-op
    await writer.aclose()
    assert writer._closed is True
    await reader.aclose()


async def test_reader_double_close_is_safe() -> None:
    writer: StreamWriter[Any]
    reader: StreamReader[Any]
    writer, reader = create_memory_stream(0)
    await reader.aclose()
    await reader.aclose()
    assert reader._closed is True
    await writer.aclose()
