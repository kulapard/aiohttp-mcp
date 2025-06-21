import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar
from urllib.parse import quote
from uuid import UUID, uuid4

import anyio
import mcp.types as types
from aiohttp import web
from aiohttp_sse import EventSourceResponse, sse_response
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from pydantic import ValidationError

__all__ = [
    "Event",
    "EventSourceResponse",
    "EventType",
    "MessageConverter",
    "SSEConnection",
    "SSEServerTransport",
    "Stream",
]

logger = logging.getLogger(__name__)


class EventType(str, Enum):  # for Py10 compatibility
    """Event types for SSE."""

    ENDPOINT = "endpoint"
    MESSAGE = "message"

    def __str__(self) -> str:  # for Py11+ compatibility
        return self.value


@dataclass
class Event:
    """A class to represent an event for SSE."""

    event_type: EventType
    data: str
    event_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SSEConnection:
    """A class to manage the connection for SSE."""

    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception]
    write_stream: MemoryObjectSendStream[SessionMessage | Exception]
    request: web.Request
    response: EventSourceResponse


T = TypeVar("T")


class Stream(Generic[T]):
    """A pair of connected streams for bidirectional communication."""

    __slots__ = ("_reader", "_writer")

    def __init__(self, reader: MemoryObjectReceiveStream[T], writer: MemoryObjectSendStream[T]):
        self._reader = reader
        self._writer = writer

    @property
    def reader(self) -> MemoryObjectReceiveStream[T]:
        """Return the reader stream."""
        return self._reader

    @property
    def writer(self) -> MemoryObjectSendStream[T]:
        """Return the writer stream."""
        return self._writer

    @classmethod
    def create(cls, max_buffer_size: int = 0) -> "Stream[T]":
        """Create a new Stream instance.

        Parameters:
            max_buffer_size: Number of items held in the buffer until ``send()`` starts blocking

        Returns:
            A new Stream instance
        """
        writer, reader = anyio.create_memory_object_stream[T](max_buffer_size)
        return cls(reader=reader, writer=writer)

    async def close(self) -> None:
        """Close both streams."""
        await self._reader.aclose()
        await self._writer.aclose()


class MessageConverter:
    """Converts between different message formats."""

    @staticmethod
    def to_string(session_message: SessionMessage | Exception) -> str:
        """Convert session_message to string."""
        if isinstance(session_message, SessionMessage):
            return session_message.message.model_dump_json(by_alias=True, exclude_none=True)
        return str(session_message)

    @staticmethod
    def to_event(session_message: SessionMessage | Exception, event_type: EventType = EventType.MESSAGE) -> Event:
        """Convert session_message to SSE event."""
        data = MessageConverter.to_string(session_message)
        return Event(event_type=event_type, data=data)

    @staticmethod
    def from_json(json_data: str) -> types.JSONRPCMessage:
        """Convert JSON string to JSONRPCMessage."""
        return types.JSONRPCMessage.model_validate_json(json_data)


class SSEServerTransport:
    __slots__ = ("_message_path", "_out_streams", "_send_timeout")

    def __init__(self, message_path: str, send_timeout: float | None = None) -> None:
        self._message_path = message_path
        self._send_timeout = send_timeout
        self._out_streams: dict[uuid.UUID, Stream[SessionMessage | Exception]] = {}

    def _create_session_uri(self, session_id: UUID) -> str:
        """Create a session URI from a session ID."""
        return f"{quote(self._message_path)}?session_id={session_id.hex}"

    @asynccontextmanager
    async def connect_sse(self, request: web.Request) -> AsyncIterator[SSEConnection]:
        logger.info("Setting up SSE connection")

        # Input and output streams
        in_stream = Stream[SessionMessage | Exception].create()
        out_stream = Stream[SessionMessage | Exception].create()

        # Internal event stream for SSE
        sse_stream = Stream[Event].create()

        # Initialize the SSE session
        session_id = uuid4()
        session_uri = self._create_session_uri(session_id)
        logger.debug("Session URI: %s", session_uri)

        # Save the out stream writer for this session to use in handle_post_message
        self._out_streams[session_id] = out_stream
        logger.debug("Created new session with ID: %s", session_id)

        async def _process_input_stream() -> None:
            """Redirect messages from the input stream to the SSE stream."""
            logger.debug("Starting IN stream processor")
            async with sse_stream.writer, in_stream.reader:
                logger.debug("Sending initial endpoint event on startup")
                endpoint_event = Event(event_type=EventType.ENDPOINT, data=session_uri)
                await sse_stream.writer.send(endpoint_event)
                logger.debug("Sent event: %s", endpoint_event)

                async for msg in in_stream.reader:
                    event = MessageConverter.to_event(msg)
                    logger.debug("Sending event: %s", msg)
                    await sse_stream.writer.send(event)
                    logger.debug("Sent event: %s", event)

        async def _process_response() -> None:
            """Redirect messages from the SSE stream to the response."""
            logger.debug("Starting SSE stream processor")
            async with sse_stream.reader:
                async for event in sse_stream.reader:
                    logger.debug("Got event to send: %s", event)
                    with anyio.move_on_after(self._send_timeout) as cancel_scope:
                        logger.debug("Sending event via SSE: %s", event)
                        await response.send(data=event.data, event=event.event_type)
                        logger.debug("Sent event via SSE: %s", event)

                    if cancel_scope and cancel_scope.cancel_called:
                        await sse_stream.close()
                        raise TimeoutError()

        async with sse_response(request) as response:
            async with anyio.create_task_group() as tg:
                # https://trio.readthedocs.io/en/latest/reference-core.html#custom-supervisors
                async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                    await coro()
                    tg.cancel_scope.cancel()

                tg.start_soon(cancel_on_finish, _process_response)
                tg.start_soon(cancel_on_finish, _process_input_stream)

                try:
                    yield SSEConnection(
                        read_stream=out_stream.reader,
                        write_stream=in_stream.writer,
                        request=request,
                        response=response,
                    )
                finally:
                    # Clean up session when connection is closed
                    await out_stream.close()
                    del self._out_streams[session_id]
                    logger.debug("Removed session with ID: %s", session_id)

    async def handle_post_message(self, request: web.Request) -> web.Response:
        logger.debug("Handling POST message")
        session_id_param = request.query.get("session_id")
        if session_id_param is None:
            logger.warning("Received request without session ID")
            return web.Response(text="No session ID provided", status=400)

        try:
            session_id = UUID(hex=session_id_param)
            logger.debug("Parsed session ID: %s", session_id)
        except ValueError:
            logger.warning("Received invalid session ID: %s", session_id_param)
            return web.Response(text="Invalid session ID", status=400)

        out_stream = self._out_streams.get(session_id)
        if not out_stream:
            logger.warning("Could not find session for ID: %s", session_id)
            return web.Response(text="Could not find session", status=404)

        body = await request.text()
        logger.debug("Received JSON: %s", body)

        try:
            message = MessageConverter.from_json(body)
            logger.debug("Validated client message: %s", message)
        except ValidationError as err:
            logger.error("Failed to parse message: %s", err)
            await out_stream.writer.send(err)
            return web.Response(text="Could not parse message", status=400)

        metadata = ServerMessageMetadata(request_context=request)
        session_message = SessionMessage(message, metadata=metadata)
        logger.debug("Sending message to writer: %s", message)
        await out_stream.writer.send(session_message)
        return web.Response(text="Accepted", status=202)
