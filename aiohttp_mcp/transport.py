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
from pydantic import ValidationError

__all__ = ["EventSourceResponse", "SSEConnection", "SSEServerTransport"]

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Event types for SSE."""

    ENDPOINT = "endpoint"
    MESSAGE = "message"


@dataclass
class Event:
    """A class to represent an event for SSE."""

    event_type: EventType
    data: str


T = TypeVar("T", covariant=True)


class Stream(Generic[T]):
    """A pair of connected streams for bidirectional communication."""

    def __init__(self, reader: MemoryObjectReceiveStream[T], writer: MemoryObjectSendStream[T]):
        self.reader = reader
        self.writer = writer

    @classmethod
    def create(cls, max_buffer_size: int = 0) -> "Stream[T]":
        """Create a new stream pair."""
        writer, reader = anyio.create_memory_object_stream[T](max_buffer_size)
        return cls(reader=reader, writer=writer)

    async def close(self) -> None:
        """Close both streams."""
        await self.reader.aclose()
        await self.writer.aclose()


@dataclass
class SSEConnection:
    """A class to manage the connection for SSE."""

    read_stream: MemoryObjectReceiveStream[types.JSONRPCMessage | Exception]
    write_stream: MemoryObjectSendStream[types.JSONRPCMessage | Exception]
    request: web.Request
    response: EventSourceResponse


class MessageConverter:
    """Converts between different message formats."""

    @staticmethod
    def to_string(msg: types.JSONRPCMessage | Exception) -> str:
        """Convert message to string."""
        if isinstance(msg, types.JSONRPCMessage):
            return msg.model_dump_json(by_alias=True, exclude_none=True)
        return str(msg)

    @staticmethod
    def to_event(msg: types.JSONRPCMessage | Exception, event_type: EventType = EventType.MESSAGE) -> Event:
        """Convert message to SSE event."""
        data = MessageConverter.to_string(msg)
        return Event(event_type=event_type, data=data)

    @staticmethod
    def from_json(json_data: str) -> types.JSONRPCMessage:
        """Convert JSON string to JSONRPCMessage."""
        return types.JSONRPCMessage.model_validate_json(json_data)


class SSEServerTransport:
    _out_stream_writers: dict[UUID, MemoryObjectSendStream[types.JSONRPCMessage | Exception]]

    def __init__(self, message_path: str, send_timeout: float | None = None) -> None:
        super().__init__()
        self._message_path = message_path
        self._send_timeout = send_timeout
        self._out_stream_writers: dict[uuid.UUID, MemoryObjectSendStream[types.JSONRPCMessage | Exception]] = {}

    @staticmethod
    def _ensure_string(msg: types.JSONRPCMessage | Exception) -> str:
        """Convert message to string."""
        if isinstance(msg, types.JSONRPCMessage):
            return msg.model_dump_json(by_alias=True, exclude_none=True)
        return str(msg)

    def _create_session_uri(self, session_id: UUID) -> str:
        """Create a session URI from a session ID."""
        return f"{quote(self._message_path)}?session_id={session_id.hex}"

    @asynccontextmanager
    async def connect_sse(self, request: web.Request) -> AsyncIterator[SSEConnection]:
        logger.info("Setting up SSE connection")

        # Input and output streams
        in_stream = Stream[types.JSONRPCMessage | Exception].create()
        out_stream = Stream[types.JSONRPCMessage | Exception].create()

        # Internal event stream for SSE
        sse_stream = Stream[Event].create()

        # Initialize the SSE session
        session_id = uuid4()
        session_uri = self._create_session_uri(session_id)
        logger.debug("Session URI: %s", session_uri)

        # Save the out stream writer for this session to use in handle_post_message
        self._out_stream_writers[session_id] = out_stream.writer
        logger.debug("Created new session with ID: %s", session_id)

        async def _in_stream_processor() -> None:
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

        async def _response_processor() -> None:
            """Redirect messages from the SSE stream to the response."""
            logger.debug("Starting SSE stream processor")
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

                tg.start_soon(cancel_on_finish, _response_processor)
                tg.start_soon(cancel_on_finish, _in_stream_processor)

                try:
                    yield SSEConnection(
                        read_stream=out_stream.reader,
                        write_stream=in_stream.writer,
                        request=request,
                        response=response,
                    )
                finally:
                    # Clean up session when connection is closed
                    del self._out_stream_writers[session_id]
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

        out_stream_writers = self._out_stream_writers.get(session_id)
        if not out_stream_writers:
            logger.warning("Could not find session for ID: %s", session_id)
            return web.Response(text="Could not find session", status=404)

        body = await request.text()
        logger.debug("Received JSON: %s", body)

        try:
            message = MessageConverter.from_json(body)
            logger.debug("Validated client message: %s", message)
        except ValidationError as err:
            logger.error("Failed to parse message: %s", err)
            await out_stream_writers.send(err)
            return web.Response(text="Could not parse message", status=400)

        logger.debug("Sending message to writer: %s", message)
        await out_stream_writers.send(message)
        return web.Response(text="Accepted", status=202)
