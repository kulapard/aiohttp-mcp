import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
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


@dataclass
class SSEConnection:
    """A class to manage the connection for SSE."""

    read_stream: MemoryObjectReceiveStream[types.JSONRPCMessage | Exception]
    write_stream: MemoryObjectSendStream[types.JSONRPCMessage | Exception]
    request: web.Request
    response: EventSourceResponse


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

    @asynccontextmanager
    async def connect_sse(self, request: web.Request) -> AsyncIterator[SSEConnection]:
        logger.info("Setting up SSE connection")

        # Create memory object streams
        # Input and output streams
        in_stream_writer, in_stream_reader = anyio.create_memory_object_stream[types.JSONRPCMessage | Exception](0)
        out_stream_writer, out_stream_reader = anyio.create_memory_object_stream[types.JSONRPCMessage | Exception](0)

        # Internal streams
        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[Event](0)

        # Initialize the SSE session
        session_id = uuid4()
        session_uri = f"{quote(self._message_path)}?session_id={session_id.hex}"
        logger.debug("Session URI: %s", session_uri)

        # Save the out stream writer for this session to use in handle_post_message
        self._out_stream_writers[session_id] = out_stream_writer
        logger.debug("Created new session with ID: %s", session_id)

        async def _in_stream_processor() -> None:
            """Redirect messages from the input stream to the SSE stream."""
            logger.debug("Starting SSE writer")
            async with sse_stream_writer, in_stream_reader:
                logger.debug("Sending initial endpoint event on startup")
                event = Event(event_type=EventType.ENDPOINT, data=session_uri)
                await sse_stream_writer.send(event)
                logger.debug("Sent event: %s", event)

                async for msg in in_stream_reader:
                    data = self._ensure_string(msg)
                    event = Event(event_type=EventType.MESSAGE, data=data)
                    logger.debug("Sending event: %s", msg)
                    await sse_stream_writer.send(event)
                    logger.debug("Sent event: %s", event)

        async def _response_writer() -> None:
            """Redirect messages from the SSE stream to the response."""
            logger.debug("Starting SSE stream processor")
            async for event in sse_stream_reader:
                logger.debug("Got event to send: %s", event)
                with anyio.move_on_after(self._send_timeout) as cancel_scope:
                    logger.debug("Sending event via SSE: %s", event)
                    await response.send(data=event.data, event=event.event_type)
                    logger.debug("Sent event via SSE: %s", event)

                if cancel_scope and cancel_scope.cancel_called:
                    await sse_stream_reader.aclose()
                    raise TimeoutError()

        async with sse_response(request) as response:
            async with anyio.create_task_group() as tg:
                # https://trio.readthedocs.io/en/latest/reference-core.html#custom-supervisors
                async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                    await coro()
                    tg.cancel_scope.cancel()

                tg.start_soon(cancel_on_finish, _response_writer)
                tg.start_soon(cancel_on_finish, _in_stream_processor)

                yield SSEConnection(
                    read_stream=out_stream_reader,
                    write_stream=in_stream_writer,
                    request=request,
                    response=response,
                )

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

        out_stream = self._out_stream_writers.get(session_id)
        if not out_stream:
            logger.warning("Could not find session for ID: %s", session_id)
            return web.Response(text="Could not find session", status=404)

        body = await request.text()
        logger.debug("Received JSON: %s", body)

        try:
            message = types.JSONRPCMessage.model_validate_json(body)
            logger.debug("Validated client message: %s", message)
        except ValidationError as err:
            logger.error("Failed to parse message: %s", err)
            await out_stream.send(err)
            return web.Response(text="Could not parse message", status=400)

        logger.debug("Sending message to writer: %s", message)
        await out_stream.send(message)
        return web.Response(text="Accepted", status=202)
