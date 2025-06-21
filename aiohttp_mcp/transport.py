import json
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from typing import TYPE_CHECKING, Generic, TypeVar
from urllib.parse import quote
from uuid import UUID, uuid4

import anyio
import mcp.types as types
from aiohttp import web
from aiohttp_sse import EventSourceResponse, sse_response
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

# Removed transport security imports as per user request
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    PARSE_ERROR,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
)
from pydantic import ValidationError

if TYPE_CHECKING:
    from .core import AiohttpMCP

__all__ = [
    "Event",
    "EventSourceResponse",
    "EventType",
    "MessageConverter",
    "SSEConnection",
    "SSEServerTransport",
    "StatelessStreamableHTTPTransport",
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


# Constants for streamable transport
MAXIMUM_MESSAGE_SIZE = 4 * 1024 * 1024  # 4MB
MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"
CONTENT_TYPE_JSON = "application/json"


class StatelessStreamableHTTPTransport:
    """
    Stateless HTTP transport for MCP.

    Handles JSON-RPC messages in HTTP POST requests with JSON responses.
    No session management - each request is processed independently.
    """

    def __init__(self, mcp: "AiohttpMCP") -> None:
        """
        Initialize a new stateless streamable HTTP transport.

        Args:
            mcp: The MCP server instance for processing requests.
        """
        self._mcp = mcp

    def _create_error_response(
        self,
        error_message: str,
        status_code: HTTPStatus,
        error_code: int = INVALID_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> web.Response:
        """Create an error response with JSON-RPC error format."""
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)

        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",
            error=ErrorData(
                code=error_code,
                message=error_message,
            ),
        )

        return web.Response(
            text=error_response.model_dump_json(by_alias=True, exclude_none=True),
            status=status_code.value,
            headers=response_headers,
        )

    def _create_json_response(
        self,
        response_message: JSONRPCMessage | None,
        status_code: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> web.Response:
        """Create a JSON response from a JSONRPCMessage."""
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)

        response_text = response_message.model_dump_json(by_alias=True, exclude_none=True) if response_message else None

        return web.Response(
            text=response_text,
            status=status_code.value,
            headers=response_headers,
        )

    def _check_content_type(self, request: web.Request) -> bool:
        """Check if the request has the correct Content-Type."""
        content_type = request.headers.get("content-type", "")
        content_type_parts = [part.strip() for part in content_type.split(";")[0].split(",")]
        return any(part == CONTENT_TYPE_JSON for part in content_type_parts)

    def _validate_protocol_version(self, request: web.Request) -> str | None:
        """Validate the protocol version header and return error message if invalid."""
        protocol_version = request.headers.get(MCP_PROTOCOL_VERSION_HEADER)

        if protocol_version is None:
            protocol_version = "2024-11-05"  # Default version

        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            supported_versions = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
            return f"Unsupported protocol version: {protocol_version}. Supported versions: {supported_versions}"

        return None

    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle HTTP requests for the stateless transport."""
        # Security validation removed as per user request

        if request.method == "POST":
            return await self._handle_post_request(request)
        elif request.method in ("GET", "DELETE"):
            return self._create_error_response(
                "Method Not Allowed: Stateless transport only supports POST requests",
                HTTPStatus.METHOD_NOT_ALLOWED,
                headers={"Allow": "POST"},
            )
        else:
            return self._create_error_response(
                "Method Not Allowed",
                HTTPStatus.METHOD_NOT_ALLOWED,
                headers={"Allow": "POST"},
            )

    async def _handle_post_request(self, request: web.Request) -> web.Response:
        """Handle POST requests containing JSON-RPC messages."""
        try:
            # Validate protocol version
            if error_msg := self._validate_protocol_version(request):
                return self._create_error_response(error_msg, HTTPStatus.BAD_REQUEST)

            # Validate Content-Type
            if not self._check_content_type(request):
                return self._create_error_response(
                    "Unsupported Media Type: Content-Type must be application/json",
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )

            # Parse the body
            body = await request.text()
            if len(body.encode()) > MAXIMUM_MESSAGE_SIZE:
                return self._create_error_response(
                    "Payload Too Large: Message exceeds maximum size",
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )

            try:
                raw_message = json.loads(body)
            except json.JSONDecodeError as e:
                return self._create_error_response(f"Parse error: {e!s}", HTTPStatus.BAD_REQUEST, PARSE_ERROR)

            try:
                message = JSONRPCMessage.model_validate(raw_message)
            except ValidationError as e:
                return self._create_error_response(
                    f"Validation error: {e!s}",
                    HTTPStatus.BAD_REQUEST,
                    INVALID_PARAMS,
                )

            # For notifications (no response expected), return 202 Accepted
            if not isinstance(message.root, JSONRPCRequest):
                return self._create_json_response(None, HTTPStatus.ACCEPTED)

            # For requests, we need to process them and return the response
            # This will be handled by the calling code that sets up the transport
            # For now, return a placeholder response
            return self._create_error_response(
                "Not Implemented: Request processing not yet implemented",
                HTTPStatus.NOT_IMPLEMENTED,
                INTERNAL_ERROR,
            )

        except Exception as err:
            logger.exception("Error handling POST request")
            return self._create_error_response(
                f"Internal Server Error: {err!s}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )

    @asynccontextmanager
    async def connect(
        self,
    ) -> AsyncIterator[
        tuple[
            MemoryObjectReceiveStream[SessionMessage | Exception],
            MemoryObjectSendStream[SessionMessage],
        ]
    ]:
        """Context manager that provides read and write streams for a connection."""
        read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

        try:
            yield read_stream, write_stream
        finally:
            await read_stream_writer.aclose()
            await read_stream.aclose()
            await write_stream_reader.aclose()
            await write_stream.aclose()

    async def handle_mcp_request(self, request: web.Request) -> web.Response:
        """Handle streamable HTTP requests with full MCP server integration."""
        return await self._process_streamable_request(request)

    async def _process_streamable_request(self, request: web.Request) -> web.Response:
        """Process a stateless request through the MCP server."""
        async with self.connect() as (read_stream, write_stream):
            try:
                return await self._run_streamable_session(request, read_stream, write_stream)
            except Exception as e:
                logger.exception("Error processing streamable request")
                return self._create_streamable_error_response(f"Error processing request: {e!s}")

    async def _run_streamable_session(
        self,
        request: web.Request,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
    ) -> web.Response:
        """Run the MCP server session for a streamable request."""
        async with anyio.create_task_group() as tg:
            response_holder: dict[str, web.Response | Exception | None] = {"response": None, "error": None}

            async def run_server() -> None:
                try:
                    await self._mcp.server.run(
                        read_stream=read_stream,
                        write_stream=write_stream,
                        initialization_options=self._mcp.server.create_initialization_options(),
                        raise_exceptions=True,
                    )
                except Exception as e:
                    response_holder["error"] = e
                    tg.cancel_scope.cancel()

            async def handle_http() -> None:
                try:
                    response = await self.handle_request(request)
                    response_holder["response"] = response
                    tg.cancel_scope.cancel()
                except Exception as e:
                    response_holder["error"] = e
                    tg.cancel_scope.cancel()

            tg.start_soon(run_server)
            tg.start_soon(handle_http)

        return self._handle_streamable_response(response_holder)

    def _handle_streamable_response(self, response_holder: dict[str, web.Response | Exception | None]) -> web.Response:
        """Handle the response from a streamable request."""
        if response_holder["error"]:
            logger.exception("Error in streamable request processing")
            return self._create_streamable_error_response(f"Server error: {response_holder['error']!s}")

        response = response_holder["response"]
        if isinstance(response, web.Response):
            return response

        return self._create_streamable_error_response("No response generated")

    def _create_streamable_error_response(self, message: str) -> web.Response:
        """Create an error response for streamable transport."""
        return self._create_error_response(message, HTTPStatus.INTERNAL_SERVER_ERROR)
