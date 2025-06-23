"""
StreamableHTTP Server Transport Module

This module implements the StreamableHTTP transport layer for MCP servers.
It provides FastMCP-compatible session management with support for both
stateful and stateless operation modes.

The transport handles bidirectional JSON-RPC communication using:
- HTTP POST requests for client-to-server messages
- Server-Sent Events (SSE) streams for server-to-client messages
- Session management with optional resumability via event stores
- Support for both streaming responses and direct JSON responses

Features:
- Session ID-based request routing and validation
- Protocol version negotiation and validation
- Event replay for resumable connections
- Memory stream management for concurrent request handling
- Comprehensive error handling with proper HTTP status codes
"""

import json
import logging
import re
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from http import HTTPStatus

import anyio
from aiohttp import web
from aiohttp_sse import sse_response
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server.streamable_http import EventMessage, EventStore
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
    JSONRPCResponse,
    RequestId,
)
from pydantic import ValidationError

from aiohttp_mcp.transport import Event, EventType

logger = logging.getLogger(__name__)

# TODO: Import from mcp.types when available
DEFAULT_NEGOTIATED_VERSION = "2025-03-26"

# Maximum size for incoming messages
MAXIMUM_MESSAGE_SIZE = 4 * 1024 * 1024  # 4MB

# Header names
MCP_SESSION_ID_HEADER = "mcp-session-id"
MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"
LAST_EVENT_ID_HEADER = "last-event-id"

# Content types
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_SSE = "text/event-stream"

# Special key for the standalone GET stream
GET_STREAM_KEY = "_GET_stream"

# Session ID validation pattern (visible ASCII characters ranging from 0x21 to 0x7E)
# Pattern ensures entire string contains only valid characters by using ^ and $ anchors
SESSION_ID_PATTERN = re.compile(r"^[\x21-\x7E]+$")


class StreamableHTTPServerTransport:
    """
    FastMCP-compatible HTTP server transport with advanced session management.

    This transport provides a complete HTTP-based communication layer for MCP servers,
    supporting both stateful and stateless operation modes. It implements the
    StreamableHTTP protocol specification with comprehensive session management,
    event streaming, and resumability features.

    Key Features:
    - **Session Management**: Optional session ID-based request routing
    - **Dual Response Modes**: SSE streaming or direct JSON responses
    - **Resumability**: Event replay via configurable event stores
    - **Protocol Compliance**: Full MCP protocol version negotiation
    - **Concurrent Handling**: Memory streams for multiple simultaneous requests
    - **Error Resilience**: Comprehensive error handling and recovery

    Transport Modes:
    - **Streaming Mode** (default): Uses SSE for real-time server-to-client communication
    - **JSON Mode**: Returns direct JSON responses for request-response patterns

    Supported HTTP Methods:
    - **GET**: Establishes SSE streams for server-initiated messages
    - **POST**: Handles client JSON-RPC messages with streaming or JSON responses
    - **DELETE**: Terminates sessions explicitly (when session management enabled)

    Session Management:
    - Sessions are identified by the 'mcp-session-id' header
    - Session IDs must contain only visible ASCII characters (0x21-0x7E)
    - Sessions maintain state between requests for resumable connections
    - Optional session termination via DELETE requests

    Resumability:
    - When an event store is configured, events are persisted
    - Clients can reconnect using 'Last-Event-ID' header to replay missed events
    - Event IDs are generated and tracked automatically
    - Seamless reconnection and message continuity
    """

    # Server notification streams for POST requests as well as standalone SSE stream
    _read_stream_writer: MemoryObjectSendStream[SessionMessage | Exception] | None = None
    _read_stream: MemoryObjectReceiveStream[SessionMessage | Exception] | None = None
    _write_stream: MemoryObjectSendStream[SessionMessage] | None = None
    _write_stream_reader: MemoryObjectReceiveStream[SessionMessage] | None = None

    def __init__(
        self,
        mcp_session_id: str | None,
        is_json_response_enabled: bool = False,
        event_store: EventStore | None = None,
    ) -> None:
        """
        Initialize a new StreamableHTTP server transport.

        Args:
            mcp_session_id: Optional session identifier for this connection.
                            Must contain only visible ASCII characters (0x21-0x7E).
            is_json_response_enabled: If True, return JSON responses for requests
                                    instead of SSE streams. Default is False.
            event_store: Event store for resumability support. If provided,
                        resumability will be enabled, allowing clients to
                        reconnect and resume messages.

        Raises:
            ValueError: If the session ID contains invalid characters.
        """
        if mcp_session_id is not None and not SESSION_ID_PATTERN.fullmatch(mcp_session_id):
            raise ValueError("Session ID must only contain visible ASCII characters (0x21-0x7E)")

        self.mcp_session_id = mcp_session_id
        self.is_json_response_enabled = is_json_response_enabled
        self._event_store = event_store
        self._request_streams: dict[
            RequestId,
            tuple[
                MemoryObjectSendStream[EventMessage],
                MemoryObjectReceiveStream[EventMessage],
            ],
        ] = {}
        self._terminated = False

    def _create_error_response(
        self,
        error_message: str,
        status_code: HTTPStatus,
        error_code: int = INVALID_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> web.Response:
        """
        Create a properly formatted JSON-RPC error response.

        Args:
            error_message: Human-readable error description
            status_code: HTTP status code for the response
            error_code: JSON-RPC error code (default: INVALID_REQUEST)
            headers: Additional HTTP headers to include

        Returns:
            web.Response with JSON-RPC error format and appropriate headers
        """
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)

        if self.mcp_session_id:
            response_headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        # Return a properly formatted JSON error response
        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",  # We don't have a request ID for general errors
            error=ErrorData(
                code=error_code,
                message=error_message,
            ),
        )

        return web.Response(
            body=error_response.model_dump_json(by_alias=True, exclude_none=True),
            status=status_code,
            headers=response_headers,
        )

    def _create_json_response(
        self,
        response_message: JSONRPCMessage | None,
        status_code: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> web.Response:
        """
        Create an HTTP response with JSON-RPC message content.

        Args:
            response_message: JSON-RPC message to serialize, or None for empty response
            status_code: HTTP status code (default: 200 OK)
            headers: Additional HTTP headers to include

        Returns:
            web.Response with serialized JSON-RPC content and session headers
        """
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)

        if self.mcp_session_id:
            response_headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        return web.Response(
            body=response_message.model_dump_json(by_alias=True, exclude_none=True) if response_message else None,
            status=status_code,
            headers=response_headers,
        )

    def _get_session_id(self, request: web.Request) -> str | None:
        """
        Extract the MCP session ID from request headers.

        Args:
            request: HTTP request object

        Returns:
            Session ID string if present, None otherwise
        """
        return request.headers.get(MCP_SESSION_ID_HEADER)

    def _create_event_data(self, event_message: EventMessage) -> Event:
        """
        Convert an EventMessage to SSE Event format.

        Args:
            event_message: Message with optional event ID for SSE transmission

        Returns:
            Event object suitable for Server-Sent Events streaming
        """
        data = event_message.message.model_dump_json(by_alias=True, exclude_none=True)

        if event_message.event_id:
            # If an event ID was provided, include it
            return Event(data=data, event_type=EventType.MESSAGE, event_id=event_message.event_id)
        else:
            # If no event ID, just return the message data
            return Event(data=data, event_type=EventType.MESSAGE)

    async def _clean_up_memory_streams(self, request_id: RequestId) -> None:
        """
        Safely close and remove memory streams for a specific request.

        Args:
            request_id: Identifier of the request whose streams should be cleaned up
        """
        if request_id in self._request_streams:
            try:
                # Close the request stream
                await self._request_streams[request_id][0].aclose()
                await self._request_streams[request_id][1].aclose()
            except Exception as e:
                logger.debug("Error closing memory streams: %s", e)
            finally:
                # Remove the request stream from the mapping
                self._request_streams.pop(request_id, None)

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        """
        Main entry point for processing HTTP requests to the transport.

        Routes requests to appropriate handlers based on HTTP method:
        - GET: Establish SSE streams or replay events
        - POST: Process JSON-RPC messages
        - DELETE: Terminate sessions
        - Others: Return Method Not Allowed

        Args:
            request: HTTP request to process

        Returns:
            HTTP response (streaming or JSON depending on configuration)

        Raises:
            ValueError: If transport is not properly initialized
        """
        if self._terminated:
            # If the session has been terminated, return 404 Not Found
            return self._create_error_response(
                "Not Found: Session has been terminated",
                HTTPStatus.NOT_FOUND,
            )

        if request.method == "POST":
            return await self._handle_post_request(request)
        elif request.method == "GET":
            return await self._handle_get_request(request)
        elif request.method == "DELETE":
            return await self._handle_delete_request(request)
        else:
            return await self._handle_unsupported_request(request)

    def _check_accept_headers(self, request: web.Request) -> tuple[bool, bool]:
        """
        Validate Accept headers for required content types.

        Args:
            request: HTTP request to check

        Returns:
            Tuple of (accepts_json, accepts_sse) indicating support for each content type
        """
        accept_header = request.headers.get("accept", "")
        accept_types = [media_type.strip() for media_type in accept_header.split(",")]

        has_json = any(media_type.startswith(CONTENT_TYPE_JSON) for media_type in accept_types)
        has_sse = any(media_type.startswith(CONTENT_TYPE_SSE) for media_type in accept_types)

        return has_json, has_sse

    def _check_content_type(self, request: web.Request) -> bool:
        """
        Validate that request Content-Type is application/json.

        Args:
            request: HTTP request to validate

        Returns:
            True if Content-Type is acceptable, False otherwise
        """
        content_type = request.headers.get("content-type", "")
        content_type_parts = [part.strip() for part in content_type.split(";")[0].split(",")]

        return any(part == CONTENT_TYPE_JSON for part in content_type_parts)

    async def _handle_post_request(self, request: web.Request) -> web.StreamResponse:  # noqa: C901
        """
        Process HTTP POST requests containing JSON-RPC messages.

        This method handles the core message processing workflow:
        1. Validates Accept and Content-Type headers
        2. Parses and validates JSON-RPC message format
        3. Performs session and protocol version validation
        4. Routes messages based on type (request, notification, response)
        5. Returns appropriate response (SSE stream or JSON)

        For JSON-RPC requests, creates dedicated streams for responses.
        For notifications, returns immediate 202 Accepted status.

        Args:
            request: HTTP POST request with JSON-RPC message body

        Returns:
            StreamResponse (SSE) or Response (JSON) based on configuration
        """
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError("No read stream writer available. Ensure connect() is called first.")
        try:
            # Check Accept headers
            has_json, has_sse = self._check_accept_headers(request)
            if not (has_json and has_sse):
                return self._create_error_response(
                    ("Not Acceptable: Client must accept both application/json and text/event-stream"),
                    HTTPStatus.NOT_ACCEPTABLE,
                )

            # Validate Content-Type
            if not self._check_content_type(request):
                return self._create_error_response(
                    "Unsupported Media Type: Content-Type must be application/json",
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )

            # Parse the body - only read it once
            body = await request.text()
            if len(body) > MAXIMUM_MESSAGE_SIZE:
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

            # Check if this is an initialization request
            is_initialization_request = isinstance(message.root, JSONRPCRequest) and message.root.method == "initialize"

            if is_initialization_request:
                # Check if the server already has an established session
                if self.mcp_session_id:
                    # Check if request has a session ID
                    request_session_id = self._get_session_id(request)

                    # If request has a session ID but doesn't match, return 404
                    if request_session_id and request_session_id != self.mcp_session_id:
                        return self._create_error_response(
                            "Not Found: Invalid or expired session ID",
                            HTTPStatus.NOT_FOUND,
                        )

            elif error_response := await self._validate_request_headers(request):
                return error_response

            # For notifications and responses only, return 202 Accepted
            if not isinstance(message.root, JSONRPCRequest):
                # Create response object and send it
                response = self._create_json_response(
                    None,
                    HTTPStatus.ACCEPTED,
                )

                # Process the message after sending the response
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)

                return response

            # Extract the request ID outside the try block for proper scope
            request_id = str(message.root.id)
            # Register this stream for the request ID
            self._request_streams[request_id] = anyio.create_memory_object_stream[EventMessage](0)
            request_stream_reader = self._request_streams[request_id][1]

            if self.is_json_response_enabled:
                # Process the message
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)
                try:
                    # Process messages from the request-specific stream
                    # We need to collect all messages until we get a response
                    response_message = None

                    # Use similar approach to SSE writer for consistency
                    async for event_message in request_stream_reader:
                        # If it's a response, this is what we're waiting for
                        if isinstance(event_message.message.root, JSONRPCResponse | JSONRPCError):
                            response_message = event_message.message
                            break
                        # For notifications and request, keep waiting
                        else:
                            logger.debug("received: %s", event_message.message.root.method)

                    # At this point we should have a response
                    if response_message:
                        # Create JSON response
                        return self._create_json_response(response_message)
                    else:
                        # This shouldn't happen in normal operation
                        logger.error("No response message received before stream closed")
                        return self._create_error_response(
                            "Error processing request: No response received",
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                        )
                except Exception as e:
                    logger.exception("Error processing JSON response: %s", e)
                    return self._create_error_response(
                        f"Error processing request: {e!s}",
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        INTERNAL_ERROR,
                    )
                finally:
                    await self._clean_up_memory_streams(request_id)
            else:
                # Create SSE stream
                sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[Event](0)

                async def _sse_writer() -> None:
                    try:
                        async with sse_stream_writer, request_stream_reader:
                            # Process messages from the request-specific stream
                            async for event_message in request_stream_reader:
                                # Build the event data
                                event_data = self._create_event_data(event_message)
                                await sse_stream_writer.send(event_data)

                                # If response, remove from pending streams and close
                                if isinstance(
                                    event_message.message.root,
                                    JSONRPCResponse | JSONRPCError,
                                ):
                                    break
                    except Exception as e:
                        logger.exception("Error in SSE writer: %s", e)
                    finally:
                        logger.debug("Closing SSE writer")
                        await self._clean_up_memory_streams(request_id)

                # Start the SSE response (this will send headers immediately)
                try:
                    # First send the response to establish the SSE connection
                    async with sse_response(request) as sse_resp:  # Create and start EventSourceResponse
                        # SSE stream mode (original behavior)
                        # Set up headers
                        headers = {
                            "Cache-Control": "no-cache, no-transform",
                            "Connection": "keep-alive",
                            "Content-Type": CONTENT_TYPE_SSE,
                            **({MCP_SESSION_ID_HEADER: self.mcp_session_id} if self.mcp_session_id else {}),
                        }
                        sse_resp.headers.update(headers)

                        async with anyio.create_task_group() as tg:
                            # https://trio.readthedocs.io/en/latest/reference-core.html#custom-supervisors
                            async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                                await coro()
                                tg.cancel_scope.cancel()

                            async def _process_response_inner() -> None:
                                """Redirect messages from the SSE stream to the response."""
                                logger.debug("Starting SSE stream processor")
                                async with sse_stream_reader:
                                    async for event in sse_stream_reader:
                                        logger.debug("Sending event via SSE: %s", event)
                                        await sse_resp.send(data=event.data, event=event.event_type, id=event.event_id)
                                        logger.debug("Sent event via SSE: %s", event)

                            tg.start_soon(cancel_on_finish, _process_response_inner)
                            tg.start_soon(cancel_on_finish, _sse_writer)

                            # Then send the message to be processed by the server
                            metadata = ServerMessageMetadata(request_context=request)
                            session_message = SessionMessage(message, metadata=metadata)
                            await writer.send(session_message)

                        return sse_resp
                except Exception:
                    logger.exception("SSE response error")
                    await sse_stream_writer.aclose()
                    await sse_stream_reader.aclose()
                    await self._clean_up_memory_streams(request_id)
                    raise

        except Exception as err:
            logger.exception("Error handling POST request")
            response = self._create_error_response(
                f"Error handling POST request: {err}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )
            if writer:
                await writer.send(Exception(err))
            return response

    async def _handle_get_request(self, request: web.Request) -> web.StreamResponse:  # noqa: C901
        """
        Establish Server-Sent Events stream for server-initiated communication.

        GET requests create persistent SSE connections that allow the server to:
        - Send JSON-RPC requests to the client
        - Send notifications to the client
        - Maintain long-lived bidirectional communication

        Supports resumability via Last-Event-ID header for reconnection scenarios.
        Only one SSE stream is allowed per session to prevent conflicts.

        Args:
            request: HTTP GET request for SSE establishment

        Returns:
            StreamResponse with Server-Sent Events stream

        Raises:
            ValueError: If transport streams are not initialized
        """
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError("No read stream writer available. Ensure connect() is called first.")

        # Validate Accept header - must include text/event-stream
        _, has_sse = self._check_accept_headers(request)

        if not has_sse:
            return self._create_error_response(
                "Not Acceptable: Client must accept text/event-stream",
                HTTPStatus.NOT_ACCEPTABLE,
            )

        if error_response := await self._validate_request_headers(request):
            return error_response

        # Handle resumability: check for Last-Event-ID header
        if last_event_id := request.headers.get(LAST_EVENT_ID_HEADER):
            return await self._replay_events(last_event_id, request)

        headers = {
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "Content-Type": CONTENT_TYPE_SSE,
        }

        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        # Check if we already have an active GET stream
        if GET_STREAM_KEY in self._request_streams:
            return self._create_error_response(
                "Conflict: Only one SSE stream is allowed per session",
                HTTPStatus.CONFLICT,
            )

        # Create SSE stream
        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[Event](0)

        async def standalone_sse_writer() -> None:
            try:
                # Create a standalone message stream for server-initiated messages

                self._request_streams[GET_STREAM_KEY] = anyio.create_memory_object_stream[EventMessage](0)
                standalone_stream_reader = self._request_streams[GET_STREAM_KEY][1]

                async with sse_stream_writer, standalone_stream_reader:
                    # Process messages from the standalone stream
                    async for event_message in standalone_stream_reader:
                        # For the standalone stream, we handle:
                        # - JSONRPCNotification (server sends notifications to client)
                        # - JSONRPCRequest (server sends requests to client)
                        # We should NOT receive JSONRPCResponse

                        # Send the message via SSE
                        event_data = self._create_event_data(event_message)
                        await sse_stream_writer.send(event_data)
            except Exception as e:
                logger.exception("Error in standalone SSE writer: %s", e)
            finally:
                logger.debug("Closing standalone SSE writer")
                await self._clean_up_memory_streams(GET_STREAM_KEY)

        try:
            # This will send headers immediately and establish the SSE connection
            async with sse_response(request) as sse_resp:  # Set up headers
                sse_resp.headers.update(headers)

                async with anyio.create_task_group() as tg:
                    # https://trio.readthedocs.io/en/latest/reference-core.html#custom-supervisors
                    async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                        await coro()
                        tg.cancel_scope.cancel()

                    async def _process_response_inner() -> None:
                        """Redirect messages from the SSE stream to the response."""
                        logger.debug("Starting SSE stream processor")
                        async with sse_stream_reader:
                            async for event in sse_stream_reader:
                                logger.debug("Sending event via SSE: %s", event)
                                await sse_resp.send(data=event.data, event=event.event_type, id=event.event_id)
                                logger.debug("Sent event via SSE: %s", event)

                    tg.start_soon(cancel_on_finish, _process_response_inner)
                    tg.start_soon(cancel_on_finish, standalone_sse_writer)

                return sse_resp
        except Exception as e:
            logger.exception("Error in standalone SSE response: %s", e)
            await sse_stream_writer.aclose()
            await sse_stream_reader.aclose()
            await self._clean_up_memory_streams(GET_STREAM_KEY)
            raise

    async def _handle_delete_request(self, request: web.Request) -> web.StreamResponse:
        """
        Process DELETE requests for explicit session termination.

        Terminates the current session, closes all streams, and prevents
        further requests with the same session ID (returns 404 Not Found).
        Only available when session management is enabled.

        Args:
            request: HTTP DELETE request for session termination

        Returns:
            JSON response confirming termination or error response
        """
        # Validate session ID
        if not self.mcp_session_id:
            # If no session ID set, return Method Not Allowed
            return self._create_error_response(
                "Method Not Allowed: Session termination not supported",
                HTTPStatus.METHOD_NOT_ALLOWED,
            )

        if error_response := await self._validate_request_headers(request):
            return error_response

        await self._terminate_session()

        return self._create_json_response(
            None,
            HTTPStatus.OK,
        )

    async def _terminate_session(self) -> None:
        """
        Terminate the current session and clean up all resources.

        This method:
        1. Marks the session as terminated
        2. Closes all active request streams
        3. Closes transport read/write streams
        4. Clears internal stream mappings

        After termination, all subsequent requests will receive 404 Not Found.
        This is irreversible - a new transport instance is needed for new sessions.
        """

        self._terminated = True
        logger.info("Terminating session: %s", self.mcp_session_id)

        # We need a copy of the keys to avoid modification during iteration
        request_stream_keys = list(self._request_streams.keys())

        # Close all request streams asynchronously
        for key in request_stream_keys:
            try:
                await self._clean_up_memory_streams(key)
            except Exception as e:
                logger.debug("Error closing stream %s during termination: %s", key, e)

        # Clear the request streams dictionary immediately
        self._request_streams.clear()
        try:
            if self._read_stream_writer is not None:
                await self._read_stream_writer.aclose()
            if self._read_stream is not None:
                await self._read_stream.aclose()
            if self._write_stream_reader is not None:
                await self._write_stream_reader.aclose()
            if self._write_stream is not None:
                await self._write_stream.aclose()
        except Exception as e:
            logger.debug("Error closing streams: %s", e)

    async def _handle_unsupported_request(self, request: web.Request) -> web.StreamResponse:
        """
        Handle HTTP methods not supported by the transport.

        Returns 405 Method Not Allowed with proper Allow header indicating
        supported methods (GET, POST, DELETE).

        Args:
            request: HTTP request with unsupported method

        Returns:
            Error response with Method Not Allowed status
        """
        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Allow": "GET, POST, DELETE",
        }
        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        return self._create_error_response(
            "Method Not Allowed",
            HTTPStatus.METHOD_NOT_ALLOWED,
            headers=headers,
        )

    async def _validate_request_headers(self, request: web.Request) -> web.Response | None:
        """
        Validate required request headers (session ID and protocol version).

        Args:
            request: HTTP request to validate

        Returns:
            Error response if validation fails, None if validation passes
        """
        if error_response := await self._validate_session(request):
            return error_response
        if error_response := await self._validate_protocol_version(request):
            return error_response
        return None

    async def _validate_session(self, request: web.Request) -> web.Response | None:
        """
        Validate session identifier in request headers.

        Checks that:
        - Session ID is provided when required
        - Session ID matches the transport's expected session
        - Session ID format is valid

        Args:
            request: HTTP request to validate

        Returns:
            Error response if session validation fails, None if valid
        """
        if not self.mcp_session_id:
            # If we're not using session IDs, return None
            return None

        # Get the session ID from the request headers
        request_session_id = self._get_session_id(request)

        # If no session ID provided but required, return error
        if not request_session_id:
            return self._create_error_response(
                "Bad Request: Missing session ID",
                HTTPStatus.BAD_REQUEST,
            )

        # If session ID doesn't match, return error
        if request_session_id != self.mcp_session_id:
            return self._create_error_response(
                "Not Found: Invalid or expired session ID",
                HTTPStatus.NOT_FOUND,
            )

        return None

    async def _validate_protocol_version(self, request: web.Request) -> web.Response | None:
        """
        Validate MCP protocol version compatibility.

        Checks the mcp-protocol-version header against supported versions.
        Uses default version if header is not provided.

        Args:
            request: HTTP request to validate

        Returns:
            Error response if version is unsupported, None if compatible
        """
        # Get the protocol version from the request headers
        protocol_version = request.headers.get(MCP_PROTOCOL_VERSION_HEADER)

        # If no protocol version provided, assume default version
        if protocol_version is None:
            protocol_version = DEFAULT_NEGOTIATED_VERSION

        # Check if the protocol version is supported
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            supported_versions = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
            return self._create_error_response(
                f"Bad Request: Unsupported protocol version: {protocol_version}. "
                + f"Supported versions: {supported_versions}",
                HTTPStatus.BAD_REQUEST,
            )

        # If the version is supported, return None (no error)
        return None

    async def _replay_events(self, last_event_id: str, request: web.Request) -> web.StreamResponse:  # noqa: C901
        """
        Replay missed events for resumable connections.

        When clients reconnect with Last-Event-ID header, this method:
        1. Queries the event store for events after the specified ID
        2. Replays historical events via SSE
        3. Continues with new events as they arrive

        This enables seamless reconnection and message continuity.
        Only available when event store is configured.

        Args:
            last_event_id: ID of the last event the client received
            request: HTTP request for event replay

        Returns:
            SSE StreamResponse with replayed and new events
        """
        event_store = self._event_store
        if not event_store:
            return self._create_error_response(
                "Internal Server Error: Event store not configured for resumability",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )

        try:
            headers = {
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "Content-Type": CONTENT_TYPE_SSE,
            }

            if self.mcp_session_id:
                headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

            # Create SSE stream for replay
            sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[Event](0)

            async def replay_sender() -> None:
                try:
                    async with sse_stream_writer:
                        # Define an async callback for sending events
                        async def send_event(event_message: EventMessage) -> None:
                            event_data = self._create_event_data(event_message)
                            await sse_stream_writer.send(event_data)

                        # Replay past events and get the stream ID
                        stream_id = await event_store.replay_events_after(last_event_id, send_event)

                        # If stream ID not in mapping, create it
                        if stream_id and stream_id not in self._request_streams:
                            self._request_streams[stream_id] = anyio.create_memory_object_stream[EventMessage](0)
                            msg_reader = self._request_streams[stream_id][1]

                            # Forward messages to SSE
                            async with msg_reader:
                                async for event_message in msg_reader:
                                    event_data = self._create_event_data(event_message)

                                    await sse_stream_writer.send(event_data)
                except Exception as e:
                    logger.exception("Error in replay sender: %s", e)

            try:
                async with sse_response(request) as sse_resp:  # Set up headers
                    sse_resp.headers.update(headers)

                    async with anyio.create_task_group() as tg:
                        # https://trio.readthedocs.io/en/latest/reference-core.html#custom-supervisors
                        async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                            await coro()
                            tg.cancel_scope.cancel()

                        async def _process_response_inner() -> None:
                            """Redirect messages from the SSE stream to the response."""
                            logger.debug("Starting SSE stream processor")
                            async with sse_stream_reader:
                                async for event in sse_stream_reader:
                                    logger.debug("Sending event via SSE: %s", event)
                                    await sse_resp.send(data=event.data, event=event.event_type, id=event.event_id)
                                    logger.debug("Sent event via SSE: %s", event)

                        tg.start_soon(cancel_on_finish, _process_response_inner)
                        tg.start_soon(cancel_on_finish, replay_sender)

                    return sse_resp
            except Exception as e:
                logger.exception("Error in replay response: %s", e)
                raise
            finally:
                await sse_stream_writer.aclose()
                await sse_stream_reader.aclose()

        except Exception as e:
            logger.exception("Error replaying events: %s", e)
            return self._create_error_response(
                f"Error replaying events: {e!s}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )

    @asynccontextmanager
    async def connect(  # noqa: C901
        self,
    ) -> AsyncGenerator[
        tuple[
            MemoryObjectReceiveStream[SessionMessage | Exception],
            MemoryObjectSendStream[SessionMessage],
        ],
        None,
    ]:
        """Context manager that provides read and write streams for a connection.

        Yields:
            Tuple of (read_stream, write_stream) for bidirectional communication
        """

        # Create the memory streams for this connection

        read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

        # Store the streams
        self._read_stream_writer = read_stream_writer
        self._read_stream = read_stream
        self._write_stream_reader = write_stream_reader
        self._write_stream = write_stream

        # Start a task group for message routing
        async with anyio.create_task_group() as tg:
            # Create a message router that distributes messages to request streams
            async def message_router() -> None:
                try:
                    async for session_message in write_stream_reader:
                        # Determine which request stream(s) should receive this message
                        message = session_message.message
                        target_request_id = None
                        # Check if this is a response
                        if isinstance(message.root, JSONRPCResponse | JSONRPCError):
                            response_id = str(message.root.id)
                            # If this response is for an existing request stream,
                            # send it there
                            if response_id in self._request_streams:
                                target_request_id = response_id

                        else:
                            # Extract related_request_id from meta if it exists
                            if (
                                session_message.metadata is not None
                                and isinstance(
                                    session_message.metadata,
                                    ServerMessageMetadata,
                                )
                                and session_message.metadata.related_request_id is not None
                            ):
                                target_request_id = str(session_message.metadata.related_request_id)

                        request_stream_id = target_request_id if target_request_id is not None else GET_STREAM_KEY

                        # Store the event if we have an event store,
                        # regardless of whether a client is connected
                        # messages will be replayed on the re-connect
                        event_id = None
                        if self._event_store:
                            event_id = await self._event_store.store_event(request_stream_id, message)
                            logger.debug("Stored %s from %s", event_id, request_stream_id)

                        if request_stream_id in self._request_streams:
                            try:
                                # Send both the message and the event ID
                                await self._request_streams[request_stream_id][0].send(EventMessage(message, event_id))
                            except (
                                anyio.BrokenResourceError,
                                anyio.ClosedResourceError,
                            ):
                                # Stream might be closed, remove from registry
                                self._request_streams.pop(request_stream_id, None)
                        else:
                            logging.debug(
                                "Request stream %s not found for message. "
                                "Still processing message as the client might reconnect and replay.",
                                request_stream_id,
                            )
                except Exception as e:
                    logger.exception("Error in message router: %s", e)

            # Start the message router
            tg.start_soon(message_router)

            try:
                # Yield the streams for the caller to use
                yield read_stream, write_stream
            finally:
                for stream_id in list(self._request_streams.keys()):
                    try:
                        await self._clean_up_memory_streams(stream_id)
                    except Exception as e:
                        logger.debug("Error closing request stream: %s", e)
                        pass
                self._request_streams.clear()

                # Clean up the read and write streams
                try:
                    await read_stream_writer.aclose()
                    await read_stream.aclose()
                    await write_stream_reader.aclose()
                    await write_stream.aclose()
                except Exception as e:
                    logger.debug("Error closing streams: %s", e)
