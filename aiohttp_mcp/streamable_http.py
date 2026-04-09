"""StreamableHTTP Server Transport Module.

Implements the StreamableHTTP transport layer for MCP servers using
native asyncio instead of anyio.
"""

import asyncio
import json
import logging
import re
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus

from aiohttp import web
from aiohttp_sse import sse_response
from pydantic import ValidationError

from .protocol.messages import EventMessage, EventStore, ServerMessageMetadata, SessionMessage
from .protocol.models import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    LATEST_PROTOCOL_VERSION,
    PARSE_ERROR,
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
)
from .protocol.streams import ClosedStreamError, StreamReader, StreamWriter, create_memory_stream
from .protocol.typedefs import RequestId

logger = logging.getLogger(__name__)

DEFAULT_NEGOTIATED_VERSION = LATEST_PROTOCOL_VERSION

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
SESSION_ID_PATTERN = re.compile(r"^[\x21-\x7E]+$")


class EventType(StrEnum):
    ENDPOINT = "endpoint"
    MESSAGE = "message"


@dataclass
class Event:
    event_type: EventType
    data: str
    event_id: str | None = None


class StreamableHTTPServerTransport:
    """HTTP server transport with session management for MCP.

    Supports GET/POST/DELETE for full session lifecycle,
    SSE streaming and JSON response modes.
    """

    _read_stream_writer: StreamWriter[SessionMessage | Exception] | None = None
    _read_stream: StreamReader[SessionMessage | Exception] | None = None
    _write_stream: StreamWriter[SessionMessage] | None = None
    _write_stream_reader: StreamReader[SessionMessage] | None = None

    def __init__(
        self,
        mcp_session_id: str | None,
        is_json_response_enabled: bool = False,
        event_store: EventStore | None = None,
    ) -> None:
        if mcp_session_id is not None and not SESSION_ID_PATTERN.fullmatch(mcp_session_id):
            raise ValueError("Session ID must only contain visible ASCII characters (0x21-0x7E)")

        self.mcp_session_id = mcp_session_id
        self.is_json_response_enabled = is_json_response_enabled
        self._event_store = event_store
        self._request_streams: dict[
            RequestId,
            tuple[StreamWriter[EventMessage], StreamReader[EventMessage]],
        ] = {}
        self._terminated = False

    def _create_error_response(
        self,
        error_message: str,
        status_code: HTTPStatus,
        error_code: int = INVALID_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> web.Response:
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)
        if self.mcp_session_id:
            response_headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",
            error=ErrorData(code=error_code, message=error_message),
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
        return request.headers.get(MCP_SESSION_ID_HEADER)

    def _create_event_data(self, event_message: EventMessage) -> Event:
        data = event_message.message.model_dump_json(by_alias=True, exclude_none=True)
        if event_message.event_id:
            return Event(data=data, event_type=EventType.MESSAGE, event_id=event_message.event_id)
        return Event(data=data, event_type=EventType.MESSAGE)

    async def _clean_up_memory_streams(self, request_id: RequestId) -> None:
        if request_id in self._request_streams:
            try:
                await self._request_streams[request_id][0].aclose()
                await self._request_streams[request_id][1].aclose()
            except Exception as e:
                logger.warning("Error closing memory streams for request %s: %s", request_id, e)
            finally:
                self._request_streams.pop(request_id, None)

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        if self._terminated:
            return self._create_error_response("Not Found: Session has been terminated", HTTPStatus.NOT_FOUND)

        if request.method == "POST":
            return await self._handle_post_request(request)
        elif request.method == "GET":
            return await self._handle_get_request(request)
        elif request.method == "DELETE":
            return await self._handle_delete_request(request)
        else:
            return await self._handle_unsupported_request(request)

    def _check_accept_headers(self, request: web.Request) -> tuple[bool, bool]:
        accept_header = request.headers.get("accept", "")
        accept_types = [media_type.strip() for media_type in accept_header.split(",")]
        has_json = any(media_type.startswith(CONTENT_TYPE_JSON) for media_type in accept_types)
        has_sse = any(media_type.startswith(CONTENT_TYPE_SSE) for media_type in accept_types)
        return has_json, has_sse

    def _check_content_type(self, request: web.Request) -> bool:
        content_type = request.headers.get("content-type", "")
        content_type_parts = [part.strip() for part in content_type.split(";")[0].split(",")]
        return any(part == CONTENT_TYPE_JSON for part in content_type_parts)

    async def _handle_post_request(self, request: web.Request) -> web.StreamResponse:  # noqa: C901
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError("No read stream writer available. Ensure connect() is called first.")
        try:
            has_json, has_sse = self._check_accept_headers(request)
            if not (has_json and has_sse):
                return self._create_error_response(
                    "Not Acceptable: Client must accept both application/json and text/event-stream",
                    HTTPStatus.NOT_ACCEPTABLE,
                )

            if not self._check_content_type(request):
                return self._create_error_response(
                    "Unsupported Media Type: Content-Type must be application/json",
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )

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
                return self._create_error_response(f"Validation error: {e!s}", HTTPStatus.BAD_REQUEST, INVALID_PARAMS)

            is_initialization_request = isinstance(message.root, JSONRPCRequest) and message.root.method == "initialize"

            if is_initialization_request:
                if self.mcp_session_id:
                    request_session_id = self._get_session_id(request)
                    if request_session_id and request_session_id != self.mcp_session_id:
                        return self._create_error_response(
                            "Not Found: Invalid or expired session ID", HTTPStatus.NOT_FOUND
                        )
            elif error_response := await self._validate_request_headers(request):
                return error_response

            # For notifications and responses only, return 202 Accepted
            if not isinstance(message.root, JSONRPCRequest):
                response = self._create_json_response(None, HTTPStatus.ACCEPTED)
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)
                return response

            request_id = str(message.root.id)
            self._request_streams[request_id] = create_memory_stream(0)
            request_stream_reader = self._request_streams[request_id][1]

            if self.is_json_response_enabled:
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)
                try:
                    response_message = None
                    async for event_message in request_stream_reader:
                        if isinstance(event_message.message.root, JSONRPCResponse | JSONRPCError):
                            response_message = event_message.message
                            break
                        else:
                            logger.debug("received: %s", event_message.message.root.method)

                    if response_message:
                        return self._create_json_response(response_message)
                    else:
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
                sse_stream_writer, sse_stream_reader = create_memory_stream(0)  # type: ignore[var-annotated]

                async def _sse_writer() -> None:
                    try:
                        async for event_message in request_stream_reader:
                            event_data = self._create_event_data(event_message)
                            await sse_stream_writer.send(event_data)
                            if isinstance(event_message.message.root, JSONRPCResponse | JSONRPCError):
                                break
                    finally:
                        logger.debug("Closing SSE writer")
                        await sse_stream_writer.aclose()
                        await request_stream_reader.aclose()
                        await self._clean_up_memory_streams(request_id)

                try:
                    headers = {
                        "Cache-Control": "no-cache, no-transform",
                        "Connection": "keep-alive",
                        **({MCP_SESSION_ID_HEADER: self.mcp_session_id} if self.mcp_session_id else {}),
                    }
                    async with sse_response(request, headers=headers) as sse_resp:
                        async with asyncio.TaskGroup() as tg:

                            async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                                await coro()

                            async def _process_response_inner() -> None:
                                logger.debug("Starting SSE stream processor")
                                async for event in sse_stream_reader:
                                    logger.debug("Sending event via SSE: %s", event)
                                    await sse_resp.send(data=event.data, event=event.event_type, id=event.event_id)
                                    logger.debug("Sent event via SSE: %s", event)

                            tg.create_task(cancel_on_finish(_process_response_inner))
                            tg.create_task(cancel_on_finish(_sse_writer))

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
            return self._create_error_response(
                f"Error handling POST request: {err}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )

    async def _handle_get_request(self, request: web.Request) -> web.StreamResponse:  # noqa: C901
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError("No read stream writer available. Ensure connect() is called first.")

        _, has_sse = self._check_accept_headers(request)
        if not has_sse:
            return self._create_error_response(
                "Not Acceptable: Client must accept text/event-stream", HTTPStatus.NOT_ACCEPTABLE
            )

        if error_response := await self._validate_request_headers(request):
            return error_response

        if last_event_id := request.headers.get(LAST_EVENT_ID_HEADER):
            return await self._replay_events(last_event_id, request)

        headers = {
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "Content-Type": CONTENT_TYPE_SSE,
        }
        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        if GET_STREAM_KEY in self._request_streams:
            return self._create_error_response(
                "Conflict: Only one SSE stream is allowed per session", HTTPStatus.CONFLICT
            )

        sse_stream_writer, sse_stream_reader = create_memory_stream(0)  # type: ignore[var-annotated]

        async def standalone_sse_writer() -> None:
            try:
                self._request_streams[GET_STREAM_KEY] = create_memory_stream(0)
                standalone_stream_reader = self._request_streams[GET_STREAM_KEY][1]

                async for event_message in standalone_stream_reader:
                    event_data = self._create_event_data(event_message)
                    await sse_stream_writer.send(event_data)
            except Exception as e:
                logger.exception("Error in standalone SSE writer: %s", e)
            finally:
                logger.debug("Closing standalone SSE writer")
                await sse_stream_writer.aclose()
                await self._clean_up_memory_streams(GET_STREAM_KEY)

        try:
            async with sse_response(request, headers=headers) as sse_resp:
                async with asyncio.TaskGroup() as tg:

                    async def _process_response_inner() -> None:
                        logger.debug("Starting SSE stream processor")
                        async for event in sse_stream_reader:
                            logger.debug("Sending event via SSE: %s", event)
                            await sse_resp.send(data=event.data, event=event.event_type, id=event.event_id)
                            logger.debug("Sent event via SSE: %s", event)

                    tg.create_task(_process_response_inner())
                    tg.create_task(standalone_sse_writer())

                return sse_resp
        except Exception as e:
            logger.exception("Error in standalone SSE response: %s", e)
            await sse_stream_writer.aclose()
            await sse_stream_reader.aclose()
            await self._clean_up_memory_streams(GET_STREAM_KEY)
            raise

    async def _handle_delete_request(self, request: web.Request) -> web.StreamResponse:
        if not self.mcp_session_id:
            return self._create_error_response(
                "Method Not Allowed: Session termination not supported", HTTPStatus.METHOD_NOT_ALLOWED
            )

        if error_response := await self._validate_request_headers(request):
            return error_response

        await self._terminate_session()
        return self._create_json_response(None, HTTPStatus.OK)

    async def _terminate_session(self) -> None:
        self._terminated = True
        logger.info("Terminating session: %s", self.mcp_session_id)

        request_stream_keys = list(self._request_streams.keys())
        for key in request_stream_keys:
            try:
                await self._clean_up_memory_streams(key)
            except Exception as e:
                logger.warning("Error closing stream %s during termination: %s", key, e)

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
            logger.warning("Error closing streams: %s", e)

    async def _handle_unsupported_request(self, request: web.Request) -> web.StreamResponse:
        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Allow": "GET, POST, DELETE",
        }
        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id
        return self._create_error_response("Method Not Allowed", HTTPStatus.METHOD_NOT_ALLOWED, headers=headers)

    async def _validate_request_headers(self, request: web.Request) -> web.Response | None:
        if error_response := await self._validate_session(request):
            return error_response
        if error_response := await self._validate_protocol_version(request):
            return error_response
        return None

    async def _validate_session(self, request: web.Request) -> web.Response | None:
        if not self.mcp_session_id:
            return None

        request_session_id = self._get_session_id(request)
        if not request_session_id:
            return self._create_error_response("Bad Request: Missing session ID", HTTPStatus.BAD_REQUEST)
        if request_session_id != self.mcp_session_id:
            return self._create_error_response("Not Found: Invalid or expired session ID", HTTPStatus.NOT_FOUND)
        return None

    async def _validate_protocol_version(self, request: web.Request) -> web.Response | None:
        protocol_version = request.headers.get(MCP_PROTOCOL_VERSION_HEADER)
        if protocol_version is None:
            protocol_version = DEFAULT_NEGOTIATED_VERSION

        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            supported_versions = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
            return self._create_error_response(
                f"Bad Request: Unsupported protocol version: {protocol_version}. "
                + f"Supported versions: {supported_versions}",
                HTTPStatus.BAD_REQUEST,
            )
        return None

    async def _replay_events(self, last_event_id: str, request: web.Request) -> web.StreamResponse:  # noqa: C901
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

            sse_stream_writer, sse_stream_reader = create_memory_stream(0)  # type: ignore[var-annotated]

            async def replay_sender() -> None:
                try:

                    async def send_event(event_message: EventMessage) -> None:
                        event_data = self._create_event_data(event_message)
                        await sse_stream_writer.send(event_data)

                    stream_id = await event_store.replay_events_after(last_event_id, send_event)

                    if stream_id and stream_id not in self._request_streams:
                        self._request_streams[stream_id] = create_memory_stream(0)
                        msg_reader = self._request_streams[stream_id][1]
                        async for event_message in msg_reader:
                            event_data = self._create_event_data(event_message)
                            await sse_stream_writer.send(event_data)
                except Exception as e:
                    logger.exception("Error in replay sender: %s", e)
                finally:
                    await sse_stream_writer.aclose()

            try:
                async with sse_response(request, headers=headers) as sse_resp:
                    async with asyncio.TaskGroup() as tg:

                        async def _process_response_inner() -> None:
                            logger.debug("Starting SSE stream processor")
                            async for event in sse_stream_reader:
                                logger.debug("Sending event via SSE: %s", event)
                                await sse_resp.send(data=event.data, event=event.event_type, id=event.event_id)
                                logger.debug("Sent event via SSE: %s", event)

                        tg.create_task(_process_response_inner())
                        tg.create_task(replay_sender())

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
            StreamReader[SessionMessage | Exception],
            StreamWriter[SessionMessage],
        ],
        None,
    ]:
        """Context manager providing read and write streams for a connection."""
        read_stream_writer, read_stream = create_memory_stream(0)  # type: ignore[var-annotated]
        write_stream, write_stream_reader = create_memory_stream(0)  # type: ignore[var-annotated]

        self._read_stream_writer = read_stream_writer
        self._read_stream = read_stream
        self._write_stream_reader = write_stream_reader
        self._write_stream = write_stream

        async with asyncio.TaskGroup() as tg:

            async def message_router() -> None:
                async for session_message in write_stream_reader:
                    message = session_message.message
                    target_request_id = None

                    if isinstance(message.root, JSONRPCResponse | JSONRPCError):
                        response_id = str(message.root.id)
                        if response_id in self._request_streams:
                            target_request_id = response_id
                    else:
                        if (
                            session_message.metadata is not None
                            and isinstance(session_message.metadata, ServerMessageMetadata)
                            and session_message.metadata.related_request_id is not None
                        ):
                            target_request_id = str(session_message.metadata.related_request_id)

                    request_stream_id = target_request_id if target_request_id is not None else GET_STREAM_KEY

                    event_id = None
                    if self._event_store:
                        event_id = await self._event_store.store_event(request_stream_id, message)
                        logger.debug("Stored %s from %s", event_id, request_stream_id)

                    if request_stream_id in self._request_streams:
                        try:
                            await self._request_streams[request_stream_id][0].send(EventMessage(message, event_id))
                        except ClosedStreamError:
                            self._request_streams.pop(request_stream_id, None)
                    else:
                        logging.debug(
                            "Request stream %s not found for message. "
                            "Still processing message as the client might reconnect and replay.",
                            request_stream_id,
                        )

            tg.create_task(message_router())

            try:
                yield read_stream, write_stream
            finally:
                for stream_id in list(self._request_streams.keys()):
                    try:
                        await self._clean_up_memory_streams(stream_id)
                    except Exception as e:
                        logger.debug("Error closing request stream: %s", e)
                self._request_streams.clear()

                try:
                    await read_stream_writer.aclose()
                    await read_stream.aclose()
                    await write_stream_reader.aclose()
                    await write_stream.aclose()
                except Exception as e:
                    logger.warning("Error closing streams: %s", e)
