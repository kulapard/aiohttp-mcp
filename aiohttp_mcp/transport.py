import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import quote
from uuid import UUID, uuid4

import anyio
import mcp.types as types
from aiohttp import web
from aiohttp_sse import sse_response
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from pydantic import ValidationError

logger = logging.getLogger(__name__)


@dataclass
class Event:
    event: str
    data: str


class SseServerTransport:
    _read_stream_writers: dict[UUID, MemoryObjectSendStream[types.JSONRPCMessage | Exception]]

    def __init__(self, message_path: str, send_timeout: float | None = None) -> None:
        super().__init__()
        self._message_path = message_path
        self._send_timeout = send_timeout
        self._read_stream_writers: dict[uuid.UUID, MemoryObjectSendStream[types.JSONRPCMessage | Exception]] = {}

    @asynccontextmanager
    async def connect_sse(
        self, request: web.Request
    ) -> AsyncIterator[
        tuple[
            MemoryObjectReceiveStream[types.JSONRPCMessage | Exception],
            MemoryObjectSendStream[types.JSONRPCMessage | Exception],
        ]
    ]:
        logger.info("Setting up SSE connection")

        # Create memory object streams
        read_stream_writer, read_stream = anyio.create_memory_object_stream[types.JSONRPCMessage | Exception](0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream[types.JSONRPCMessage | Exception](0)
        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[Event](0)

        session_id = uuid4()
        session_uri = f"{quote(self._message_path)}?session_id={session_id.hex}"
        self._read_stream_writers[session_id] = read_stream_writer
        logger.debug("Created new session with ID: %s", session_id)

        async def sse_writer() -> None:
            logger.debug("Starting SSE writer")
            async with sse_stream_writer, write_stream_reader:
                logger.debug("[sse_writer] Sending initial endpoint event")
                await sse_stream_writer.send(
                    Event(
                        event="endpoint",
                        data=session_uri,
                    )
                )
                logger.debug("[sse_writer] Sent endpoint event: %s", session_uri)

                async for message in write_stream_reader:
                    logger.debug("[sse_writer] Sending message via SSE: %s", message)

                    if isinstance(message, types.JSONRPCMessage):
                        data = message.model_dump_json(by_alias=True, exclude_none=True)
                    else:
                        data = str(message)

                    await sse_stream_writer.send(Event(event="message", data=data))

        # ----------------------------------------------------------------
        async def _stream_response(request: web.Request) -> None:
            async with sse_response(request) as response:
                async for msg in sse_stream_reader:
                    logger.debug("[_stream_response] chunk: %s", msg)
                    with anyio.move_on_after(self._send_timeout) as cancel_scope:
                        logger.debug("[_stream_response] Sending message via SSE: %s", msg)
                        await response.send(data=msg.data, event=msg.event)
                    logger.debug("[_stream_response] Sent message via SSE: %s", msg)

                    if cancel_scope and cancel_scope.cancel_called:
                        await sse_stream_reader.aclose()
                        raise TimeoutError()

        # ----------------------------------------------------------------
        async with anyio.create_task_group() as tg:
            logger.debug("Starting SSE response task")

            # https://trio.readthedocs.io/en/latest/reference-core.html#custom-supervisors
            async def cancel_on_finish(coro: Callable[[], Awaitable[None]]) -> None:
                await coro()
                tg.cancel_scope.cancel()

            tg.start_soon(cancel_on_finish, lambda: _stream_response(request))
            tg.start_soon(cancel_on_finish, sse_writer)
            yield read_stream, write_stream

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

        writer = self._read_stream_writers.get(session_id)
        if not writer:
            logger.warning("Could not find session for ID: %s", session_id)
            return web.Response(text="Could not find session", status=404)

        body = await request.text()
        logger.debug("Received JSON: %s", body)

        try:
            message = types.JSONRPCMessage.model_validate_json(body)
            logger.debug("Validated client message: %s", message)
        except ValidationError as err:
            logger.error("Failed to parse message: %s", err)
            await writer.send(err)
            return web.Response(text="Could not parse message", status=400)

        logger.debug("Sending message to writer: %s", message)
        await writer.send(message)
        return web.Response(text="Accepted", status=202)
