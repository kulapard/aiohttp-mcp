"""StreamableHTTP Session Manager for MCP Servers.

Manages multiple client sessions and routes requests to appropriate transport
instances. Supports both stateful and stateless operation modes.
Uses native asyncio instead of anyio.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from collections.abc import AsyncIterator
from http import HTTPStatus
from uuid import uuid4

from aiohttp import web

from .protocol.messages import EventStore
from .protocol.server import MCPServer
from .streamable_http import MCP_SESSION_ID_HEADER, StreamableHTTPServerTransport

logger = logging.getLogger(__name__)


class StreamableHTTPSessionManager:
    """Session orchestrator for StreamableHTTP transports.

    Manages multiple client sessions and routes requests to appropriate transport
    instances. Supports both stateful and stateless operation modes.
    """

    def __init__(
        self,
        server: MCPServer,
        event_store: EventStore | None = None,
        json_response: bool = False,
        stateless: bool = False,
    ) -> None:
        self.server = server
        self.event_store = event_store
        self.json_response = json_response
        self.stateless = stateless

        self._session_creation_lock = asyncio.Lock()
        self._server_instances: dict[str, StreamableHTTPServerTransport] = {}
        self._tasks: set[asyncio.Task[None]] = set()

        self._run_lock = threading.Lock()
        self._has_started = False
        self._running = False

    @contextlib.asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        with self._run_lock:
            if self._has_started:
                raise RuntimeError(
                    "StreamableHTTPSessionManager .run() can only be called "
                    "once per instance. Create a new instance if you need to run again."
                )
            self._has_started = True

        self._running = True
        logger.info("StreamableHTTP session manager started")
        try:
            yield
        finally:
            logger.info("StreamableHTTP session manager shutting down")
            self._running = False
            # Cancel all running tasks
            for task in self._tasks:
                task.cancel()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()
            self._server_instances.clear()

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        if not self._running:
            raise RuntimeError("Task group is not initialized. Make sure to use run().")

        if self.stateless:
            return await self._handle_stateless_request(request)
        else:
            return await self._handle_stateful_request(request)

    async def _handle_stateless_request(self, request: web.Request) -> web.StreamResponse:
        logger.debug("Stateless mode: Creating new transport for this request")
        http_transport = StreamableHTTPServerTransport(
            mcp_session_id=None,
            is_json_response_enabled=self.json_response,
            event_store=None,
        )

        ready_event = asyncio.Event()

        async def run_stateless_server() -> None:
            async with http_transport.connect() as streams:
                read_stream, write_stream = streams
                ready_event.set()
                await self.server.run(read_stream, write_stream, self.server.create_initialization_options(), stateless=True)

        task = asyncio.create_task(run_stateless_server())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        await ready_event.wait()
        return await http_transport.handle_request(request)

    async def _handle_stateful_request(self, request: web.Request) -> web.StreamResponse:
        request_mcp_session_id = request.headers.get(MCP_SESSION_ID_HEADER)

        # Existing session
        if request_mcp_session_id is not None and request_mcp_session_id in self._server_instances:
            transport = self._server_instances[request_mcp_session_id]
            logger.debug("Session already exists, handling request directly")
            return await transport.handle_request(request)

        if request_mcp_session_id is None:
            # New session
            logger.debug("Creating new transport")
            async with self._session_creation_lock:
                new_session_id = uuid4().hex
                http_transport = StreamableHTTPServerTransport(
                    mcp_session_id=new_session_id,
                    is_json_response_enabled=self.json_response,
                    event_store=self.event_store,
                )

                assert http_transport.mcp_session_id is not None
                self._server_instances[http_transport.mcp_session_id] = http_transport
                logger.info("Created new transport with session ID: %s", new_session_id)

                ready_event = asyncio.Event()

                async def run_server() -> None:
                    async with http_transport.connect() as streams:
                        read_stream, write_stream = streams
                        ready_event.set()
                        await self.server.run(
                            read_stream,
                            write_stream,
                            self.server.create_initialization_options(),
                            stateless=False,
                        )

                task = asyncio.create_task(run_server())
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

                await ready_event.wait()
                return await http_transport.handle_request(request)
        else:
            return web.Response(
                text="Bad Request: No valid session ID provided",
                status=HTTPStatus.BAD_REQUEST,
            )
