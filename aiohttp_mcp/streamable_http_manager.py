"""
StreamableHTTP Session Manager for MCP Servers

This module provides high-level session management for FastMCP-compatible
StreamableHTTP transports. It orchestrates multiple client sessions,
handles session lifecycle, and provides both stateful and stateless
operation modes for production deployment scenarios.

The StreamableHTTPSessionManager serves as the orchestration layer between
aiohttp web requests and the underlying MCP server instances, automatically
managing transport creation, session tracking, and request routing.

Key Features:
- **Dual Operation Modes**: Stateful (with session persistence) and stateless (fresh per request)
- **Session Lifecycle Management**: Automatic creation, tracking, and cleanup of client sessions
- **Event Store Integration**: Optional resumability support for reconnection scenarios
- **Concurrent Session Handling**: Thread-safe management of multiple simultaneous client sessions
- **Resource Management**: Proper cleanup and task group management for production deployments

Architecture:
- **Session Manager**: High-level orchestrator (this module)
- **Transport Layer**: StreamableHTTPServerTransport instances per session
- **MCP Server**: Underlying FastMCP server instances
- **Task Management**: anyio task groups for concurrent session handling

Operation Modes:
1. **Stateful Mode** (default):
   - Sessions persist between requests
   - Session IDs track client state
   - Supports resumability with event stores
   - Optimal for persistent client connections

2. **Stateless Mode**:
   - Fresh transport created per request
   - No session persistence or tracking
   - Suitable for load-balanced deployments
   - Lower memory overhead for high-throughput scenarios

Usage Patterns:
- **Single Instance Deployment**: Use stateful mode with optional event store
- **Load Balanced Deployment**: Use stateless mode for horizontal scaling
- **Development/Testing**: Either mode works, stateless is simpler for testing
- **High Availability**: Stateful with event store for seamless failover
"""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import AsyncIterator
from http import HTTPStatus
from typing import Any
from uuid import uuid4

import anyio
from aiohttp import web
from anyio.abc import TaskStatus
from mcp.server.lowlevel.server import Server as MCPServer
from mcp.server.streamable_http import EventStore

from .streamable_http import (
    MCP_SESSION_ID_HEADER,
    StreamableHTTPServerTransport,
)

logger = logging.getLogger(__name__)


class StreamableHTTPSessionManager:
    """
    Session orchestrator for StreamableHTTP transports with dual operation modes.

    Manages multiple client sessions and routes requests to appropriate transport
    instances. Supports both stateful (persistent sessions) and stateless
    (fresh per request) operation modes.

    Important: Each instance can only call run() once. Create new instances
    for subsequent operations.

    Args:
        server: FastMCP server instance for MCP protocol operations
        event_store: Optional event store for resumability (default: None)
        json_response: Use JSON responses instead of SSE streams (default: False)
        stateless: Create fresh transport per request (default: False)

    Example:
        ```python
        manager = StreamableHTTPSessionManager(server=mcp_server)

        async with manager.run():
            response = await manager.handle_request(request)
        ```
    """

    def __init__(
        self,
        server: MCPServer[Any, Any],
        event_store: EventStore | None = None,
        json_response: bool = False,
        stateless: bool = False,
    ) -> None:
        """
        Initialize the StreamableHTTP session manager.

        Args:
            server: FastMCP server instance for handling MCP protocol operations
            event_store: Optional event store for resumability (default: None)
            json_response: Use JSON responses instead of SSE streams (default: False)
            stateless: Create fresh transport per request (default: False)
        """
        self.server = server
        self.event_store = event_store
        self.json_response = json_response
        self.stateless = stateless

        # Session tracking (only used if not stateless)
        self._session_creation_lock = anyio.Lock()
        self._server_instances: dict[str, StreamableHTTPServerTransport] = {}

        # The task group will be set during lifespan
        self._task_group: anyio.abc.TaskGroup | None = None
        # Thread-safe tracking of run() calls
        self._run_lock = threading.Lock()
        self._has_started = False

    @contextlib.asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """
        Initialize session manager with task group for concurrent operations.

        Creates task group infrastructure, manages active sessions, and ensures
        proper cleanup on exit. Can only be called once per instance.

        Yields:
            None: Control while manager is active

        Raises:
            RuntimeError: If called multiple times on same instance
        """
        # Thread-safe check to ensure run() is only called once
        with self._run_lock:
            if self._has_started:
                raise RuntimeError(
                    "StreamableHTTPSessionManager .run() can only be called "
                    "once per instance. Create a new instance if you need to run again."
                )
            self._has_started = True

        async with anyio.create_task_group() as tg:
            # Store the task group for later use
            self._task_group = tg
            logger.info("StreamableHTTP session manager started")
            try:
                yield  # Let the application run
            finally:
                logger.info("StreamableHTTP session manager shutting down")
                # Cancel task group to stop all spawned tasks
                tg.cancel_scope.cancel()
                self._task_group = None
                # Clear any remaining server instances
                self._server_instances.clear()

    async def handle_request(
        self,
        request: web.Request,
    ) -> web.StreamResponse:
        """
        Route HTTP request to appropriate handler based on operation mode.

        Args:
            request: HTTP request to process

        Returns:
            HTTP response (StreamResponse for SSE or Response for JSON)

        Raises:
            RuntimeError: If task group not initialized (run() not called)
        """
        if self._task_group is None:
            raise RuntimeError("Task group is not initialized. Make sure to use run().")

        # Dispatch to the appropriate handler
        if self.stateless:
            return await self._handle_stateless_request(request)
        else:
            return await self._handle_stateful_request(request)

    async def _handle_stateless_request(
        self,
        request: web.Request,
    ) -> web.StreamResponse:
        """
        Handle request in stateless mode by creating fresh transport instance.

        In stateless mode, each request gets a completely fresh transport with no
        session tracking or state persistence. This is ideal for load-balanced
        deployments where requests can be handled by any server instance with:
        - No session ID tracking or validation
        - Fresh MCP server instance per request
        - No event store or resumability support
        - Lower memory overhead for high-throughput scenarios
        - Suitable for horizontally scaled deployments

        Args:
            request: HTTP request to process with fresh transport

        Returns:
            HTTP response from the newly created transport instance
        """
        logger.debug("Stateless mode: Creating new transport for this request")
        # No session ID needed in stateless mode
        http_transport = StreamableHTTPServerTransport(
            mcp_session_id=None,  # No session tracking in stateless mode
            is_json_response_enabled=self.json_response,
            event_store=None,  # No event store in stateless mode
        )

        # Start server in a new task
        async def run_stateless_server(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
            async with http_transport.connect() as streams:
                read_stream, write_stream = streams
                task_status.started()
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options(),
                    stateless=True,
                )

        # Assert task group is not None for type checking
        assert self._task_group is not None
        # Start the server task
        await self._task_group.start(run_stateless_server)

        # Handle the HTTP request and return the response
        return await http_transport.handle_request(request)

    async def _handle_stateful_request(
        self,
        request: web.Request,
    ) -> web.StreamResponse:
        """
        Handle request in stateful mode with session persistence and tracking.

        In stateful mode, sessions persist between requests using session IDs.
        This enables advanced features like resumability, event replay, and
        long-lived client connections with maintained state.

        Session handling logic:
        1. **Existing Session**: If session ID exists, route to existing transport
        2. **New Session**: If no session ID, create new session with unique ID
        3. **Invalid Session**: If session ID provided but not found, return error

        This mode provides:
        - Session ID generation and tracking
        - Session-based transport routing
        - Event store integration for resumability
        - Persistent MCP server state between requests
        - Support for long-lived client connections

        Args:
            request: HTTP request to process with session management

        Returns:
            HTTP response from the appropriate session transport

        Raises:
            RuntimeError: If task group not available for starting new sessions
        """
        request_mcp_session_id = request.headers.get(MCP_SESSION_ID_HEADER)

        # Existing session case
        if request_mcp_session_id is not None and request_mcp_session_id in self._server_instances:
            transport = self._server_instances[request_mcp_session_id]
            logger.debug("Session already exists, handling request directly")
            return await transport.handle_request(request)

        if request_mcp_session_id is None:
            # New session case
            logger.debug("Creating new transport")
            async with self._session_creation_lock:
                new_session_id = uuid4().hex
                http_transport = StreamableHTTPServerTransport(
                    mcp_session_id=new_session_id,
                    is_json_response_enabled=self.json_response,
                    event_store=self.event_store,  # May be None (no resumability)
                )

                assert http_transport.mcp_session_id is not None
                self._server_instances[http_transport.mcp_session_id] = http_transport
                logger.info("Created new transport with session ID: %s", new_session_id)

                # Define the server runner
                async def run_server(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
                    async with http_transport.connect() as streams:
                        read_stream, write_stream = streams
                        task_status.started()
                        await self.server.run(
                            read_stream,
                            write_stream,
                            self.server.create_initialization_options(),
                            stateless=False,  # Stateful mode
                        )

                # Assert task group is not None for type checking
                assert self._task_group is not None
                # Start the server task
                await self._task_group.start(run_server)

                # Handle the HTTP request and return the response
                return await http_transport.handle_request(request)
        else:
            # Invalid session ID
            return web.Response(
                text="Bad Request: No valid session ID provided",
                status=HTTPStatus.BAD_REQUEST,
            )
