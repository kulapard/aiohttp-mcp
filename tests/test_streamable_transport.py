"""
Tests for StreamableHTTP transport functionality.

This module provides comprehensive test coverage for:
- StreamableHTTPServerTransport: Core transport implementation
- StreamableHTTPSessionManager: Session management and orchestration
- Integration with AppBuilder and MCP clients
- Both stateful and stateless operation modes
- Event replay and resumability features
- Error handling and edge cases
"""

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http import EventMessage, EventStore
from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)

from aiohttp_mcp import AiohttpMCP, AppBuilder, TransportMode, build_mcp_app
from aiohttp_mcp.streamable_http import (
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_SSE,
    MCP_PROTOCOL_VERSION_HEADER,
    MCP_SESSION_ID_HEADER,
    StreamableHTTPServerTransport,
)
from aiohttp_mcp.streamable_http_manager import StreamableHTTPSessionManager

from .utils import register_mcp_resources

logger = logging.getLogger(__name__)

# Set the pytest marker for async tests/fixtures
pytestmark = pytest.mark.anyio

TEST_PATH = "/streamable-mcp"


def create_mock_request(
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body_text: str = "",
    query_params: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock aiohttp request with proper attributes."""
    request = MagicMock()
    request.method = method
    request.headers = headers or {}
    request.text = AsyncMock(return_value=body_text)
    request.query = query_params or {}

    # Add version attribute for aiohttp compatibility
    from aiohttp import HttpVersion

    request.version = HttpVersion(1, 1)

    # Add transport and other required attributes
    request.transport = MagicMock()
    request.url = MagicMock()
    request.url.path = TEST_PATH
    request.remote = "127.0.0.1"
    request.content_type = headers.get("content-type", "") if headers else ""

    return request


class MockEventStore(EventStore):
    """Mock event store for testing resumability."""

    def __init__(self) -> None:
        self.events: dict[str, list[tuple[str, JSONRPCMessage]]] = {}
        self.event_counter = 0

    async def store_event(self, stream_id: str, message: JSONRPCMessage) -> str:
        """Store an event and return its ID."""
        event_id = f"event-{self.event_counter}"
        self.event_counter += 1

        if stream_id not in self.events:
            self.events[stream_id] = []
        self.events[stream_id].append((event_id, message))

        return event_id

    async def replay_events_after(
        self, last_event_id: str, callback: Callable[[EventMessage], Awaitable[None]]
    ) -> str | None:
        """Replay events after the given event ID."""
        # Find which stream contains this event
        target_stream = None
        start_index = 0

        for stream_id, events in self.events.items():
            for i, (event_id, _) in enumerate(events):
                if event_id == last_event_id:
                    target_stream = stream_id
                    start_index = i + 1
                    break
            if target_stream:
                break

        if target_stream and start_index < len(self.events[target_stream]):
            # Replay events after the last event ID
            for event_id, message in self.events[target_stream][start_index:]:
                await callback(EventMessage(message, event_id))
            return target_stream

        return None


@pytest.fixture
def mock_event_store() -> MockEventStore:
    """Provide a mock event store for testing."""
    return MockEventStore()


@pytest.fixture
def mcp_server() -> Server[Any]:
    """Create an AiohttpMCP server for testing."""
    mcp = AiohttpMCP("test-server")

    @mcp.tool()
    def echo_tool(message: str) -> str:
        """Echo a message back."""
        return f"Echo: {message}"

    return mcp.server


@pytest.fixture
def transport_stateless(mcp_server: Server[Any]) -> StreamableHTTPServerTransport:
    """Create a stateless StreamableHTTPServerTransport."""
    return StreamableHTTPServerTransport(
        mcp_session_id=None,
        is_json_response_enabled=False,
        event_store=None,
    )


@pytest.fixture
def transport_stateful(mcp_server: Server[Any], mock_event_store: MockEventStore) -> StreamableHTTPServerTransport:
    """Create a stateful StreamableHTTPServerTransport with session ID."""
    return StreamableHTTPServerTransport(
        mcp_session_id="test-session-123",
        is_json_response_enabled=False,
        event_store=mock_event_store,
    )


@pytest.fixture
def transport_json_mode(mcp_server: Server[Any]) -> StreamableHTTPServerTransport:
    """Create a transport with JSON response mode enabled."""
    return StreamableHTTPServerTransport(
        mcp_session_id="json-session-456",
        is_json_response_enabled=True,
        event_store=None,
    )


@pytest.fixture
def session_manager_stateful(mcp_server: Server[Any], mock_event_store: MockEventStore) -> StreamableHTTPSessionManager:
    """Create a stateful session manager."""
    return StreamableHTTPSessionManager(
        server=mcp_server,
        event_store=mock_event_store,
        json_response=False,
        stateless=False,
    )


@pytest.fixture
def session_manager_stateless(mcp_server: Server[Any]) -> StreamableHTTPSessionManager:
    """Create a stateless session manager."""
    return StreamableHTTPSessionManager(
        server=mcp_server,
        event_store=None,
        json_response=False,
        stateless=True,
    )


@pytest.fixture
def valid_jsonrpc_request() -> JSONRPCRequest:
    """Create a valid JSON-RPC request."""
    return JSONRPCRequest(jsonrpc="2.0", id="test-request-1", method="echo_tool", params={"message": "test"})


@pytest.fixture
def valid_jsonrpc_notification() -> JSONRPCNotification:
    """Create a valid JSON-RPC notification."""
    return JSONRPCNotification(jsonrpc="2.0", method="test_notification", params={"data": "test"})


@pytest.fixture
def valid_jsonrpc_response() -> JSONRPCResponse:
    """Create a valid JSON-RPC response."""
    return JSONRPCResponse(jsonrpc="2.0", id="test-request-1", result={"message": "Echo: test"})


@asynccontextmanager
async def create_test_app(
    transport_or_manager: Any, is_session_manager: bool = False
) -> AsyncIterator[web.Application]:
    """Create a test app with the given transport or session manager."""
    app = web.Application()

    if is_session_manager:
        # Session manager setup
        async def setup_session_manager(_app: web.Application) -> AsyncIterator[None]:
            async with transport_or_manager.run():
                yield

        app.cleanup_ctx.append(setup_session_manager)
        app.router.add_route("*", TEST_PATH, transport_or_manager.handle_request)
    else:
        # Direct transport setup
        async def handler(request: web.Request) -> web.StreamResponse:
            async with transport_or_manager.connect() as (read_stream, write_stream):
                # Echo messages back for testing
                async def echo_handler() -> None:
                    async for msg in read_stream:
                        if isinstance(msg, SessionMessage):
                            await write_stream.send(msg)

                import anyio

                async with anyio.create_task_group() as tg:
                    tg.start_soon(echo_handler)
                    result = await transport_or_manager.handle_request(request)
                    return result  # type: ignore[no-any-return]

        app.router.add_route("*", TEST_PATH, handler)

    yield app


class TestStreamableHTTPServerTransport:
    """Test cases for StreamableHTTPServerTransport."""

    def test_init_with_invalid_session_id(self) -> None:
        """Test that invalid session IDs raise ValueError."""
        with pytest.raises(ValueError, match="Session ID must only contain visible ASCII characters"):
            StreamableHTTPServerTransport(mcp_session_id="invalid\x00session")

    def test_init_with_valid_session_id(self) -> None:
        """Test initialization with valid session ID."""
        transport = StreamableHTTPServerTransport(mcp_session_id="valid-session-123")
        assert transport.mcp_session_id == "valid-session-123"

    async def test_handle_unsupported_method(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test handling of unsupported HTTP methods."""
        request = create_mock_request(method="PUT")

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.METHOD_NOT_ALLOWED
            assert response.headers["Allow"] == "GET, POST, DELETE"

    async def test_terminated_session_returns_404(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Test that terminated sessions return 404."""
        async with transport_stateful.connect():
            # Terminate the session
            await transport_stateful._terminate_session()

            # Any request should now return 404
            request = create_mock_request(method="GET", headers={MCP_SESSION_ID_HEADER: "test-session-123"})

            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.NOT_FOUND

    async def test_post_without_accept_headers(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test POST request without proper Accept headers."""
        request = create_mock_request(method="POST", headers={"content-type": CONTENT_TYPE_JSON})

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.NOT_ACCEPTABLE

    async def test_post_without_json_content_type(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test POST request without JSON content type."""
        request = create_mock_request(
            method="POST", headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": "text/plain"}
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.UNSUPPORTED_MEDIA_TYPE

    async def test_post_with_oversized_payload(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test POST request with payload exceeding maximum size."""
        large_payload = "x" * (4 * 1024 * 1024 + 1)  # Exceed 4MB limit

        request = create_mock_request(
            method="POST",
            headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
            body_text=large_payload,
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    async def test_post_with_invalid_json(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test POST request with invalid JSON."""
        request = create_mock_request(
            method="POST",
            headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
            body_text="invalid json",
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST

    async def test_session_validation_missing_session_id(
        self, transport_stateful: StreamableHTTPServerTransport
    ) -> None:
        """Test that requests without session ID are rejected when required."""
        request = create_mock_request(method="GET", headers={"accept": CONTENT_TYPE_SSE})

        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST

    async def test_session_validation_wrong_session_id(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Test that requests with wrong session ID are rejected."""
        request = create_mock_request(
            method="GET", headers={"accept": CONTENT_TYPE_SSE, MCP_SESSION_ID_HEADER: "wrong-session"}
        )

        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.NOT_FOUND

    async def test_protocol_version_validation(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test protocol version validation."""
        request = create_mock_request(
            method="GET", headers={"accept": CONTENT_TYPE_SSE, MCP_PROTOCOL_VERSION_HEADER: "unsupported-version"}
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST

    async def test_delete_without_session_id(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test DELETE request on transport without session management."""
        request = create_mock_request(method="DELETE")

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.METHOD_NOT_ALLOWED

    async def test_delete_with_valid_session(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Test successful session deletion."""
        request = create_mock_request(method="DELETE", headers={MCP_SESSION_ID_HEADER: "test-session-123"})

        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.OK
            assert transport_stateful._terminated is True


class TestStreamableHTTPSessionManager:
    """Test cases for StreamableHTTPSessionManager."""

    def test_init_stateful_mode(self, mcp_server: Server[Any], mock_event_store: MockEventStore) -> None:
        """Test initialization in stateful mode."""
        manager = StreamableHTTPSessionManager(
            server=mcp_server,
            event_store=mock_event_store,
            json_response=True,
            stateless=False,
        )
        assert manager.server is mcp_server
        assert manager.event_store is mock_event_store
        assert manager.json_response is True
        assert manager.stateless is False

    def test_init_stateless_mode(self, mcp_server: Server[Any]) -> None:
        """Test initialization in stateless mode."""
        manager = StreamableHTTPSessionManager(
            server=mcp_server,
            event_store=None,
            json_response=False,
            stateless=True,
        )
        assert manager.stateless is True
        assert manager.event_store is None

    async def test_run_context_manager_single_use(self, session_manager_stateful: StreamableHTTPSessionManager) -> None:
        """Test that run() can only be called once per instance."""
        async with session_manager_stateful.run():
            pass

        # Second call should raise error
        with pytest.raises(RuntimeError, match="can only be called once"):
            async with session_manager_stateful.run():
                pass

    async def test_handle_request_without_run(self, session_manager_stateful: StreamableHTTPSessionManager) -> None:
        """Test that handle_request fails without calling run() first."""
        request = create_mock_request()

        with pytest.raises(RuntimeError, match="Task group is not initialized"):
            await session_manager_stateful.handle_request(request)

    async def test_stateless_request_handling(self, session_manager_stateless: StreamableHTTPSessionManager) -> None:
        """Test stateless request handling."""
        request = create_mock_request(
            method="POST",
            headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
            body_text='{"jsonrpc": "2.0", "method": "test", "id": 1}',
        )

        async with session_manager_stateless.run():
            # This should create a fresh transport for each request
            response = await session_manager_stateless.handle_request(request)
            assert isinstance(response, web.StreamResponse)

    async def test_stateful_new_session_creation(self, session_manager_stateful: StreamableHTTPSessionManager) -> None:
        """Test creation of new session in stateful mode."""
        request = create_mock_request(
            method="POST",
            headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
            body_text='{"jsonrpc": "2.0", "method": "initialize", "id": 1}',
        )

        async with session_manager_stateful.run():
            response = await session_manager_stateful.handle_request(request)
            assert isinstance(response, web.StreamResponse)

    async def test_stateful_existing_session_routing(
        self, session_manager_stateful: StreamableHTTPSessionManager
    ) -> None:
        """Test routing to existing session in stateful mode."""
        # First request creates a session
        request1 = create_mock_request(
            method="POST",
            headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
            body_text='{"jsonrpc": "2.0", "method": "initialize", "id": 1}',
        )

        async with session_manager_stateful.run():
            await session_manager_stateful.handle_request(request1)

            # Extract session ID from first response (would be in headers)
            session_id = "test-session-id"  # In real scenario, extracted from response

            # Second request with same session ID should route to existing session
            request2 = create_mock_request(
                method="POST",
                headers={
                    "accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}",
                    "content-type": CONTENT_TYPE_JSON,
                    MCP_SESSION_ID_HEADER: session_id,
                },
                body_text='{"jsonrpc": "2.0", "method": "test", "id": 2}',
            )

            # This would route to existing session if it existed
            response2 = await session_manager_stateful.handle_request(request2)
            assert isinstance(response2, web.StreamResponse)

    async def test_invalid_session_id_in_stateful_mode(
        self, session_manager_stateful: StreamableHTTPSessionManager
    ) -> None:
        """Test handling of invalid session ID in stateful mode."""
        request = create_mock_request(
            method="POST",
            headers={
                "accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}",
                "content-type": CONTENT_TYPE_JSON,
                MCP_SESSION_ID_HEADER: "non-existent-session",
            },
            body_text='{"jsonrpc": "2.0", "method": "test", "id": 1}',
        )

        async with session_manager_stateful.run():
            response = await session_manager_stateful.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST


class TestAppBuilderIntegration:
    """Test integration with AppBuilder and streamable transport mode."""

    @pytest.fixture
    def mcp_registry(self) -> AiohttpMCP:
        """Create an MCP registry for testing."""
        mcp = AiohttpMCP()
        register_mcp_resources(mcp)
        return mcp

    async def test_app_builder_streamable_mode(self, mcp_registry: AiohttpMCP, mcp_server: Server[Any]) -> None:
        """Test AppBuilder with streamable transport mode."""
        app_builder = AppBuilder(
            mcp=mcp_registry,
            path=TEST_PATH,
            transport_mode=TransportMode.STREAMABLE_HTTP,
            json_response=False,
            stateless=False,
        )

        app = app_builder.build()
        assert isinstance(app, web.Application)

        # Check that the correct route is set up
        routes = list(app.router.routes())
        assert len(routes) == 1
        assert routes[0].method == "*"  # Streamable uses wildcard route

    async def test_build_mcp_app_streamable_mode(self, mcp_registry: AiohttpMCP) -> None:
        """Test build_mcp_app with streamable transport mode."""
        app = build_mcp_app(
            mcp_registry,
            path=TEST_PATH,
            transport_mode=TransportMode.STREAMABLE_HTTP,
            json_response=True,
            stateless=True,
        )

        assert isinstance(app, web.Application)

    async def test_mixed_transport_modes(self, mcp_registry: AiohttpMCP) -> None:
        """Test application with both SSE and streamable transports."""
        app = web.Application()

        # Add SSE subapp
        mcp_sse = AiohttpMCP()
        register_mcp_resources(mcp_sse)

        sse_builder = AppBuilder(
            mcp=mcp_sse,
            path="/sse",
            transport_mode=TransportMode.SSE,
        )
        sse_app = sse_builder.build(is_subapp=True)
        app.add_subapp("/sse", sse_app)

        # Add streamable subapp
        mcp_streamable = AiohttpMCP()
        register_mcp_resources(mcp_streamable)

        streamable_builder = AppBuilder(
            mcp=mcp_streamable,
            path="/streamable",
            transport_mode=TransportMode.STREAMABLE_HTTP,
        )
        streamable_app = streamable_builder.build(is_subapp=True)
        app.add_subapp("/streamable", streamable_app)

        assert isinstance(app, web.Application)


class TestEventStore:
    """Test event store functionality and resumability."""

    async def test_mock_event_store_basic_operations(self, mock_event_store: MockEventStore) -> None:
        """Test basic event store operations."""
        message = JSONRPCMessage(root=JSONRPCNotification(jsonrpc="2.0", method="test", params={"data": "test"}))

        # Store an event
        event_id = await mock_event_store.store_event("stream-1", message)
        assert event_id.startswith("event-")

        # Check that event was stored
        assert "stream-1" in mock_event_store.events
        assert len(mock_event_store.events["stream-1"]) == 1

    async def test_event_replay_functionality(self, mock_event_store: MockEventStore) -> None:
        """Test event replay after reconnection."""
        # Store multiple events
        messages = []
        event_ids = []

        for i in range(3):
            message = JSONRPCMessage(
                root=JSONRPCNotification(jsonrpc="2.0", method=f"test_{i}", params={"data": f"test_{i}"})
            )
            messages.append(message)
            event_id = await mock_event_store.store_event("stream-1", message)
            event_ids.append(event_id)

        # Replay events after the first event
        replayed_events = []

        async def callback(event_message: EventMessage) -> None:
            replayed_events.append(event_message)

        stream_id = await mock_event_store.replay_events_after(event_ids[0], callback)

        assert stream_id == "stream-1"
        assert len(replayed_events) == 2  # Should replay events 1 and 2
        # Check that the right events were replayed
        assert hasattr(replayed_events[0].message.root, "method")
        assert hasattr(replayed_events[1].message.root, "method")
        assert replayed_events[0].message.root.method == "test_1"
        assert replayed_events[1].message.root.method == "test_2"

    async def test_transport_with_event_store(self, mcp_server: Server[Any], mock_event_store: MockEventStore) -> None:
        """Test transport integration with event store."""
        transport = StreamableHTTPServerTransport(
            mcp_session_id="test-session",
            is_json_response_enabled=False,
            event_store=mock_event_store,
        )

        # Test that event store is properly integrated
        assert transport._event_store is mock_event_store


class TestErrorHandling:
    """Test error handling and edge cases."""

    async def test_connection_cleanup_on_error(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test proper cleanup when connection encounters errors."""
        async with transport_stateless.connect() as (read_stream, write_stream):
            # Simulate an error condition by closing the write stream
            await write_stream.aclose()

            # The test passes if we can successfully close the connection
            # without raising exceptions during cleanup
            pass

    async def test_malformed_jsonrpc_message(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test handling of malformed JSON-RPC messages."""
        request = create_mock_request(
            method="POST",
            headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
            body_text='{"invalid": "jsonrpc"}',
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST

    async def test_concurrent_session_operations(self, session_manager_stateful: StreamableHTTPSessionManager) -> None:
        """Test concurrent operations on session manager."""
        import asyncio

        async def make_request(request_id: str) -> web.StreamResponse:
            request = create_mock_request(
                method="POST",
                headers={"accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}", "content-type": CONTENT_TYPE_JSON},
                body_text=f'{{"jsonrpc": "2.0", "method": "initialize", "id": "{request_id}"}}',
            )
            return await session_manager_stateful.handle_request(request)

        async with session_manager_stateful.run():
            # Make multiple concurrent requests
            tasks = [make_request(f"req-{i}") for i in range(5)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # All requests should complete successfully
            for response in responses:
                assert not isinstance(response, Exception)
                assert isinstance(response, web.StreamResponse)

    async def test_resource_cleanup_on_termination(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Test that resources are properly cleaned up on session termination."""
        async with transport_stateful.connect():
            # Terminate session
            await transport_stateful._terminate_session()

            # All streams should be cleaned up
            assert len(transport_stateful._request_streams) == 0
            assert transport_stateful._terminated is True
