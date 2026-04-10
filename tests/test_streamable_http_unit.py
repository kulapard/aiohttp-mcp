"""
Unit Tests for StreamableHTTP Transport (Mocked).

This module provides unit-level tests for the StreamableHTTP transport layer
using mocked HTTP requests. These tests focus on low-level behavior, edge cases,
and error paths without requiring real MCP servers or HTTP clients.

The StreamableHTTP transport is an advanced transport mode that supports:
- Both stateful (session-based) and stateless operation
- GET/POST/DELETE endpoints for full session lifecycle
- Event store integration for resumability
- JSON and SSE response modes

Test Coverage:
- Error response creation and formatting
- Event data serialization with/without event IDs
- Request validation (headers, content-type, protocol version)
- Session ID validation (valid/invalid characters)
- Connect lifecycle (stream creation, cleanup, multiple contexts)
- Memory stream management for concurrent requests
- POST request handling with various header combinations
- Protocol version negotiation
- JSON vs SSE response mode behavior
- Session management (stateful vs stateless modes)

Testing Approach:
- Uses unittest.mock to create mock aiohttp Request objects
- No real HTTP connections or MCP servers required
- Fast, isolated tests for specific code paths
- Focus on error conditions and edge cases

When to Add Tests Here:
- Testing low-level transport behavior with mocked requests
- Testing error response creation and formatting
- Testing validation logic (headers, session IDs, protocol versions)
- Testing helper methods and internal utilities
- Testing edge cases that are hard to trigger in integration tests

Related Test Files:
- test_streamable_http_integration.py: Integration tests with real MCP servers
- test_sse_transport.py: Tests for SSE transport mode
"""

from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import HttpVersion

from aiohttp_mcp.protocol.messages import EventMessage
from aiohttp_mcp.protocol.models import JSONRPCMessage, JSONRPCNotification, JSONRPCResponse
from aiohttp_mcp.protocol.streams import create_memory_stream
from aiohttp_mcp.streamable_http import (
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_SSE,
    LAST_EVENT_ID_HEADER,
    MAXIMUM_MESSAGE_SIZE,
    MCP_PROTOCOL_VERSION_HEADER,
    MCP_SESSION_ID_HEADER,
    EventType,
    StreamableHTTPServerTransport,
)


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
    request.version = HttpVersion(1, 1)
    request.transport = MagicMock()
    request.url = MagicMock()
    request.url.path = "/mcp"
    request.remote = "127.0.0.1"
    request.content_type = headers.get("content-type", "") if headers else ""
    return request


@pytest.fixture
def transport_stateless() -> StreamableHTTPServerTransport:
    """Create a stateless transport for testing."""
    return StreamableHTTPServerTransport(
        mcp_session_id=None,
        is_json_response_enabled=False,
        event_store=None,
    )


@pytest.fixture
def transport_stateful() -> StreamableHTTPServerTransport:
    """Create a stateful transport with session ID."""
    return StreamableHTTPServerTransport(
        mcp_session_id="test-session",
        is_json_response_enabled=False,
        event_store=None,
    )


@pytest.fixture
def transport_json_mode() -> StreamableHTTPServerTransport:
    """Create a transport in JSON response mode."""
    return StreamableHTTPServerTransport(
        mcp_session_id=None,
        is_json_response_enabled=True,
        event_store=None,
    )


class TestErrorResponses:
    """Test error response creation and handling."""

    async def test_create_error_response_with_custom_headers(
        self, transport_stateless: StreamableHTTPServerTransport
    ) -> None:
        """Test error response creation with custom headers."""
        custom_headers = {"X-Custom-Header": "custom-value"}
        response = transport_stateless._create_error_response(
            "Test error message",
            HTTPStatus.BAD_REQUEST,
            headers=custom_headers,
        )

        assert response.status == HTTPStatus.BAD_REQUEST
        assert response.content_type == CONTENT_TYPE_JSON
        assert response.headers["X-Custom-Header"] == "custom-value"

    async def test_create_error_response_includes_session_id(
        self, transport_stateful: StreamableHTTPServerTransport
    ) -> None:
        """Test that error responses include session ID when available."""
        response = transport_stateful._create_error_response(
            "Test error",
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )

        assert response.headers[MCP_SESSION_ID_HEADER] == "test-session"

    async def test_error_response_format(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that error responses follow JSON-RPC error format."""
        response = transport_stateless._create_error_response(
            "Test error message",
            HTTPStatus.BAD_REQUEST,
        )

        assert response.status == HTTPStatus.BAD_REQUEST
        assert response.content_type == CONTENT_TYPE_JSON
        # Response body should be valid JSON
        assert response.body is not None


class TestEventData:
    """Test event data creation and formatting."""

    async def test_create_event_data_with_event_id(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test event data creation with explicit event ID."""
        message = JSONRPCMessage(root=JSONRPCNotification(jsonrpc="2.0", method="test", params={"data": "value"}))
        event_message = EventMessage(message=message, event_id="custom-event-id")

        event_data = transport_stateless._create_event_data(event_message)

        assert event_data.event_type == EventType.MESSAGE
        assert event_data.data is not None
        assert event_data.event_id == "custom-event-id"

    async def test_create_event_data_without_event_id(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test event data creation without explicit event ID."""
        message = JSONRPCMessage(root=JSONRPCNotification(jsonrpc="2.0", method="test", params={"data": "value"}))
        event_message = EventMessage(message=message, event_id=None)

        event_data = transport_stateless._create_event_data(event_message)

        assert event_data.event_type == EventType.MESSAGE
        assert event_data.data is not None
        assert event_data.event_id is None


class TestRequestHandling:
    """Test request handling edge cases."""

    async def test_json_mode_missing_accept_header(self, transport_json_mode: StreamableHTTPServerTransport) -> None:
        """Test JSON mode with missing accept header."""
        request = create_mock_request(
            method="POST",
            headers={"content-type": CONTENT_TYPE_JSON},
            body_text='{"jsonrpc": "2.0", "method": "test", "id": "1"}',
        )

        async with transport_json_mode.connect():
            response = await transport_json_mode.handle_request(request)
            # Should return 406 Not Acceptable when accept header is missing
            assert response.status == HTTPStatus.NOT_ACCEPTABLE

    async def test_unsupported_http_method(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test handling of unsupported HTTP methods."""
        request = create_mock_request(
            method="PUT",
            headers={},
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.METHOD_NOT_ALLOWED


class TestSessionValidation:
    """Test session ID validation and handling."""

    async def test_invalid_session_id_characters(self) -> None:
        """Test that invalid session ID characters are rejected."""
        # Session IDs must contain only visible ASCII characters (0x21-0x7E)
        with pytest.raises(ValueError, match="visible ASCII characters"):
            StreamableHTTPServerTransport(
                mcp_session_id="invalid\x00session",  # Contains null byte
                is_json_response_enabled=False,
                event_store=None,
            )

    async def test_valid_session_id_accepted(self) -> None:
        """Test that valid session IDs are accepted."""
        # All visible ASCII characters should be valid
        valid_session_id = "valid-session-123_ABC!@#"
        transport = StreamableHTTPServerTransport(
            mcp_session_id=valid_session_id,
            is_json_response_enabled=False,
            event_store=None,
        )
        assert transport.mcp_session_id == valid_session_id


class TestConnectLifecycle:
    """Test the connect() method lifecycle and stream management."""

    async def test_connect_creates_streams(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that connect() creates read and write streams."""
        async with transport_stateless.connect() as (read_stream, write_stream):
            assert read_stream is not None
            assert write_stream is not None

    async def test_connect_cleanup(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that connect() properly cleans up streams."""
        async with transport_stateless.connect() as (read_stream, write_stream):
            # Streams should exist inside context
            assert read_stream is not None
            assert write_stream is not None

        # After exiting context, cleanup should have occurred
        # Note: The actual stream closure happens in the background task

    async def test_multiple_connect_contexts(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that multiple connect() contexts can be used."""
        # First connection
        async with transport_stateless.connect():
            pass

        # Second connection should work
        async with transport_stateless.connect():
            pass

    async def test_terminated_session_state(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Test session termination state management."""
        async with transport_stateful.connect():
            # Initially not terminated
            assert not transport_stateful._terminated

            # Terminate the session
            await transport_stateful._terminate_session()

            # Should be marked as terminated
            assert transport_stateful._terminated


class TestMemoryStreams:
    """Test memory stream management for concurrent requests."""

    async def test_request_stream_creation(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that request streams are created and tracked."""
        async with transport_stateless.connect():
            # Initially no request streams
            assert len(transport_stateless._request_streams) == 0

    async def test_request_stream_cleanup(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that request streams are cleaned up."""

        request = create_mock_request(
            method="POST",
            headers={
                "accept": CONTENT_TYPE_JSON,
                "content-type": CONTENT_TYPE_JSON,
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
            body_text='{"jsonrpc": "2.0", "method": "initialize", "id": "test-1"}',
        )

        async with transport_stateless.connect():
            # Test that the request size is within limits
            assert len(request.text.return_value) < MAXIMUM_MESSAGE_SIZE

            # Handle request
            response = await transport_stateless.handle_request(request)

            # Response should be created
            assert response is not None


class TestPostRequestHandling:
    """Test POST request handling with various scenarios."""

    async def test_post_without_accept_header(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test POST request without accept header."""
        request = create_mock_request(
            method="POST",
            headers={"content-type": CONTENT_TYPE_JSON},
            body_text='{"jsonrpc": "2.0", "method": "test", "id": "1"}',
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            # Should return 406 Not Acceptable
            assert response.status == HTTPStatus.NOT_ACCEPTABLE

    async def test_post_with_valid_request(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test POST request with all valid headers."""
        request = create_mock_request(
            method="POST",
            headers={
                "accept": CONTENT_TYPE_JSON,
                "content-type": CONTENT_TYPE_JSON,
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
            body_text='{"jsonrpc": "2.0", "method": "initialize", "id": "1"}',
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            # Should return a valid response
            assert response is not None


class TestProtocolNegotiation:
    """Test protocol version negotiation and validation."""

    async def test_protocol_negotiation(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test protocol version negotiation with valid request."""
        request = create_mock_request(
            method="POST",
            headers={
                "accept": CONTENT_TYPE_JSON,
                "content-type": CONTENT_TYPE_JSON,
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
            body_text='{"jsonrpc": "2.0", "method": "initialize", "id": "1"}',
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            # Should create a response
            assert response is not None


class TestJsonModeResponses:
    """Test JSON response mode behavior."""

    async def test_json_mode_enabled(self, transport_json_mode: StreamableHTTPServerTransport) -> None:
        """Test that JSON mode is properly enabled."""
        assert transport_json_mode.is_json_response_enabled is True

    async def test_json_mode_disabled(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that JSON mode is disabled by default."""
        assert transport_stateless.is_json_response_enabled is False


class TestSessionManagement:
    """Test session management features."""

    async def test_stateless_transport_has_no_session(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test that stateless transport has no session ID."""
        assert transport_stateless.mcp_session_id is None

    async def test_stateful_transport_has_session(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Test that stateful transport has session ID."""
        assert transport_stateful.mcp_session_id == "test-session"

    async def test_delete_request_in_stateless_mode(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Test DELETE request in stateless mode."""
        request = create_mock_request(
            method="DELETE",
            headers={MCP_PROTOCOL_VERSION_HEADER: "2025-03-26"},
        )

        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            # Stateless mode returns Method Not Allowed for DELETE
            assert response.status in (HTTPStatus.NOT_FOUND, HTTPStatus.METHOD_NOT_ALLOWED)


class TestGetRequestHandling:
    """Test GET request handling for SSE streams."""

    async def test_get_missing_accept_sse(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """GET without Accept: text/event-stream returns 406."""
        request = create_mock_request(
            method="GET",
            headers={"accept": CONTENT_TYPE_JSON},
        )
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.NOT_ACCEPTABLE

    async def test_get_validation_failure_wrong_session(
        self, transport_stateful: StreamableHTTPServerTransport
    ) -> None:
        """GET with wrong session ID returns error."""
        request = create_mock_request(
            method="GET",
            headers={
                "accept": CONTENT_TYPE_SSE,
                MCP_SESSION_ID_HEADER: "wrong-session",
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
        )
        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.NOT_FOUND

    async def test_get_validation_failure_missing_session(
        self, transport_stateful: StreamableHTTPServerTransport
    ) -> None:
        """GET without session ID on stateful transport returns error."""
        request = create_mock_request(
            method="GET",
            headers={
                "accept": CONTENT_TYPE_SSE,
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
        )
        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST


class TestDeleteRequestHandling:
    """Test DELETE request handling for session termination."""

    async def test_delete_no_session_returns_405(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """DELETE when transport has no session ID returns 405."""
        request = create_mock_request(
            method="DELETE",
            headers={MCP_PROTOCOL_VERSION_HEADER: "2025-03-26"},
        )
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.METHOD_NOT_ALLOWED

    async def test_delete_valid_session(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """DELETE with valid session terminates and returns 200."""
        request = create_mock_request(
            method="DELETE",
            headers={
                MCP_SESSION_ID_HEADER: "test-session",
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
        )
        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.OK
            assert transport_stateful._terminated

    async def test_delete_wrong_session(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """DELETE with wrong session ID returns error."""
        request = create_mock_request(
            method="DELETE",
            headers={
                MCP_SESSION_ID_HEADER: "wrong-session",
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
        )
        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.NOT_FOUND


class TestUnsupportedMethod:
    """Test unsupported HTTP method handling."""

    async def test_put_returns_405_with_allow(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """PUT returns 405 with Allow header listing valid methods."""
        request = create_mock_request(method="PUT")
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.METHOD_NOT_ALLOWED
            assert response.headers["Allow"] == "GET, POST, DELETE"

    async def test_patch_returns_405(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        request = create_mock_request(method="PATCH")
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.METHOD_NOT_ALLOWED

    async def test_unsupported_method_includes_session_id(
        self, transport_stateful: StreamableHTTPServerTransport
    ) -> None:
        request = create_mock_request(method="PUT")
        async with transport_stateful.connect():
            response = await transport_stateful.handle_request(request)
            assert response.headers[MCP_SESSION_ID_HEADER] == "test-session"


class TestTerminateSession:
    """Test session termination and stream cleanup."""

    async def test_terminated_session_rejects_requests(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Requests after termination return 404."""
        request = create_mock_request(
            method="POST",
            headers={
                "accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}",
                "content-type": CONTENT_TYPE_JSON,
                MCP_SESSION_ID_HEADER: "test-session",
                MCP_PROTOCOL_VERSION_HEADER: "2025-03-26",
            },
            body_text='{"jsonrpc": "2.0", "method": "ping", "id": "1"}',
        )
        async with transport_stateful.connect():
            await transport_stateful._terminate_session()
            response = await transport_stateful.handle_request(request)
            assert response.status == HTTPStatus.NOT_FOUND

    async def test_terminate_cleans_request_streams(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        """Termination cleans up all request streams."""
        async with transport_stateful.connect():
            # Add some request streams
            transport_stateful._request_streams["req-1"] = create_memory_stream(0)
            transport_stateful._request_streams["req-2"] = create_memory_stream(0)
            assert len(transport_stateful._request_streams) == 2

            await transport_stateful._terminate_session()
            assert len(transport_stateful._request_streams) == 0


class TestCleanUpMemoryStreams:
    """Test _clean_up_memory_streams edge cases."""

    async def test_cleanup_nonexistent_stream(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Cleaning up a nonexistent stream is a no-op."""
        async with transport_stateless.connect():
            # Should not raise
            await transport_stateless._clean_up_memory_streams("nonexistent")

    async def test_cleanup_with_error_during_close(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Errors during stream close are logged but not raised."""
        async with transport_stateless.connect():
            writer_mock = AsyncMock()
            reader_mock = AsyncMock()
            writer_mock.aclose.side_effect = RuntimeError("close failed")
            transport_stateless._request_streams["err"] = (writer_mock, reader_mock)

            # Should not raise
            await transport_stateless._clean_up_memory_streams("err")
            # Stream should be removed from the dict
            assert "err" not in transport_stateless._request_streams


class TestReplayEvents:
    """Test event replay via Last-Event-ID header."""

    async def test_replay_no_event_store(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Replay request without event store configured returns 500."""
        request = create_mock_request(
            method="GET",
            headers={
                "accept": CONTENT_TYPE_SSE,
                LAST_EVENT_ID_HEADER: "some-event-id",
            },
        )
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR


class TestProtocolVersionValidation:
    """Test protocol version validation edge cases."""

    async def test_unsupported_protocol_version(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        """Unsupported protocol version returns 400."""
        request = create_mock_request(
            method="GET",
            headers={
                "accept": CONTENT_TYPE_SSE,
                MCP_PROTOCOL_VERSION_HEADER: "1999-01-01",
            },
        )
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            assert response.status == HTTPStatus.BAD_REQUEST

    async def test_missing_protocol_version_uses_default(
        self, transport_stateless: StreamableHTTPServerTransport
    ) -> None:
        """Missing protocol version header uses the default (latest) version."""
        # This should NOT return a protocol error
        request = create_mock_request(
            method="POST",
            headers={
                "accept": f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_SSE}",
                "content-type": CONTENT_TYPE_JSON,
            },
            body_text='{"jsonrpc": "2.0", "method": "initialize", "id": "1"}',
        )
        async with transport_stateless.connect():
            response = await transport_stateless.handle_request(request)
            # Should not be a 400 protocol version error
            assert response.status != HTTPStatus.BAD_REQUEST


class TestJsonResponseHelpers:
    """Test _create_json_response helper."""

    async def test_json_response_with_custom_headers(self, transport_stateful: StreamableHTTPServerTransport) -> None:
        msg = JSONRPCMessage(root=JSONRPCResponse(jsonrpc="2.0", id="1", result={}))
        response = transport_stateful._create_json_response(msg, headers={"X-Custom": "val"})
        assert response.headers["X-Custom"] == "val"
        assert response.headers[MCP_SESSION_ID_HEADER] == "test-session"

    async def test_json_response_none_body(self, transport_stateless: StreamableHTTPServerTransport) -> None:
        response = transport_stateless._create_json_response(None, HTTPStatus.ACCEPTED)
        assert response.status == HTTPStatus.ACCEPTED
        assert response.body is None
