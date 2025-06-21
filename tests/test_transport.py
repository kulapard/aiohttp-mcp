import logging
import uuid
from collections.abc import AsyncIterator

import mcp.types as types
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

from aiohttp_mcp.transport import (
    Event,
    EventType,
    MessageConverter,
    SSEServerTransport,
    Stream,
)

logger = logging.getLogger(__name__)

# Set the pytest marker for async tests/fixtures
pytestmark = pytest.mark.anyio


@pytest.fixture
def transport() -> SSEServerTransport:
    return SSEServerTransport(message_path="/messages")


async def echo(
    reader: MemoryObjectReceiveStream[SessionMessage | Exception],
    writer: MemoryObjectSendStream[SessionMessage | Exception],
) -> None:
    """Send messages from reader to writer."""
    async for message in reader:
        await writer.send(message)


@pytest.fixture
def app(transport: SSEServerTransport) -> web.Application:
    app = web.Application()

    async def sse_handler(request: web.Request) -> web.StreamResponse:
        async with transport.connect_sse(request) as sse_connection:
            # Read stream to avoid blocking the connection
            await echo(sse_connection.read_stream, sse_connection.write_stream)
        return sse_connection.response

    app.router.add_get("/sse", sse_handler)
    app.router.add_post("/messages", transport.handle_post_message)
    return app


@pytest.fixture
async def aiohttp_client(app: web.Application) -> AsyncIterator[TestClient[web.Request, web.Application]]:
    client = TestClient(TestServer(app))
    await client.start_server()
    yield client
    await client.close()


@pytest.fixture
def valid_message() -> JSONRPCMessage:
    return types.JSONRPCMessage(root=types.JSONRPCRequest(jsonrpc="2.0", id=1, method="test", params={"foo": "bar"}))


@pytest.fixture
def valid_session_message(valid_message: JSONRPCMessage) -> SessionMessage:
    """Create a valid session message from a JSONRPCRequest."""
    return SessionMessage(
        message=valid_message,
        metadata=ServerMessageMetadata(),
    )


class TestMessageConverter:
    def test_to_string_with_jsonrpc_message(self, valid_session_message: SessionMessage) -> None:
        result = MessageConverter.to_string(valid_session_message)
        assert isinstance(result, str)
        assert "id" in result
        assert "method" in result
        assert "jsonrpc" in result

    def test_to_string_with_exception(self) -> None:
        msg = ValueError("test error")
        result = MessageConverter.to_string(msg)
        assert result == "test error"

    def test_to_event_with_jsonrpc_message(self, valid_session_message: SessionMessage) -> None:
        event = MessageConverter.to_event(valid_session_message)
        assert isinstance(event, Event)
        assert event.event_type == EventType.MESSAGE
        assert "id" in event.data
        assert "method" in event.data
        assert "jsonrpc" in event.data

    def test_to_event_with_exception(self) -> None:
        msg = ValueError("test error")
        event = MessageConverter.to_event(msg)
        assert isinstance(event, Event)
        assert event.event_type == EventType.MESSAGE
        assert event.data == "test error"

    def test_from_json(self) -> None:
        json_data = '{"jsonrpc": "2.0", "id": "1", "method": "test", "params": {"foo": "bar"}}'
        msg = MessageConverter.from_json(json_data)
        assert isinstance(msg, JSONRPCMessage)
        request = msg.root
        assert isinstance(request, JSONRPCRequest)
        assert request.id == 1  # Access id through the root object
        assert request.method == "test"
        assert request.jsonrpc == "2.0"


class TestStream:
    async def test_create(self) -> None:
        stream: Stream[str] = Stream.create()
        assert isinstance(stream.reader, MemoryObjectReceiveStream)
        assert isinstance(stream.writer, MemoryObjectSendStream)

    async def test_close(self) -> None:
        stream: Stream[str] = Stream.create()
        await stream.close()
        assert stream.reader._closed
        assert stream.writer._closed


class TestSSEServerTransport:
    async def test_connect_sse(self, aiohttp_client: TestClient[web.Request, web.Application]) -> None:
        async with aiohttp_client.get("/sse") as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "text/event-stream"
            assert response.headers["Cache-Control"] == "no-cache"
            assert response.headers["Connection"] == "keep-alive"

            # Read the first event which should be the endpoint
            event = await response.content.readline()
            assert b"event: endpoint" in event

            data = await response.content.readline()
            assert b"data: " in data
            session_uri = data.decode().replace("data: ", "").strip()
            assert session_uri.startswith("/messages?session_id=")

    async def test_handle_post_message_success(
        self, aiohttp_client: TestClient[web.Request, web.Application], valid_message: types.JSONRPCRequest
    ) -> None:
        # Start SSE connection
        async with aiohttp_client.get("/sse") as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "text/event-stream"
            assert response.headers["Cache-Control"] == "no-cache"
            assert response.headers["Connection"] == "keep-alive"

            # Read the first event which should be the endpoint
            event = await response.content.readline()
            assert b"event: endpoint" in event

            data = await response.content.readline()
            assert b"data: " in data
            session_uri = data.decode().replace("data: ", "").strip()
            assert session_uri.startswith("/messages?session_id=")
            # CHeck empty line after data
            empty_line = await response.content.readline()
            assert empty_line == b"\r\n"

            # Send message and verify response
            post_response = await aiohttp_client.post(
                session_uri,
                json=valid_message.model_dump(),
                headers={"Content-Type": "application/json"},
            )
            assert post_response.status == 202
            response_text = await post_response.text()
            assert response_text == "Accepted"

            # Check if the message was sent to the SSE stream
            event = await response.content.readline()
            assert b"event: message" in event
            data = await response.content.readline()
            assert b"data: " in data
            msg = data.decode().replace("data: ", "").strip()
            assert msg == valid_message.model_dump_json(by_alias=True, exclude_none=True)

    async def test_handle_post_message_wrong_status(
        self, aiohttp_client: TestClient[web.Request, web.Application], valid_message: types.JSONRPCRequest
    ) -> None:
        # Start SSE connection
        async with aiohttp_client.get("/sse") as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "text/event-stream"
            assert response.headers["Cache-Control"] == "no-cache"
            assert response.headers["Connection"] == "keep-alive"

            # Read the first event which should be the endpoint
            event = await response.content.readline()
            assert b"event: endpoint" in event

            data = await response.content.readline()
            assert b"data: " in data
            session_uri = data.decode().replace("data: ", "").strip()
            assert session_uri.startswith("/messages?session_id=")

            # Close the SSE connection by closing the response
            response.close()

            # Send message and verify response
            post_response = await aiohttp_client.post(
                session_uri,
                json=valid_message.model_dump(),
                headers={"Content-Type": "application/json"},
            )
            assert post_response.status == 404
            response_text = await post_response.text()
            assert response_text == "Could not find session"

    async def test_handle_post_message_missing_session_id(
        self,
        aiohttp_client: TestClient[web.Request, web.Application],
    ) -> None:
        response = await aiohttp_client.post("/messages")
        assert response.status == 400
        assert await response.text() == "No session ID provided"

    async def test_handle_post_message_invalid_session_id(
        self,
        aiohttp_client: TestClient[web.Request, web.Application],
    ) -> None:
        response = await aiohttp_client.post(
            "/messages",
            params={"session_id": "invalid"},
        )
        assert response.status == 400
        assert await response.text() == "Invalid session ID"

    async def test_handle_post_message_session_not_found(
        self,
        aiohttp_client: TestClient[web.Request, web.Application],
    ) -> None:
        response = await aiohttp_client.post(
            "/messages",
            params={"session_id": str(uuid.uuid4())},
            json={"jsonrpc": "2.0", "id": "1", "method": "test", "params": {}},
        )
        assert response.status == 404
        assert await response.text() == "Could not find session"

    async def test_handle_post_message_invalid_json(
        self, aiohttp_client: TestClient[web.Request, web.Application]
    ) -> None:
        # Start SSE connection
        async with aiohttp_client.get("/sse") as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "text/event-stream"
            assert response.headers["Cache-Control"] == "no-cache"
            assert response.headers["Connection"] == "keep-alive"

            # Read the first event which should be the endpoint
            event = await response.content.readline()
            assert b"event: endpoint" in event

            data = await response.content.readline()
            assert b"data: " in data
            session_uri = data.decode().replace("data: ", "").strip()
            assert session_uri.startswith("/messages?session_id=")

            # Send invalid JSON and verify response
            post_response = await aiohttp_client.post(
                session_uri,
                data="invalid json",
                headers={"Content-Type": "application/json"},
            )
            assert post_response.status == 400
            response_text = await post_response.text()
            assert response_text == "Could not parse message"
