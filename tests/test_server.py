"""Tests for MCPServer JSON-RPC dispatch engine.

Tests the full dispatch loop using memory streams — the core of the
native MCP protocol implementation.
"""

import asyncio
from typing import Any

import pytest

from aiohttp_mcp.protocol.context import Context
from aiohttp_mcp.protocol.messages import SessionMessage
from aiohttp_mcp.protocol.models import (
    LATEST_PROTOCOL_VERSION,
    METHOD_NOT_FOUND,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)
from aiohttp_mcp.protocol.registry import Registry
from aiohttp_mcp.protocol.server import MCPServer
from aiohttp_mcp.protocol.streams import create_memory_stream


async def _run_request(server: MCPServer, request: JSONRPCRequest) -> dict[str, Any]:
    """Helper: send a single request through the server and return the response result."""
    read_writer, read_reader = create_memory_stream(0)  # type: ignore[var-annotated]
    write_writer, write_reader = create_memory_stream(0)  # type: ignore[var-annotated]

    msg = SessionMessage(message=JSONRPCMessage(root=request))
    await read_writer.send(msg)
    await read_writer.aclose()

    server_task = asyncio.create_task(server.run(read_reader, write_writer))

    # Collect the first response/error (with timeout to avoid hangs)
    result: dict[str, Any] = {}
    try:
        async with asyncio.timeout(5.0):
            async for session_msg in write_reader:
                root = session_msg.message.root
                if isinstance(root, JSONRPCResponse):
                    result = root.result
                    break
                if isinstance(root, JSONRPCError):
                    result = {"_error": root.error.model_dump()}
                    break
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    return result


@pytest.fixture
def registry() -> Registry:
    reg = Registry()

    def echo_tool(message: str) -> str:
        """Echo a message back."""
        return f"Echo: {message}"

    def failing_tool() -> str:
        """A tool that always fails."""
        raise ValueError("Something went wrong")

    async def context_tool(ctx: Context[Any]) -> str:
        """A tool that reads context."""
        return f"request_id={ctx.request_id}"

    reg.register_tool(echo_tool)
    reg.register_tool(failing_tool)
    reg.register_tool(context_tool)

    reg.register_resource(
        lambda: "resource content",
        uri="test://resource",
        name="test_resource",
        description="A test resource",
    )

    reg.register_resource(
        lambda msg: f"echo: {msg}",
        uri="echo://{msg}",
        name="echo_resource",
        description="Echo resource",
    )

    reg.register_prompt(
        lambda topic: f"Write about {topic}",
        name="writer",
        description="Writing prompt",
    )

    return reg


@pytest.fixture
def server(registry: Registry) -> MCPServer:
    return MCPServer(name="test-server", version="1.0.0", registry=registry)


class TestInitialize:
    async def test_initialize_returns_server_info(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="initialize", params={"protocolVersion": LATEST_PROTOCOL_VERSION}),
        )
        assert result["protocolVersion"] == LATEST_PROTOCOL_VERSION
        assert result["serverInfo"]["name"] == "test-server"
        assert result["serverInfo"]["version"] == "1.0.0"
        assert "tools" in result["capabilities"]
        assert "resources" in result["capabilities"]
        assert "prompts" in result["capabilities"]

    async def test_initialize_with_old_version(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="initialize", params={"protocolVersion": "2025-03-26"}),
        )
        assert result["protocolVersion"] == "2025-03-26"

    async def test_initialize_with_unsupported_version(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="initialize", params={"protocolVersion": "9999-01-01"}),
        )
        assert result["protocolVersion"] == LATEST_PROTOCOL_VERSION


class TestPing:
    async def test_ping(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="ping"),
        )
        assert result == {}


class TestToolsList:
    async def test_tools_list(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="tools/list"),
        )
        tools = result["tools"]
        names = {t["name"] for t in tools}
        assert "echo_tool" in names
        assert "failing_tool" in names
        assert "context_tool" in names


class TestToolsCall:
    async def test_call_tool_success(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="tools/call", params={"name": "echo_tool", "arguments": {"message": "hi"}}),
        )
        assert result["isError"] is False
        assert result["content"][0]["text"] == "Echo: hi"

    async def test_call_tool_error(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="tools/call", params={"name": "failing_tool", "arguments": {}}),
        )
        assert result["isError"] is True
        assert "Something went wrong" in result["content"][0]["text"]

    async def test_call_unknown_tool(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="tools/call", params={"name": "nonexistent", "arguments": {}}),
        )
        assert result["isError"] is True
        assert "Unknown tool" in result["content"][0]["text"]

    async def test_call_tool_with_context(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=42, method="tools/call", params={"name": "context_tool", "arguments": {}}),
        )
        assert result["isError"] is False
        assert "request_id=42" in result["content"][0]["text"]


class TestResources:
    async def test_resources_list(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="resources/list"),
        )
        resources = result["resources"]
        assert len(resources) == 1
        assert resources[0]["name"] == "test_resource"

    async def test_resources_read(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="resources/read", params={"uri": "test://resource"}),
        )
        assert result["contents"][0]["text"] == "resource content"

    async def test_resource_templates_list(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="resources/templates/list"),
        )
        templates = result["resourceTemplates"]
        assert len(templates) == 1
        assert templates[0]["uriTemplate"] == "echo://{msg}"


class TestPrompts:
    async def test_prompts_list(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="prompts/list"),
        )
        prompts = result["prompts"]
        assert len(prompts) == 1
        assert prompts[0]["name"] == "writer"

    async def test_prompts_get(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="prompts/get", params={"name": "writer", "arguments": {"topic": "cats"}}),
        )
        assert result["messages"][0]["content"]["text"] == "Write about cats"


class TestMethodNotFound:
    async def test_unknown_method_returns_method_not_found(self, server: MCPServer) -> None:
        result = await _run_request(
            server,
            JSONRPCRequest(id=1, method="nonexistent/method"),
        )
        assert "_error" in result
        assert result["_error"]["code"] == METHOD_NOT_FOUND


class TestNotifications:
    async def test_initialized_notification_accepted(self, server: MCPServer) -> None:
        """Notifications should not produce a response."""
        read_writer, read_reader = create_memory_stream(0)  # type: ignore[var-annotated]
        write_writer, write_reader = create_memory_stream(0)  # type: ignore[var-annotated]

        notif = JSONRPCNotification(method="notifications/initialized")
        msg = SessionMessage(message=JSONRPCMessage(root=notif))
        await read_writer.send(msg)
        await read_writer.aclose()

        server_task = asyncio.create_task(server.run(read_reader, write_writer))

        # Give the server a moment to process, then cancel
        await asyncio.sleep(0.05)
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

        # No response should be produced for notifications
        assert write_reader._queue.empty()


class TestExceptionFromStream:
    async def test_exception_in_stream_is_handled(self, server: MCPServer) -> None:
        """Exceptions received from the read stream should be logged, not crash."""
        read_writer, read_reader = create_memory_stream(0)  # type: ignore[var-annotated]
        write_writer, write_reader = create_memory_stream(0)  # type: ignore[var-annotated]

        await read_writer.send(RuntimeError("stream error"))
        await read_writer.aclose()

        server_task = asyncio.create_task(server.run(read_reader, write_writer))

        await asyncio.sleep(0.05)
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

        assert write_reader._queue.empty()


class TestContextNotifications:
    async def test_tool_can_send_log_notification(self, server: MCPServer) -> None:
        """Tools using ctx.info() should produce notifications on the write stream."""
        registry = server.registry

        async def logging_tool(ctx: Context[Any]) -> str:
            await ctx.info("Processing request")
            return "done"

        registry.register_tool(logging_tool)

        read_writer, read_reader = create_memory_stream(0)  # type: ignore[var-annotated]
        write_writer, write_reader = create_memory_stream(0)  # type: ignore[var-annotated]

        await read_writer.send(
            SessionMessage(
                message=JSONRPCMessage(
                    root=JSONRPCRequest(id=1, method="tools/call", params={"name": "logging_tool", "arguments": {}})
                )
            )
        )
        await read_writer.aclose()

        server_task = asyncio.create_task(server.run(read_reader, write_writer))

        messages: list[SessionMessage] = []
        got_response = False
        async for session_msg in write_reader:
            messages.append(session_msg)
            if isinstance(session_msg.message.root, JSONRPCResponse):
                got_response = True
                break

        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

        assert got_response
        roots = [m.message.root for m in messages]
        notifications = [r for r in roots if isinstance(r, JSONRPCNotification)]
        responses = [r for r in roots if isinstance(r, JSONRPCResponse)]

        assert len(responses) == 1
        assert len(notifications) >= 1
        assert notifications[0].method == "notifications/message"
        assert notifications[0].params is not None
        assert notifications[0].params["level"] == "info"
        assert notifications[0].params["data"] == "Processing request"
