#!/usr/bin/env python3
"""
Streamable HTTP Client Example

This example demonstrates how to interact with a Streamable HTTP MCP server.
Shows both JSON response mode and SSE streaming mode interactions.

Run this after starting the streamable_http_server.py example.
"""

import asyncio
import json
import logging
from typing import Any

import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StreamableHTTPClient:
    """Client for interacting with Streamable HTTP MCP servers."""

    def __init__(self, base_url: str, session_id: str = "client-session-123"):
        self.base_url = base_url
        self.session_id = session_id
        self.client = httpx.AsyncClient()
        self.initialized = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the client and terminate the session."""
        if self.initialized:
            try:
                await self.terminate_session()
            except Exception as e:
                logger.warning("Error terminating session: %s", e)

        await self.client.aclose()

    def _get_headers(self, content_type: str = "application/json") -> dict[str, str]:
        """Get standard headers for requests."""
        return {
            "Content-Type": content_type,
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": self.session_id,
            "mcp-protocol-version": "2025-03-26",
        }

    async def initialize(self) -> dict[str, Any]:
        """Initialize the MCP session."""
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                "clientInfo": {"name": "streamable-http-client", "version": "1.0.0"},
            },
        }

        logger.info("Initializing MCP session...")
        response = await self.client.post(f"{self.base_url}/mcp", json=init_request, headers=self._get_headers())

        if response.status_code == 200:
            if response.headers.get("Content-Type", "").startswith("application/json"):
                result = response.json()
                self.initialized = True
                logger.info("Session initialized successfully")
                return result
            else:
                # Handle SSE response
                logger.info("Received SSE response for initialization")
                return await self._handle_sse_response(response)
        else:
            raise Exception(f"Failed to initialize: {response.status_code} - {response.text}")

    async def _handle_sse_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle Server-Sent Events response."""
        result = None

        async for line in response.aiter_lines():
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])  # Remove "data: " prefix
                    logger.info("SSE data: %s", data)
                    if not result:  # Take the first response as the result
                        result = data
                except json.JSONDecodeError as e:
                    logger.warning("Failed to parse SSE data: %s", e)

        return result or {}

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any], use_json_response: bool = True
    ) -> dict[str, Any]:
        """Call a tool on the MCP server."""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

        logger.info("Calling tool: %s with args: %s", tool_name, arguments)

        headers = self._get_headers()
        if not use_json_response:
            # Request SSE response by not accepting JSON
            headers["Accept"] = "text/event-stream"

        response = await self.client.post(f"{self.base_url}/mcp", json=request, headers=headers)

        if response.status_code == 200:
            if response.headers.get("Content-Type", "").startswith("application/json"):
                return response.json()
            else:
                return await self._handle_sse_response(response)
        else:
            raise Exception(f"Tool call failed: {response.status_code} - {response.text}")

    async def list_tools(self) -> dict[str, Any]:
        """List available tools."""
        request = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}

        logger.info("Listing available tools...")
        response = await self.client.post(f"{self.base_url}/mcp", json=request, headers=self._get_headers())

        if response.status_code == 200:
            if response.headers.get("Content-Type", "").startswith("application/json"):
                return response.json()
            else:
                return await self._handle_sse_response(response)
        else:
            raise Exception(f"Failed to list tools: {response.status_code} - {response.text}")

    async def get_sse_stream(self):
        """Get a persistent SSE stream for server-initiated messages."""
        logger.info("Opening SSE stream...")

        headers = {
            "Accept": "text/event-stream",
            "mcp-session-id": self.session_id,
            "mcp-protocol-version": "2025-03-26",
        }

        async with self.client.stream("GET", f"{self.base_url}/mcp", headers=headers) as response:
            if response.status_code == 200:
                logger.info("SSE stream established")
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            logger.info("Server message: %s", data)
                            yield data
                        except json.JSONDecodeError as e:
                            logger.warning("Failed to parse SSE data: %s", e)
            else:
                raise Exception(f"Failed to establish SSE stream: {response.status_code}")

    async def terminate_session(self):
        """Terminate the MCP session."""
        logger.info("Terminating session...")
        response = await self.client.delete(f"{self.base_url}/mcp", headers={"mcp-session-id": self.session_id})

        if response.status_code == 200:
            logger.info("Session terminated successfully")
        else:
            raise Exception(f"Failed to terminate session: {response.status_code} - {response.text}")


async def demo_json_responses():
    """Demonstrate JSON response mode."""
    logger.info("=== JSON Response Mode Demo ===")

    async with StreamableHTTPClient("http://localhost:8000") as client:
        # Initialize session
        init_result = await client.initialize()
        logger.info("Initialization result: %s", init_result)

        # List tools
        tools_result = await client.list_tools()
        logger.info("Available tools: %s", tools_result)

        # Call echo tool
        echo_result = await client.call_tool("echo_tool", {"text": "Hello, World!"})
        logger.info("Echo result: %s", echo_result)

        # Call add_numbers tool
        add_result = await client.call_tool("add_numbers", {"a": 10, "b": 5})
        logger.info("Add result: %s", add_result)

        # Call get_time tool
        time_result = await client.call_tool("get_time", {})
        logger.info("Time result: %s", time_result)


async def demo_sse_responses():
    """Demonstrate SSE response mode."""
    logger.info("=== SSE Response Mode Demo ===")

    async with StreamableHTTPClient("http://localhost:8000", "sse-session-456") as client:
        # Initialize session
        await client.initialize()

        # Call tools with SSE responses
        echo_result = await client.call_tool("echo_tool", {"text": "Hello via SSE!"}, use_json_response=False)
        logger.info("SSE Echo result: %s", echo_result)


async def demo_sse_stream():
    """Demonstrate persistent SSE stream."""
    logger.info("=== SSE Stream Demo ===")

    async with StreamableHTTPClient("http://localhost:8000", "stream-session-789") as client:
        # Initialize session
        await client.initialize()

        # This would demonstrate server-initiated messages
        # In a real scenario, the server might send notifications or requests
        logger.info("Opening SSE stream (would receive server-initiated messages)")

        # Simulate a short stream session
        try:
            count = 0
            async for message in client.get_sse_stream():
                logger.info("Received: %s", message)
                count += 1
                if count >= 3:  # Limit for demo
                    break
        except Exception as e:
            logger.info("SSE stream ended: %s", e)


async def main():
    """Run all demos."""
    logger.info("Starting Streamable HTTP Client Demo")
    logger.info("Make sure the streamable_http_server.py is running on port 8000")

    try:
        # Test server availability
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/health")
            if response.status_code != 200:
                raise Exception("Server not available")

        logger.info("Server is running, starting demos...")

        # Run demos
        await demo_json_responses()
        await asyncio.sleep(1)

        await demo_sse_responses()
        await asyncio.sleep(1)

        await demo_sse_stream()

    except Exception as e:
        logger.error("Demo failed: %s", e)
        logger.error("Make sure to run 'python examples/streamable_http_server.py' first")


if __name__ == "__main__":
    asyncio.run(main())
