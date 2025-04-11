from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from mcp.types import TextContent

from aiohttp_mcp import AiohttpMCP
from aiohttp_mcp.types import Tool

# Set the pytest marker for async tests/fixtures
pytestmark = pytest.mark.anyio


async def test_tool_registration(mcp: AiohttpMCP) -> None:
    @mcp.tool()
    def get_time(timezone: str) -> str:
        """Get the current time in the specified timezone."""
        tz = ZoneInfo(timezone)
        return datetime.now(tz).isoformat()

    # Test the tool directly
    result: str = get_time("UTC")
    assert isinstance(result, str)
    assert "T" in result  # ISO format contains T between date and time

    # Test tool registration
    tools: list[Tool] = await mcp.list_tools()
    assert len(tools) == 1
    tool: Tool = tools[0]
    assert tool.name == "get_time"
    assert tool.description == "Get the current time in the specified timezone."
    assert "timezone" in tool.inputSchema["properties"]


async def test_tool_execution(mcp: AiohttpMCP) -> None:
    @mcp.tool()
    def add_numbers(a: int, b: int) -> int:
        """Add two numbers together."""
        return a + b

    # Test tool execution
    result = add_numbers(2, 3)
    assert result == 5

    # Test tool execution through MCP
    tools: list[Tool] = await mcp.list_tools()
    tool: Tool = next(t for t in tools if t.name == "add_numbers")
    result = await mcp.call_tool(tool.name, {"a": 4, "b": 5})
    assert isinstance(result, list)
    assert len(result) == 1
    content = result[0]
    assert isinstance(content, TextContent)
    assert content.text == "9"
