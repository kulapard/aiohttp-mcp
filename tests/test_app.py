from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from aiohttp import web
from mcp.types import TextContent

from aiohttp_mcp import AiohttpMCP, AppBuilder, build_mcp_application, setup_mcp_application
from aiohttp_mcp.types import Tool


@pytest.fixture
def mcp() -> AiohttpMCP:
    return AiohttpMCP(debug=False)


@pytest.fixture
def app(mcp: AiohttpMCP) -> web.Application:
    return build_mcp_application(mcp, path="/mcp")


@pytest.fixture
def subapp(mcp: AiohttpMCP) -> web.Application:
    app = web.Application()
    setup_mcp_application(app, mcp, prefix="/mcp")
    return app


@pytest.fixture
def custom_app(mcp: AiohttpMCP) -> web.Application:
    app_builder = AppBuilder(mcp, path="/mcp")
    app = web.Application()
    app.router.add_get(app_builder.path, app_builder.handle_sse)
    app.router.add_post(app_builder.path, app_builder.handle_message)
    return app


@pytest.mark.asyncio
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


def has_route(app: web.Application, path: str) -> bool:
    """Check if the given path exists in the app."""
    return any(
        route.resource.canonical == path for route in app.router.routes() if isinstance(route.resource, web.Resource)
    )


@pytest.mark.asyncio
async def test_server_initialization(app: web.Application) -> None:
    assert isinstance(app, web.Application)
    assert has_route(app, "/mcp")


@pytest.mark.asyncio
async def test_subapp_initialization(subapp: web.Application) -> None:
    assert isinstance(subapp, web.Application)
    assert has_route(subapp, "/mcp")


@pytest.mark.asyncio
async def test_custom_app_initialization(custom_app: web.Application) -> None:
    assert isinstance(custom_app, web.Application)
    assert has_route(custom_app, "/mcp")


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
