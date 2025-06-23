import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.types import TextContent, TextResourceContents
from pydantic import AnyUrl

from aiohttp_mcp import AiohttpMCP, AppBuilder, build_mcp_app, setup_mcp_subapp

from .utils import register_mcp_resources

logger = logging.getLogger(__name__)

# Set the pytest marker for async tests/fixtures
pytestmark = pytest.mark.anyio


TEST_PATH = "/test-mcp"


@asynccontextmanager
async def aiohttp_server(app: web.Application) -> AsyncIterator[TestServer]:
    server = TestServer(app)
    await server.start_server()
    yield server
    await server.close()


@asynccontextmanager
async def aiohttp_client(app: web.Application) -> AsyncIterator[TestClient[web.Request, web.Application]]:
    client = TestClient(TestServer(app))
    await client.start_server()
    yield client
    await client.close()


def get_mcp_server_url(server: TestServer) -> str:
    return f"http://{server.host}:{server.port}{TEST_PATH}"


@asynccontextmanager
async def mcp_client_session(mcp_server_url: str) -> AsyncIterator[ClientSession]:
    async with sse_client(mcp_server_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@pytest.fixture
def standalone_app(mcp: AiohttpMCP) -> web.Application:
    return build_mcp_app(mcp, path=TEST_PATH)


@pytest.fixture
def subapp(mcp: AiohttpMCP) -> web.Application:
    app = web.Application()
    setup_mcp_subapp(app, mcp, prefix=TEST_PATH)
    return app


@pytest.fixture
def custom_app(mcp: AiohttpMCP) -> web.Application:
    app_builder = AppBuilder(mcp=mcp, path=TEST_PATH)

    async def custom_sse_handler(request: web.Request) -> web.StreamResponse:
        """Custom SSE handler."""
        logger.info("Do something before starting the SSE connection")
        response = await app_builder.sse_handler(request)
        logger.info("Do something after closing the SSE connection")
        return response

    async def custom_message_handler(request: web.Request) -> web.Response:
        """Custom message handler."""
        logger.info("Do something before sending the message")
        response = await app_builder.message_handler(request)
        logger.info("Do something after sending the message")
        return response

    app = web.Application()
    app.router.add_get(app_builder.path, custom_sse_handler)
    app.router.add_post(app_builder.path, custom_message_handler)
    return app


def has_route(app: web.Application, method: str, path: str) -> bool:
    """Check if the given path exists in the app."""
    return any(
        route.resource.canonical == path and route.method == method
        for route in app.router.routes()
        if isinstance(route.resource, web.Resource)
    )


@pytest.mark.parametrize("app_fixture", ["standalone_app", "subapp", "custom_app"])
async def test_app_initialization(mcp: AiohttpMCP, request: pytest.FixtureRequest, app_fixture: str) -> None:
    """Test MCP functionality with different types of apps."""
    app = request.getfixturevalue(app_fixture)

    assert isinstance(app, web.Application), type(app)
    assert has_route(app, "GET", TEST_PATH)
    assert has_route(app, "POST", TEST_PATH)


@pytest.mark.parametrize("app_fixture", ["standalone_app", "subapp", "custom_app"])
async def test_mcp_app(mcp: AiohttpMCP, request: pytest.FixtureRequest, app_fixture: str) -> None:
    """Test MCP functionality with different types of apps."""
    app = request.getfixturevalue(app_fixture)

    register_mcp_resources(mcp)

    async with aiohttp_server(app) as server:
        url = get_mcp_server_url(server)
        async with mcp_client_session(url) as session:
            # Tools
            tools_result = await session.list_tools()
            tools = tools_result.tools
            assert len(tools) == 1

            # Test call_tool
            tool_result = await session.call_tool("echo_tool", {"message": "test message"})
            assert len(tool_result.content) == 1
            assert isinstance(tool_result.content[0], TextContent)
            assert tool_result.content[0].text == "Tool echo: test message"

            # Resources
            resources_result = await session.list_resources()
            assert len(resources_result.resources) == 1
            assert resources_result.resources[0].uri == AnyUrl("config://my-config")

            # Test read_resource
            resource_result = await session.read_resource(AnyUrl("config://my-config"))
            contents = resource_result.contents
            assert len(contents) == 1
            assert isinstance(contents[0], TextResourceContents)
            assert contents[0].text == "This is a config resource"

            # Resource Templates
            templates_result = await session.list_resource_templates()
            assert len(templates_result.resourceTemplates) == 1
            assert templates_result.resourceTemplates[0].uriTemplate == "echo://{message}"

            # Prompts
            prompts_result = await session.list_prompts()
            assert len(prompts_result.prompts) == 1
            assert prompts_result.prompts[0].name == "echo_prompt"

            # Test get_prompt
            prompt_result = await session.get_prompt("echo_prompt", {"message": "test prompt"})
            messages = prompt_result.messages
            assert len(messages) == 1
            message = messages[0]
            assert message.role == "user"
            assert message.content.type == "text"
            assert message.content.text == "Please process this message: test prompt"
