import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from mcp import ClientSession
from mcp.client.sse import sse_client

from aiohttp_mcp import AiohttpMCP, AppBuilder, build_mcp_app, setup_mcp_subapp

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
    app_builder = AppBuilder(mcp, path=TEST_PATH)

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


def register_mcp_resources(mcp: AiohttpMCP) -> None:
    """Register MCP resources."""

    @mcp.tool()
    def echo_tool(message: str) -> str:
        """Echo a message as a tool"""
        return f"Tool echo: {message}"

    @mcp.resource("echo://{message}")
    def echo_resource(message: str) -> str:
        """Echo a message as a resource. The is template resource"""
        return f"Resource echo: {message}"

    @mcp.resource("config://my-config")
    def config_resource() -> str:
        """Return a config resource. This is static resource"""
        return "This is a config resource"

    @mcp.prompt()
    def echo_prompt(message: str) -> str:
        """Create an echo prompt"""
        return f"Please process this message: {message}"


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
async def test_mcp_apps(mcp: AiohttpMCP, request: pytest.FixtureRequest, app_fixture: str) -> None:
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

            # Resources
            resources_result = await session.list_resources()
            resources = resources_result.resources
            assert len(resources) == 1

            resource_templates_result = await session.list_resource_templates()
            resource_templates = resource_templates_result.resourceTemplates
            assert len(resource_templates) == 1

            # Prompts
            prompts_result = await session.list_prompts()
            prompts = prompts_result.prompts
            assert len(prompts) == 1
