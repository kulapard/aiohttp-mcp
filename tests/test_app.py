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


PATH = "/test-mcp"


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
    return f"http://{server.host}:{server.port}{PATH}"


@asynccontextmanager
async def mcp_client_session(mcp_server_url: str) -> AsyncIterator[ClientSession]:
    async with sse_client(mcp_server_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@pytest.fixture
def standalone_app(mcp: AiohttpMCP) -> web.Application:
    return build_mcp_app(mcp, path=PATH)


@pytest.fixture
def subapp(mcp: AiohttpMCP) -> web.Application:
    app = web.Application()
    setup_mcp_subapp(app, mcp, prefix=PATH)
    return app


@pytest.fixture
def custom_app(mcp: AiohttpMCP) -> web.Application:
    app_builder = AppBuilder(mcp, path=PATH)

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


async def test_server_initialization(standalone_app: web.Application) -> None:
    assert isinstance(standalone_app, web.Application), type(standalone_app)
    assert has_route(standalone_app, "GET", PATH)
    assert has_route(standalone_app, "POST", PATH)


async def test_subapp_initialization(subapp: web.Application) -> None:
    assert isinstance(subapp, web.Application)
    assert has_route(subapp, "GET", PATH)
    assert has_route(subapp, "POST", PATH)


async def test_custom_app_initialization(custom_app: web.Application) -> None:
    assert isinstance(custom_app, web.Application)
    assert has_route(custom_app, "GET", PATH)
    assert has_route(custom_app, "POST", PATH)


async def test_standalone_app(standalone_app: web.Application) -> None:
    async with aiohttp_server(standalone_app) as server:
        url = get_mcp_server_url(server)
        async with mcp_client_session(url) as session:
            response = await session.list_tools()
            tools = response.tools
            assert len(tools) == 0


async def test_subapp(subapp: web.Application) -> None:
    async with aiohttp_server(subapp) as server:
        url = get_mcp_server_url(server)
        async with mcp_client_session(url) as session:
            response = await session.list_tools()
            tools = response.tools
            assert len(tools) == 0


async def test_custom_app(custom_app: web.Application) -> None:
    async with aiohttp_server(custom_app) as server:
        url = get_mcp_server_url(server)
        async with mcp_client_session(url) as session:
            response = await session.list_tools()
            tools = response.tools
            assert len(tools) == 0
