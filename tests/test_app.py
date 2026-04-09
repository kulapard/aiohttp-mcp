import logging
from unittest.mock import MagicMock

import pytest
from aiohttp import web

from aiohttp_mcp import AiohttpMCP, AppBuilder, build_mcp_app, setup_mcp_subapp

logger = logging.getLogger(__name__)

TEST_PATH = "/test-mcp"


@pytest.fixture
def standalone_app(mcp: AiohttpMCP) -> web.Application:
    return build_mcp_app(mcp, path=TEST_PATH)


@pytest.fixture
def subapp(mcp: AiohttpMCP) -> web.Application:
    app = web.Application()
    setup_mcp_subapp(app, mcp, prefix=TEST_PATH)
    return app


def has_route(app: web.Application, path: str) -> bool:
    """Check if the given path exists in the app."""
    return any(
        route.resource is not None and route.resource.canonical == path for route in app.router.routes()
    )


@pytest.mark.parametrize("app_fixture", ["standalone_app", "subapp"])
async def test_app_initialization(mcp: AiohttpMCP, request: pytest.FixtureRequest, app_fixture: str) -> None:
    """Test MCP functionality with different types of apps."""
    app = request.getfixturevalue(app_fixture)
    assert isinstance(app, web.Application), type(app)
    assert has_route(app, TEST_PATH)


async def test_streamable_http_app_initialization() -> None:
    """Test that streamable HTTP transport mode initializes correctly."""
    mcp = AiohttpMCP()
    app = build_mcp_app(mcp, path=TEST_PATH)

    assert isinstance(app, web.Application)
    assert any(route.resource is not None and route.resource.canonical == TEST_PATH for route in app.router.routes())


async def test_streamable_http_app_with_json_response() -> None:
    """Test streamable HTTP transport with JSON response mode."""
    mcp = AiohttpMCP()
    app = build_mcp_app(mcp, path=TEST_PATH, json_response=True)
    assert isinstance(app, web.Application)


async def test_streamable_http_app_stateless_mode() -> None:
    """Test streamable HTTP transport in stateless mode."""
    mcp = AiohttpMCP()
    app = build_mcp_app(mcp, path=TEST_PATH, stateless=True)
    assert isinstance(app, web.Application)


async def test_app_builder_path_property() -> None:
    """Test AppBuilder path property."""
    mcp = AiohttpMCP()
    app_builder = AppBuilder(mcp=mcp, path="/custom/path")
    assert app_builder.path == "/custom/path"


async def test_streamable_handler_without_initialization() -> None:
    """Test streamable HTTP handler when session manager is not running."""
    mcp = AiohttpMCP()
    app_builder = AppBuilder(mcp=mcp, path=TEST_PATH)

    mock_request = MagicMock(spec=web.Request)

    with pytest.raises(RuntimeError, match="Task group is not initialized"):
        await app_builder.streamable_http_handler(mock_request)


async def test_setup_routes_with_empty_path() -> None:
    """Test route setup with empty path (for subapps)."""
    mcp = AiohttpMCP()
    app_builder = AppBuilder(mcp=mcp, path=TEST_PATH)

    app = web.Application()
    app_builder.setup_routes(app, path="")

    assert has_route(app, "")
