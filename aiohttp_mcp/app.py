import logging

from aiohttp import web

from .core import AiohttpMCP
from .transport import EventSourceResponse, SSEServerTransport
from .utils.discover import discover_modules

__all__ = ["AppBuilder", "build_mcp_app", "setup_mcp_subapp"]

logger = logging.getLogger(__name__)


class AppBuilder:
    """Aiohttp application builder for MCP server."""

    __slots__ = ("_mcp", "_path", "_sse")

    def __init__(self, mcp: AiohttpMCP, path: str = "/mcp") -> None:
        self._mcp = mcp
        self._sse = SSEServerTransport(path)
        self._path = path

    @property
    def path(self) -> str:
        """Return the path for the MCP server."""
        return self._path

    def build(self, is_subapp: bool = False) -> web.Application:
        """Build the MCP server application."""
        app = web.Application()

        if is_subapp:
            # Use empty path due to building the app to use as a subapp with a prefix
            self.setup_routes(app, path="")
        else:
            # Use the provided path for the main app
            self.setup_routes(app, path=self._path)
        return app

    def setup_routes(self, app: web.Application, path: str) -> None:
        """Setup routes for the MCP server.
        1. GET: Handles the SSE connection.
        2. POST: Handles incoming messages.
        """
        # Use empty path due to building the app to use as a subapp with a prefix
        app.router.add_get(path, self.sse_handler)
        app.router.add_post(path, self.message_handler)

    async def sse_handler(self, request: web.Request) -> EventSourceResponse:
        """Handle the SSE connection and start the MCP server."""
        async with self._sse.connect_sse(request) as sse_connection:
            await self._mcp.server.run(
                read_stream=sse_connection.read_stream,
                write_stream=sse_connection.write_stream,
                initialization_options=self._mcp.server.create_initialization_options(),
                raise_exceptions=False,
            )
        return sse_connection.response

    async def message_handler(self, request: web.Request) -> web.Response:
        """Handle incoming messages from the client."""
        return await self._sse.handle_post_message(request)


def build_mcp_app(
    mcp_registry: AiohttpMCP,
    path: str = "/mcp",
    is_subapp: bool = False,
) -> web.Application:
    """Build the MCP server application."""
    return AppBuilder(mcp_registry, path).build(is_subapp=is_subapp)


def setup_mcp_subapp(
    app: web.Application,
    mcp_registry: AiohttpMCP,
    prefix: str = "/mcp",
    package_names: list[str] | None = None,
) -> None:
    """Set up the MCP server sub-application with the given prefix."""
    # Go through the discovery process to find all decorated functions
    discover_modules(package_names)

    mcp_app = build_mcp_app(mcp_registry, prefix, is_subapp=True)
    app.add_subapp(prefix, mcp_app)
