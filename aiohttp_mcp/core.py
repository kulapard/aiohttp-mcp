import logging

from aiohttp import web

from .registry import mcp
from .transport import EventSourceResponse, SSEServerTransport
from .utils.discover import discover_modules

__all__ = ["setup_mcp_server"]

logger = logging.getLogger(__name__)


class AiohttpMCPServer:
    """Aiohttp MCP server."""

    __slots__ = ("_path", "_sse")

    def __init__(self, path: str = "/mcp") -> None:
        self._path = path
        self._sse = SSEServerTransport(path)

    def setup_routes(self, app: web.Application) -> None:
        """Setup routes for the MCP server.
        1. GET /mcp: Handles the SSE connection.
        2. POST /mcp: Handles incoming messages.
        """
        app.router.add_get(self._path, self.handle_sse)
        app.router.add_post(self._path, self.handle_message)

    async def handle_sse(self, request: web.Request) -> EventSourceResponse:
        """Handle the SSE connection and start the MCP server."""
        async with self._sse.connect_sse(request) as sse_connection:
            await mcp.server.run(
                read_stream=sse_connection.read_stream,
                write_stream=sse_connection.write_stream,
                initialization_options=mcp.server.create_initialization_options(),
                raise_exceptions=False,
            )
        return sse_connection.response

    async def handle_message(self, request: web.Request) -> web.Response:
        """Handle incoming messages from the client."""
        return await self._sse.handle_post_message(request)


def setup_mcp_server(
    app: web.Application,
    path: str = "/mcp",
    package_names: list[str] | None = None,
) -> None:
    # Go through the discovery process to find all decorated functions
    discover_modules(package_names)

    mcp_server = AiohttpMCPServer(path=path)
    mcp_server.setup_routes(app)
