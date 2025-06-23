import logging
from collections.abc import AsyncIterator
from enum import Enum

from aiohttp import web

from .core import AiohttpMCP
from .streamable_http_manager import StreamableHTTPSessionManager
from .transport import EventSourceResponse, SSEServerTransport
from .utils.discover import discover_modules

__all__ = ["AppBuilder", "TransportMode", "build_mcp_app", "setup_mcp_subapp"]

logger = logging.getLogger(__name__)


class TransportMode(str, Enum):
    """Transport modes for MCP server deployment."""

    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"

    def __str__(self) -> str:
        return self.value


class AppBuilder:
    """Aiohttp application builder for MCP server."""

    __slots__ = ("_mcp", "_path", "_session_manager", "_sse", "_transport_mode")

    def __init__(
        self,
        *,
        mcp: AiohttpMCP,
        path: str = "/mcp",
        transport_mode: TransportMode = TransportMode.SSE,
        json_response: bool = False,
        stateless: bool = False,
    ) -> None:
        self._mcp = mcp
        self._path = path

        self._sse: SSEServerTransport | None = None
        self._session_manager: StreamableHTTPSessionManager | None = None

        self._transport_mode = transport_mode

        if transport_mode == TransportMode.SSE:
            self._sse = SSEServerTransport(path)
        elif transport_mode == TransportMode.STREAMABLE_HTTP:
            self._session_manager = StreamableHTTPSessionManager(
                server=self._mcp.server,
                event_store=self._mcp.event_store,
                json_response=json_response,
                stateless=stateless,
            )
        else:
            raise ValueError(f"Unsupported transport mode: {transport_mode}")

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
        if self._transport_mode == TransportMode.SSE:
            app.router.add_get(path, self.sse_handler)
            app.router.add_post(path, self.message_handler)
        elif self._transport_mode == TransportMode.STREAMABLE_HTTP:

            async def _setup_session_manager(_app: web.Application) -> AsyncIterator[None]:
                if self._session_manager is None:
                    raise RuntimeError("Session manager not initialized")
                async with self._session_manager.run():
                    yield

            app.cleanup_ctx.append(_setup_session_manager)
            app.router.add_route("*", path, self.streamable_http_handler)

    async def sse_handler(self, request: web.Request) -> EventSourceResponse:
        """Handle the SSE connection and start the MCP server."""
        if self._sse is None:
            raise RuntimeError("SSE transport not initialized")
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
        if self._sse is None:
            raise RuntimeError("SSE transport not initialized")
        return await self._sse.handle_post_message(request)

    async def streamable_http_handler(self, request: web.Request) -> web.StreamResponse:
        """Handle requests in streamable HTTP mode."""
        if self._session_manager is None:
            raise RuntimeError("Session manager not initialized")
        return await self._session_manager.handle_request(request)


def build_mcp_app(
    mcp_registry: AiohttpMCP,
    path: str = "/mcp",
    is_subapp: bool = False,
    transport_mode: TransportMode = TransportMode.SSE,
    json_response: bool = False,
    stateless: bool = False,
) -> web.Application:
    """Build the MCP server application."""
    return AppBuilder(
        mcp=mcp_registry,
        path=path,
        transport_mode=transport_mode,
        json_response=json_response,
        stateless=stateless,
    ).build(is_subapp=is_subapp)


def setup_mcp_subapp(
    app: web.Application,
    mcp_registry: AiohttpMCP,
    prefix: str = "/mcp",
    package_names: list[str] | None = None,
    transport_mode: TransportMode = TransportMode.SSE,
    json_response: bool = False,
    stateless: bool = False,
) -> None:
    """Set up the MCP server sub-application with the given prefix."""
    # Go through the discovery process to find all decorated functions
    discover_modules(package_names)

    mcp_app = build_mcp_app(
        mcp_registry,
        prefix,
        is_subapp=True,
        transport_mode=transport_mode,
        json_response=json_response,
        stateless=stateless,
    )
    app.add_subapp(prefix, mcp_app)

    # Store the main app in the MCP registry for access from tools
    mcp_registry.setup_app(app)
