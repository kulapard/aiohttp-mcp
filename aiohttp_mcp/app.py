import logging
from collections.abc import AsyncIterator

from aiohttp import web

from .core import AiohttpMCP
from .streamable_http_manager import StreamableHTTPSessionManager
from .utils.discover import discover_modules

__all__ = ["AppBuilder", "build_mcp_app", "setup_mcp_subapp"]

logger = logging.getLogger(__name__)


class AppBuilder:
    """Aiohttp application builder for MCP server (Streamable HTTP transport)."""

    __slots__ = ("_mcp", "_path", "_session_manager")

    def __init__(
        self,
        *,
        mcp: AiohttpMCP,
        path: str = "/mcp",
        json_response: bool = False,
        stateless: bool = True,
    ) -> None:
        self._mcp = mcp
        self._path = path

        self._session_manager = StreamableHTTPSessionManager(
            server=self._mcp.server,
            event_store=self._mcp.event_store,
            json_response=json_response,
            stateless=stateless,
        )

    @property
    def path(self) -> str:
        """Return the path for the MCP server."""
        return self._path

    def build(self, is_subapp: bool = False) -> web.Application:
        """Build the MCP server application."""
        app = web.Application()

        if is_subapp:
            self.setup_routes(app, path="")
        else:
            self.setup_routes(app, path=self._path)
        return app

    def setup_routes(self, app: web.Application, path: str) -> None:
        """Setup routes for the MCP server (Streamable HTTP)."""

        async def _setup_session_manager(_app: web.Application) -> AsyncIterator[None]:
            async with self._session_manager.run():
                yield

        app.cleanup_ctx.append(_setup_session_manager)
        app.router.add_route("*", path, self.streamable_http_handler)

    async def streamable_http_handler(self, request: web.Request) -> web.StreamResponse:
        """Handle requests in streamable HTTP mode."""
        return await self._session_manager.handle_request(request)


def build_mcp_app(
    mcp: AiohttpMCP,
    path: str = "/mcp",
    is_subapp: bool = False,
    json_response: bool = False,
    stateless: bool = True,
) -> web.Application:
    """Build the MCP server application."""
    return AppBuilder(
        mcp=mcp,
        path=path,
        json_response=json_response,
        stateless=stateless,
    ).build(is_subapp=is_subapp)


def setup_mcp_subapp(
    app: web.Application,
    mcp: AiohttpMCP,
    prefix: str = "/mcp",
    package_names: list[str] | None = None,
    json_response: bool = False,
    stateless: bool = True,
) -> None:
    """Set up the MCP server sub-application with the given prefix."""
    discover_modules(package_names)

    mcp_app = build_mcp_app(
        mcp,
        prefix,
        is_subapp=True,
        json_response=json_response,
        stateless=stateless,
    )
    app.add_subapp(prefix, mcp_app)

    mcp.setup_app(app)
