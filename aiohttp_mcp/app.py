import logging
from http import HTTPStatus

import anyio
from aiohttp import web

from .core import AiohttpMCP
from .transport import EventSourceResponse, SSEServerTransport, StatelessStreamableHTTPTransport
from .types import TransportMode
from .utils.discover import discover_modules

__all__ = ["AppBuilder", "build_mcp_app", "setup_mcp_subapp"]

logger = logging.getLogger(__name__)


class AppBuilder:
    """Aiohttp application builder for MCP server."""

    __slots__ = ("_mcp", "_path", "_sse", "_streamable", "_transport_mode")

    def __init__(self, mcp: AiohttpMCP, path: str = "/mcp", transport_mode: TransportMode = TransportMode.SSE) -> None:
        self._mcp = mcp
        self._path = path
        self._transport_mode = transport_mode

        if transport_mode == TransportMode.SSE:
            self._sse: SSEServerTransport | None = SSEServerTransport(path)
            self._streamable: StatelessStreamableHTTPTransport | None = None
        elif transport_mode == TransportMode.STREAMABLE:
            self._sse = None
            self._streamable = StatelessStreamableHTTPTransport()
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
        """Setup routes for the MCP server based on transport mode."""
        if self._transport_mode == TransportMode.SSE:
            # SSE transport: GET for SSE connection, POST for messages
            app.router.add_get(path, self.sse_handler)
            app.router.add_post(path, self.message_handler)
        elif self._transport_mode == TransportMode.STREAMABLE:
            # Streamable transport: Only POST for stateless requests
            app.router.add_post(path, self.streamable_handler)
        else:
            raise ValueError(f"Unsupported transport mode: {self._transport_mode}")

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

    async def streamable_handler(self, request: web.Request) -> web.Response:
        """Handle streamable HTTP requests with full MCP server integration."""
        if self._streamable is None:
            raise RuntimeError("Streamable transport not initialized")

        # Process the request through a complete MCP server session
        return await self._process_streamable_request(request)

    async def _process_streamable_request(self, request: web.Request) -> web.Response:
        """Process a stateless request through the MCP server."""
        if self._streamable is None:
            return web.Response(text="Transport not available", status=500)

        async with self._streamable.connect() as (read_stream, write_stream):
            try:
                # Create a task group to run the server and handle the request
                async with anyio.create_task_group() as tg:
                    response_holder: dict[str, web.Response | Exception | None] = {"response": None, "error": None}

                    # Start the MCP server
                    async def run_server() -> None:
                        try:
                            await self._mcp.server.run(
                                read_stream=read_stream,
                                write_stream=write_stream,
                                initialization_options=self._mcp.server.create_initialization_options(),
                                raise_exceptions=True,
                            )
                        except Exception as e:
                            response_holder["error"] = e
                            tg.cancel_scope.cancel()

                    # Handle the HTTP request
                    async def handle_http() -> None:
                        try:
                            if self._streamable is not None:
                                response = await self._streamable.handle_request(request)
                                response_holder["response"] = response
                            tg.cancel_scope.cancel()
                        except Exception as e:
                            response_holder["error"] = e
                            tg.cancel_scope.cancel()

                    tg.start_soon(run_server)
                    tg.start_soon(handle_http)

                # Return the response or error
                if response_holder["error"]:
                    logger.exception("Error in streamable request processing")
                    if self._streamable is not None:
                        return self._streamable._create_error_response(
                            f"Server error: {response_holder['error']!s}",
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                        )
                    else:
                        return web.Response(text="Internal Server Error", status=500)

                response = response_holder["response"]
                if isinstance(response, web.Response):
                    return response
                elif self._streamable is not None:
                    return self._streamable._create_error_response(
                        "No response generated",
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                else:
                    return web.Response(text="Error", status=500)

            except Exception as e:
                logger.exception("Error processing streamable request")
                if self._streamable is not None:
                    return self._streamable._create_error_response(
                        f"Error processing request: {e!s}",
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                else:
                    return web.Response(text="Internal Server Error", status=500)


def build_mcp_app(
    mcp_registry: AiohttpMCP,
    path: str = "/mcp",
    is_subapp: bool = False,
    transport_mode: TransportMode = TransportMode.SSE,
) -> web.Application:
    """Build the MCP server application."""
    return AppBuilder(mcp_registry, path, transport_mode).build(is_subapp=is_subapp)


def setup_mcp_subapp(
    app: web.Application,
    mcp_registry: AiohttpMCP,
    prefix: str = "/mcp",
    package_names: list[str] | None = None,
    transport_mode: TransportMode = TransportMode.SSE,
) -> None:
    """Set up the MCP server sub-application with the given prefix."""
    # Go through the discovery process to find all decorated functions
    discover_modules(package_names)

    mcp_app = build_mcp_app(mcp_registry, prefix, is_subapp=True, transport_mode=transport_mode)
    app.add_subapp(prefix, mcp_app)

    # Store the main app in the MCP registry for access from tools
    mcp_registry.setup_app(app)
