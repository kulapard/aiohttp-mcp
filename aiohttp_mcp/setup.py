import logging

from aiohttp import web

from .discover import discover_modules
from .registry import mcp
from .transport import SseServerTransport

__all__ = ["setup_mcp_server"]

logger = logging.getLogger(__name__)


def setup_mcp_server(
    app: web.Application,
    path: str = "/mcp",
    package_names: list[str] | None = None,
):
    # Go through the discovery process to find all decorated functions
    discover_modules(package_names)

    sse = SseServerTransport(path)

    async def handle_sse(request: web.Request) -> web.Response:
        async with sse.connect_sse(request) as (read_stream, write_stream):
            await mcp.server.run(
                read_stream,
                write_stream,
                mcp.server.create_initialization_options(),
            )
        return web.Response(text="SSE connection closed", status=200)

    async def handle_messages(request: web.Request) -> web.Response:
        return await sse.handle_post_message(request)

    app.router.add_get(path, handle_sse)
    app.router.add_post(path, handle_messages)
    return app
