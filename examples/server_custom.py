import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, AppBuilder, EventSourceResponse

mcp = AiohttpMCP()
app_builder = AppBuilder(mcp, path="/mcp")


async def handle_sse(request: web.Request) -> EventSourceResponse:
    """Custom handler for SSE connection."""
    # Do any preprocessing here if needed. For example, add authentication checks
    return await app_builder.handle_sse(request)


async def handle_message(request: web.Request) -> web.Response:
    """Custom handler for incoming messages."""
    # Do any preprocessing here if needed. For example, add authentication checks
    return await app_builder.handle_message(request)


@mcp.tool()
async def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


app = web.Application()

# Setup custom handlers
app.router.add_get(app_builder.path, handle_sse)
app.router.add_post(app_builder.path, handle_message)

web.run_app(app)
