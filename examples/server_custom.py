import datetime
from zoneinfo import ZoneInfo

from aiohttp import web
from aiohttp_sse import EventSourceResponse

from aiohttp_mcp import AiohttpMCP, AppBuilder

mcp = AiohttpMCP()
app_builder = AppBuilder(mcp, path="/mcp")


async def handle_sse(request: web.Request) -> EventSourceResponse:
    """Custom handler for SSE connection."""
    # Do something before starting the SSE connection
    response = await app_builder.sse_handler(request)
    # Do something after closing the SSE connection
    return response


async def handle_message(request: web.Request) -> web.Response:
    """Custom handler for incoming messages."""
    # Do something before sending the message
    response = await app_builder.message_handler(request)
    # Do something after sending the message
    return response


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
