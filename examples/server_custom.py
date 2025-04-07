import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCPServer, EventSourceResponse, mcp

mcp_server = AiohttpMCPServer(path="/mcp")


async def handle_sse(request: web.Request) -> EventSourceResponse:
    """Custom handler for SSE connection."""
    # Do any preprocessing here if needed. For example, add authentication checks
    return await mcp_server.handle_sse(request)


async def handle_message(request: web.Request) -> web.Response:
    """Custom handler for incoming messages."""
    # Do any preprocessing here if needed. For example, add authentication checks
    return await mcp_server.handle_message(request)


@mcp.tool()
async def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


app = web.Application()

# Setup custom handlers
app.router.add_get(mcp_server.path, handle_sse)
app.router.add_post(mcp_server.path, handle_message)

web.run_app(app)
