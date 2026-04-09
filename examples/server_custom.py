import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, AppBuilder

mcp = AiohttpMCP()
app_builder = AppBuilder(mcp=mcp, path="/mcp")


async def custom_handler(request: web.Request) -> web.StreamResponse:
    """Custom handler that wraps the streamable HTTP handler."""
    # Do something before processing the MCP request
    print(f"Received {request.method} request to {request.path}")
    response = await app_builder.streamable_http_handler(request)
    # Do something after processing the MCP request
    print(f"Sent response with status {response.status}")
    return response


@mcp.tool()
async def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


app = app_builder.build()

# Override the default route with our custom handler
# Note: This replaces the auto-configured routes from build()
# For more control, build the app manually:
# app = web.Application()
# app.router.add_route("*", "/mcp", custom_handler)

web.run_app(app)
