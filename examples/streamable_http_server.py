import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, TransportMode, build_mcp_app

mcp = AiohttpMCP(debug=False)


@mcp.tool()
def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


app = build_mcp_app(mcp, path="/mcp", transport_mode=TransportMode.STREAMABLE, stateless=True)
web.run_app(app)
