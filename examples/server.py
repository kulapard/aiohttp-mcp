import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import mcp, setup_mcp_server


@mcp.tool()
def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


app = web.Application()
setup_mcp_server(app)
web.run_app(app)
