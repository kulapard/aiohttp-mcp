import logging
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel import Server
from mcp.types import (
    AnyFunction,
)

logger = logging.getLogger(__name__)


class Registry:
    def __init__(self):
        self._fastmcp = FastMCP(warn_on_duplicate_tools=True)

    @property
    def server(self) -> Server:
        return self._fastmcp._mcp_server  # type: ignore[return-value]

    def tool(
        self, name: str | None = None, description: str | None = None
    ) -> Callable[[AnyFunction], AnyFunction]:
        return self._fastmcp.tool(name, description)


mcp: Registry = Registry()
