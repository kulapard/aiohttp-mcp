import logging
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel import Server
from mcp.types import (
    AnyFunction,
)

logger = logging.getLogger(__name__)


class Registry:
    def __init__(self) -> None:
        self._fastmcp = FastMCP(warn_on_duplicate_tools=True, log_level="DEBUG")

    @property
    def server(self) -> Server[Any]:
        return self._fastmcp._mcp_server

    def tool(
        self, name: str | None = None, description: str | None = None
    ) -> Callable[[AnyFunction], AnyFunction]:
        return self._fastmcp.tool(name, description)


mcp: Registry = Registry()
