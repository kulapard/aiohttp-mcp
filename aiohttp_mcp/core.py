import logging
from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.server import LifespanResultT
from mcp.types import (
    AnyFunction,
    EmbeddedResource,
    ImageContent,
    TextContent,
    Tool,
)

logger = logging.getLogger(__name__)

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class AiohttpMCP:
    def __init__(
        self,
        name: str | None = None,
        instructions: str | None = None,
        debug: bool = False,
        log_level: LogLevel = "INFO",
        warn_on_duplicate_resources: bool = True,
        warn_on_duplicate_tools: bool = True,
        warn_on_duplicate_prompts: bool = True,
        lifespan: Callable[[FastMCP], AbstractAsyncContextManager[LifespanResultT]] | None = None,
    ) -> None:
        self._fastmcp = FastMCP(
            name=name,
            instructions=instructions,
            debug=debug,
            log_level=log_level,
            warn_on_duplicate_resources=warn_on_duplicate_resources,
            warn_on_duplicate_tools=warn_on_duplicate_tools,
            warn_on_duplicate_prompts=warn_on_duplicate_prompts,
            lifespan=lifespan,
        )

    @property
    def server(self) -> Server[Any]:
        return self._fastmcp._mcp_server

    def tool(self, name: str | None = None, description: str | None = None) -> Callable[[AnyFunction], AnyFunction]:
        return self._fastmcp.tool(name, description)

    def resource(
        self,
        uri: str,
        *,
        name: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        return self._fastmcp.resource(uri, name=name, description=description, mime_type=mime_type)

    def prompt(self, name: str | None = None, description: str | None = None) -> Callable[[AnyFunction], AnyFunction]:
        return self._fastmcp.prompt(name, description)

    async def list_tools(self) -> list[Tool]:
        """List all available tools."""
        return await self._fastmcp.list_tools()

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        """Call a tool by name with arguments."""
        return await self._fastmcp.call_tool(name, arguments)
