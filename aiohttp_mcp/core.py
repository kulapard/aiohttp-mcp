import logging
from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.lowlevel.server import LifespanResultT
from mcp.types import (
    AnyFunction,
    EmbeddedResource,
    GetPromptResult,
    ImageContent,
    Prompt,
    Resource,
    ResourceTemplate,
    TextContent,
    Tool,
    ToolAnnotations,
)
from pydantic import AnyUrl

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

    def tool(
        self, name: str | None = None, description: str | None = None, annotations: ToolAnnotations | None = None
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a tool."""
        return self._fastmcp.tool(name, description, annotations)

    def resource(
        self,
        uri: str,
        *,
        name: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a resource."""
        return self._fastmcp.resource(uri, name=name, description=description, mime_type=mime_type)

    def prompt(self, name: str | None = None, description: str | None = None) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a prompt."""
        return self._fastmcp.prompt(name, description)

    async def list_tools(self) -> list[Tool]:
        """List all available tools."""
        return await self._fastmcp.list_tools()

    async def list_resources(self) -> list[Resource]:
        """List all available resources."""
        return await self._fastmcp.list_resources()

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        """List all available resource templates."""
        return await self._fastmcp.list_resource_templates()

    async def list_prompts(self) -> list[Prompt]:
        """List all available prompts."""
        return await self._fastmcp.list_prompts()

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        """Call a tool by name with arguments."""
        return await self._fastmcp.call_tool(name, arguments)

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[ReadResourceContents]:
        """Read a resource by URI."""
        return await self._fastmcp.read_resource(uri)

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        """Get a prompt by name with arguments."""
        return await self._fastmcp.get_prompt(name, arguments)
