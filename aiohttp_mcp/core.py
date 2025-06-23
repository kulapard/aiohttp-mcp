import logging
from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Literal

from aiohttp import web
from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.lowlevel.server import LifespanResultT
from mcp.server.streamable_http import EventStore
from mcp.types import (
    AnyFunction,
    Content,
    GetPromptResult,
    Prompt,
    Resource,
    ResourceTemplate,
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
        event_store: EventStore | None = None,
    ) -> None:
        self._fastmcp = FastMCP(
            name=name,
            instructions=instructions,
            event_store=event_store,
            debug=debug,
            log_level=log_level,
            warn_on_duplicate_resources=warn_on_duplicate_resources,
            warn_on_duplicate_tools=warn_on_duplicate_tools,
            warn_on_duplicate_prompts=warn_on_duplicate_prompts,
            lifespan=lifespan,
        )
        self._app: web.Application | None = None
        self._event_store = event_store

    @property
    def server(self) -> Server[Any]:
        return self._fastmcp._mcp_server

    @property
    def event_store(self) -> EventStore | None:
        return self._event_store

    @property
    def app(self) -> web.Application:
        if self._app is None:
            raise RuntimeError("Application has not been built yet. Call `setup_app()` first.")
        return self._app

    def setup_app(self, app: web.Application) -> None:
        """Set the aiohttp application instance."""
        if self._app is not None:
            raise RuntimeError("Application has already been set. Cannot set it again.")
        self._app = app

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

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[Content]:
        """Call a tool by name with arguments."""
        return await self._fastmcp.call_tool(name, arguments)

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[ReadResourceContents]:
        """Read a resource by URI."""
        return await self._fastmcp.read_resource(uri)

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        """Get a prompt by name with arguments."""
        return await self._fastmcp.get_prompt(name, arguments)
