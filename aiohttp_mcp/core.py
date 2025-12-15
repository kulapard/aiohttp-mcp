import logging
from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Literal

from aiohttp import web
from pydantic import AnyUrl

from .types import (
    Annotations,
    AnyFunction,
    Content,
    Context,
    EventStore,
    FastMCP,
    FastMCPPrompt,
    FastMCPResource,
    GetPromptResult,
    Icon,
    LifespanResultT,
    Prompt,
    ReadResourceContents,
    Resource,
    ResourceTemplate,
    Server,
    Tool,
    ToolAnnotations,
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
        self,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        icons: list[Icon] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a tool."""
        return self._fastmcp.tool(
            name,
            title=title,
            description=description,
            annotations=annotations,
            icons=icons,
            meta=meta,
            structured_output=structured_output,
        )

    def add_tool(
        self,
        fn: AnyFunction,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        icons: list[Icon] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
    ) -> None:
        """Add a tool directly without using a decorator."""
        return self._fastmcp.add_tool(
            fn,
            name=name,
            title=title,
            description=description,
            annotations=annotations,
            icons=icons,
            meta=meta,
            structured_output=structured_output,
        )

    def remove_tool(self, name: str) -> None:
        """Remove a registered tool by name."""
        return self._fastmcp.remove_tool(name)

    def resource(
        self,
        uri: str,
        *,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
        icons: list[Icon] | None = None,
        annotations: Annotations | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a resource."""
        return self._fastmcp.resource(
            uri,
            name=name,
            title=title,
            description=description,
            mime_type=mime_type,
            icons=icons,
            annotations=annotations,
        )

    def add_resource(self, resource: FastMCPResource) -> None:
        """Add a resource directly without using a decorator."""
        return self._fastmcp.add_resource(resource)

    def prompt(
        self,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        icons: list[Icon] | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a prompt."""
        return self._fastmcp.prompt(name, title=title, description=description, icons=icons)

    def add_prompt(self, prompt: FastMCPPrompt) -> None:
        """Add a prompt directly without using a decorator."""
        return self._fastmcp.add_prompt(prompt)

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
        result = await self._fastmcp.call_tool(name, arguments)
        # FastMCP.call_tool returns tuple (content, result_dict) for structured output support
        if isinstance(result, tuple):
            content_list: Sequence[Content] = result[0]
            return content_list
        # For backwards compatibility with older FastMCP versions
        if isinstance(result, dict):
            raise TypeError(f"Unexpected dict return from call_tool: {result}")
        return result

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[ReadResourceContents]:
        """Read a resource by URI."""
        return await self._fastmcp.read_resource(uri)

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        """Get a prompt by name with arguments."""
        return await self._fastmcp.get_prompt(name, arguments)

    def get_context(self) -> Context[Any, Any, Any]:
        """Get the current request context."""
        return self._fastmcp.get_context()

    def completion(self) -> Any:
        """Decorator to register a completion handler."""
        return self._fastmcp.completion()  # type: ignore[no-untyped-call]

    def custom_route(
        self,
        path: str,
        methods: list[str],
        name: str | None = None,
        include_in_schema: bool = True,
    ) -> Any:
        """Decorator to register a custom HTTP route."""
        return self._fastmcp.custom_route(path, methods, name=name, include_in_schema=include_in_schema)
