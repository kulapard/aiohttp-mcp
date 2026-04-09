import logging
from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any

from aiohttp import web
from pydantic import AnyUrl

from .protocol.context import Context
from .protocol.context import get_current_context as _get_current_context
from .protocol.messages import EventStore
from .protocol.models import (
    Annotations,
    AnyFunction,
    Content,
    GetPromptResult,
    Icon,
    Prompt,
    Resource,
    ResourceTemplate,
    TextResourceContents,
    Tool,
    ToolAnnotations,
)
from .protocol.registry import Registry, ToolError
from .protocol.server import MCPServer

logger = logging.getLogger(__name__)

# Re-export for public API
__all__ = ["AiohttpMCP", "ToolError"]


class AiohttpMCP:
    def __init__(
        self,
        name: str | None = None,
        instructions: str | None = None,
        debug: bool = False,
        log_level: str = "INFO",
        warn_on_duplicate_resources: bool = True,
        warn_on_duplicate_tools: bool = True,
        warn_on_duplicate_prompts: bool = True,
        lifespan: Callable[["AiohttpMCP"], AbstractAsyncContextManager[Any]] | None = None,
        event_store: EventStore | None = None,
    ) -> None:
        self._registry = Registry(
            warn_on_duplicate_tools=warn_on_duplicate_tools,
            warn_on_duplicate_resources=warn_on_duplicate_resources,
            warn_on_duplicate_prompts=warn_on_duplicate_prompts,
        )
        self._server = MCPServer(
            name=name,
            instructions=instructions,
            registry=self._registry,
            lifespan=lifespan,
        )
        self._app: web.Application | None = None
        self._event_store = event_store

        if debug:
            logging.getLogger("aiohttp_mcp").setLevel(logging.DEBUG)

    @property
    def server(self) -> MCPServer:
        return self._server

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

        def decorator(fn: AnyFunction) -> AnyFunction:
            self._registry.register_tool(
                fn,
                name=name,
                title=title,
                description=description,
                annotations=annotations,
                icons=icons,
                meta=meta,
                structured_output=structured_output,
            )
            return fn

        return decorator

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
        self._registry.register_tool(
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
        self._registry.remove_tool(name)

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

        def decorator(fn: AnyFunction) -> AnyFunction:
            self._registry.register_resource(
                fn,
                uri=uri,
                name=name,
                title=title,
                description=description,
                mime_type=mime_type,
                icons=icons,
                annotations=annotations,
            )
            return fn

        return decorator

    def add_resource(self, fn: AnyFunction, uri: str, **kwargs: Any) -> None:
        """Add a resource directly without using a decorator."""
        self._registry.register_resource(fn, uri=uri, **kwargs)

    def prompt(
        self,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        icons: list[Icon] | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a prompt."""

        def decorator(fn: AnyFunction) -> AnyFunction:
            self._registry.register_prompt(
                fn,
                name=name,
                title=title,
                description=description,
                icons=icons,
            )
            return fn

        return decorator

    def add_prompt(self, fn: AnyFunction, **kwargs: Any) -> None:
        """Add a prompt directly without using a decorator."""
        self._registry.register_prompt(fn, **kwargs)

    async def list_tools(self) -> list[Tool]:
        """List all available tools."""
        return await self._registry.list_tools()

    async def list_resources(self) -> list[Resource]:
        """List all available resources."""
        return await self._registry.list_resources()

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        """List all available resource templates."""
        return await self._registry.list_resource_templates()

    async def list_prompts(self) -> list[Prompt]:
        """List all available prompts."""
        return await self._registry.list_prompts()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[Content]:
        """Call a tool by name with arguments."""
        return await self._registry.call_tool(name, arguments)

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[TextResourceContents]:
        """Read a resource by URI."""
        return await self._registry.read_resource(uri)

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        """Get a prompt by name with arguments."""
        return await self._registry.get_prompt(name, arguments)

    def get_context(self) -> Context[Any, Any]:
        """Get the current request context."""
        return _get_current_context()
