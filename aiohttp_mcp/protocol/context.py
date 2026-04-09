"""Context system for MCP tools.

Provides request context propagation via contextvars, with support for
logging, progress reporting, and resource reading.
"""

from __future__ import annotations

import contextvars
import inspect
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, get_args, get_origin

if TYPE_CHECKING:
    from aiohttp.web import Request

from .typedefs import NotificationSender, ResourceReader


@dataclass
class RequestContext:
    """Per-request context holding the aiohttp Request."""

    request_id: str | int | None = None
    request: Request | None = None
    session: Any = None
    _send_notification: NotificationSender | None = field(default=None, repr=False)
    _read_resource: ResourceReader | None = field(default=None, repr=False)


class Context:
    """MCP tool context providing access to request data, logging, and progress.

    Tools can declare a parameter of this type to receive the context::

        @mcp.tool()
        async def my_tool(arg: str, ctx: Context) -> str:
            await ctx.info(f"Processing {arg}")
            db = ctx.app["db_pool"]
            ...
    """

    def __init__(self, request_context: RequestContext) -> None:
        self._request_context = request_context

    @property
    def request_context(self) -> RequestContext:
        return self._request_context

    @property
    def request_id(self) -> str | int | None:
        """The JSON-RPC request ID for the current call."""
        return self._request_context.request_id

    @property
    def app(self) -> Any:
        """The aiohttp Application instance for the current request.

        Use this to access shared state stored on the app::

            @mcp.tool()
            async def my_tool(query: str) -> str:
                ctx = get_current_context()
                db_pool = ctx.app["db_pool"]
                ...
        """
        request = self._request_context.request
        if request is None:
            raise RuntimeError("No HTTP request context available — app is not accessible outside of an HTTP request")
        return request.app

    # -- Logging methods (send notifications/message to client) --

    async def log(
        self,
        level: Literal["debug", "info", "warning", "error"],
        message: str,
        *,
        logger_name: str | None = None,
    ) -> None:
        """Send a log message to the MCP client."""
        sender = self._request_context._send_notification
        if sender is None:
            return
        params: dict[str, Any] = {"level": level, "data": message}
        if logger_name is not None:
            params["logger"] = logger_name
        await sender("notifications/message", params)

    async def debug(self, message: str, **extra: Any) -> None:
        """Send a debug log message to the client."""
        await self.log("debug", message)

    async def info(self, message: str, **extra: Any) -> None:
        """Send an info log message to the client."""
        await self.log("info", message)

    async def warning(self, message: str, **extra: Any) -> None:
        """Send a warning log message to the client."""
        await self.log("warning", message)

    async def error(self, message: str, **extra: Any) -> None:
        """Send an error log message to the client."""
        await self.log("error", message)

    # -- Progress reporting --

    async def report_progress(
        self,
        progress: float,
        total: float | None = None,
        message: str | None = None,
    ) -> None:
        """Report progress for the current operation."""
        sender = self._request_context._send_notification
        if sender is None:
            return
        params: dict[str, Any] = {"progress": progress}
        if total is not None:
            params["total"] = total
        if message is not None:
            params["message"] = message
        if self._request_context.request_id is not None:
            params["progressToken"] = self._request_context.request_id
        await sender("notifications/progress", params)

    # -- Resource reading --

    async def read_resource(self, uri: str) -> Iterable[Any]:
        """Read a resource by URI."""
        reader = self._request_context._read_resource
        if reader is None:
            raise RuntimeError("read_resource is not available outside of a server request")
        return await reader(uri)


# ContextVar for propagating the current context through async call chains
_current_context: contextvars.ContextVar[Context | None] = contextvars.ContextVar("_current_context", default=None)


def get_current_context() -> Context:
    """Get the current MCP context from the contextvar.

    Raises ValueError if no context is set.
    """
    ctx = _current_context.get()
    if ctx is None:
        raise ValueError("No MCP context is currently set")
    return ctx


def set_current_context(ctx: Context | None) -> contextvars.Token[Context | None]:
    """Set the current MCP context."""
    return _current_context.set(ctx)


def find_context_kwarg(fn: Callable[..., Any]) -> str | None:
    """Find the parameter name typed as Context in a function signature."""
    try:
        sig = inspect.signature(fn, eval_str=True)
    except (ValueError, TypeError):
        return None

    for param in sig.parameters.values():
        annotation = param.annotation
        if annotation is inspect.Parameter.empty:
            continue
        if annotation is Context:
            return param.name
        origin = get_origin(annotation)
        if origin is Context:
            return param.name
        args = get_args(annotation)
        if args:
            for arg in args:
                if arg is Context or get_origin(arg) is Context:
                    return param.name
    return None
