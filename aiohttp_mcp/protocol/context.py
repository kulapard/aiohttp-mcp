"""Context system for MCP tools.

Provides request context propagation via contextvars, preserving the
ctx.request_context.request and ctx.request_context.lifespan_context
access patterns from the mcp library.
"""

import contextvars
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar, get_args, get_origin

ServerT = TypeVar("ServerT")
LifespanT = TypeVar("LifespanT")
RequestT = TypeVar("RequestT")


@dataclass
class RequestContext(Generic[ServerT, LifespanT]):
    """Per-request context holding the aiohttp Request and lifespan context."""

    request_id: str | int | None = None
    lifespan_context: LifespanT = field(default=None)  # type: ignore[assignment]
    request: Any = None  # aiohttp.web.Request
    session: Any = None


class Context(Generic[ServerT, LifespanT, RequestT]):
    """MCP tool context, providing access to request and lifespan data.

    Tools can declare a parameter of this type to receive the context:
        @mcp.tool()
        async def my_tool(arg: str, ctx: Context) -> str:
            request = ctx.request_context.request
            ...
    """

    def __init__(self, request_context: RequestContext[ServerT, LifespanT]) -> None:
        self._request_context = request_context

    @property
    def request_context(self) -> RequestContext[ServerT, LifespanT]:
        return self._request_context


# ContextVar for propagating the current context through async call chains
_current_context: contextvars.ContextVar[Context[Any, Any, Any] | None] = contextvars.ContextVar(
    "_current_context", default=None
)


def get_current_context() -> Context[Any, Any, Any]:
    """Get the current MCP context from the contextvar.

    Raises ValueError if no context is set.
    """
    ctx = _current_context.get()
    if ctx is None:
        raise ValueError("No MCP context is currently set")
    return ctx


def set_current_context(ctx: Context[Any, Any, Any] | None) -> contextvars.Token[Context[Any, Any, Any] | None]:
    """Set the current MCP context."""
    return _current_context.set(ctx)


def find_context_kwarg(fn: Callable[..., Any]) -> str | None:
    """Find the parameter name typed as Context in a function signature.

    Returns the parameter name if found, or None.
    """
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
        # Handle string annotations
        if isinstance(annotation, str) and "Context" in annotation:
            return param.name
        # Check get_args for Annotated types etc.
        args = get_args(annotation)
        if args:
            for arg in args:
                if arg is Context or get_origin(arg) is Context:
                    return param.name
    return None
