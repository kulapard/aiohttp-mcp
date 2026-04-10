"""Type aliases and type definitions for the MCP protocol layer."""

import types
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from pydantic import StrictInt

# JSON-RPC request ID type
RequestId = StrictInt | str

# Any callable (used for tool/resource/prompt function registration)
AnyFunction = Callable[..., Any]

# Callback for sending JSON-RPC notifications from Context
NotificationSender = Callable[[str, dict[str, Any] | None], Awaitable[None]]

# Callback for reading resources from Context
ResourceReader = Callable[[str], Awaitable[Iterable[Any]]]


def get_fn_name(fn: Callable[..., Any]) -> str:
    """Get the __name__ of a callable, with type narrowing for ty/mypy."""
    if isinstance(fn, types.FunctionType):
        return fn.__name__
    return getattr(fn, "__name__", type(fn).__name__)
