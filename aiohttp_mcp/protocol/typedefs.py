"""Type aliases and type definitions for the MCP protocol layer."""

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
