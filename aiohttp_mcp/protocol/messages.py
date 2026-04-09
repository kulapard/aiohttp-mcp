"""Session and event message types for MCP transport layer.

Replaces mcp.shared.message and mcp.server.streamable_http event types.
"""

import abc
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .models import JSONRPCMessage
from .typedefs import RequestId


@dataclass
class ServerMessageMetadata:
    """Metadata attached to server-sent messages."""

    related_request_id: RequestId | None = None
    request_context: Any = None  # aiohttp.web.Request or None


@dataclass
class SessionMessage:
    """A JSON-RPC message with optional metadata, as passed through transport streams."""

    message: JSONRPCMessage
    metadata: ServerMessageMetadata | None = field(default=None)


@dataclass
class EventMessage:
    """A JSON-RPC message with an optional event ID for SSE resumability."""

    message: JSONRPCMessage
    event_id: str | None = None


class EventStore(abc.ABC):
    """Abstract base class for event stores supporting resumability."""

    @abc.abstractmethod
    async def store_event(self, stream_id: str | RequestId, message: JSONRPCMessage) -> str:
        """Store an event and return its event ID."""
        ...

    @abc.abstractmethod
    async def replay_events_after(
        self,
        last_event_id: str,
        send_callback: Callable[[EventMessage], Awaitable[None]],
    ) -> str | None:
        """Replay events after the given event ID.

        Returns the stream ID that was being replayed, or None.
        """
        ...
