"""Session and event message types for MCP transport layer.

Replaces mcp.shared.message and mcp.server.streamable_http event types.
"""

import abc
import uuid
from collections import defaultdict
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


class InMemoryEventStore(EventStore):
    """In-memory event store for SSE resumability.

    Stores events in memory, keyed by stream ID. Each event gets a unique
    UUID-based event ID. Suitable for single-process deployments and testing.

    For production deployments with multiple processes or persistence needs,
    implement a custom EventStore backed by Redis, a database, etc.
    """

    def __init__(self) -> None:
        self._events_by_stream: dict[str, list[tuple[str, JSONRPCMessage]]] = defaultdict(list)
        self._event_id_to_stream: dict[str, str] = {}

    async def store_event(self, stream_id: str | RequestId, message: JSONRPCMessage) -> str:
        event_id = uuid.uuid4().hex
        key = str(stream_id)
        self._events_by_stream[key].append((event_id, message))
        self._event_id_to_stream[event_id] = key
        return event_id

    async def replay_events_after(
        self,
        last_event_id: str,
        send_callback: Callable[[EventMessage], Awaitable[None]],
    ) -> str | None:
        stream_id = self._event_id_to_stream.get(last_event_id)
        if stream_id is None:
            return None

        events = self._events_by_stream[stream_id]

        # Find index of last_event_id
        start_index = None
        for i, (eid, _) in enumerate(events):
            if eid == last_event_id:
                start_index = i + 1
                break

        if start_index is None or start_index >= len(events):
            return stream_id

        for event_id, message in events[start_index:]:
            await send_callback(EventMessage(message, event_id))

        return stream_id
