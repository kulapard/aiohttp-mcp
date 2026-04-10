"""Tests for InMemoryEventStore and event store integration with transport."""

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from aiohttp_mcp.protocol.messages import EventMessage, InMemoryEventStore
from aiohttp_mcp.protocol.models import (
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCResponse,
)


def _make_notification(method: str = "test", **params: str) -> JSONRPCMessage:
    return JSONRPCMessage(root=JSONRPCNotification(jsonrpc="2.0", method=method, params=params or {"data": "test"}))


def _make_response(request_id: str = "1", result: dict[str, Any] | None = None) -> JSONRPCMessage:
    return JSONRPCMessage(root=JSONRPCResponse(jsonrpc="2.0", id=request_id, result=result or {"status": "ok"}))


def _collector() -> tuple[list[EventMessage], Callable[[EventMessage], Awaitable[None]]]:
    """Return a list and an async callback that appends to it."""
    events: list[EventMessage] = []

    async def callback(event: EventMessage) -> None:
        events.append(event)

    return events, callback


@pytest.fixture
def store() -> InMemoryEventStore:
    return InMemoryEventStore()


class TestStoreEvent:
    async def test_returns_unique_event_ids(self, store: InMemoryEventStore) -> None:
        msg = _make_notification()
        id1 = await store.store_event("s1", msg)
        id2 = await store.store_event("s1", msg)
        assert id1 != id2

    async def test_stores_events_per_stream(self, store: InMemoryEventStore) -> None:
        await store.store_event("s1", _make_notification(method="a"))
        await store.store_event("s2", _make_notification(method="b"))
        await store.store_event("s1", _make_notification(method="c"))

        assert len(store._events_by_stream["s1"]) == 2
        assert len(store._events_by_stream["s2"]) == 1

    async def test_accepts_integer_stream_id(self, store: InMemoryEventStore) -> None:
        eid = await store.store_event(42, _make_notification())
        assert eid in store._event_id_to_stream
        assert store._event_id_to_stream[eid] == "42"


class TestReplayEventsAfter:
    async def test_replays_events_after_given_id(self, store: InMemoryEventStore) -> None:
        ids = []
        for i in range(5):
            eid = await store.store_event("s1", _make_notification(method=f"m{i}"))
            ids.append(eid)

        replayed, cb = _collector()
        stream_id = await store.replay_events_after(ids[1], cb)

        assert stream_id == "s1"
        assert len(replayed) == 3
        assert replayed[0].event_id == ids[2]
        assert replayed[1].event_id == ids[3]
        assert replayed[2].event_id == ids[4]

    async def test_replays_nothing_when_last_event_is_latest(self, store: InMemoryEventStore) -> None:
        eid = await store.store_event("s1", _make_notification())

        replayed, cb = _collector()
        stream_id = await store.replay_events_after(eid, cb)

        assert stream_id == "s1"
        assert len(replayed) == 0

    async def test_returns_none_for_unknown_event_id(self, store: InMemoryEventStore) -> None:
        replayed, cb = _collector()
        stream_id = await store.replay_events_after("nonexistent", cb)

        assert stream_id is None
        assert len(replayed) == 0

    async def test_replays_correct_stream_when_multiple_exist(self, store: InMemoryEventStore) -> None:
        await store.store_event("s1", _make_notification(method="s1_first"))
        s2_first = await store.store_event("s2", _make_notification(method="s2_first"))
        await store.store_event("s1", _make_notification(method="s1_second"))
        await store.store_event("s2", _make_notification(method="s2_second"))

        replayed, cb = _collector()
        stream_id = await store.replay_events_after(s2_first, cb)

        assert stream_id == "s2"
        assert len(replayed) == 1
        root = replayed[0].message.root
        assert isinstance(root, JSONRPCNotification)
        assert root.method == "s2_second"

    async def test_replayed_messages_have_correct_content(self, store: InMemoryEventStore) -> None:
        msg = _make_response(request_id="req-1", result={"value": "hello"})
        first_id = await store.store_event("s1", _make_notification())
        await store.store_event("s1", msg)

        replayed, cb = _collector()
        await store.replay_events_after(first_id, cb)

        assert len(replayed) == 1
        assert isinstance(replayed[0].message.root, JSONRPCResponse)
        assert replayed[0].message.root.result == {"value": "hello"}

    async def test_replay_preserves_event_order(self, store: InMemoryEventStore) -> None:
        first = await store.store_event("s1", _make_notification(method="first"))
        await store.store_event("s1", _make_notification(method="second"))
        await store.store_event("s1", _make_notification(method="third"))

        replayed, cb = _collector()
        await store.replay_events_after(first, cb)

        assert len(replayed) == 2
        assert isinstance(replayed[0].message.root, JSONRPCNotification)
        assert replayed[0].message.root.method == "second"
        assert isinstance(replayed[1].message.root, JSONRPCNotification)
        assert replayed[1].message.root.method == "third"
