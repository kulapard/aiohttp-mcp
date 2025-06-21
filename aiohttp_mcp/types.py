from enum import Enum

from aiohttp_sse import EventSourceResponse  # noqa: F401
from mcp.types import *  # noqa: F403

__all__ = ["TransportMode"]


class TransportMode(str, Enum):
    """Transport modes for MCP server deployment."""

    SSE = "sse"
    STREAMABLE = "streamable"

    def __str__(self) -> str:
        return self.value
