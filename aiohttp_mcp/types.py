"""Type definitions and re-exports for aiohttp-mcp.

All types now come from the native protocol implementation
instead of the mcp package.
"""

# aiohttp-sse types
from aiohttp_sse import EventSourceResponse

# Protocol context
from .protocol.context import Context, get_current_context

# Protocol messages
from .protocol.messages import EventMessage, EventStore, ServerMessageMetadata, SessionMessage

# Protocol models
# Re-export from models
from .protocol.models import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    LATEST_PROTOCOL_VERSION,
    PARSE_ERROR,
    SUPPORTED_PROTOCOL_VERSIONS,
    Annotations,
    AnyFunction,
    Content,
    ErrorData,
    GetPromptResult,
    Icon,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
    Prompt,
    ReadResourceContents,
    RequestId,
    Resource,
    ResourceTemplate,
    TextContent,
    TextResourceContents,
    Tool,
    ToolAnnotations,
)

# Protocol registry
from .protocol.registry import ToolError

# Protocol server
from .protocol.server import MCPServer

__all__ = [
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "LATEST_PROTOCOL_VERSION",
    "PARSE_ERROR",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "Annotations",
    "AnyFunction",
    "Content",
    "Context",
    "get_current_context",
    "ErrorData",
    "EventMessage",
    "EventSourceResponse",
    "EventStore",
    "GetPromptResult",
    "Icon",
    "JSONRPCError",
    "JSONRPCMessage",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "MCPServer",
    "Prompt",
    "ReadResourceContents",
    "RequestId",
    "Resource",
    "ResourceTemplate",
    "ServerMessageMetadata",
    "SessionMessage",
    "TextContent",
    "TextResourceContents",
    "Tool",
    "ToolAnnotations",
    "ToolError",
]
