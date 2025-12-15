"""Type definitions and re-exports from MCP library."""

# aiohttp-sse types
from aiohttp_sse import EventSourceResponse

# MCP Server types
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.prompts.base import Prompt as FastMCPPrompt
from mcp.server.fastmcp.resources.base import Resource as FastMCPResource
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.lowlevel.server import LifespanResultT
from mcp.server.streamable_http import EventMessage, EventStore

# MCP shared types
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS

# MCP protocol types
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    PARSE_ERROR,
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
    RequestId,
    Resource,
    ResourceTemplate,
    TextContent,
    TextResourceContents,
    Tool,
    ToolAnnotations,
)

__all__ = [
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "PARSE_ERROR",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "Annotations",
    "AnyFunction",
    "Content",
    "Context",
    "ErrorData",
    "EventMessage",
    "EventSourceResponse",
    "EventStore",
    "FastMCP",
    "FastMCPPrompt",
    "FastMCPResource",
    "GetPromptResult",
    "Icon",
    "JSONRPCError",
    "JSONRPCMessage",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "LifespanResultT",
    "Prompt",
    "ReadResourceContents",
    "RequestId",
    "Resource",
    "ResourceTemplate",
    "Server",
    "ServerMessageMetadata",
    "SessionMessage",
    "TextContent",
    "TextResourceContents",
    "Tool",
    "ToolAnnotations",
]
