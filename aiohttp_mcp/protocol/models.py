"""MCP protocol Pydantic models (2025-11-25 spec).

Defines all JSON-RPC and MCP entity types needed for the protocol,
replacing imports from the `mcp` package.
"""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, RootModel, StrictInt

# ---------------------------------------------------------------------------
# JSON-RPC 2.0 error codes
# ---------------------------------------------------------------------------
PARSE_ERROR: int = -32700
INVALID_REQUEST: int = -32600
METHOD_NOT_FOUND: int = -32601
INVALID_PARAMS: int = -32602
INTERNAL_ERROR: int = -32603

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------
RequestId = StrictInt | str
AnyFunction = Callable[..., Any]


# ---------------------------------------------------------------------------
# Protocol version constants
# ---------------------------------------------------------------------------
LATEST_PROTOCOL_VERSION: str = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS: list[str] = [
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
]

# ---------------------------------------------------------------------------
# JSON-RPC 2.0 message types
# ---------------------------------------------------------------------------


class ErrorData(BaseModel):
    model_config = ConfigDict(extra="allow")

    code: int
    message: str
    data: Any | None = None


class JSONRPCRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    id: RequestId
    method: str
    params: dict[str, Any] | None = None


class JSONRPCNotification(BaseModel):
    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: dict[str, Any] | None = None


class JSONRPCResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    id: RequestId
    result: dict[str, Any]


class JSONRPCError(BaseModel):
    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int
    error: ErrorData


class JSONRPCMessage(RootModel[JSONRPCRequest | JSONRPCNotification | JSONRPCResponse | JSONRPCError]):
    """Discriminated union of all JSON-RPC message types."""

    pass


# ---------------------------------------------------------------------------
# MCP entity types
# ---------------------------------------------------------------------------


class Icon(BaseModel):
    model_config = ConfigDict(extra="allow")

    src: str
    mimeType: str | None = None
    sizes: list[str] | None = None


class Annotations(BaseModel):
    model_config = ConfigDict(extra="allow")

    audience: list[Literal["user", "assistant"]] | None = None
    priority: Annotated[float, Field(ge=0.0, le=1.0)] | None = None


class ToolAnnotations(BaseModel):
    model_config = ConfigDict(extra="allow")

    title: str | None = None
    readOnlyHint: bool | None = None
    destructiveHint: bool | None = None
    idempotentHint: bool | None = None
    openWorldHint: bool | None = None


class ToolExecution(BaseModel):
    model_config = ConfigDict(extra="allow")

    taskSupport: Literal["forbidden", "optional", "required"] | None = None


class Tool(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    title: str | None = None
    description: str | None = None
    inputSchema: dict[str, Any]
    outputSchema: dict[str, Any] | None = None
    icons: list[Icon] | None = None
    annotations: ToolAnnotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")
    execution: ToolExecution | None = None


class PromptArgument(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    description: str | None = None
    required: bool | None = None


class Prompt(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    title: str | None = None
    description: str | None = None
    arguments: list[PromptArgument] | None = None
    icons: list[Icon] | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class Resource(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    title: str | None = None
    uri: AnyUrl
    description: str | None = None
    mimeType: str | None = None
    size: int | None = None
    icons: list[Icon] | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class ResourceTemplate(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    title: str | None = None
    uriTemplate: str
    description: str | None = None
    mimeType: str | None = None
    icons: list[Icon] | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


# ---------------------------------------------------------------------------
# Content types
# ---------------------------------------------------------------------------


class TextContent(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["text"] = "text"
    text: str
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class ImageContent(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["image"] = "image"
    data: str
    mimeType: str
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class AudioContent(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["audio"] = "audio"
    data: str
    mimeType: str
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class TextResourceContents(BaseModel):
    model_config = ConfigDict(extra="allow")

    uri: AnyUrl
    mimeType: str | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")
    text: str


class BlobResourceContents(BaseModel):
    model_config = ConfigDict(extra="allow")

    uri: AnyUrl
    mimeType: str | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")
    blob: str


ReadResourceContents = TextResourceContents | BlobResourceContents


class EmbeddedResource(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["resource"] = "resource"
    resource: TextResourceContents | BlobResourceContents
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


class ResourceLink(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["resource_link"] = "resource_link"
    name: str
    title: str | None = None
    uri: AnyUrl
    description: str | None = None
    mimeType: str | None = None
    size: int | None = None
    icons: list[Icon] | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(default=None, alias="_meta")


# Union of all content block types
Content = TextContent | ImageContent | AudioContent | ResourceLink | EmbeddedResource
ContentBlock = Content  # Alias


# ---------------------------------------------------------------------------
# Prompt results
# ---------------------------------------------------------------------------


class PromptMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: Literal["user", "assistant"]
    content: TextContent | ImageContent | AudioContent | ResourceLink | EmbeddedResource


class GetPromptResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    meta: dict[str, Any] | None = Field(default=None, alias="_meta")
    description: str | None = None
    messages: list[PromptMessage]


# ---------------------------------------------------------------------------
# Server capabilities and initialization
# ---------------------------------------------------------------------------


class PromptsCapability(BaseModel):
    model_config = ConfigDict(extra="allow")

    listChanged: bool | None = None


class ResourcesCapability(BaseModel):
    model_config = ConfigDict(extra="allow")

    subscribe: bool | None = None
    listChanged: bool | None = None


class ToolsCapability(BaseModel):
    model_config = ConfigDict(extra="allow")

    listChanged: bool | None = None


class LoggingCapability(BaseModel):
    model_config = ConfigDict(extra="allow")


class CompletionsCapability(BaseModel):
    model_config = ConfigDict(extra="allow")


class ServerCapabilities(BaseModel):
    model_config = ConfigDict(extra="allow")

    experimental: dict[str, dict[str, Any]] | None = None
    logging: LoggingCapability | None = None
    prompts: PromptsCapability | None = None
    resources: ResourcesCapability | None = None
    tools: ToolsCapability | None = None
    completions: CompletionsCapability | None = None


class Implementation(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    title: str | None = None
    version: str
    websiteUrl: str | None = None
    icons: list[Icon] | None = None


class InitializeResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    protocolVersion: str
    capabilities: ServerCapabilities
    serverInfo: Implementation
    instructions: str | None = None
