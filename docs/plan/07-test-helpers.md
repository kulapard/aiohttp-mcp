# Feature 7: Test Helpers

## Problem

Testing MCP tools requires unwrapping `list[Content]`, checking `isinstance(result[0], TextContent)`, accessing `.text`. Every test has 3-5 lines of boilerplate just to assert on a tool result.

There's also no way to verify tool/resource/prompt **configuration** — that descriptions, annotations, schemas, and middleware are set up correctly.

## Before

```python
from aiohttp_mcp.protocol.models import TextContent

async def test_my_tool():
    mcp = AiohttpMCP()

    @mcp.tool()
    async def my_tool(x: int) -> str:
        return f"result-{x}"

    result = await mcp.call_tool("my_tool", {"x": 42})
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == "result-42"

async def test_tool_config():
    tools = await mcp.list_tools()
    tool = next(t for t in tools if t.name == "my_tool")
    assert tool.description == "..."
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    # tedious manual lookup every time
```

## After

```python
from aiohttp_mcp.testing import MCPTestClient

async def test_my_tool():
    mcp = AiohttpMCP()

    @mcp.tool()
    async def my_tool(x: int) -> str:
        return f"result-{x}"

    client = MCPTestClient(mcp)
    result = await client.call_tool("my_tool", x=42)
    assert result.text == "result-42"
    assert not result.is_error

async def test_tool_config():
    client = MCPTestClient(mcp)

    # Inspect tool configuration
    tool = await client.get_tool("my_tool")
    assert tool.description == "Get something"
    assert tool.annotations.readOnlyHint is True
    assert "x" in tool.inputSchema["properties"]
    assert tool.inputSchema["properties"]["x"]["type"] == "integer"

    # Inspect resource configuration
    resource = await client.get_resource("config://app")
    assert resource.mimeType == "application/json"

    # Inspect prompt configuration
    prompt = await client.get_prompt_info("summarize")
    assert prompt.arguments[0].name == "text"
    assert prompt.arguments[0].required is True

    # List all names
    assert "my_tool" in await client.list_tool_names()
    assert "config://app" in await client.list_resource_uris()
    assert "summarize" in await client.list_prompt_names()

async def test_middleware_config():
    client = MCPTestClient(mcp)

    assert client.middleware_count == 2
    assert client.has_middleware(require_auth)
    assert client.middleware_scope(require_auth) is None  # all primitives
    assert client.middleware_scope(log_tools) == {"tool"}

async def test_tool_tags():
    client = MCPTestClient(mcp)

    assert await client.get_tool_tags("invoice_get") == ["billing", "read"]
```

## Changes

### New file: `aiohttp_mcp/testing.py`

```python
import json
from typing import Any

from .core import AiohttpMCP
from .protocol.models import Content, Prompt, Resource, ResourceTemplate, TextContent, Tool
from .protocol.registry import ToolError


class ToolResult:
    """Wrapper around tool call results with convenient accessors."""

    def __init__(self, contents: list[Content], is_error: bool = False) -> None:
        self.contents = contents
        self.is_error = is_error

    @property
    def text(self) -> str:
        """First TextContent's text. Raises if no text content."""
        for c in self.contents:
            if isinstance(c, TextContent):
                return c.text
        raise ValueError("No TextContent in result")

    @property
    def json(self) -> Any:
        """First TextContent parsed as JSON."""
        return json.loads(self.text)

    @property
    def texts(self) -> list[str]:
        """All TextContent texts."""
        return [c.text for c in self.contents if isinstance(c, TextContent)]


class MCPTestClient:
    """Test helper that wraps AiohttpMCP with a friendlier API."""

    def __init__(self, mcp: AiohttpMCP) -> None:
        self._mcp = mcp

    # -- Execution helpers --

    async def call_tool(self, name: str, **kwargs: Any) -> ToolResult:
        """Call a tool with keyword arguments."""
        try:
            contents = await self._mcp.call_tool(name, kwargs)
            return ToolResult(list(contents))
        except ToolError as e:
            return ToolResult([TextContent(text=str(e))], is_error=True)

    async def read_resource(self, uri: str) -> str:
        """Read a resource and return its text."""
        results = await self._mcp.read_resource(uri)
        return list(results)[0].text

    async def get_prompt(self, name: str, **kwargs: Any) -> str:
        """Get a prompt and return its first message text."""
        result = await self._mcp.get_prompt(name, kwargs)
        content = result.messages[0].content
        if isinstance(content, TextContent):
            return content.text
        raise ValueError(f"Expected TextContent, got {type(content)}")

    # -- Configuration inspection --

    async def get_tool(self, name: str) -> Tool:
        """Get a tool's full configuration by name. Raises ValueError if not found."""
        tools = await self._mcp.list_tools()
        for t in tools:
            if t.name == name:
                return t
        raise ValueError(f"Tool not found: {name}")

    async def get_resource(self, uri: str) -> Resource | ResourceTemplate:
        """Get a resource's configuration by URI. Raises ValueError if not found."""
        for r in await self._mcp.list_resources():
            if str(r.uri) == uri:
                return r
        for rt in await self._mcp.list_resource_templates():
            if rt.uriTemplate == uri:
                return rt
        raise ValueError(f"Resource not found: {uri}")

    async def get_prompt_info(self, name: str) -> Prompt:
        """Get a prompt's configuration by name. Raises ValueError if not found."""
        prompts = await self._mcp.list_prompts()
        for p in prompts:
            if p.name == name:
                return p
        raise ValueError(f"Prompt not found: {name}")

    # -- Listing helpers --

    async def list_tool_names(self) -> list[str]:
        """List all registered tool names."""
        tools = await self._mcp.list_tools()
        return [t.name for t in tools]

    async def list_resource_uris(self) -> list[str]:
        """List all registered resource URIs (static + templates)."""
        resources = await self._mcp.list_resources()
        templates = await self._mcp.list_resource_templates()
        return [str(r.uri) for r in resources] + [rt.uriTemplate for rt in templates]

    async def list_prompt_names(self) -> list[str]:
        """List all registered prompt names."""
        prompts = await self._mcp.list_prompts()
        return [p.name for p in prompts]

    # -- Middleware & group inspection --
    # These access the registry directly since there's no public API for introspection.

    @property
    def middleware_count(self) -> int:
        """Number of registered middlewares."""
        return len(self._mcp._registry._middlewares)

    @property
    def middlewares(self) -> list[tuple[Any, set[str] | None]]:
        """Registered middlewares as (fn, scope) tuples."""
        return list(self._mcp._registry._middlewares)

    def has_middleware(self, fn: Any) -> bool:
        """Check if a specific middleware function is registered."""
        return any(mw is fn for mw, _ in self._mcp._registry._middlewares)

    def middleware_scope(self, fn: Any) -> set[str] | None:
        """Get the scope of a registered middleware. None means all primitives."""
        for mw, scope in self._mcp._registry._middlewares:
            if mw is fn:
                return scope
        raise ValueError(f"Middleware not found: {fn}")

    async def get_tool_tags(self, name: str) -> list[str]:
        """Get tags for a tool by name."""
        td = self._mcp._registry._tools.get(name)
        if td is None:
            raise ValueError(f"Tool not found: {name}")
        return list(td.tags)
```

### Import convention

NOT exported from `aiohttp_mcp/__init__.py`. Users import from `aiohttp_mcp.testing` explicitly, following the `aiohttp.test_utils` convention.

## Complexity

**S (Small)** — One new file, simple wrapper classes, no changes to existing files. Middleware and tag inspection accesses registry internals — this is acceptable for a testing module (same pattern as `aiohttp.test_utils` accessing internal state).

## Test Plan

- Test `ToolResult.text` returns first TextContent
- Test `ToolResult.json` parses JSON
- Test `ToolResult.texts` returns all text contents
- Test `ToolResult.is_error` set correctly on ToolError
- Test `MCPTestClient.call_tool` with kwargs
- Test `MCPTestClient.read_resource`
- Test `MCPTestClient.get_prompt`
- Test `MCPTestClient.get_tool` returns Tool with correct schema/description/annotations
- Test `MCPTestClient.get_tool` raises ValueError for unknown tool
- Test `MCPTestClient.get_resource` returns Resource with correct mimeType
- Test `MCPTestClient.get_resource` returns ResourceTemplate for template URIs
- Test `MCPTestClient.get_prompt_info` returns Prompt with correct arguments
- Test `MCPTestClient.list_tool_names`
- Test `MCPTestClient.list_resource_uris` includes both static and template URIs
- Test `MCPTestClient.list_prompt_names`
- Test `MCPTestClient.middleware_count`
- Test `MCPTestClient.middlewares` returns correct (fn, scope) tuples
- Test `MCPTestClient.has_middleware` finds registered middleware
- Test `MCPTestClient.has_middleware` returns False for unregistered function
- Test `MCPTestClient.middleware_scope` returns None for global middleware
- Test `MCPTestClient.middleware_scope` returns correct scope set
- Test `MCPTestClient.middleware_scope` raises ValueError for unknown middleware
- Test `MCPTestClient.get_tool_tags` returns correct tags
- Test `MCPTestClient.get_tool_tags` raises ValueError for unknown tool
