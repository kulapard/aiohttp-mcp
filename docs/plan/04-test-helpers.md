# Feature 4: Test Helpers

## Problem

Testing MCP tools requires unwrapping `list[Content]`, checking `isinstance(result[0], TextContent)`, accessing `.text`. Every test has 3-5 lines of boilerplate just to assert on a tool result.

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
```

## Changes

### New file: `aiohttp_mcp/testing.py`

```python
class ToolResult:
    """Wrapper around tool call results with convenient accessors."""

    def __init__(self, contents: list[Content], is_error: bool = False):
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

    def __init__(self, mcp: AiohttpMCP):
        self._mcp = mcp

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
        return result.messages[0].content.text  # type: ignore

    async def list_tool_names(self) -> list[str]:
        """List all registered tool names."""
        tools = await self._mcp.list_tools()
        return [t.name for t in tools]
```

### Import convention

NOT exported from `aiohttp_mcp/__init__.py`. Users import from `aiohttp_mcp.testing` explicitly, following the `aiohttp.test_utils` convention.

## Complexity

**S (Small)** — One new file, simple wrapper classes, no changes to existing files.

## Test Plan

- Test `ToolResult.text` returns first TextContent
- Test `ToolResult.json` parses JSON
- Test `ToolResult.is_error` set correctly on ToolError
- Test `MCPTestClient.call_tool` with kwargs
- Test `MCPTestClient.read_resource`
- Test `MCPTestClient.list_tool_names`
