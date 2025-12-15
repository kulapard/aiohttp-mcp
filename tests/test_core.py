import pytest
from aiohttp import web
from mcp.server.fastmcp.exceptions import ToolError

from aiohttp_mcp import AiohttpMCP
from aiohttp_mcp.types import Annotations, Icon, TextContent, Tool

from .utils import register_mcp_resources

# Set the pytest marker for async tests/fixtures
pytestmark = pytest.mark.anyio


async def test_list_tools(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test tool registration
    tools: list[Tool] = await mcp.list_tools()
    assert len(tools) == 1
    tool: Tool = tools[0]
    assert tool.name == "echo_tool"
    assert tool.description == "Echo a message as a tool"
    assert "message" in tool.inputSchema["properties"]


async def test_tool_with_title() -> None:
    """Test that tool decorator supports title parameter."""
    mcp = AiohttpMCP()

    @mcp.tool(name="titled_tool", title="My Tool Title", description="My tool description")
    def my_tool(arg: str) -> str:
        """Tool docstring"""
        return f"Result: {arg}"

    tools = await mcp.list_tools()
    assert len(tools) == 1
    tool = tools[0]
    assert tool.name == "titled_tool"
    assert tool.title == "My Tool Title"
    assert tool.description == "My tool description"


async def test_call_tool(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test tool execution through MCP
    call_result = await mcp.call_tool("echo_tool", {"message": "test message"})
    assert len(call_result) == 1
    content = call_result[0]
    assert isinstance(content, TextContent)
    assert content.text == "Tool echo: test message"


async def test_list_resources(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test resource registration
    resources = await mcp.list_resources()
    assert len(resources) == 1  # Only static resource is returned

    # Check static resource
    static_resource = resources[0]
    assert str(static_resource.uri) == "config://my-config"
    assert static_resource.name == "config_resource"  # Name is the URI when not explicitly provided
    assert static_resource.description == "Return a config resource. This is static resource"


async def test_list_resource_templates(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test resource template listing
    templates = await mcp.list_resource_templates()
    assert len(templates) == 1

    template = templates[0]
    assert template.uriTemplate == "echo://{message}"
    assert template.name == "echo_resource"
    assert template.description == "Echo a message as a resource. The is template resource"


async def test_list_prompts(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test prompt registration
    prompts = await mcp.list_prompts()
    assert len(prompts) == 1

    prompt = prompts[0]
    assert prompt.name == "echo_prompt"
    assert prompt.description == "Create an echo prompt"
    assert prompt.arguments is not None
    assert len(prompt.arguments) == 1
    assert prompt.arguments[0].name == "message"
    assert prompt.arguments[0].required is True


async def test_read_resource(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test reading static resource
    static_resource = await mcp.read_resource("config://my-config")
    contents = list(static_resource)
    assert len(contents) == 1
    content = contents[0]
    assert content.content == "This is a config resource"
    assert content.mime_type == "text/plain"

    # Test reading template resource
    template_resource = await mcp.read_resource("echo://test-message")
    contents = list(template_resource)
    assert len(contents) == 1
    content = contents[0]
    assert content.content == "Resource echo: test-message"
    assert content.mime_type == "text/plain"


async def test_get_prompt(mcp: AiohttpMCP) -> None:
    register_mcp_resources(mcp)

    # Test getting prompt with arguments
    prompt_result = await mcp.get_prompt("echo_prompt", {"message": "test message"})
    assert len(prompt_result.messages) == 1
    assert prompt_result.messages[0].role == "user"
    assert isinstance(prompt_result.messages[0].content, TextContent)
    assert prompt_result.messages[0].content.text == "Please process this message: test message"


async def test_app_property_error_before_setup() -> None:
    """Test that accessing app property before setup raises RuntimeError."""
    mcp = AiohttpMCP()

    with pytest.raises(RuntimeError, match=r"Application has not been built yet. Call `setup_app\(\)` first."):
        _ = mcp.app


async def test_setup_app_twice_error() -> None:
    """Test that calling setup_app twice raises RuntimeError."""
    mcp = AiohttpMCP()
    app1 = web.Application()
    app2 = web.Application()

    # First setup should work
    mcp.setup_app(app1)
    assert mcp.app is app1

    # Second setup should raise error
    with pytest.raises(RuntimeError, match=r"Application has already been set. Cannot set it again."):
        mcp.setup_app(app2)


async def test_add_tool() -> None:
    """Test adding tools directly without decorator."""
    mcp = AiohttpMCP()

    # Define a function to add as a tool
    def my_function(message: str) -> str:
        """Process a message."""
        return f"Processed: {message}"

    # Add the tool directly
    mcp.add_tool(my_function, name="my_tool", description="A test tool")

    # Verify it was added
    tools = await mcp.list_tools()
    assert len(tools) == 1
    assert tools[0].name == "my_tool"
    assert tools[0].description == "A test tool"

    # Test calling the tool
    result = await mcp.call_tool("my_tool", {"message": "test"})
    assert len(result) == 1


async def test_remove_tool() -> None:
    """Test removing a registered tool."""
    mcp = AiohttpMCP()

    @mcp.tool(name="test_tool")
    def my_tool(arg: str) -> str:
        return f"Result: {arg}"

    # Verify tool exists
    tools = await mcp.list_tools()
    assert len(tools) == 1
    assert tools[0].name == "test_tool"

    # Remove the tool
    mcp.remove_tool("test_tool")

    # Verify tool was removed
    tools = await mcp.list_tools()
    assert len(tools) == 0


async def test_tool_with_enhanced_parameters() -> None:
    """Test tool decorator with icons, meta, and structured_output parameters."""
    mcp = AiohttpMCP()

    icon = Icon(src="https://example.com/icon.png")

    @mcp.tool(
        name="enhanced_tool",
        title="Enhanced Tool",
        description="Tool with extra parameters",
        icons=[icon],
        meta={"version": "1.0"},
        structured_output=True,
    )
    def enhanced_tool(value: int) -> int:
        """Enhanced tool."""
        return value * 2

    tools = await mcp.list_tools()
    assert len(tools) == 1
    tool = tools[0]
    assert tool.name == "enhanced_tool"
    assert tool.title == "Enhanced Tool"


async def test_resource_with_enhanced_parameters() -> None:
    """Test resource decorator with title, icons, and annotations parameters."""
    mcp = AiohttpMCP()

    icon = Icon(src="https://example.com/icon.png")
    annotations = Annotations(audience=["user"])

    @mcp.resource(
        "test://resource",
        name="test_resource",
        title="Test Resource",
        description="Enhanced resource",
        mime_type="text/plain",
        icons=[icon],
        annotations=annotations,
    )
    def test_resource() -> str:
        """Test resource."""
        return "resource content"

    resources = await mcp.list_resources()
    assert len(resources) == 1
    resource = resources[0]
    assert resource.name == "test_resource"
    assert resource.title == "Test Resource"


async def test_prompt_with_enhanced_parameters() -> None:
    """Test prompt decorator with title and icons parameters."""
    mcp = AiohttpMCP()

    icon = Icon(src="https://example.com/icon.png")

    @mcp.prompt(
        name="enhanced_prompt",
        title="Enhanced Prompt",
        description="Prompt with icons",
        icons=[icon],
    )
    def enhanced_prompt(value: str) -> str:
        """Enhanced prompt."""
        return f"Prompt: {value}"

    prompts = await mcp.list_prompts()
    assert len(prompts) == 1
    prompt = prompts[0]
    assert prompt.name == "enhanced_prompt"
    assert prompt.title == "Enhanced Prompt"


async def test_get_context() -> None:
    """Test getting the current context."""
    mcp = AiohttpMCP()

    # get_context() should return the FastMCP context
    # This is a simple test to ensure the method exists and returns something
    context = mcp.get_context()
    assert context is not None


async def test_completion() -> None:
    """Test completion decorator."""
    mcp = AiohttpMCP()

    # Test that completion decorator returns a callable
    decorator = mcp.completion()
    assert callable(decorator)


async def test_custom_route() -> None:
    """Test custom route decorator."""
    mcp = AiohttpMCP()

    # Test that custom_route decorator returns a callable
    decorator = mcp.custom_route("/test", ["GET"], name="test_route")
    assert callable(decorator)


async def test_server_property() -> None:
    """Test that server property returns the underlying MCP server."""
    mcp = AiohttpMCP()

    server = mcp.server
    assert server is not None


async def test_event_store_property() -> None:
    """Test that event_store property returns None when not configured."""
    mcp = AiohttpMCP()

    event_store = mcp.event_store
    assert event_store is None


async def test_call_tool_with_nonexistent_tool() -> None:
    """Test calling a tool that doesn't exist."""
    mcp = AiohttpMCP()

    # Calling non-existent tool should raise a ToolError
    with pytest.raises(ToolError, match="Unknown tool"):
        await mcp.call_tool("nonexistent_tool", {})


async def test_get_prompt_with_nonexistent_prompt() -> None:
    """Test getting a prompt that doesn't exist."""
    mcp = AiohttpMCP()

    # Getting non-existent prompt should raise a ValueError
    with pytest.raises(ValueError, match="Unknown prompt"):
        await mcp.get_prompt("nonexistent_prompt", {})


async def test_read_resource_with_invalid_uri() -> None:
    """Test read_resource with invalid or non-existent URI."""
    mcp = AiohttpMCP()

    # Reading non-existent resource should raise a ValueError
    with pytest.raises(ValueError, match="Unknown resource"):
        await mcp.read_resource("invalid://nonexistent")
