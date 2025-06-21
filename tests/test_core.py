import pytest
from mcp.types import TextContent

from aiohttp_mcp import AiohttpMCP
from aiohttp_mcp.types import Tool

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

    with pytest.raises(RuntimeError, match="Application has not been built yet. Call `setup_app\\(\\)` first."):
        _ = mcp.app


async def test_setup_app_twice_error() -> None:
    """Test that calling setup_app twice raises RuntimeError."""
    from aiohttp import web

    mcp = AiohttpMCP()
    app1 = web.Application()
    app2 = web.Application()

    # First setup should work
    mcp.setup_app(app1)
    assert mcp.app is app1

    # Second setup should raise error
    with pytest.raises(RuntimeError, match="Application has already been set. Cannot set it again."):
        mcp.setup_app(app2)
