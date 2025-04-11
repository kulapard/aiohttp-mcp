from aiohttp_mcp import AiohttpMCP


def register_mcp_resources(mcp: AiohttpMCP) -> None:
    """Register MCP resources."""

    @mcp.tool()
    def echo_tool(message: str) -> str:
        """Echo a message as a tool"""
        return f"Tool echo: {message}"

    @mcp.resource("echo://{message}", description="Echo a message as a resource. The is template resource")
    def echo_resource(message: str) -> str:
        """Echo a message as a resource. The is template resource"""
        return f"Resource echo: {message}"

    @mcp.resource("config://my-config", description="Return a config resource. This is static resource")
    def config_resource() -> str:
        """Return a config resource. This is static resource"""
        return "This is a config resource"

    @mcp.prompt()
    def echo_prompt(message: str) -> str:
        """Create an echo prompt"""
        return f"Please process this message: {message}"
