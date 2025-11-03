import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from anthropic import Anthropic
from anthropic.types import ContentBlock, MessageParam, TextBlock, ToolParam, ToolResultBlockParam, ToolUseBlock
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.sse import sse_client
from typing_extensions import Self

load_dotenv()  # load environment variables from .env

MCP_SERVER_URL = "http://localhost:8080/mcp"
ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
MAX_TOKENS = 1000


class MCPClient:
    def __init__(self: Self):
        # Initialize session and client objects
        self.session: ClientSession | None = None
        self.exit_stack: AsyncExitStack = AsyncExitStack()
        self.anthropic: Anthropic = Anthropic()

    @asynccontextmanager
    async def connect_sse(self, url: str) -> AsyncIterator[None]:
        async with sse_client(url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                self.session = session

                await session.initialize()
                # List available tools
                response = await self.session.list_tools()
                tools = response.tools
                print("\nConnected to server with tools:", [tool.name for tool in tools])
                yield

    async def process_query(self, query: str) -> str:
        """Process a query using Claude and available tools"""
        assert self.session, "Session not initialized"

        # Prepare the initial message
        messages: list[MessageParam] = [
            MessageParam(
                role="user",
                content=query,
            )
        ]

        tools_list = await self.session.list_tools()
        available_tools = [
            ToolParam(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.inputSchema,
            )
            for tool in tools_list.tools
        ]

        # Initial Claude API call
        response = self.anthropic.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=MAX_TOKENS,
            messages=messages,
            tools=available_tools,
        )

        # Process response and handle tool calls
        final_text: list[str] = []

        assistant_message_content: list[ContentBlock] = []
        for content in response.content:
            if isinstance(content, TextBlock):
                final_text.append(content.text)
                assistant_message_content.append(content)
            elif isinstance(content, ToolUseBlock):
                tool_name = content.name
                tool_args = content.input

                # Execute tool call
                call_tool_result = await self.session.call_tool(tool_name, tool_args)
                final_text.append(f"[Calling tool {tool_name} with args {tool_args}]")

                assistant_message_content.append(content)
                messages.append(
                    MessageParam(
                        role="assistant",
                        content=assistant_message_content,
                    )
                )
                messages.append(
                    MessageParam(
                        role="user",
                        content=[
                            ToolResultBlockParam(
                                type="tool_result",
                                tool_use_id=content.id,
                                content=call_tool_result.content,  # type: ignore
                            )
                        ],
                    )
                )

                # Get next response from Claude
                response = self.anthropic.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=MAX_TOKENS,
                    messages=messages,
                    tools=available_tools,
                )
                content = response.content[0]
                if isinstance(content, TextBlock):
                    final_text.append(content.text)
                else:
                    raise TypeError(f"Expected TextBlock type, got {type(content)}")

        return "\n".join(final_text)

    async def chat_loop(self) -> None:
        """Run an interactive chat loop"""
        print("\nMCP Client Started!")
        print("Type your queries or 'quit' to exit.")

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == "quit":
                    break

                response = await self.process_query(query)
                print("\n" + response)

            except Exception as e:
                print(f"\nError: {e!s}")

    async def cleanup(self) -> None:
        """Clean up resources"""
        await self.exit_stack.aclose()


async def main() -> None:
    client = MCPClient()
    try:
        async with client.connect_sse(MCP_SERVER_URL):
            await client.chat_loop()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
