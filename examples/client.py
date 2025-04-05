# ruff: noqa: T201
import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any

from anthropic import Anthropic
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
        messages: list[dict[str, Any]] = [{"role": "user", "content": query}]

        response = await self.session.list_tools()
        available_tools = [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            for tool in response.tools
        ]

        # Initial Claude API call
        response = self.anthropic.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=MAX_TOKENS,
            messages=messages,
            tools=available_tools,
        )

        # Process response and handle tool calls
        final_text = []

        assistant_message_content = []
        for content in response.content:  # type: ignore[attr-defined]
            if content.type == "text":
                final_text.append(content.text)
                assistant_message_content.append(content)
            elif content.type == "tool_use":
                tool_name = content.name
                tool_args = content.input

                # Execute tool call
                result = await self.session.call_tool(tool_name, tool_args)
                final_text.append(f"[Calling tool {tool_name} with args {tool_args}]")

                assistant_message_content.append(content)
                messages.append({"role": "assistant", "content": assistant_message_content})
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": content.id,
                                "content": result.content,
                            }
                        ],
                    }
                )

                # Get next response from Claude
                response = self.anthropic.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=1000,
                    messages=messages,
                    tools=available_tools,
                )

                final_text.append(response.content[0].text)  # type: ignore[attr-defined]

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
