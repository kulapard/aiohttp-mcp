# aiohttp-mcp

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/kulapard/aiohttp-mcp/ci.yml?branch=master)
[![codecov](https://codecov.io/gh/kulapard/aiohttp-mcp/graph/badge.svg?token=BW3WBM8OVF)](https://codecov.io/gh/kulapard/aiohttp-mcp)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/kulapard/aiohttp-mcp/master.svg)](https://results.pre-commit.ci/latest/github/kulapard/aiohttp-mcp/master)
[![PyPI - Version](https://img.shields.io/pypi/v/aiohttp-mcp?color=blue&label=pypi%20package)](https://pypi.org/project/aiohttp-mcp)
[![PyPI Downloads](https://static.pepy.tech/badge/aiohttp-mcp)](https://pepy.tech/projects/aiohttp-mcp)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aiohttp-mcp)
![GitHub License](https://img.shields.io/github/license/kulapard/aiohttp-mcp?style=flat&color=blue)
---

Tools for building [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers on top of [aiohttp](https://docs.aiohttp.org/).

Implements the MCP protocol natively — no heavy SDK dependencies. Only 3 runtime dependencies: `aiohttp`, `aiohttp-sse`, `pydantic`.

## Features

- Native MCP protocol implementation (supports specs 2025-11-25, 2025-06-18, 2025-03-26)
- Streamable HTTP transport with SSE streaming
- Easy integration with aiohttp web applications
- Tool, Resource, and Prompt support with decorator-based registration
- Shared state via `ctx.app` and per-request data via `ctx.request_context.request`
- Stateless by default, with optional stateful mode for server push and resumability
- Event store support for resumability
- Async-first design with full type hints
- JSON response mode for non-streaming deployments

## Installation

With [uv](https://docs.astral.sh/uv/) package manager:

```bash
uv add aiohttp-mcp
```

Or with pip:

```bash
pip install aiohttp-mcp
```

## Quick Start

### Basic Server Setup

Create a simple MCP server with a custom tool:

```python
import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, build_mcp_app

# Initialize MCP
mcp = AiohttpMCP()


# Define a tool
@mcp.tool()
def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


# Create and run the application
app = build_mcp_app(mcp, path="/mcp")
web.run_app(app)
```

### Using as a Sub-Application

You can also use aiohttp-mcp as a sub-application in your existing aiohttp server:

```python
import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, setup_mcp_subapp

mcp = AiohttpMCP()


# Define a tool
@mcp.tool()
def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


# Create your main application
app = web.Application()

# Add MCP as a sub-application
setup_mcp_subapp(app, mcp, prefix="/mcp")

web.run_app(app)
```

### Stateful Mode & Resumability

By default, the server runs in **stateless mode** — each request creates a fresh transport, making it safe for load-balanced and multi-instance deployments. Tool notifications (`ctx.info()`) work inline via SSE POST responses.

For single-instance deployments that need server-initiated push (via GET SSE stream) or SSE resumability, enable **stateful mode**. Session state and events are stored in-process memory — this is not suitable for multi-instance deployments without sticky sessions.

```python
from aiohttp_mcp import AiohttpMCP, InMemoryEventStore, build_mcp_app

# Stateful with resumability (single instance only)
# If client disconnects, it can reconnect with Last-Event-ID to replay missed events
mcp = AiohttpMCP(event_store=InMemoryEventStore())
app = build_mcp_app(mcp, path="/mcp", stateless=False)
```

> **Note:** `InMemoryEventStore` is in-process only. For multi-instance stateful deployments, implement a custom `EventStore` backed by shared storage (e.g., Redis) and use sticky sessions.

### Context Access

Tools access shared state via `ctx.app` and HTTP request data via `ctx.request_context.request`:

```python
from collections.abc import AsyncIterator

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, build_mcp_app, get_current_context

mcp = AiohttpMCP()


@mcp.tool()
async def secure_query(sql: str) -> str:
    """Run a database query with auth validation."""
    ctx = get_current_context()

    # Access HTTP request (headers, cookies, client IP)
    user_id = ctx.request_context.request.headers.get("X-User-ID", "anonymous")

    # Access shared resources from aiohttp app
    db_pool = ctx.app["db_pool"]

    # Send log to client
    await ctx.info(f"Query by {user_id}")

    return f"Query by {user_id}: {sql}"


async def startup(app: web.Application) -> AsyncIterator[None]:
    app["db_pool"] = await create_db_pool()
    yield
    await app["db_pool"].close()


app = build_mcp_app(mcp, path="/mcp")
app.cleanup_ctx.append(startup)
```

You can also use `ctx: Context` as an explicit parameter (auto-injected) or `mcp.get_context()`. See [CLAUDE.md](CLAUDE.md#context-access) for all options.

### Client Example

Here's how to create a client that interacts with the MCP server using the `mcp` client library:

```python
import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def main():
    # Connect to the MCP server
    async with streamablehttp_client("http://localhost:8080/mcp") as (
        read_stream,
        write_stream,
        _,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the session
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Available tools:", [tool.name for tool in tools.tools])

            # Call a tool
            result = await session.call_tool("get_time", {"timezone": "UTC"})
            print("Current time in UTC:", result.content)


if __name__ == "__main__":
    asyncio.run(main())
```

### More Examples

For more examples, check the [examples](examples) directory.

## Development

### Setup Development Environment

1. Clone the repository:

```bash
git clone https://github.com/kulapard/aiohttp-mcp.git
cd aiohttp-mcp
```

2. Create and activate a virtual environment:

```bash
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install development dependencies:

```bash
uv sync --all-extras
```

### Running Tests

```bash
uv run pytest
```

## Requirements

- Python 3.11 or higher
- aiohttp >= 3.9.0, < 4.0.0
- aiohttp-sse >= 2.2.0, < 3.0.0
- pydantic >= 2.0.0, < 3.0.0

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
