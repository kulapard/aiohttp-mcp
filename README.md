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

## Features

- Easy integration with aiohttp web applications
- Support for Model Context Protocol (MCP) tools
- Async-first design
- Type hints support
- Debug mode for development
- Flexible routing options

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

### Using Streamable HTTP Transport

For production deployments requiring advanced session management, you can use the streamable HTTP transport mode:

```python
import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, TransportMode, build_mcp_app

# Initialize MCP
mcp = AiohttpMCP()


# Define a tool
@mcp.tool()
def get_time(timezone: str) -> str:
    """Get the current time in the specified timezone."""
    tz = ZoneInfo(timezone)
    return datetime.datetime.now(tz).isoformat()


# Create application with streamable transport
app = build_mcp_app(mcp, path="/mcp", transport_mode=TransportMode.STREAMABLE_HTTP, stateless=True)
web.run_app(app)
```

### Client Example

Here's how to create a client that interacts with the MCP server:

```python
import asyncio

from mcp import ClientSession
from mcp.client.sse import sse_client


async def main():
    # Connect to the MCP server
    async with sse_client("http://localhost:8080/mcp") as (read_stream, write_stream):
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

- Python 3.10 or higher
- aiohttp >= 3.9.0, < 4.0.0
- aiohttp-sse >= 2.2.0, < 3.0.0
- anyio >= 4.9.0, < 5.0.0
- mcp >= 1.8.0, < 2.0.0

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
