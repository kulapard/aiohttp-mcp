# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Run tests**: `uv run pytest` (with coverage reporting configured)
- **Lint code**: `make lint` (runs pre-commit hooks and mypy)  
- **Type checking**: `uv run mypy .`
- **Build package**: `uv build`
- **Clean artifacts**: `make clean`
- **Install dependencies**: `uv sync --all-extras`

## Architecture Overview

This is a Python library (requires Python 3.11+) that provides Model Context Protocol (MCP) server functionality built on top of aiohttp. It implements the MCP protocol natively without depending on the `mcp` SDK at runtime.

### Runtime Dependencies

Only 3 runtime dependencies: `aiohttp`, `aiohttp-sse`, `pydantic`

### Key Components

- **AiohttpMCP** (`aiohttp_mcp/core.py`): Main class providing decorators for registering tools, resources, and prompts. Uses a native `Registry` and `MCPServer` internally.
- **AppBuilder** (`aiohttp_mcp/app.py`): Builds aiohttp applications with MCP server capabilities (Streamable HTTP transport), supporting both standalone apps and sub-applications.
- **Native Protocol Layer** (`aiohttp_mcp/protocol/`): Complete MCP protocol implementation:
  - `models.py` — MCP Pydantic models (JSON-RPC, Tool, Resource, Prompt, Content types) targeting MCP spec 2025-11-25
  - `server.py` — `MCPServer` JSON-RPC dispatch engine (handles initialize, ping, tools/*, resources/*, prompts/*)
  - `registry.py` — Tool/Resource/Prompt registration, execution, and URI template matching
  - `func_metadata.py` — Function introspection for generating JSON Schema from type hints via pydantic
  - `context.py` — Context system with `contextvars` propagation for request/lifespan context
  - `streams.py` — asyncio.Queue-based memory streams (replacing anyio)
  - `messages.py` — SessionMessage, EventMessage, EventStore types
- **StreamableHTTPServerTransport** (`aiohttp_mcp/streamable_http.py`): Streamable HTTP transport with SSE streaming, session management, and resumability
- **StreamableHTTPSessionManager** (`aiohttp_mcp/streamable_http_manager.py`): Session orchestrator supporting stateful and stateless modes
- **Discovery utilities** (`aiohttp_mcp/utils/discover.py`): Module discovery for finding decorated MCP functions

### Integration Patterns

The library supports two main integration patterns:
1. **Standalone MCP server**: Using `build_mcp_app()` to create a complete aiohttp application
2. **Sub-application**: Using `setup_mcp_subapp()` to integrate MCP functionality into existing aiohttp applications

### Transport

The library uses **Streamable HTTP** transport (MCP spec 2025-11-25):
- GET/POST/DELETE endpoints for full session lifecycle
- SSE streaming for server-to-client messages
- Supports both stateful (session persistence) and stateless operation modes
- Event store support for resumability
- JSON response mode for request-response patterns

**Usage:**
```python
from aiohttp_mcp import AiohttpMCP, build_mcp_app

mcp = AiohttpMCP()

# Default (stateful)
app = build_mcp_app(mcp, path="/mcp")

# Stateless mode (for load-balanced deployments)
app = build_mcp_app(mcp, path="/mcp", stateless=True)

# JSON response mode (instead of SSE streaming)
app = build_mcp_app(mcp, path="/mcp", json_response=True)
```

## Context Patterns

### Lifespan Context (Shared Resources)

Use lifespan context to provide shared resources (database pools, API clients, config) to all tools:

```python
from contextlib import asynccontextmanager
from dataclasses import dataclass
from aiohttp_mcp import AiohttpMCP, Context

@dataclass
class AppContext:
    db_pool: DatabasePool
    config: dict

@asynccontextmanager
async def app_lifespan(server):
    # Startup: Initialize resources
    db_pool = await create_db_pool("postgresql://localhost/mydb")
    config = {"max_results": 100}

    try:
        yield AppContext(db_pool=db_pool, config=config)
    finally:
        # Shutdown: Clean up
        await db_pool.close()

# Create MCP with lifespan
mcp = AiohttpMCP(lifespan=app_lifespan)

@mcp.tool()
async def query_db(sql: str, ctx: Context) -> str:
    # Access shared DB pool from lifespan context
    db_pool = ctx.request_context.lifespan_context.db_pool
    return await db_pool.query(sql)
```

### Request Context (Per-Request Data)

Access HTTP request data (headers, auth, cookies, client IP) in tools via the `Context` parameter:

```python
@mcp.tool()
async def secure_operation(data: str, ctx: Context) -> str:
    # Access the aiohttp Request object
    request = ctx.request_context.request

    if not request:
        return "No request context"

    # Access headers (auth tokens, identity, etc.)
    auth_token = request.headers.get("Authorization", "")
    user_id = request.headers.get("X-User-ID", "anonymous")
    api_key = request.headers.get("X-API-Key", "")

    # Access cookies
    session = request.cookies.get("session")

    # Access client IP
    client_ip = request.remote

    # Use auth info in your logic
    if not auth_token.startswith("Bearer "):
        return "Authentication required"

    return f"Processing for user {user_id} from {client_ip}"
```

**Available from `ctx.request_context.request`:**
- Headers: `request.headers.get("Header-Name")`
- Cookies: `request.cookies.get("cookie_name")`
- Client IP: `request.remote`
- Query params: `request.query`
- Path, method, URL: `request.path`, `request.method`, `request.url`

**Authentication Middleware Pattern:**

For enforcing authentication before MCP processing:

```python
from aiohttp_mcp import AppBuilder

mcp = AiohttpMCP()
app_builder = AppBuilder(mcp=mcp, path="/mcp")

async def authenticated_handler(request):
    # Validate auth before processing
    if not is_valid_token(request.headers.get("Authorization", "")):
        return web.Response(text="Unauthorized", status=401)

    # Pass to MCP handler
    return await app_builder.streamable_http_handler(request)
```

**Combining Both Contexts:**

See `examples/server_context.py` for a complete example showing how to use both lifespan context (shared resources) and request context (per-request auth/identity) together.

## Examples

- `examples/server.py` - Basic MCP server with simple tools
- `examples/server_streamable_http.py` - Streamable HTTP transport with stateless mode
- `examples/server_auth.py` - Authentication patterns and request context access
- `examples/server_context.py` - Combined lifespan and request context usage
- `examples/server_custom.py` - Custom handlers and advanced patterns

## Testing

- Tests are located in the `tests/` directory
- Uses pytest-asyncio with `asyncio_mode = "auto"` (configured in pyproject.toml)
- Coverage reporting configured for branch coverage
- Test utilities are in `tests/utils.py`
- Run individual test files: `uv run pytest tests/test_<module>.py`
- `mcp` package is a dev dependency used only for E2E test client (`mcp.ClientSession`)

## Documentation Policy

When making meaningful code changes (new features, API changes, bug fixes, dependency changes, removed/added modules), you **must** update the relevant documentation in the same commit or PR:

- **`CHANGELOG.md`** — Add an entry under `[Unreleased]` describing the change
- **`README.md`** — Update if the change affects public API, usage examples, installation, or requirements
- **`docs/`** — Update any relevant design documents if architecture changes
- **`CLAUDE.md`** — Update if the change affects development workflow, architecture, or project conventions

Do not defer documentation to a follow-up task. Code and docs ship together.
