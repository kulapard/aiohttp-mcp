"""Example MCP server demonstrating shared state via aiohttp Application.

This example shows a real-world pattern:
1. Store shared resources (DB pools, config, API clients) on the aiohttp app
2. Access per-request data (auth credentials, user identity) via ctx
3. Use ctx.app["key"] to read shared state from tools

Run with: uv run python examples/server_context.py
"""

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, build_mcp_app, get_current_context


# Mock database pool for demonstration
class DatabasePool:
    """Simulated database connection pool."""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.is_connected = False

    async def connect(self) -> None:
        print(f"[DB] Connecting to {self.connection_string}...")
        await asyncio.sleep(0.1)
        self.is_connected = True
        print("[DB] Connected!")

    async def disconnect(self) -> None:
        print("[DB] Disconnecting...")
        await asyncio.sleep(0.1)
        self.is_connected = False
        print("[DB] Disconnected!")

    async def query(self, sql: str, user_id: str) -> list[dict[str, object]]:
        if not self.is_connected:
            raise RuntimeError("Database not connected")
        await asyncio.sleep(0.05)
        return [
            {"id": 1, "user_id": user_id, "data": f"Result for query: {sql}"},
            {"id": 2, "user_id": user_id, "data": "More data"},
        ]

    async def get_user_permissions(self, user_id: str) -> set[str]:
        if not self.is_connected:
            raise RuntimeError("Database not connected")
        await asyncio.sleep(0.05)
        if user_id == "admin":
            return {"read", "write", "delete", "admin"}
        elif user_id == "user":
            return {"read", "write"}
        else:
            return {"read"}


# Mock API client for demonstration
class ExternalAPIClient:
    """Simulated external API client."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

    async def call(self, endpoint: str, user_id: str) -> dict[str, object]:
        await asyncio.sleep(0.05)
        return {
            "status": "success",
            "endpoint": f"{self.base_url}/{endpoint}",
            "user": user_id,
            "api_key_used": self.api_key[:10] + "...",
        }


# Create MCP server
mcp = AiohttpMCP(name="Context Demo Server", debug=True)


# Helper to extract user identity from request
def get_user_id() -> str:
    """Extract user ID from request headers."""
    ctx = get_current_context()
    request = ctx.request_context.request
    if not request:
        return "anonymous"
    user_id = request.headers.get("X-User-ID")
    if user_id:
        return str(user_id)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return "authenticated_user"
    return "anonymous"


# --- Tools that use ctx.app for shared state and ctx for request data ---


@mcp.tool(
    title="Query Database",
    description="Execute a SQL query with user identity tracking",
)
async def query_database(sql: str) -> str:
    """Execute a database query with user identity for logging."""
    ctx = get_current_context()
    db_pool: DatabasePool = ctx.app["db_pool"]
    user_id = get_user_id()
    request = ctx.request_context.request
    client_ip = request.remote if request else "unknown"

    await ctx.info(f"Database query by user '{user_id}' from {client_ip}: {sql}")

    try:
        results = await db_pool.query(sql, user_id)
        return f"Query results for user {user_id}: {results}"
    except Exception as e:
        await ctx.error(f"Database error: {e}")
        return f"Error: {e}"


@mcp.tool(
    title="Check Permissions",
    description="Check if the current user has permission to perform a specific action",
)
async def check_permissions(action: str) -> dict[str, object]:
    """Check if the current user has permission to perform an action."""
    ctx = get_current_context()
    db_pool: DatabasePool = ctx.app["db_pool"]
    user_id = get_user_id()

    permissions = await db_pool.get_user_permissions(user_id)

    return {
        "user_id": user_id,
        "action": action,
        "has_permission": action in permissions,
        "all_permissions": list(permissions),
    }


@mcp.tool(
    title="Call External Service",
    description="Call an external API using the shared HTTP client",
)
async def call_external_service(endpoint: str) -> dict[str, object]:
    """Call an external API using shared client and user identity."""
    ctx = get_current_context()
    api_client: ExternalAPIClient = ctx.app["api_client"]
    user_id = get_user_id()

    await ctx.info(f"External API call by user '{user_id}': {endpoint}")

    result: dict[str, object] = await api_client.call(endpoint, user_id)
    return result


@mcp.tool(
    title="Get Configuration",
    description="Get application configuration",
)
def get_config() -> dict[str, object]:
    """Get application configuration stored on the app."""
    ctx = get_current_context()
    config: dict[str, Any] = ctx.app["config"]
    user_id = get_user_id()

    return {
        "user": user_id,
        "config": config,
        "info": "Configuration loaded from app context",
    }


@mcp.tool(
    title="Get Context Info",
    description="Show all available context information for debugging",
)
def get_context_info() -> dict[str, Any]:
    """Show all available context information (for debugging)."""
    ctx = get_current_context()
    config: dict[str, Any] = ctx.app["config"]
    db_pool: DatabasePool = ctx.app["db_pool"]
    user_id = get_user_id()

    result: dict[str, Any] = {
        "mcp_request_id": ctx.request_id,
        "user_id": user_id,
        "app_state": {
            "db_connected": db_pool.is_connected,
            "config_keys": list(config.keys()),
            "api_client_available": "api_client" in ctx.app,
        },
    }

    request = ctx.request_context.request
    if request:
        result["request_context"] = {
            "client_ip": request.remote,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "auth_present": bool(request.headers.get("Authorization")),
            "path": request.path,
        }

    return result


async def startup(app_instance: web.Application) -> AsyncIterator[None]:
    """Initialize shared resources on startup, cleanup on shutdown."""
    print("\n=== Application Startup ===")

    db_pool = DatabasePool("postgresql://localhost/mydb")
    await db_pool.connect()

    api_client = ExternalAPIClient(
        base_url="https://api.example.com",
        api_key="sk-secret-key-12345",
    )

    config = {
        "max_results": 100,
        "timeout_seconds": 30,
        "feature_flags": {"new_feature": True},
    }

    # Store shared resources on the aiohttp app
    app_instance["db_pool"] = db_pool
    app_instance["api_client"] = api_client
    app_instance["config"] = config

    print("=== Startup Complete ===\n")

    yield

    # Cleanup on shutdown
    print("\n=== Application Shutdown ===")
    await db_pool.disconnect()
    print("=== Shutdown Complete ===\n")


if __name__ == "__main__":
    print("Starting MCP server with shared app context")
    print("\nServer will be available at: http://localhost:8080/mcp")
    print("\nTry these user IDs (via X-User-ID header):")
    print("  - admin: read, write, delete, admin")
    print("  - user: read, write")
    print("  - guest: read only")

    app = build_mcp_app(mcp, path="/mcp")
    app.cleanup_ctx.append(startup)
    web.run_app(app, host="localhost", port=8080)
