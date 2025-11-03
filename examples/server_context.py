"""Example MCP server demonstrating both lifespan context and request context.

This example shows a real-world pattern:
1. Lifespan context: Shared resources (database pools, config, API clients)
2. Request context: Per-request data (auth credentials, user identity)

This pattern is useful when you need to:
- Share expensive resources (DB connections) across all requests
- Access user-specific information for authorization and logging
- Maintain proper resource lifecycle management

Run with: uv run python examples/server_context.py
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, Context, build_mcp_app


# Mock database pool for demonstration
class DatabasePool:
    """Simulated database connection pool."""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.is_connected = False

    async def connect(self) -> None:
        """Establish database connections."""
        print(f"[DB] Connecting to {self.connection_string}...")
        await asyncio.sleep(0.1)  # Simulate connection time
        self.is_connected = True
        print("[DB] Connected!")

    async def disconnect(self) -> None:
        """Close database connections."""
        print("[DB] Disconnecting...")
        await asyncio.sleep(0.1)  # Simulate cleanup time
        self.is_connected = False
        print("[DB] Disconnected!")

    async def query(self, sql: str, user_id: str) -> list[dict[str, object]]:
        """Execute a query (simulated)."""
        if not self.is_connected:
            raise RuntimeError("Database not connected")

        # Simulate query execution
        await asyncio.sleep(0.05)

        # Return mock results
        return [
            {"id": 1, "user_id": user_id, "data": f"Result for query: {sql}"},
            {"id": 2, "user_id": user_id, "data": "More data"},
        ]

    async def get_user_permissions(self, user_id: str) -> set[str]:
        """Get user permissions from database (simulated)."""
        if not self.is_connected:
            raise RuntimeError("Database not connected")

        await asyncio.sleep(0.05)

        # Mock permissions based on user_id
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
        """Call external API (simulated)."""
        await asyncio.sleep(0.05)
        return {
            "status": "success",
            "endpoint": f"{self.base_url}/{endpoint}",
            "user": user_id,
            "api_key_used": self.api_key[:10] + "...",
        }


# Define application lifespan context
@dataclass
class AppContext:
    """Shared application resources available to all tools."""

    db_pool: DatabasePool
    api_client: ExternalAPIClient
    config: dict[str, object]


# Create lifespan context manager
@asynccontextmanager
async def app_lifespan(_server: object) -> AsyncIterator[AppContext]:
    """Initialize shared resources on startup, cleanup on shutdown."""
    print("\n=== Application Startup ===")

    # Initialize database pool
    db_pool = DatabasePool("postgresql://localhost/mydb")
    await db_pool.connect()

    # Initialize external API client
    api_client = ExternalAPIClient(base_url="https://api.example.com", api_key="sk-secret-key-12345")

    # Load configuration
    config = {
        "max_results": 100,
        "timeout_seconds": 30,
        "feature_flags": {"new_feature": True},
    }

    print("=== Startup Complete ===\n")

    try:
        # Yield the context that will be available to all tools
        yield AppContext(db_pool=db_pool, api_client=api_client, config=config)
    finally:
        # Cleanup on shutdown
        print("\n=== Application Shutdown ===")
        await db_pool.disconnect()
        print("=== Shutdown Complete ===\n")


# Create MCP server with lifespan context
mcp = AiohttpMCP(name="Context Demo Server", debug=True, lifespan=app_lifespan)


# Helper function to extract user identity from request
def get_user_id(
    ctx: Context,  # type: ignore[type-arg]
) -> str:
    """Extract user ID from request headers."""
    request = ctx.request_context.request
    if not request:
        return "anonymous"

    # Try to get user ID from header
    user_id = request.headers.get("X-User-ID")
    if user_id:
        return str(user_id)

    # Try to extract from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        # In real app, decode JWT token to get user ID
        return "authenticated_user"

    return "anonymous"


# Tools that use BOTH lifespan context (DB, API client) AND request context (user identity)


@mcp.tool(
    title="Query Database",
    description="Execute a SQL query with user identity tracking and logging",
)
async def query_database(
    sql: str,
    ctx: Context,  # type: ignore[type-arg]
) -> str:
    """Execute a database query with user identity for logging.

    Args:
        sql: SQL query to execute
        ctx: Context with both lifespan (DB) and request (user) data
    """
    # Access shared database pool from lifespan context
    db_pool = ctx.request_context.lifespan_context.db_pool

    # Access user identity from request context
    user_id = get_user_id(ctx)
    request = ctx.request_context.request
    client_ip = request.remote if request else "unknown"

    # Log the operation
    await ctx.info(f"Database query by user '{user_id}' from {client_ip}: {sql}")

    try:
        # Execute query with user identity
        results = await db_pool.query(sql, user_id)
        return f"Query results for user {user_id}: {results}"
    except Exception as e:
        await ctx.error(f"Database error: {e}")
        return f"Error: {e}"


@mcp.tool(
    title="Check Permissions",
    description="Check if the current user has permission to perform a specific action",
)
async def check_permissions(
    action: str,
    ctx: Context,  # type: ignore[type-arg]
) -> dict[str, object]:
    """Check if the current user has permission to perform an action.

    Args:
        action: Action to check (e.g., "read", "write", "delete")
        ctx: Context with DB and user data
    """
    # Access database from lifespan context
    db_pool = ctx.request_context.lifespan_context.db_pool

    # Get user identity from request
    user_id = get_user_id(ctx)

    # Query user permissions
    permissions = await db_pool.get_user_permissions(user_id)

    has_permission = action in permissions

    result: dict[str, object] = {
        "user_id": user_id,
        "action": action,
        "has_permission": has_permission,
        "all_permissions": list(permissions),
    }
    return result


@mcp.tool(
    title="Call External Service",
    description="Call an external API using the shared HTTP client with user identity",
)
async def call_external_service(
    endpoint: str,
    ctx: Context,  # type: ignore[type-arg]
) -> dict[str, object]:
    """Call an external API using shared client and user identity.

    Args:
        endpoint: API endpoint to call
        ctx: Context with API client and user data
    """
    # Access API client from lifespan context
    api_client = ctx.request_context.lifespan_context.api_client

    # Get user identity from request
    user_id = get_user_id(ctx)

    # Log the operation
    await ctx.info(f"External API call by user '{user_id}': {endpoint}")

    # Make API call with user identity
    result: dict[str, object] = await api_client.call(endpoint, user_id)

    return result


@mcp.tool(
    title="Get Configuration",
    description="Get application configuration from the lifespan context",
)
def get_config(
    ctx: Context,  # type: ignore[type-arg]
) -> dict[str, object]:
    """Get application configuration from lifespan context."""
    config = ctx.request_context.lifespan_context.config
    user_id = get_user_id(ctx)

    return {
        "user": user_id,
        "config": config,
        "info": "Configuration loaded from lifespan context",
    }


@mcp.tool(
    title="Get Context Info",
    description="Show all available lifespan and request context information for debugging",
)
def get_context_info(
    ctx: Context,  # type: ignore[type-arg]
) -> dict[str, object]:
    """Show all available context information (for debugging).

    Demonstrates accessing both lifespan and request context.
    """
    # Lifespan context
    config = ctx.request_context.lifespan_context.config
    db_connected = ctx.request_context.lifespan_context.db_pool.is_connected

    # Request context
    request = ctx.request_context.request
    user_id = get_user_id(ctx)

    result = {
        "mcp_request_id": ctx.request_id,
        "user_id": user_id,
        "lifespan_context": {
            "db_connected": db_connected,
            "config_keys": list(config.keys()),
            "api_client_available": True,
        },
    }

    if request:
        result["request_context"] = {
            "client_ip": request.remote,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "auth_present": bool(request.headers.get("Authorization")),
            "path": request.path,
        }
    else:
        result["request_context"] = "Not available"

    return result  # type: ignore[return-value]


if __name__ == "__main__":
    print("Starting MCP server with both lifespan and request context")
    print("\nServer will be available at: http://localhost:8080/mcp")
    print("\nExample request:")
    print("curl -H 'X-User-ID: admin' \\")
    print("     -H 'Authorization: Bearer token123' \\")
    print("     http://localhost:8080/mcp")
    print("\nTry these user IDs to see different permissions:")
    print("  - admin: read, write, delete, admin")
    print("  - user: read, write")
    print("  - guest: read only")

    app = build_mcp_app(mcp, path="/mcp")
    web.run_app(app, host="localhost", port=8080)
