"""Example MCP server demonstrating request context access for authentication.

This example shows how to:
1. Access HTTP headers (Authorization, API keys, User-ID) from MCP tools
2. Access cookies, client IP, and other request data
3. Implement authentication middleware with custom handlers
4. Make authorization decisions based on request context

Run with: uv run python examples/server_auth.py
"""

import datetime
from zoneinfo import ZoneInfo

from aiohttp import web

from aiohttp_mcp import AiohttpMCP, Context, build_mcp_app

# Example 1: Simple tool that accesses request context
simple_mcp = AiohttpMCP(name="Simple Auth Server", debug=True)


@simple_mcp.tool()
async def get_time_with_auth(
    timezone: str,
    ctx: Context,  # type: ignore[type-arg]
) -> str:
    """Get the current time, including authentication info from the request.

    Args:
        timezone: Timezone name (e.g., "America/New_York")
        ctx: MCP context with request information
    """
    # Access the aiohttp request
    request = ctx.request_context.request

    result = {
        "time": datetime.datetime.now(ZoneInfo(timezone)).isoformat(),
        "timezone": timezone,
        "request_id": ctx.request_id,
    }

    if request:
        # Extract authentication and identity information
        result["auth_header"] = request.headers.get("Authorization", "No auth provided")
        result["api_key"] = request.headers.get("X-API-Key", "No API key")
        result["user_id"] = request.headers.get("X-User-ID", "anonymous")
        result["user_agent"] = request.headers.get("User-Agent", "Unknown")
        result["client_ip"] = request.remote or "Unknown"
        result["session_cookie"] = request.cookies.get("session", "No session")

        # Log the request
        await ctx.info(f"Request from {result['client_ip']} by user {result['user_id']}")
    else:
        result["warning"] = "No request context available"

    return str(result)


@simple_mcp.tool()
async def echo_headers(
    ctx: Context,  # type: ignore[type-arg]
) -> dict[str, object]:
    """Echo all HTTP headers from the request.

    Useful for debugging and understanding what headers are available.
    """
    request = ctx.request_context.request

    if not request:
        return {"error": "No request context available"}

    # Convert headers to dict for easy viewing
    headers = dict(request.headers)

    return {
        "headers": headers,
        "cookies": dict(request.cookies),
        "path": request.path,
        "method": request.method,
        "query": dict(request.query),
        "remote": request.remote,
    }


# Example 2: Server with authentication middleware
auth_mcp = AiohttpMCP(name="Authenticated Server", debug=True)

# Simple token validation (in production, use proper auth)
VALID_TOKENS = {"secret-token-123", "demo-token-456"}
VALID_API_KEYS = {"api-key-abc", "api-key-xyz"}


def validate_bearer_token(auth_header: str) -> tuple[bool, str]:
    """Validate Bearer token from Authorization header."""
    if not auth_header.startswith("Bearer "):
        return False, "Invalid auth format. Expected 'Bearer <token>'"

    token = auth_header.replace("Bearer ", "")
    if token not in VALID_TOKENS:
        return False, "Invalid token"

    return True, "OK"


def validate_api_key(api_key: str) -> tuple[bool, str]:
    """Validate API key from X-API-Key header."""
    if api_key not in VALID_API_KEYS:
        return False, "Invalid API key"

    return True, "OK"


@auth_mcp.tool()
async def secure_operation(
    data: str,
    ctx: Context,  # type: ignore[type-arg]
) -> str:
    """Perform a secure operation that requires authentication.

    This tool validates authentication before performing the operation.

    Args:
        data: Data to process
        ctx: MCP context with request information
    """
    request = ctx.request_context.request

    if not request:
        return "Error: No request context available"

    # Extract auth information
    auth_header = request.headers.get("Authorization", "")
    user_id = request.headers.get("X-User-ID", "anonymous")
    client_ip = request.remote or "unknown"

    # Validate authentication (Bearer token)
    if auth_header:
        is_valid, message = validate_bearer_token(auth_header)
        if not is_valid:
            await ctx.warning(f"Auth failed for {client_ip}: {message}")
            return f"Authentication error: {message}"
    else:
        # Try API key authentication
        api_key = request.headers.get("X-API-Key", "")
        if api_key:
            is_valid, message = validate_api_key(api_key)
            if not is_valid:
                await ctx.warning(f"Auth failed for {client_ip}: {message}")
                return f"Authentication error: {message}"
        else:
            return "Authentication error: No credentials provided"

    # Authentication successful - perform the operation
    await ctx.info(f"Secure operation by user {user_id} from {client_ip}")
    result = f"Processed '{data}' for user {user_id} from {client_ip}"

    return result


@auth_mcp.tool()
def get_user_info(
    ctx: Context,  # type: ignore[type-arg]
) -> dict[str, object]:
    """Get information about the authenticated user."""
    request = ctx.request_context.request

    if not request:
        return {"error": "No request context"}

    return {
        "user_id": request.headers.get("X-User-ID", "anonymous"),
        "client_ip": request.remote,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "authenticated": bool(request.headers.get("Authorization") or request.headers.get("X-API-Key")),
    }


if __name__ == "__main__":
    print("Starting MCP server with authentication examples on http://localhost:8080/mcp")
    print("\nExample request:")
    print("curl -H 'Authorization: Bearer my-token' \\")
    print("     -H 'X-User-ID: alice' \\")
    print("     -H 'X-API-Key: my-key' \\")
    print("     http://localhost:8080/mcp")

    # You can switch between simple_mcp and auth_mcp here
    app = build_mcp_app(auth_mcp, path="/mcp")
    web.run_app(app, host="localhost", port=8080)
