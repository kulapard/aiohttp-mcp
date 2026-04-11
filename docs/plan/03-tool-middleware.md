# Feature 3: Middleware

## Problem

Auth, logging, rate limiting must be duplicated in every tool/resource/prompt function. There's no way to apply cross-cutting concerns once and have them run for all (or a subset of) MCP operations.

## Before (from `examples/server_auth.py` — repeated in every tool)

```python
@mcp.tool()
async def secure_op(data: str, ctx: Context) -> str:
    request = ctx.request
    if not request:
        return "Error: No request context"
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return "Authentication error: No credentials"
    is_valid, msg = validate_token(auth_header)
    if not is_valid:
        return f"Authentication error: {msg}"
    # Finally, the actual logic
    return f"Processed: {data}"
```

## After

```python
from typing import Any

from aiohttp_mcp import AiohttpMCP, Handler, ToolError, get_current_context

mcp = AiohttpMCP()

@mcp.middleware
async def require_auth(handler: Handler) -> Any:
    ctx = get_current_context()
    request = ctx.request
    if not request or not validate(request.headers.get("Authorization", "")):
        raise ToolError("Unauthorized")
    return await handler()

@mcp.middleware
async def log_calls(handler: Handler) -> Any:
    ctx = get_current_context()
    await ctx.info("Starting...")
    result = await handler()
    await ctx.info("Done")
    return result

@mcp.tool()
async def secure_op(data: str) -> str:
    return f"Processed: {data}"  # auth + logging already handled

@mcp.resource("config://app")
def get_config() -> str:
    return '{"version": "1.0"}'  # auth already handled
```

## Design

Follows the **aiohttp middleware pattern**: middleware receives `handler` and wraps it. Context is accessed via `get_current_context()` (contextvar) — not passed as a parameter, keeping the signature minimal.

Middlewares execute in registration order (outermost first). Each can:
- Short-circuit by raising before `handler()`
- Modify the result by transforming what `handler()` returns
- Run code before/after via `handler()`

## API

```python
# Type aliases (exported from aiohttp_mcp)
Handler = Callable[[], Awaitable[Any]]
Middleware = Callable[[Handler], Awaitable[Any]]

# Registration — applies to all primitives by default
@mcp.middleware
async def auth(handler: Handler) -> Any:
    ...

# With scope — only specific primitives
@mcp.middleware(scope=["tool"])
async def log_tools(handler: Handler) -> Any:
    ...

@mcp.middleware(scope=["tool", "resource"])
async def audit(handler: Handler) -> Any:
    ...

# Also available as a method call
mcp.add_middleware(auth_fn)
mcp.add_middleware(log_fn, scope=["tool"])
```

## Changes

### `aiohttp_mcp/protocol/typedefs.py`

Add type aliases:

```python
from collections.abc import Awaitable, Callable
from typing import Any

Handler = Callable[[], Awaitable[Any]]
Middleware = Callable[[Handler], Awaitable[Any]]
```

### `aiohttp_mcp/protocol/registry.py`

1. **`Registry.__init__`**: Add `self._middlewares: list[tuple[Middleware, set[str] | None]] = []`
   - `None` scope means "all primitives"

2. **New method `Registry.add_middleware()`**:
   ```python
   def add_middleware(
       self,
       middleware: Middleware,
       scope: list[str] | None = None,
   ) -> None:
       scope_set = set(scope) if scope else None
       self._middlewares.append((middleware, scope_set))
   ```

3. **Private helper `_run_with_middlewares()`** — shared by `call_tool`, `_call_resource`, `get_prompt`:
   ```python
   async def _run_with_middlewares(
       self, primitive: str, invoke: Handler,
   ) -> Any:
       handler = invoke
       for mw, scope in reversed(self._middlewares):
           if scope is None or primitive in scope:
               prev = handler
               async def make_handler(m=mw, p=prev):
                   return await m(p)
               handler = make_handler
       return await handler()
   ```

4. **`call_tool()`** — Wrap existing tool invocation:
   ```python
   async def invoke():
       return await td.fn_metadata.call_fn_with_arg_validation(...)

   result = await self._run_with_middlewares("tool", invoke)
   return _convert_to_content(result)
   ```

5. **`_call_resource()`** — Same pattern with `"resource"`.

6. **`get_prompt()`** — Same pattern with `"prompt"`.

### `aiohttp_mcp/core.py`

Add decorator and method:
```python
def middleware(self, fn=None, *, scope=None):
    """Decorator to register middleware. aiohttp-style."""
    def decorator(fn):
        self._registry.add_middleware(fn, scope=scope)
        return fn
    if fn is not None:
        return decorator(fn)
    return decorator

def add_middleware(self, middleware, scope=None):
    """Register middleware directly."""
    self._registry.add_middleware(middleware, scope=scope)
```

### `aiohttp_mcp/__init__.py`

Export `Middleware` and `Handler`.

## Complexity

**M (Medium)** — One shared middleware runner, but touches three execution paths. The aiohttp-style decorator pattern with optional `scope` kwarg requires handling both `@mcp.middleware` and `@mcp.middleware(scope=...)` forms.

## Test Plan

- Test middleware applies to tools
- Test middleware applies to resources
- Test middleware applies to prompts
- Test `scope=["tool"]` only runs for tool calls, not resources/prompts
- Test `scope=["resource", "prompt"]` skips tools
- Test default (no scope) runs for all primitives
- Test middleware that raises ToolError (short-circuit)
- Test middleware that modifies result
- Test middleware execution order (first registered = outermost)
- Test middleware accessing context via `get_current_context()`
- Test middleware chain with multiple middlewares
- Test all primitives work with no middleware registered (backward compat)
- Test `@mcp.middleware` decorator form
- Test `@mcp.middleware(scope=["tool"])` decorator with scope
- Test `mcp.add_middleware()` method form
