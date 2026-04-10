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
from aiohttp_mcp import AiohttpMCP, Context, ToolError

# Applies to all MCP operations (tools, resources, prompts)
async def require_auth(ctx: Context, call_next):
    request = ctx.request
    if not request or not validate(request.headers.get("Authorization", "")):
        raise ToolError("Unauthorized")
    return await call_next()

# Applies only to tools
async def log_tool_calls(ctx: Context, call_next):
    await ctx.info(f"Calling tool...")
    result = await call_next()
    await ctx.info(f"Done")
    return result

mcp = AiohttpMCP()
mcp.add_middleware(require_auth)                        # all primitives
mcp.add_middleware(log_tool_calls, scope=["tool"])       # tools only

@mcp.tool()
async def secure_op(data: str) -> str:
    return f"Processed: {data}"  # auth + logging already handled

@mcp.resource("config://app")
def get_config() -> str:
    return '{"version": "1.0"}'  # auth already handled
```

Middlewares execute in registration order (outermost first). Each can:
- Short-circuit by raising `ToolError` (or `ValueError` for resources/prompts)
- Modify the result by returning a different value
- Run code before/after the handler via `call_next()`

This mirrors aiohttp's own middleware pattern, so it feels natural to aiohttp developers.

## API

```python
# Scope type
Scope = Literal["tool", "resource", "prompt"]

# Middleware signature — same for all primitives
CallNext = Callable[[], Awaitable[Any]]
Middleware = Callable[[Context, CallNext], Awaitable[Any]]

# Registration
mcp.add_middleware(fn)                          # all primitives (default)
mcp.add_middleware(fn, scope=["tool"])           # tools only
mcp.add_middleware(fn, scope=["tool", "resource"])  # tools + resources
```

## Changes

### `aiohttp_mcp/protocol/typedefs.py`

Add type aliases:

```python
CallNext = Callable[[], Awaitable[Any]]
Middleware = Callable[["Context", CallNext], Awaitable[Any]]
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

3. **Private helper `_build_middleware_chain()`** — shared by `call_tool`, `_call_resource`, `get_prompt`:
   ```python
   def _applicable_middlewares(self, primitive: str) -> list[Middleware]:
       return [
           mw for mw, scope in self._middlewares
           if scope is None or primitive in scope
       ]

   async def _run_with_middlewares(
       self, primitive: str, ctx: Context, invoke: CallNext,
   ) -> Any:
       call_next = invoke
       for mw in reversed(self._applicable_middlewares(primitive)):
           prev = call_next
           call_next = functools.partial(mw, ctx, prev)  # type: ignore
       return await call_next()
   ```

4. **`call_tool()`** — Wrap existing tool invocation with middleware chain:
   ```python
   async def invoke():
       return await td.fn_metadata.call_fn_with_arg_validation(...)

   result = await self._run_with_middlewares("tool", ctx, invoke)
   return _convert_to_content(result)
   ```

5. **`_call_resource()`** — Same pattern:
   ```python
   async def invoke():
       if rd.is_async:
           return await rd.fn(**kwargs)
       return rd.fn(**kwargs)

   result = await self._run_with_middlewares("resource", ctx, invoke)
   # ... convert to TextResourceContents
   ```

6. **`get_prompt()`** — Same pattern:
   ```python
   async def invoke():
       if pd.is_async:
           return await pd.fn(**kwargs)
       return pd.fn(**kwargs)

   result = await self._run_with_middlewares("prompt", ctx, invoke)
   # ... convert to GetPromptResult
   ```

### `aiohttp_mcp/core.py`

Add delegation method:
```python
def add_middleware(
    self,
    middleware: Middleware,
    scope: list[str] | None = None,
) -> None:
    self._registry.add_middleware(middleware, scope=scope)
```

### `aiohttp_mcp/__init__.py`

Export `Middleware` and `CallNext`.

## Complexity

**M (Medium)** — The chain-building logic is straightforward (one shared helper), but it touches three execution paths (`call_tool`, `_call_resource`, `get_prompt`). Context must be available in all three, which it already is for tools but needs plumbing for resources and prompts.

## Test Plan

- Test middleware applies to tools
- Test middleware applies to resources
- Test middleware applies to prompts
- Test `scope=["tool"]` only runs for tool calls, not resources/prompts
- Test `scope=["resource", "prompt"]` skips tools
- Test default (no scope) runs for all primitives
- Test single middleware that raises error (short-circuit)
- Test middleware execution order (first registered = outermost)
- Test middleware receives correct Context
- Test middleware chain with multiple middlewares
- Test all primitives still work with no middleware registered (backward compat)
