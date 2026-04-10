# Feature 5: McpGroup — Blueprint for MCP Primitives

## Problem

Large MCP servers have many tools/resources/prompts with no organizational structure. Related primitives can't share a name prefix, middleware, tags, or annotations without repeating configuration on each one.

This feature subsumes [Feature 6 (Tool Tags)](06-tool-tags.md) — groups provide a more natural organizational unit than flat tags, while tags can still exist as metadata within a group.

## Before

```python
mcp = AiohttpMCP()

# All tools are flat — no grouping, no shared config
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def invoice_get(invoice_id: str) -> str: ...

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def invoice_list(limit: int = 10) -> str: ...

@mcp.tool()
def user_get(user_id: str) -> str: ...

# Auth must be global or duplicated per-tool
```

## After

```python
from typing import Any

from aiohttp_mcp import AiohttpMCP, Handler, McpGroup, ToolAnnotations, ToolError, get_current_context

mcp = AiohttpMCP()

# --- Invoice group ---
invoices = McpGroup(
    prefix="invoice",
    annotations=ToolAnnotations(readOnlyHint=True),
    tags=["billing"],
)

@invoices.middleware
async def billing_auth(handler: Handler) -> Any:
    ctx = get_current_context()
    if not has_billing_access(ctx.request):
        raise ToolError("Billing access required")
    return await handler()

@invoices.tool()
def get(invoice_id: str) -> str:
    """Get invoice by ID."""
    ...  # → tool name: "invoice_get"

@invoices.tool()
def list_all(limit: int = 10) -> str:
    """List invoices."""
    ...  # → tool name: "invoice_list_all"

@invoices.resource("invoice://{id}")
def data(id: str) -> str:
    ...

# --- User group ---
users = McpGroup(prefix="user")

@users.tool()
def get(user_id: str) -> str:
    ...  # → tool name: "user_get"

# --- Compose ---
mcp.include(invoices)
mcp.include(users)

# Global middleware still applies to everything
@mcp.middleware
async def global_logging(handler: Handler) -> Any:
    ...
```

## DI Compatibility

### Factory function (closure-based DI)

```python
def create_invoice_tools(service: InvoiceService) -> McpGroup:
    group = McpGroup(prefix="invoice")

    @group.tool()
    async def get(invoice_id: str) -> str:
        return await service.get(invoice_id)

    @group.tool()
    async def create(data: str) -> str:
        return await service.create(data)

    return group

mcp.include(create_invoice_tools(container.resolve(InvoiceService)))
```

### `ctx.app` (aiohttp's native pattern)

```python
invoices = McpGroup(prefix="invoice")

@invoices.tool()
async def get(invoice_id: str) -> str:
    ctx = get_current_context()
    service = ctx.app["invoice_service"]
    return await service.get(invoice_id)
```

### Programmatic registration (for framework builders)

```python
group = McpGroup(prefix="invoice")
controller = container.resolve(InvoiceController)
group.add_tool(controller.get_invoice, name="get")
group.add_tool(controller.create_invoice, name="create")
mcp.include(group)
```

## API

```python
class McpGroup:
    def __init__(
        self,
        prefix: str,
        *,
        tags: list[str] | None = None,
        annotations: ToolAnnotations | None = None,
    ) -> None: ...

    # Same decorator API as AiohttpMCP
    def tool(self, name=None, ...) -> Callable: ...
    def resource(self, uri, ...) -> Callable: ...
    def prompt(self, name=None, ...) -> Callable: ...

    # Direct registration
    def add_tool(self, fn, name=None, ...) -> None: ...
    def add_resource(self, fn, uri, ...) -> None: ...
    def add_prompt(self, fn, name=None, ...) -> None: ...

    # Group-scoped middleware
    def middleware(self, fn=None, *, scope=None): ...
    def add_middleware(self, fn, scope=None) -> None: ...

# On AiohttpMCP
def include(self, group: McpGroup) -> None: ...
```

## Naming

`prefix` is prepended to tool/prompt names with `_` separator:

| `prefix` | `@group.tool()` on `def get(...)` | Result |
|----------|-----------------------------------|--------|
| `"invoice"` | `name=None` (default) | `"invoice_get"` |
| `"invoice"` | `name="fetch"` | `"invoice_fetch"` |

Resources use their URI directly — no prefix applied.

## Changes

### New file: `aiohttp_mcp/group.py`

`McpGroup` class that stores:
- `prefix: str`
- `tags: list[str]` — auto-applied to all tools
- `annotations: ToolAnnotations | None` — default for all tools (overridable per-tool)
- `_tools: list[tuple[fn, kwargs]]` — deferred tool registrations
- `_resources: list[tuple[fn, kwargs]]` — deferred resource registrations
- `_prompts: list[tuple[fn, kwargs]]` — deferred prompt registrations
- `_middlewares: list[tuple[Middleware, scope]]` — group-scoped middlewares

Provides the same decorator/method API as `AiohttpMCP` but stores registrations internally instead of registering immediately.

### `aiohttp_mcp/core.py`

Add `include()` method:
```python
def include(self, group: McpGroup) -> None:
    """Include all primitives and middleware from a group."""
    for fn, kwargs in group.tools:
        name = f"{group.prefix}_{kwargs.pop('name', None) or get_fn_name(fn)}"
        tags = (group.tags or []) + (kwargs.pop('tags', None) or [])
        annotations = kwargs.pop('annotations', None) or group.annotations
        self._registry.register_tool(fn, name=name, tags=tags, annotations=annotations, **kwargs)

    for fn, kwargs in group.resources:
        self._registry.register_resource(fn, **kwargs)

    for fn, kwargs in group.prompts:
        name = f"{group.prefix}_{kwargs.pop('name', None) or get_fn_name(fn)}"
        self._registry.register_prompt(fn, name=name, **kwargs)

    for mw, scope in group.middlewares:
        # Group middleware is scoped to this group's tool/resource/prompt names
        self._registry.add_middleware(mw, scope=scope, group_prefix=group.prefix)
```

### `aiohttp_mcp/__init__.py`

Export `McpGroup`.

### Related features

- [Feature 3 (Middleware)](03-tool-middleware.md) — group-scoped middleware builds on the global middleware system
- [Feature 6 (Tags)](06-tool-tags.md) — tags can be auto-applied via group config; groups are the primary organizational unit, tags are secondary metadata

## Complexity

**M (Medium)** — New class with deferred registration pattern. The `include()` method handles prefix/tag/annotation merging. Group-scoped middleware requires filtering by group membership in the middleware runner.

## Test Plan

- Test `McpGroup` with prefix → tool names are prefixed
- Test `McpGroup` with shared annotations → applied to all tools
- Test `McpGroup` with shared tags → merged with per-tool tags
- Test `@group.tool()` / `@group.resource()` / `@group.prompt()` decorators
- Test `group.add_tool()` / `group.add_resource()` / `group.add_prompt()` methods
- Test `mcp.include(group)` registers all primitives
- Test multiple groups with different prefixes
- Test group-scoped middleware only runs for that group's primitives
- Test global middleware + group middleware both run (correct order)
- Test per-tool annotations override group annotations
- Test resources don't get prefix (URI is the identifier)
- Test DI via factory function pattern
- Test DI via `ctx.app` pattern
