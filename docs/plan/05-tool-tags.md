# Feature 5: Tool Tags + Bulk Configuration

## Problem

No way to organize tools by category or apply bulk configuration (annotations, middleware) to a group. Large servers with many tools repeat the same annotations on each tool.

## Before

```python
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_users() -> str: ...

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_user(id: str) -> str: ...

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def search_users(query: str) -> str: ...
# Same annotations repeated on every read-only tool
```

## After

```python
@mcp.tool(tags=["users", "read"])
def list_users() -> str: ...

@mcp.tool(tags=["users", "read"])
def get_user(id: str) -> str: ...

@mcp.tool(tags=["users", "write"])
def create_user(name: str) -> str: ...

# Apply annotations to all "read" tagged tools at once
mcp.configure_tools(tags=["read"], annotations=ToolAnnotations(readOnlyHint=True))

# If middleware (Feature 3) is available, scope it by tag:
mcp.add_middleware(require_auth, tags=["write"])
```

## Changes

### `aiohttp_mcp/protocol/registry.py`

1. **`ToolDef`** — Add field:
   ```python
   tags: list[str] = field(default_factory=list)
   ```

2. **`register_tool()`** — Accept and store `tags` parameter.

3. **New method `configure_tools()`**:
   ```python
   def configure_tools(
       self,
       tags: list[str],
       annotations: ToolAnnotations | None = None,
   ) -> None:
       tag_set = set(tags)
       for td in self._tools.values():
           if tag_set & set(td.tags):
               if annotations is not None:
                   td.annotations = annotations
   ```

4. **`call_tool()`** (if Feature 3 middleware exists) — Filter middlewares:
   ```python
   # Each middleware stored as (middleware_fn, tags_or_none)
   # If tags is None → applies to all; if set → only matching tools
   applicable = [
       mw for mw, mw_tags in self._tool_middlewares
       if mw_tags is None or (set(mw_tags) & set(td.tags))
   ]
   ```

### `aiohttp_mcp/core.py`

- Add `tags` param to `tool()` decorator, pass through to `register_tool`
- Add `configure_tools()` method delegating to registry
- Update `add_middleware()` to accept optional `tags` param

### `aiohttp_mcp/__init__.py`

No new exports needed (tags are a parameter, not a type).

## Complexity

**S-M (Small to Medium)** — Tag storage is trivial. Tag-scoped middleware filtering adds some complexity but is straightforward.

## Test Plan

- Test registering tools with tags
- Test `configure_tools` applies annotations to matching tools only
- Test `configure_tools` with multiple overlapping tags
- Test tag-scoped middleware (only runs for matching tools)
- Test global middleware (no tags) still runs for all tools
- Test tools with no tags are unaffected by tag-scoped config
