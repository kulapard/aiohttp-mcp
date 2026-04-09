# Plan: Remove mcp/anyio dependencies - Native MCP Implementation

## Context

The `aiohttp-mcp` library depends on `mcp>=1.24.0` which brings ~3-4MB of unnecessary transitive deps (starlette, uvicorn, httpx, httpx-sse, pydantic-settings, sse-starlette, pyjwt, python-multipart). Goal: replace `mcp` and `anyio` runtime dependencies with a native MCP protocol implementation. This is a **major version bump** (breaking release).

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Keep pydantic | Yes | Needed for MCP model validators, aliases, JSON Schema generation |
| Python version | Require 3.11+ (drop 3.10) | Enables native `asyncio.TaskGroup` and `asyncio.timeout` |
| anyio replacement | `asyncio.Queue`, `asyncio.Lock`, `asyncio.TaskGroup` | Direct stdlib replacements |
| mcp in tests | Dev dependency only | E2E tests need `mcp.ClientSession` |
| Lifespan param | `Callable[[AiohttpMCP], ...]` | Breaking change from `FastMCP`, but natural |
| `completion()`/`custom_route()` | Drop | FastMCP-specific, not standard MCP |
| MCP protocol version | `2025-11-25` | Latest MCP spec version |
| Transport | Streamable HTTP only (drop SSE) | SSE is deprecated in MCP spec since 2025-03-26; Streamable HTTP is the standard |
| MCP methods | Full set | initialize, ping, tools/*, resources/*, prompts/* |
| Versioning | Major bump | Significant internal changes warrant it |

## Dependencies After Refactor

**Runtime:**
```toml
requires-python = ">=3.11"
dependencies = [
    "aiohttp>=3.9.0,<4.0.0",
    "aiohttp-sse>=2.2.0,<3.0.0",
    "pydantic>=2.0.0,<3.0.0",
]
```

**Dev (added):**
```toml
"mcp>=1.24.0,<2.0.0",       # E2E tests (client library)
"pytest-asyncio>=0.24.0",    # Replace pytest-anyio
```

---

## Implementation

### Phase 1: Create native protocol layer (all new files under `aiohttp_mcp/protocol/`)

#### 1.1 `protocol/__init__.py`
Re-exports key types from submodules.

#### 1.2 `protocol/streams.py` - Async memory streams (replace anyio)
- `StreamWriter[T]` / `StreamReader[T]` wrapping `asyncio.Queue`
- `create_memory_stream(max_buffer_size) -> (writer, reader)` factory
- `ClosedStreamError`, `BrokenStreamError` exceptions
- `StreamReader` implements `__aiter__`/`__anext__` for `async for` loops

#### 1.3 `protocol/models.py` - MCP Pydantic models (2025-11-25 spec)
All types needed for the MCP protocol:
- **JSON-RPC**: `JSONRPCRequest`, `JSONRPCNotification`, `JSONRPCResponse`, `JSONRPCError`, `JSONRPCMessage` (RootModel union), `ErrorData`, `RequestId`
- **Error codes**: `PARSE_ERROR=-32700`, `INVALID_REQUEST=-32600`, `INVALID_PARAMS=-32602`, `INTERNAL_ERROR=-32603`, `METHOD_NOT_FOUND=-32601`
- **Entities**: `Tool` (with `execution` field for task support), `ToolAnnotations`, `Resource`, `ResourceTemplate`, `Prompt`, `PromptArgument`, `Annotations`, `Icon`
- **Content**: `TextContent`, `ImageContent`, `AudioContent`, `EmbeddedResource`, `ResourceLink`, `Content` type alias
- **Resource contents**: `TextResourceContents`, `BlobResourceContents`
- **Prompt results**: `PromptMessage`, `GetPromptResult`
- **Protocol**: `ServerCapabilities`, `InitializeResult`, `Implementation` (with `title`, `description`, `icons`, `websiteUrl`), `SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"]`, `LATEST_PROTOCOL_VERSION = "2025-11-25"`
- **Misc**: `AnyFunction` type alias

#### 1.4 `protocol/messages.py` - Session/event message types
- `ServerMessageMetadata` dataclass (related_request_id, request_context)
- `SessionMessage` dataclass (message: JSONRPCMessage, metadata)
- `EventMessage` dataclass (message: JSONRPCMessage, event_id: str | None)
- `EventStore` abstract class (store_event, replay_events_after)

#### 1.5 `protocol/context.py` - Context system
- `RequestContext` dataclass preserving `request` (aiohttp Request) and `lifespan_context` access
- `Context[ServerT, LifespanT, RequestT]` class with `request_context` property
- `_current_context: ContextVar` for propagation
- `find_context_kwarg(fn)` utility to detect Context params in function signatures

#### 1.6 `protocol/func_metadata.py` - Function introspection
- `func_metadata(fn, skip_names)` - inspect function, create pydantic model from params via `create_model()`
- `FuncMetadata` class: `arg_model`, `call_fn_with_arg_validation()`
- `ArgModelBase` base for generated models
- Generates JSON Schema via `arg_model.model_json_schema()`

#### 1.7 `protocol/registry.py` - Tool/Resource/Prompt registries
- `ToolDef`, `ResourceDef`, `PromptDef` internal representations
- `Registry` class with:
  - `register_tool()` / `register_resource()` / `register_prompt()` / `remove_tool()`
  - `list_tools()` / `list_resources()` / `list_resource_templates()` / `list_prompts()`
  - `call_tool()` / `read_resource()` / `get_prompt()`
  - URI template matching for parameterized resources

#### 1.8 `protocol/server.py` - JSON-RPC dispatch engine
- `MCPServer` class replacing `mcp.server.lowlevel.Server`:
  - `run(read_stream, write_stream, init_options, raise_exceptions, stateless)` - reads SessionMessage, dispatches to handlers, writes responses
  - `create_initialization_options()`
  - Handles: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `resources/templates/list`, `prompts/list`, `prompts/get`
  - Protocol version negotiation (2025-11-25 spec)
  - Lifespan context via async context manager + contextvars

### Phase 2: Refactor existing files

Files to modify (in order):

#### 2.1 `aiohttp_mcp/types.py`
- Redirect all imports from `aiohttp_mcp.protocol.*` instead of `mcp.*`
- Remove: `FastMCP`, `Server`, `FastMCPPrompt`, `FastMCPResource`, `LifespanResultT`
- Add: `MCPServer` export
- Keep same `__all__` structure for backward compat where possible

#### 2.2 `aiohttp_mcp/core.py`
- Replace `FastMCP` with `Registry` + `MCPServer`
- `lifespan` param type: `Callable[[AiohttpMCP], AsyncContextManager[T]]`
- `.server` property returns `MCPServer`
- All decorators delegate to `Registry`
- Drop `completion()` and `custom_route()`
- Add `ToolError` exception class (was in `mcp.server.fastmcp.exceptions`)

#### 2.3 `aiohttp_mcp/streamable_http.py`
- `anyio.create_memory_object_stream` -> `create_memory_stream()`
- `anyio.create_task_group()` -> `asyncio.TaskGroup()`
- `anyio.BrokenResourceError`/`ClosedResourceError` -> our exceptions
- `pydantic.ValidationError` stays (pydantic remains a dep)
- Update `DEFAULT_NEGOTIATED_VERSION` to `"2025-11-25"`

#### 2.4 `aiohttp_mcp/streamable_http_manager.py`
- `anyio.Lock()` -> `asyncio.Lock()`
- `anyio.create_task_group()` -> `asyncio.TaskGroup()`
- `TaskStatus` pattern -> `asyncio.Event` for task-started signaling
- `self.server.run()` -> `MCPServer.run()`

#### 2.5 `aiohttp_mcp/app.py`
- Remove `TransportMode` enum (only Streamable HTTP now)
- Remove SSE-related code (`SSEServerTransport`, `sse_handler`, `message_handler`)
- Simplify `AppBuilder` to only support Streamable HTTP
- Update `build_mcp_app()` and `setup_mcp_subapp()` signatures (remove `transport_mode` param)
- `self._mcp.server.run()` -> `MCPServer.run()`

#### 2.6 Delete `aiohttp_mcp/transport.py`
- SSE transport is no longer needed (Streamable HTTP handles SSE streaming internally)

#### 2.7 `aiohttp_mcp/__init__.py`
- Remove `TransportMode` from exports
- Remove `Context` re-export from mcp, use ours
- Keep remaining public API surface

### Phase 3: Update tests and dependencies

#### 3.1 `pyproject.toml`
- Update `requires-python = ">=3.11"`
- Remove `mcp` and `anyio` from runtime deps
- Add `pydantic>=2.0.0`
- Add `mcp>=1.24.0` and `pytest-asyncio>=0.24.0` to dev deps
- Remove Python 3.10 from classifiers

#### 3.2 Test updates
- `conftest.py`: Remove `anyio_backend` fixture, configure `pytest-asyncio`
- `test_core.py`: Replace `from mcp.server.fastmcp.exceptions import ToolError` -> our exception
- Delete `test_sse_transport.py` (SSE transport removed)
- `test_streamable_http_unit.py`: Replace mcp type imports
- `test_streamable_http_integration.py`: Replace anyio/mcp imports, update Server references
- `test_app.py`: Remove SSE-specific tests, remove `TransportMode` references, update markers, keep `mcp` client imports (test dep)
- All tests: `pytest.mark.anyio` -> `pytest.mark.asyncio`

#### 3.3 Example updates
- Remove `examples/server.py` SSE-based example or update to Streamable HTTP
- Update all examples to use new API (no `transport_mode` param)

### Phase 4: Validation
1. `uv run pytest` - all tests pass
2. `uv run mypy .` - no type errors
3. `make lint` - passes
4. `python -c "import aiohttp_mcp"` - no mcp/anyio at runtime
5. Verify `pip install .` doesn't pull starlette/uvicorn/httpx

---

## New File Structure

```
aiohttp_mcp/
    __init__.py                    (updated - no TransportMode)
    app.py                         (simplified - Streamable HTTP only)
    core.py                        (rewritten - native registry)
    streamable_http.py             (rewritten - asyncio streams)
    streamable_http_manager.py     (rewritten - asyncio concurrency)
    types.py                       (redirected to protocol/)
    utils/
        discover.py                (unchanged)
    protocol/                      (NEW)
        __init__.py
        streams.py
        models.py                  (full 2025-11-25 models, used internally)
        versions.py                (per-version response models for older clients)
        messages.py
        context.py
        func_metadata.py
        registry.py
        server.py

DELETED:
    transport.py                   (SSE transport removed)
```

## Execution Order

1. Phase 1 first (additive, no changes to existing code)
2. Phase 2 second (refactor existing files, depends on Phase 1)
3. Phase 3 third (tests/deps, depends on Phase 2)
4. Phase 4 fourth (validation)

Within Phase 2, order: types.py -> core.py -> streamable_http.py -> streamable_http_manager.py -> app.py -> delete transport.py -> __init__.py

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| JSON-RPC dispatch correctness | High | Follow mcp Server.run() closely, comprehensive E2E tests |
| Function introspection edge cases | High | Port logic from FastMCP's func_metadata, test with varied signatures |
| Stream backpressure semantics | Medium | asyncio.Queue(maxsize=1) approximates anyio rendezvous |
| Breaking changes (SSE removal) | Medium | Major version bump, clear migration guide |
