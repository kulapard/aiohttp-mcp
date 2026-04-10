# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Structured return types**: Tools can now return Pydantic `BaseModel` or `dataclass` instances — they are automatically serialized to JSON via Pydantic's `TypeAdapter` instead of `str()`
- **`outputSchema` generation**: Tools with return type annotations automatically populate `outputSchema` in `tools/list` responses (supported in MCP protocol 2025-06-18+)
- Native MCP protocol implementation (`aiohttp_mcp/protocol/`) replacing the `mcp` SDK dependency
  - JSON-RPC 2.0 dispatch engine with full MCP method support
  - Tool, Resource, and Prompt registries with decorator-based registration
  - Function introspection for automatic JSON Schema generation from type hints
  - asyncio-based memory streams replacing anyio streams
  - Context system with `contextvars` propagation (`ctx.app`, `ctx.request`)
- MCP protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26` supported
  - Version negotiation during initialize handshake
  - Per-version response models that exclude fields absent in older specs
- `Context` features restored from FastMCP: `request_id`, `log()`/`debug()`/`info()`/`warning()`/`error()`, `report_progress()`, `read_resource()`
- Design document at `docs/native-mcp-implementation-plan.md`
- Documentation policy in CLAUDE.md — code and docs ship together
- MCPServer dispatch loop tests (18 tests, 87% server.py coverage)

### Fixed
- `build_mcp_app()` and `setup_mcp_subapp()` now default to `stateless=True`, matching `AppBuilder` and documented behavior
- Tools returning Pydantic models or dataclasses no longer produce ugly `str()` repr — they are serialized as proper JSON

### Changed
- **`stateless=True` is now the default** for `build_mcp_app()`, `setup_mcp_subapp()`, and `AppBuilder`. This is safer for multi-instance and load-balanced deployments. Use `stateless=False` to opt into stateful sessions (server push, event replay).
- **Runtime dependencies reduced from 5+ to 3**: `aiohttp`, `aiohttp-sse`, `pydantic`
- **Minimum Python version raised to 3.11** (for native `asyncio.TaskGroup`)
- `build_mcp_app()` and `setup_mcp_subapp()` no longer accept `transport_mode` parameter
- `AppBuilder` simplified to only support Streamable HTTP transport
- All `anyio` primitives replaced with `asyncio` equivalents (`asyncio.TaskGroup`, `asyncio.Lock`, `asyncio.Queue`)
- `mcp` moved from runtime dependency to dev-only dependency (used for E2E test client)
- `add_resource()` now accepts `(fn, uri, **kwargs)` instead of a `FastMCPResource` object
- `add_prompt()` now accepts `(fn, **kwargs)` instead of a `FastMCPPrompt` object

### Removed
- `mcp` and `anyio` as runtime dependencies
- SSE transport (`aiohttp_mcp/transport.py`) — Streamable HTTP is now the only transport
- `TransportMode` enum
- `AiohttpMCP.completion()` method (FastMCP-specific, not standard MCP)
- `AiohttpMCP.custom_route()` method (FastMCP-specific, not standard MCP)
- `lifespan` parameter from `AiohttpMCP` — use `app.cleanup_ctx` + `ctx.app["key"]` instead
- `Context` generic type parameters — `Context` is now a plain class
- Python 3.10 support
- `PROJECT_INDEX.md` (outdated, superseded by CLAUDE.md and README.md)
