# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Native MCP protocol implementation (`aiohttp_mcp/protocol/`) replacing the `mcp` SDK dependency
  - JSON-RPC 2.0 dispatch engine with full MCP method support
  - Tool, Resource, and Prompt registries with decorator-based registration
  - Function introspection for automatic JSON Schema generation from type hints
  - asyncio-based memory streams replacing anyio streams
  - Context system with `contextvars` propagation for request/lifespan context
- MCP protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26` supported
  - Version negotiation during initialize handshake
  - Per-version response models that exclude fields absent in older specs
- Design document at `docs/native-mcp-implementation-plan.md`
- Documentation policy in CLAUDE.md — code and docs ship together

### Changed
- **Runtime dependencies reduced from 5+ to 3**: `aiohttp`, `aiohttp-sse`, `pydantic`
- **Minimum Python version raised to 3.11** (for native `asyncio.TaskGroup`)
- `lifespan` parameter now accepts `Callable[[AiohttpMCP], AsyncContextManager[T]]` instead of `Callable[[FastMCP], ...]`
- `build_mcp_app()` and `setup_mcp_subapp()` no longer accept `transport_mode` parameter
- `AppBuilder` simplified to only support Streamable HTTP transport
- All `anyio` primitives replaced with `asyncio` equivalents (`asyncio.TaskGroup`, `asyncio.Lock`, `asyncio.Queue`)
- `mcp` moved from runtime dependency to dev-only dependency (used for E2E test client)

### Removed
- `mcp` and `anyio` as runtime dependencies
- SSE transport (`aiohttp_mcp/transport.py`) — Streamable HTTP is now the only transport
- `TransportMode` enum
- `AiohttpMCP.completion()` method (FastMCP-specific, not standard MCP)
- `AiohttpMCP.custom_route()` method (FastMCP-specific, not standard MCP)
- Python 3.10 support
- `PROJECT_INDEX.md` (outdated, superseded by CLAUDE.md and README.md)
