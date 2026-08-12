# Developer Experience Plan — Overview

## Context

The aiohttp-mcp library provides MCP server functionality on top of aiohttp with only 3 runtime dependencies (`aiohttp`, `aiohttp-sse`, `pydantic`).

This plan focuses on practical improvements at the core layer that reduce boilerplate and make common patterns easier.

## Features (by priority)

| # | Feature | Complexity | PR grouping |
|---|---------|------------|-------------|
| 1 | [Structured return types + outputSchema](01-pydantic-returns.md) | S | PR 1 |
| 2 | [Content return helpers (Image, Audio)](02-content-helpers.md) | S | PR 1 |
| 3 | [Middleware (tools, resources, prompts)](03-tool-middleware.md) | M | PR 2 |
| 4 | [McpGroup — blueprint for MCP primitives](04-mcp-group.md) | M | PR 3 |
| 5 | [Tool tags + bulk config](05-tool-tags.md) | S-M | PR 4 |
| 6 | [Test helpers](07-test-helpers.md) | S | PR 5 |

## Implementation Order

Ship incrementally as separate PRs:

| PR | Features | Rationale |
|----|----------|-----------|
| 1  | Feature 1 + 2 | Both touch `_single_to_content`, natural pairing. Fixes a real bug. |
| 2  | Feature 3 | Standalone, highest long-term value |
| 3  | Feature 4 | Builds on middleware (PR 2) |
| 4  | Feature 5 | Most valuable after McpGroup (PR 3) exists |
| 5  | Feature 6 | Last — tests benefit from inspecting all prior features |

## Key Files

- `aiohttp_mcp/protocol/registry.py` — Features 1, 2, 3, 5 (main changes)
- `aiohttp_mcp/core.py` — Features 3, 4 (delegation methods)
- `aiohttp_mcp/protocol/typedefs.py` — Feature 3 (type aliases)
- `aiohttp_mcp/__init__.py` — Features 2, 3, 4 (exports)
- New: `aiohttp_mcp/content.py` — Feature 2
- New: `aiohttp_mcp/group.py` — Feature 4
- New: `aiohttp_mcp/testing.py` — Feature 6

## Verification (per PR)

1. `uv run pytest` — all existing tests pass
2. New tests for each feature in `tests/`
3. `make lint` — passes ruff + mypy strict
4. Update `CHANGELOG.md`, `README.md`, `CLAUDE.md` per documentation policy
5. Manual smoke test with example server
