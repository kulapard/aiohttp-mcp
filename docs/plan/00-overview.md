# DX Sugar Plan — Overview

## Context

The aiohttp-mcp library provides MCP server functionality on top of aiohttp with only 3 runtime dependencies (`aiohttp`, `aiohttp-sse`, `pydantic`).

This plan focuses on practical DX improvements at the core layer that reduce boilerplate and make common patterns easier.

## Features (by priority)

| # | Feature | Complexity | PR grouping |
|---|---------|------------|-------------|
| 1 | [Pydantic BaseModel return + outputSchema](01-pydantic-returns.md) | S | PR 1 |
| 2 | [Content return helpers (Image, Audio)](02-content-helpers.md) | S | PR 1 |
| 3 | [Middleware (tools, resources, prompts)](03-tool-middleware.md) | M | PR 2 |
| 4 | [Test helpers](04-test-helpers.md) | S | PR 3 |
| 5 | [Tool tags + bulk config](05-tool-tags.md) | S-M | PR 4 |

## Implementation Order

Ship incrementally as separate PRs:

| PR | Features | Rationale |
|----|----------|-----------|
| 1  | Feature 1 + 2 | Both touch `_single_to_content`, natural pairing. Fixes a real bug. |
| 2  | Feature 3 | Standalone, highest long-term value |
| 3  | Feature 4 | Standalone, no deps on other features |
| 4  | Feature 5 | Most valuable after middleware (PR 2) exists |

## Key Files

- `aiohttp_mcp/protocol/registry.py` — Features 1, 2, 3, 5 (main changes)
- `aiohttp_mcp/core.py` — Features 3, 5 (delegation methods)
- `aiohttp_mcp/protocol/typedefs.py` — Feature 3 (type aliases)
- `aiohttp_mcp/__init__.py` — Features 2, 3 (exports)
- New: `aiohttp_mcp/content.py` — Feature 2
- New: `aiohttp_mcp/testing.py` — Feature 4

## Verification (per PR)

1. `uv run pytest` — all existing tests pass
2. New tests for each feature in `tests/`
3. `make lint` — passes ruff + mypy strict
4. Update `CHANGELOG.md`, `README.md`, `CLAUDE.md` per documentation policy
5. Manual smoke test with example server
