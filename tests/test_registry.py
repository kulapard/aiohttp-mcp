"""Tests for aiohttp_mcp.protocol.registry — tool/resource/prompt registration and execution."""

import logging
from typing import Any

import pytest

from aiohttp_mcp.protocol.context import Context
from aiohttp_mcp.protocol.models import (
    GetPromptResult,
    ImageContent,
    PromptMessage,
    TextContent,
)
from aiohttp_mcp.protocol.registry import (
    Registry,
    ToolError,
    _convert_to_content,
    _match_uri,
    _single_to_content,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registry() -> Registry:
    return Registry()


# ---------------------------------------------------------------------------
# Tool registration & execution
# ---------------------------------------------------------------------------


async def test_register_duplicate_tool_warns(registry: Registry, caplog: pytest.LogCaptureFixture) -> None:
    async def tool_a(x: int) -> str:
        return str(x)

    registry.register_tool(tool_a, name="dup")
    with caplog.at_level(logging.WARNING):
        registry.register_tool(tool_a, name="dup")
    assert "already registered" in caplog.text


async def test_register_duplicate_tool_no_warn() -> None:
    reg = Registry(warn_on_duplicate_tools=False)

    async def tool_a(x: int) -> str:
        return str(x)

    reg.register_tool(tool_a, name="dup")
    # Should not raise or log any warning
    reg.register_tool(tool_a, name="dup")


async def test_call_sync_tool(registry: Registry) -> None:
    def sync_tool(x: int) -> str:
        return f"result-{x}"

    registry.register_tool(sync_tool)
    result = await registry.call_tool("sync_tool", {"x": 42})
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == "result-42"


async def test_call_tool_raises_tool_error(registry: Registry) -> None:
    async def failing_tool() -> str:
        raise ToolError("intended failure")

    registry.register_tool(failing_tool)
    with pytest.raises(ToolError, match="intended failure"):
        await registry.call_tool("failing_tool", {})


async def test_call_tool_wraps_generic_error(registry: Registry) -> None:
    async def bad_tool() -> str:
        raise RuntimeError("oops")

    registry.register_tool(bad_tool)
    with pytest.raises(ToolError, match="oops"):
        await registry.call_tool("bad_tool", {})


async def test_call_tool_with_context_kwarg(registry: Registry) -> None:
    """Tool with ctx: Context parameter gets a fallback context when none is set."""

    async def ctx_tool(x: int, ctx: Context) -> str:
        return f"got-{x}"

    registry.register_tool(ctx_tool)
    result = await registry.call_tool("ctx_tool", {"x": 1})
    assert isinstance(result[0], TextContent)
    assert result[0].text == "got-1"


# ---------------------------------------------------------------------------
# Resource registration & execution
# ---------------------------------------------------------------------------


async def test_register_duplicate_resource_warns(registry: Registry, caplog: pytest.LogCaptureFixture) -> None:
    async def res_fn() -> str:
        return "data"

    registry.register_resource(res_fn, uri="res://dup")
    with caplog.at_level(logging.WARNING):
        registry.register_resource(res_fn, uri="res://dup")
    assert "already registered" in caplog.text


async def test_sync_resource_call(registry: Registry) -> None:
    def sync_resource() -> str:
        return "sync-data"

    registry.register_resource(sync_resource, uri="res://sync")
    result = await registry.read_resource("res://sync")
    contents = list(result)
    assert len(contents) == 1
    assert contents[0].text == "sync-data"


async def test_resource_with_context_fallback(registry: Registry) -> None:
    """Resource with ctx: Context gets a fallback context when none is active."""

    async def ctx_resource(ctx: Context) -> str:
        return "has-context"

    registry.register_resource(ctx_resource, uri="res://ctx")
    result = await registry.read_resource("res://ctx")
    contents = list(result)
    assert contents[0].text == "has-context"


async def test_resource_template_matching(registry: Registry) -> None:
    async def template_resource(name: str) -> str:
        return f"hello-{name}"

    registry.register_resource(template_resource, uri="data://{name}")
    result = await registry.read_resource("data://world")
    contents = list(result)
    assert contents[0].text == "hello-world"


async def test_read_unknown_resource_raises(registry: Registry) -> None:
    with pytest.raises(ValueError, match="Unknown resource"):
        await registry.read_resource("res://nonexistent")


# ---------------------------------------------------------------------------
# Prompt registration & execution
# ---------------------------------------------------------------------------


async def test_register_duplicate_prompt_warns(registry: Registry, caplog: pytest.LogCaptureFixture) -> None:
    async def prompt_fn() -> str:
        return "prompt"

    registry.register_prompt(prompt_fn, name="dup")
    with caplog.at_level(logging.WARNING):
        registry.register_prompt(prompt_fn, name="dup")
    assert "already registered" in caplog.text


async def test_sync_prompt_call(registry: Registry) -> None:
    def sync_prompt() -> str:
        return "sync-prompt"

    registry.register_prompt(sync_prompt)
    result = await registry.get_prompt("sync_prompt")
    assert isinstance(result, GetPromptResult)
    content = result.messages[0].content
    assert isinstance(content, TextContent)
    assert content.text == "sync-prompt"


async def test_prompt_returns_get_prompt_result(registry: Registry) -> None:
    async def structured_prompt() -> GetPromptResult:
        return GetPromptResult(
            messages=[
                PromptMessage(role="user", content=TextContent(text="structured")),
            ]
        )

    registry.register_prompt(structured_prompt)
    result = await registry.get_prompt("structured_prompt")
    content = result.messages[0].content
    assert isinstance(content, TextContent)
    assert content.text == "structured"


async def test_prompt_returns_list(registry: Registry) -> None:
    async def list_prompt() -> list[PromptMessage]:
        return [
            PromptMessage(role="user", content=TextContent(text="from-list")),
        ]

    registry.register_prompt(list_prompt)
    result = await registry.get_prompt("list_prompt")
    content = result.messages[0].content
    assert isinstance(content, TextContent)
    assert content.text == "from-list"


async def test_prompt_returns_string(registry: Registry) -> None:
    async def str_prompt() -> str:
        return "simple text"

    registry.register_prompt(str_prompt)
    result = await registry.get_prompt("str_prompt")
    assert result.messages[0].role == "user"
    content = result.messages[0].content
    assert isinstance(content, TextContent)
    assert content.text == "simple text"


async def test_prompt_with_context_fallback(registry: Registry) -> None:
    async def ctx_prompt(ctx: Context) -> str:
        return "has-context"

    registry.register_prompt(ctx_prompt)
    result = await registry.get_prompt("ctx_prompt")
    content = result.messages[0].content
    assert isinstance(content, TextContent)
    assert content.text == "has-context"


async def test_get_unknown_prompt_raises(registry: Registry) -> None:
    with pytest.raises(ValueError, match="Unknown prompt"):
        await registry.get_prompt("nonexistent")


# ---------------------------------------------------------------------------
# URI template matching
# ---------------------------------------------------------------------------


def test_match_uri_success() -> None:
    result = _match_uri("data://{name}", "data://foo")
    assert result == {"name": "foo"}


def test_match_uri_multiple_params() -> None:
    result = _match_uri("data://{org}/{repo}", "data://acme/widgets")
    assert result == {"org": "acme", "repo": "widgets"}


def test_match_uri_no_match() -> None:
    result = _match_uri("data://{name}", "other://foo")
    assert result is None


# ---------------------------------------------------------------------------
# _convert_to_content / _single_to_content helpers
# ---------------------------------------------------------------------------


def test_convert_to_content_text_content_list() -> None:
    items = [TextContent(text="a"), TextContent(text="b")]
    result = _convert_to_content(items)
    assert result == items


def test_convert_to_content_image_content_list() -> None:
    items = [ImageContent(data="abc", mimeType="image/png")]
    result = _convert_to_content(items)
    assert result == items


def test_convert_to_content_mixed_plain_list() -> None:
    result = _convert_to_content(["hello", 42])
    assert len(result) == 2
    assert isinstance(result[0], TextContent)
    assert result[0].text == "hello"
    assert isinstance(result[1], TextContent)
    assert result[1].text == "42"


def test_convert_to_content_single_string() -> None:
    result = _convert_to_content("hello")
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == "hello"


def test_single_to_content_dict() -> None:
    result = _single_to_content({"key": "value"})
    assert isinstance(result, TextContent)
    assert '"key"' in result.text
    assert '"value"' in result.text


def test_single_to_content_arbitrary_object() -> None:
    class Obj:
        def __str__(self) -> str:
            return "custom-repr"

    result = _single_to_content(Obj())
    assert isinstance(result, TextContent)
    assert result.text == "custom-repr"


def test_single_to_content_text_content_passthrough() -> None:
    tc = TextContent(text="already")
    result = _single_to_content(tc)
    assert result is tc


def test_convert_to_content_empty_list() -> None:
    result: list[Any] = _convert_to_content([])
    assert result == []
