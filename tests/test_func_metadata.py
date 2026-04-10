"""Tests for aiohttp_mcp.protocol.func_metadata — function introspection and schema generation."""

from typing import Any

import pytest

from aiohttp_mcp.protocol.func_metadata import FuncMetadata, InvalidSignature, func_metadata


async def test_basic_function_metadata() -> None:
    def f(x: int, y: str) -> str:
        return f"{x}-{y}"

    meta = func_metadata(f)
    schema = meta.arg_model.clean_schema()
    assert "x" in schema["properties"]
    assert "y" in schema["properties"]
    assert schema["properties"]["x"]["type"] == "integer"
    assert schema["properties"]["y"]["type"] == "string"
    assert set(schema["required"]) == {"x", "y"}


async def test_skip_names() -> None:
    def f(x: int, ctx: str) -> str:
        return ""

    meta = func_metadata(f, skip_names=("ctx",))
    schema = meta.arg_model.clean_schema()
    assert "x" in schema["properties"]
    assert "ctx" not in schema["properties"]


async def test_unannotated_parameter() -> None:
    def f(x) -> str:  # type: ignore[no-untyped-def]
        return str(x)

    meta = func_metadata(f)
    schema = meta.arg_model.clean_schema()
    assert "x" in schema["properties"]
    # Unannotated params get a string-typed fallback schema
    assert schema["properties"]["x"]["type"] == "string"


async def test_parameter_starting_with_underscore_raises() -> None:
    def f(_private: int) -> int:
        return _private

    with pytest.raises(InvalidSignature, match="cannot start with '_'"):
        func_metadata(f)


async def test_alias_for_basemodel_attribute() -> None:
    """Parameters named after BaseModel methods (like 'json') get aliased."""

    def f(json: str) -> str:
        return json

    meta = func_metadata(f)
    schema = meta.arg_model.clean_schema()
    # The schema should still expose the original name "json"
    assert "json" in schema["properties"]


async def test_pre_parse_json_list_string() -> None:
    """String '["a","b"]' is pre-parsed to a list when the param expects list[str]."""

    def f(items: list[str]) -> list[str]:
        return items

    meta = func_metadata(f)
    result = await meta.call_fn_with_arg_validation(
        fn=f,
        fn_is_async=False,
        arguments_to_validate={"items": '["a", "b"]'},
        arguments_to_pass_directly=None,
    )
    assert result == ["a", "b"]


async def test_pre_parse_json_ignores_plain_string() -> None:
    """String values for str params are not JSON-parsed."""

    def f(name: str) -> str:
        return name

    meta = func_metadata(f)
    result = await meta.call_fn_with_arg_validation(
        fn=f,
        fn_is_async=False,
        arguments_to_validate={"name": "hello"},
        arguments_to_pass_directly=None,
    )
    assert result == "hello"


async def test_pre_parse_json_ignores_scalar() -> None:
    """JSON-parseable scalar '42' for int param is left as string (pydantic coerces it)."""

    def f(count: int) -> int:
        return count

    meta = func_metadata(f)
    result = await meta.call_fn_with_arg_validation(
        fn=f,
        fn_is_async=False,
        arguments_to_validate={"count": "42"},
        arguments_to_pass_directly=None,
    )
    assert result == 42


async def test_default_parameter_values() -> None:
    def f(x: int, y: str = "default") -> str:
        return f"{x}-{y}"

    meta = func_metadata(f)
    schema = meta.arg_model.clean_schema()
    assert schema["required"] == ["x"]
    assert "y" not in schema.get("required", [])


async def test_call_async_function() -> None:
    async def f(x: int) -> int:
        return x * 2

    meta = func_metadata(f)
    result = await meta.call_fn_with_arg_validation(
        fn=f,
        fn_is_async=True,
        arguments_to_validate={"x": 5},
        arguments_to_pass_directly=None,
    )
    assert result == 10


async def test_call_with_extra_args() -> None:
    def f(x: int, extra: str) -> str:
        return f"{x}-{extra}"

    meta = func_metadata(f, skip_names=("extra",))
    result = await meta.call_fn_with_arg_validation(
        fn=f,
        fn_is_async=False,
        arguments_to_validate={"x": 1},
        arguments_to_pass_directly={"extra": "injected"},
    )
    assert result == "1-injected"


async def test_pre_parse_json_dict_string() -> None:
    """String '{"a": 1}' is pre-parsed to a dict when the param expects dict."""

    def f(data: dict[str, Any]) -> dict[str, Any]:
        return data

    meta = func_metadata(f)
    result = await meta.call_fn_with_arg_validation(
        fn=f,
        fn_is_async=False,
        arguments_to_validate={"data": '{"a": 1}'},
        arguments_to_pass_directly=None,
    )
    assert result == {"a": 1}


async def test_clean_schema_strips_title_and_description() -> None:
    def f(x: int) -> int:
        """Some docstring."""
        return x

    meta = func_metadata(f)
    schema = meta.arg_model.clean_schema()
    assert "title" not in schema
    assert "description" not in schema
