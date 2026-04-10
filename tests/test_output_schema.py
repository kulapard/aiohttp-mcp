"""Tests for structured return types (BaseModel, dataclass) and outputSchema generation."""

import dataclasses
import json
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import BaseModel

from aiohttp_mcp import AiohttpMCP
from aiohttp_mcp.protocol.models import TextContent
from aiohttp_mcp.protocol.registry import ToolError, _build_output_adapter

# -- Test models --


class UserModel(BaseModel):
    name: str
    email: str


class NestedModel(BaseModel):
    user: UserModel
    role: str


@dataclasses.dataclass
class UserDC:
    name: str
    email: str


@dataclasses.dataclass
class UserDCWithDefaults:
    name: str
    email: str
    age: int = 25


# -- Tests: outputSchema generation --


class TestOutputSchemaGeneration:
    """Test that outputSchema is generated from return type annotations."""

    async def test_basemodel_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user(user_id: str) -> UserModel:
            return UserModel(name="Alice", email="a@b.com")

        tools = await mcp.list_tools()
        assert len(tools) == 1
        schema = tools[0].outputSchema
        assert schema == {
            "properties": {
                "name": {"title": "Name", "type": "string"},
                "email": {"title": "Email", "type": "string"},
            },
            "required": ["name", "email"],
            "title": "UserModel",
            "type": "object",
        }

    async def test_dataclass_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user(user_id: str) -> UserDC:
            return UserDC(name="Alice", email="a@b.com")

        tools = await mcp.list_tools()
        assert len(tools) == 1
        schema = tools[0].outputSchema
        assert schema == {
            "properties": {
                "name": {"title": "Name", "type": "string"},
                "email": {"title": "Email", "type": "string"},
            },
            "required": ["name", "email"],
            "title": "UserDC",
            "type": "object",
        }

    async def test_dataclass_with_defaults_in_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDCWithDefaults:
            return UserDCWithDefaults(name="Alice", email="a@b.com")

        tools = await mcp.list_tools()
        schema = tools[0].outputSchema
        assert schema is not None
        assert schema["properties"]["name"] == {"title": "Name", "type": "string"}
        assert schema["properties"]["email"] == {"title": "Email", "type": "string"}
        assert schema["properties"]["age"] == {"default": 25, "title": "Age", "type": "integer"}
        assert schema["required"] == ["name", "email"]

    async def test_nested_model_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_admin() -> NestedModel:
            return NestedModel(user=UserModel(name="Alice", email="a@b.com"), role="admin")

        tools = await mcp.list_tools()
        schema = tools[0].outputSchema
        assert schema is not None
        assert schema["type"] == "object"
        assert schema["required"] == ["user", "role"]
        assert schema["properties"]["role"] == {"title": "Role", "type": "string"}
        assert schema["properties"]["user"] == {"$ref": "#/$defs/UserModel"}
        assert "$defs" in schema
        assert schema["$defs"]["UserModel"] == {
            "properties": {
                "name": {"title": "Name", "type": "string"},
                "email": {"title": "Email", "type": "string"},
            },
            "required": ["name", "email"],
            "title": "UserModel",
            "type": "object",
        }

    async def test_str_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def echo(msg: str) -> str:
            return msg

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {"type": "string"}

    async def test_int_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def count() -> int:
            return 42

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {"type": "integer"}

    async def test_bool_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def check() -> bool:
            return True

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {"type": "boolean"}

    async def test_float_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def measure() -> float:
            return 3.14

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {"type": "number"}

    async def test_list_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def items() -> list[str]:
            return ["a", "b"]

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {
            "items": {"type": "string"},
            "type": "array",
        }

    async def test_dict_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def data() -> dict[str, int]:
            return {"key": 1}

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {
            "additionalProperties": {"type": "integer"},
            "type": "object",
        }

    async def test_optional_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def maybe() -> str | None:
            return None

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {
            "anyOf": [{"type": "string"}, {"type": "null"}],
        }

    async def test_any_return_no_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def anything() -> Any:
            return "whatever"

        tools = await mcp.list_tools()
        assert tools[0].outputSchema is None

    async def test_none_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def noop() -> None:
            pass

        tools = await mcp.list_tools()
        assert tools[0].outputSchema == {"type": "null"}

    async def test_no_return_annotation_no_output_schema(self) -> None:
        mcp = AiohttpMCP()

        mcp.add_tool(_no_annotation_tool)

        tools = await mcp.list_tools()
        assert tools[0].outputSchema is None


def _no_annotation_tool(msg: str):  # type: ignore[no-untyped-def]
    """Tool without return annotation — defined at module level to avoid mypy error."""
    return msg


# -- Tests: error paths --


class TestErrorPaths:
    """Test error/failure paths in _build_output_adapter and call_tool serialization."""

    async def test_uninspectable_function_returns_no_schema(self) -> None:
        """Functions whose signature can't be inspected should return (None, None)."""
        # Built-in functions raise ValueError from inspect.signature
        schema, adapter = _build_output_adapter(len)
        assert schema is None
        assert adapter is None

    async def test_unsupported_annotation_returns_no_schema(self) -> None:
        """Annotations that TypeAdapter can't handle should return (None, None)."""

        # Bare Callable without args is not schema-able
        def tool_fn() -> Callable:  # type: ignore[type-arg,empty-body]
            pass

        schema, adapter = _build_output_adapter(tool_fn)
        assert schema is None
        assert adapter is None

    async def test_dump_json_failure_raises_tool_error(self) -> None:
        """If dump_json fails at runtime, it should raise ToolError, not internal error."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return object()  # type: ignore[return-value]

        with pytest.raises(ToolError, match="Failed to serialize tool output"):
            await mcp.call_tool("get_user", {})


# -- Tests: serialization --


class TestStructuredReturnSerialization:
    """Test that BaseModel and dataclass return values are serialized to JSON."""

    async def test_basemodel_return_serialized_to_json(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return UserModel(name="Alice", email="a@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Alice", "email": "a@b.com"}

    async def test_dataclass_return_serialized_to_json(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDC:
            return UserDC(name="Bob", email="b@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Bob", "email": "b@b.com"}

    async def test_dataclass_with_defaults_serialized(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDCWithDefaults:
            return UserDCWithDefaults(name="Alice", email="a@b.com")

        result = await mcp.call_tool("get_user", {})
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Alice", "email": "a@b.com", "age": 25}

    async def test_nested_model_serialized_to_json(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_admin() -> NestedModel:
            return NestedModel(user=UserModel(name="Alice", email="a@b.com"), role="admin")

        result = await mcp.call_tool("get_admin", {})
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {
            "user": {"name": "Alice", "email": "a@b.com"},
            "role": "admin",
        }

    async def test_basemodel_not_str_repr(self) -> None:
        """Ensure BaseModel is not serialized via str() which produces a repr."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return UserModel(name="Alice", email="a@b.com")

        result = await mcp.call_tool("get_user", {})
        content = result[0]
        assert isinstance(content, TextContent)
        # str(UserModel(...)) produces "name='Alice' email='a@b.com'" — must NOT appear
        assert "name='Alice'" not in content.text

    async def test_dataclass_not_str_repr(self) -> None:
        """Ensure dataclass is not serialized via str() which produces a repr."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDC:
            return UserDC(name="Alice", email="a@b.com")

        result = await mcp.call_tool("get_user", {})
        content = result[0]
        assert isinstance(content, TextContent)
        # str(UserDC(...)) produces "UserDC(name='Alice', email='a@b.com')" — must NOT appear
        assert "UserDC(" not in content.text

    async def test_async_tool_with_basemodel_return(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        async def get_user() -> UserModel:
            return UserModel(name="Async", email="async@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Async", "email": "async@b.com"}

    async def test_async_tool_with_dataclass_return(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        async def get_user() -> UserDC:
            return UserDC(name="Async", email="async@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Async", "email": "async@b.com"}


# -- Tests: backward compatibility --


class TestBackwardCompatibility:
    """Ensure existing return types still work unchanged."""

    async def test_str_return_unchanged(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def echo(msg: str) -> str:
            return msg

        result = await mcp.call_tool("echo", {"msg": "hello"})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert content.text == "hello"

    async def test_dict_return_unchanged(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def data() -> dict[str, str]:
            return {"key": "value"}

        result = await mcp.call_tool("data", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"key": "value"}

    async def test_list_return_unchanged(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def items() -> list[str]:
            return ["a", "b"]

        result = await mcp.call_tool("items", {})
        assert len(result) == 2
        assert all(isinstance(c, TextContent) for c in result)
        assert result[0].text == "a"  # type: ignore[union-attr]
        assert result[1].text == "b"  # type: ignore[union-attr]

    async def test_tool_returning_str_even_with_model_annotation(self) -> None:
        """If the tool has a model annotation but returns a string, it should still work."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return "raw string fallback"  # type: ignore[return-value]

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert content.text == "raw string fallback"

    async def test_tool_returning_dict_even_with_model_annotation(self) -> None:
        """If the tool has a model annotation but returns a dict, it should still work."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return {"name": "Alice", "email": "a@b.com"}  # type: ignore[return-value]

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Alice", "email": "a@b.com"}

    async def test_optional_basemodel_return_serialized(self) -> None:
        """Optional[BaseModel] should serialize the model to JSON, not str() repr."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel | None:
            return UserModel(name="Alice", email="a@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Alice", "email": "a@b.com"}

    async def test_optional_basemodel_return_none(self) -> None:
        """Optional[BaseModel] returning None should work."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel | None:
            return None

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert content.text == "None"

    async def test_optional_dataclass_return_serialized(self) -> None:
        """Optional[dataclass] should serialize the dataclass to JSON."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDC | None:
            return UserDC(name="Bob", email="b@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert json.loads(content.text) == {"name": "Bob", "email": "b@b.com"}

    async def test_list_basemodel_return_serialized(self) -> None:
        """list[BaseModel] should serialize each model to JSON."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_users() -> list[UserModel]:
            return [UserModel(name="Alice", email="a@b.com"), UserModel(name="Bob", email="b@b.com")]

        result = await mcp.call_tool("get_users", {})
        assert len(result) == 2
        assert all(isinstance(c, TextContent) for c in result)
        assert json.loads(result[0].text) == {"name": "Alice", "email": "a@b.com"}  # type: ignore[union-attr]
        assert json.loads(result[1].text) == {"name": "Bob", "email": "b@b.com"}  # type: ignore[union-attr]

    async def test_tool_returning_content_type_with_model_annotation(self) -> None:
        """If the tool has a model annotation but returns a Content type, it should pass through."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return TextContent(text="custom")  # type: ignore[return-value]

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert content.text == "custom"
