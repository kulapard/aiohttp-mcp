"""Tests for structured return types (BaseModel, dataclass) and outputSchema generation."""

import dataclasses

from pydantic import BaseModel

from aiohttp_mcp import AiohttpMCP
from aiohttp_mcp.protocol.models import TextContent


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
        assert tools[0].outputSchema is not None
        schema = tools[0].outputSchema
        assert schema["type"] == "object"
        assert "name" in schema["properties"]
        assert "email" in schema["properties"]

    async def test_dataclass_return_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user(user_id: str) -> UserDC:
            return UserDC(name="Alice", email="a@b.com")

        tools = await mcp.list_tools()
        assert len(tools) == 1
        assert tools[0].outputSchema is not None
        schema = tools[0].outputSchema
        assert schema["type"] == "object"
        assert "name" in schema["properties"]
        assert "email" in schema["properties"]

    async def test_dataclass_with_defaults_in_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDCWithDefaults:
            return UserDCWithDefaults(name="Alice", email="a@b.com")

        tools = await mcp.list_tools()
        schema = tools[0].outputSchema
        assert schema is not None
        assert schema["properties"]["age"]["default"] == 25

    async def test_nested_model_generates_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_admin() -> NestedModel:
            return NestedModel(user=UserModel(name="Alice", email="a@b.com"), role="admin")

        tools = await mcp.list_tools()
        schema = tools[0].outputSchema
        assert schema is not None
        assert "user" in schema["properties"]
        assert "$defs" in schema or "definitions" in schema or "$ref" in schema["properties"]["user"]

    async def test_str_return_no_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def echo(msg: str) -> str:
            return msg

        tools = await mcp.list_tools()
        assert tools[0].outputSchema is None

    async def test_dict_return_no_output_schema(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def echo() -> dict[str, str]:
            return {"key": "value"}

        tools = await mcp.list_tools()
        assert tools[0].outputSchema is None

    async def test_no_return_annotation_no_output_schema(self) -> None:
        mcp = AiohttpMCP()

        mcp.add_tool(_no_annotation_tool)

        tools = await mcp.list_tools()
        assert tools[0].outputSchema is None


def _no_annotation_tool(msg: str):  # type: ignore[no-untyped-def]
    """Tool without return annotation — defined at module level to avoid mypy error."""
    return msg


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
        assert '"name":"Alice"' in content.text or '"name": "Alice"' in content.text
        assert '"email":"a@b.com"' in content.text or '"email": "a@b.com"' in content.text

    async def test_dataclass_return_serialized_to_json(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserDC:
            return UserDC(name="Bob", email="b@b.com")

        result = await mcp.call_tool("get_user", {})
        assert len(result) == 1
        content = result[0]
        assert isinstance(content, TextContent)
        assert '"name":"Bob"' in content.text or '"name": "Bob"' in content.text
        assert '"email":"b@b.com"' in content.text or '"email": "b@b.com"' in content.text

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
        content = result[0]
        assert isinstance(content, TextContent)
        assert "Async" in content.text
        assert "async@b.com" in content.text


# -- Tests: backward compatibility --


class TestBackwardCompatibility:
    """Ensure existing return types still work unchanged."""

    async def test_str_return_unchanged(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def echo(msg: str) -> str:
            return msg

        result = await mcp.call_tool("echo", {"msg": "hello"})
        assert result[0].text == "hello"  # type: ignore[union-attr]

    async def test_dict_return_unchanged(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def data() -> dict[str, str]:
            return {"key": "value"}

        result = await mcp.call_tool("data", {})
        assert '"key"' in result[0].text  # type: ignore[union-attr]

    async def test_list_return_unchanged(self) -> None:
        mcp = AiohttpMCP()

        @mcp.tool()
        def items() -> list[str]:
            return ["a", "b"]

        result = await mcp.call_tool("items", {})
        assert len(result) == 2

    async def test_tool_returning_str_even_with_model_annotation(self) -> None:
        """If the tool has a model annotation but returns a string, it should still work."""
        mcp = AiohttpMCP()

        @mcp.tool()
        def get_user() -> UserModel:
            return "raw string fallback"  # type: ignore[return-value]

        result = await mcp.call_tool("get_user", {})
        content = result[0]
        assert isinstance(content, TextContent)
        # str is caught before the adapter path
        assert content.text == "raw string fallback"
