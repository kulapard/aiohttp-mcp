"""Tests for version-specific protocol serialization.

Verifies that responses to older MCP clients exclude fields
that didn't exist in their protocol version.
"""

import pytest
from pydantic import AnyUrl

from aiohttp_mcp.protocol.models import (
    Annotations,
    Icon,
    Implementation,
    Prompt,
    PromptArgument,
    Resource,
    ResourceTemplate,
    TextContent,
    Tool,
    ToolAnnotations,
    ToolExecution,
)
from aiohttp_mcp.protocol.server import MCPServer
from aiohttp_mcp.protocol.versions import dump_for_version

ALL_VERSIONS = ["2025-03-26", "2025-06-18", "2025-11-25"]

INPUT_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}
OUTPUT_SCHEMA = {"type": "object", "properties": {"y": {"type": "number"}}}
ICON = Icon(src="https://example.com/icon.png")


# ---------------------------------------------------------------------------
# Fixtures: models with all fields populated
# ---------------------------------------------------------------------------


@pytest.fixture
def full_tool() -> Tool:
    return Tool(
        name="test_tool",
        title="Test Tool",
        description="A test tool",
        inputSchema=INPUT_SCHEMA,
        outputSchema=OUTPUT_SCHEMA,
        icons=[ICON],
        annotations=ToolAnnotations(readOnlyHint=True),
        execution=ToolExecution(taskSupport="optional"),
    )


@pytest.fixture
def full_implementation() -> Implementation:
    return Implementation(
        name="test-server",
        title="Test Server",
        version="1.0.0",
        websiteUrl="https://example.com",
        icons=[ICON],
    )


@pytest.fixture
def full_resource() -> Resource:
    return Resource(
        name="test_resource",
        title="Test Resource",
        uri=AnyUrl("file:///test"),
        description="A test resource",
        mimeType="text/plain",
        size=42,
        icons=[ICON],
        annotations=Annotations(audience=["user"]),
    )


@pytest.fixture
def full_resource_template() -> ResourceTemplate:
    return ResourceTemplate(
        name="test_template",
        title="Test Template",
        uriTemplate="file:///{path}",
        description="A test template",
        mimeType="text/plain",
        icons=[ICON],
        annotations=Annotations(audience=["assistant"]),
    )


@pytest.fixture
def full_prompt() -> Prompt:
    return Prompt(
        name="test_prompt",
        title="Test Prompt",
        description="A test prompt",
        arguments=[PromptArgument(name="arg1", required=True)],
        icons=[ICON],
    )


# ---------------------------------------------------------------------------
# Tool version tests
# ---------------------------------------------------------------------------


class TestToolVersions:
    def test_2025_03_26(self, full_tool: Tool) -> None:
        assert dump_for_version(full_tool, "2025-03-26") == {
            "name": "test_tool",
            "description": "A test tool",
            "inputSchema": INPUT_SCHEMA,
            "annotations": {"readOnlyHint": True},
        }

    def test_2025_06_18(self, full_tool: Tool) -> None:
        assert dump_for_version(full_tool, "2025-06-18") == {
            "name": "test_tool",
            "title": "Test Tool",
            "description": "A test tool",
            "inputSchema": INPUT_SCHEMA,
            "outputSchema": OUTPUT_SCHEMA,
            "annotations": {"readOnlyHint": True},
        }

    def test_2025_11_25(self, full_tool: Tool) -> None:
        assert dump_for_version(full_tool, "2025-11-25") == {
            "name": "test_tool",
            "title": "Test Tool",
            "description": "A test tool",
            "inputSchema": INPUT_SCHEMA,
            "outputSchema": OUTPUT_SCHEMA,
            "icons": [{"src": "https://example.com/icon.png"}],
            "annotations": {"readOnlyHint": True},
            "execution": {"taskSupport": "optional"},
        }

    def test_minimal_tool_all_versions(self) -> None:
        tool = Tool(name="minimal", inputSchema={"type": "object"})
        for version in ALL_VERSIONS:
            result = dump_for_version(tool, version)
            assert result["name"] == "minimal"
            assert result["inputSchema"] == {"type": "object"}


# ---------------------------------------------------------------------------
# Implementation version tests
# ---------------------------------------------------------------------------


class TestImplementationVersions:
    def test_2025_03_26(self, full_implementation: Implementation) -> None:
        assert dump_for_version(full_implementation, "2025-03-26") == {
            "name": "test-server",
            "version": "1.0.0",
        }

    def test_2025_06_18(self, full_implementation: Implementation) -> None:
        assert dump_for_version(full_implementation, "2025-06-18") == {
            "name": "test-server",
            "title": "Test Server",
            "version": "1.0.0",
            "websiteUrl": "https://example.com",
        }

    def test_2025_11_25(self, full_implementation: Implementation) -> None:
        assert dump_for_version(full_implementation, "2025-11-25") == {
            "name": "test-server",
            "title": "Test Server",
            "version": "1.0.0",
            "websiteUrl": "https://example.com",
            "icons": [{"src": "https://example.com/icon.png"}],
        }


# ---------------------------------------------------------------------------
# Resource version tests
# ---------------------------------------------------------------------------


class TestResourceVersions:
    def test_2025_03_26(self, full_resource: Resource) -> None:
        assert dump_for_version(full_resource, "2025-03-26") == {
            "name": "test_resource",
            "uri": "file:///test",
            "description": "A test resource",
            "mimeType": "text/plain",
            "size": 42,
            "annotations": {"audience": ["user"]},
        }

    def test_2025_06_18(self, full_resource: Resource) -> None:
        assert dump_for_version(full_resource, "2025-06-18") == {
            "name": "test_resource",
            "title": "Test Resource",
            "uri": "file:///test",
            "description": "A test resource",
            "mimeType": "text/plain",
            "size": 42,
            "annotations": {"audience": ["user"]},
        }

    def test_2025_11_25(self, full_resource: Resource) -> None:
        assert dump_for_version(full_resource, "2025-11-25") == {
            "name": "test_resource",
            "title": "Test Resource",
            "uri": "file:///test",
            "description": "A test resource",
            "mimeType": "text/plain",
            "size": 42,
            "icons": [{"src": "https://example.com/icon.png"}],
            "annotations": {"audience": ["user"]},
        }


# ---------------------------------------------------------------------------
# ResourceTemplate version tests
# ---------------------------------------------------------------------------


class TestResourceTemplateVersions:
    def test_2025_03_26(self, full_resource_template: ResourceTemplate) -> None:
        assert dump_for_version(full_resource_template, "2025-03-26") == {
            "name": "test_template",
            "uriTemplate": "file:///{path}",
            "description": "A test template",
            "mimeType": "text/plain",
            "annotations": {"audience": ["assistant"]},
        }

    def test_2025_06_18(self, full_resource_template: ResourceTemplate) -> None:
        assert dump_for_version(full_resource_template, "2025-06-18") == {
            "name": "test_template",
            "title": "Test Template",
            "uriTemplate": "file:///{path}",
            "description": "A test template",
            "mimeType": "text/plain",
            "annotations": {"audience": ["assistant"]},
        }

    def test_2025_11_25(self, full_resource_template: ResourceTemplate) -> None:
        assert dump_for_version(full_resource_template, "2025-11-25") == {
            "name": "test_template",
            "title": "Test Template",
            "uriTemplate": "file:///{path}",
            "description": "A test template",
            "mimeType": "text/plain",
            "icons": [{"src": "https://example.com/icon.png"}],
            "annotations": {"audience": ["assistant"]},
        }


# ---------------------------------------------------------------------------
# Prompt version tests
# ---------------------------------------------------------------------------


class TestPromptVersions:
    def test_2025_03_26(self, full_prompt: Prompt) -> None:
        assert dump_for_version(full_prompt, "2025-03-26") == {
            "name": "test_prompt",
            "description": "A test prompt",
            "arguments": [{"name": "arg1", "required": True}],
        }

    def test_2025_06_18(self, full_prompt: Prompt) -> None:
        assert dump_for_version(full_prompt, "2025-06-18") == {
            "name": "test_prompt",
            "title": "Test Prompt",
            "description": "A test prompt",
            "arguments": [{"name": "arg1", "required": True}],
        }

    def test_2025_11_25(self, full_prompt: Prompt) -> None:
        assert dump_for_version(full_prompt, "2025-11-25") == {
            "name": "test_prompt",
            "title": "Test Prompt",
            "description": "A test prompt",
            "arguments": [{"name": "arg1", "required": True}],
            "icons": [{"src": "https://example.com/icon.png"}],
        }


# ---------------------------------------------------------------------------
# Models without version-specific handling (passthrough)
# ---------------------------------------------------------------------------


class TestPassthroughModels:
    def test_text_content_unchanged(self) -> None:
        content = TextContent(text="hello")
        for version in ALL_VERSIONS:
            assert dump_for_version(content, version) == {"type": "text", "text": "hello"}


# ---------------------------------------------------------------------------
# Initialize handshake version negotiation
# ---------------------------------------------------------------------------


class TestInitializeVersionNegotiation:
    def test_client_requests_2025_03_26(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({"protocolVersion": "2025-03-26"})
        assert version == "2025-03-26"
        assert result["protocolVersion"] == "2025-03-26"
        assert result["serverInfo"] == {"name": "test", "version": "1.0.0"}

    def test_client_requests_2025_06_18(self) -> None:
        server = MCPServer(name="test", version="2.0")
        result, version = server._handle_initialize({"protocolVersion": "2025-06-18"})
        assert version == "2025-06-18"
        assert result["protocolVersion"] == "2025-06-18"
        assert result["serverInfo"] == {"name": "test", "version": "2.0"}

    def test_client_requests_2025_11_25(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({"protocolVersion": "2025-11-25"})
        assert version == "2025-11-25"
        assert result["protocolVersion"] == "2025-11-25"
        assert result["serverInfo"] == {"name": "test", "version": "1.0.0"}

    def test_client_requests_unsupported_version(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({"protocolVersion": "2099-01-01"})
        assert version == "2025-11-25"
        assert result["protocolVersion"] == "2025-11-25"

    def test_client_requests_no_version(self) -> None:
        server = MCPServer(name="test")
        _, version = server._handle_initialize({})
        assert version == "2025-11-25"

    def test_capabilities_present(self) -> None:
        server = MCPServer(name="test")
        result, _ = server._handle_initialize({"protocolVersion": "2025-03-26"})
        assert result["capabilities"] == {
            "tools": {"listChanged": True},
            "resources": {"subscribe": False, "listChanged": True},
            "prompts": {"listChanged": True},
        }

    def test_instructions_included_when_set(self) -> None:
        server = MCPServer(name="test", instructions="Use this server for testing")
        result, _ = server._handle_initialize({"protocolVersion": "2025-11-25"})
        assert result["instructions"] == "Use this server for testing"

    def test_instructions_excluded_when_none(self) -> None:
        server = MCPServer(name="test")
        result, _ = server._handle_initialize({"protocolVersion": "2025-11-25"})
        assert "instructions" not in result
