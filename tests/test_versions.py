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


# ---------------------------------------------------------------------------
# Fixtures: models with all fields populated
# ---------------------------------------------------------------------------


@pytest.fixture
def full_tool() -> Tool:
    return Tool(
        name="test_tool",
        title="Test Tool",
        description="A test tool",
        inputSchema={"type": "object", "properties": {"x": {"type": "string"}}},
        outputSchema={"type": "object", "properties": {"y": {"type": "number"}}},
        icons=[Icon(src="https://example.com/icon.png")],
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
        icons=[Icon(src="https://example.com/icon.png")],
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
        icons=[Icon(src="https://example.com/icon.png")],
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
        icons=[Icon(src="https://example.com/icon.png")],
        annotations=Annotations(audience=["assistant"]),
    )


@pytest.fixture
def full_prompt() -> Prompt:
    return Prompt(
        name="test_prompt",
        title="Test Prompt",
        description="A test prompt",
        arguments=[PromptArgument(name="arg1", required=True)],
        icons=[Icon(src="https://example.com/icon.png")],
    )


# ---------------------------------------------------------------------------
# Tool version tests
# ---------------------------------------------------------------------------


class TestToolVersions:
    def test_2025_03_26_excludes_new_fields(self, full_tool: Tool) -> None:
        result = dump_for_version(full_tool, "2025-03-26")
        assert "name" in result
        assert "description" in result
        assert "inputSchema" in result
        assert "annotations" in result
        # Fields not in 2025-03-26
        assert "title" not in result
        assert "icons" not in result
        assert "outputSchema" not in result
        assert "execution" not in result

    def test_2025_06_18_adds_title_and_output_schema(self, full_tool: Tool) -> None:
        result = dump_for_version(full_tool, "2025-06-18")
        assert "name" in result
        assert "title" in result
        assert "description" in result
        assert "inputSchema" in result
        assert "outputSchema" in result
        assert "annotations" in result
        # Still not in 2025-06-18
        assert "icons" not in result
        assert "execution" not in result

    def test_2025_11_25_includes_all_fields(self, full_tool: Tool) -> None:
        result = dump_for_version(full_tool, "2025-11-25")
        assert "name" in result
        assert "title" in result
        assert "description" in result
        assert "inputSchema" in result
        assert "icons" in result
        assert "annotations" in result
        assert "execution" in result

    def test_minimal_tool_all_versions(self) -> None:
        """A tool with only required fields works for all versions."""
        tool = Tool(name="minimal", inputSchema={"type": "object"})
        for version in ALL_VERSIONS:
            result = dump_for_version(tool, version)
            assert result["name"] == "minimal"
            assert result["inputSchema"] == {"type": "object"}


# ---------------------------------------------------------------------------
# Implementation version tests
# ---------------------------------------------------------------------------


class TestImplementationVersions:
    def test_2025_03_26_only_name_and_version(self, full_implementation: Implementation) -> None:
        result = dump_for_version(full_implementation, "2025-03-26")
        assert result == {"name": "test-server", "version": "1.0.0"}

    def test_2025_06_18_adds_title_and_website(self, full_implementation: Implementation) -> None:
        result = dump_for_version(full_implementation, "2025-06-18")
        assert "name" in result
        assert "title" in result
        assert "version" in result
        assert "websiteUrl" in result
        assert "icons" not in result

    def test_2025_11_25_includes_all(self, full_implementation: Implementation) -> None:
        result = dump_for_version(full_implementation, "2025-11-25")
        assert "name" in result
        assert "title" in result
        assert "version" in result
        assert "websiteUrl" in result
        assert "icons" in result


# ---------------------------------------------------------------------------
# Resource version tests
# ---------------------------------------------------------------------------


class TestResourceVersions:
    def test_2025_03_26_excludes_title_and_icons(self, full_resource: Resource) -> None:
        result = dump_for_version(full_resource, "2025-03-26")
        assert "name" in result
        assert "uri" in result
        assert "description" in result
        assert "mimeType" in result
        assert "annotations" in result
        assert "title" not in result
        assert "icons" not in result

    def test_2025_06_18_adds_title(self, full_resource: Resource) -> None:
        result = dump_for_version(full_resource, "2025-06-18")
        assert "title" in result
        assert "icons" not in result

    def test_2025_11_25_includes_all(self, full_resource: Resource) -> None:
        result = dump_for_version(full_resource, "2025-11-25")
        assert "title" in result
        assert "icons" in result


# ---------------------------------------------------------------------------
# ResourceTemplate version tests
# ---------------------------------------------------------------------------


class TestResourceTemplateVersions:
    def test_2025_03_26_excludes_title_and_icons(self, full_resource_template: ResourceTemplate) -> None:
        result = dump_for_version(full_resource_template, "2025-03-26")
        assert "name" in result
        assert "uriTemplate" in result
        assert "description" in result
        assert "title" not in result
        assert "icons" not in result

    def test_2025_06_18_adds_title(self, full_resource_template: ResourceTemplate) -> None:
        result = dump_for_version(full_resource_template, "2025-06-18")
        assert "title" in result
        assert "icons" not in result

    def test_2025_11_25_includes_all(self, full_resource_template: ResourceTemplate) -> None:
        result = dump_for_version(full_resource_template, "2025-11-25")
        assert "title" in result
        assert "icons" in result


# ---------------------------------------------------------------------------
# Prompt version tests
# ---------------------------------------------------------------------------


class TestPromptVersions:
    def test_2025_03_26_excludes_title_and_icons(self, full_prompt: Prompt) -> None:
        result = dump_for_version(full_prompt, "2025-03-26")
        assert "name" in result
        assert "description" in result
        assert "arguments" in result
        assert "title" not in result
        assert "icons" not in result

    def test_2025_06_18_adds_title(self, full_prompt: Prompt) -> None:
        result = dump_for_version(full_prompt, "2025-06-18")
        assert "title" in result
        assert "icons" not in result

    def test_2025_11_25_includes_all(self, full_prompt: Prompt) -> None:
        result = dump_for_version(full_prompt, "2025-11-25")
        assert "title" in result
        assert "icons" in result


# ---------------------------------------------------------------------------
# Models without version-specific handling (passthrough)
# ---------------------------------------------------------------------------


class TestPassthroughModels:
    """Models not in _VERSION_MODELS should serialize identically for all versions."""

    def test_text_content_unchanged(self) -> None:
        content = TextContent(text="hello")
        for version in ALL_VERSIONS:
            result = dump_for_version(content, version)
            assert result == {"type": "text", "text": "hello"}


# ---------------------------------------------------------------------------
# Initialize handshake version negotiation
# ---------------------------------------------------------------------------


class TestInitializeVersionNegotiation:
    def test_client_requests_2025_03_26(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({"protocolVersion": "2025-03-26"})
        assert version == "2025-03-26"
        assert result["protocolVersion"] == "2025-03-26"
        # serverInfo should only have name/version for 2025-03-26
        assert set(result["serverInfo"].keys()) == {"name", "version"}

    def test_client_requests_2025_06_18(self) -> None:
        server = MCPServer(name="test", version="2.0")
        result, version = server._handle_initialize({"protocolVersion": "2025-06-18"})
        assert version == "2025-06-18"
        assert result["protocolVersion"] == "2025-06-18"
        assert "name" in result["serverInfo"]
        assert "version" in result["serverInfo"]
        # No icons in 2025-06-18 Implementation
        assert "icons" not in result["serverInfo"]

    def test_client_requests_2025_11_25(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({"protocolVersion": "2025-11-25"})
        assert version == "2025-11-25"
        assert result["protocolVersion"] == "2025-11-25"

    def test_client_requests_unsupported_version(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({"protocolVersion": "2099-01-01"})
        # Should fall back to latest
        assert version == "2025-11-25"
        assert result["protocolVersion"] == "2025-11-25"

    def test_client_requests_no_version(self) -> None:
        server = MCPServer(name="test")
        result, version = server._handle_initialize({})
        # Should default to latest
        assert version == "2025-11-25"

    def test_capabilities_present(self) -> None:
        server = MCPServer(name="test")
        result, _ = server._handle_initialize({"protocolVersion": "2025-03-26"})
        caps = result["capabilities"]
        assert "tools" in caps
        assert "resources" in caps
        assert "prompts" in caps

    def test_instructions_included_when_set(self) -> None:
        server = MCPServer(name="test", instructions="Use this server for testing")
        result, _ = server._handle_initialize({"protocolVersion": "2025-11-25"})
        assert result["instructions"] == "Use this server for testing"

    def test_instructions_excluded_when_none(self) -> None:
        server = MCPServer(name="test")
        result, _ = server._handle_initialize({"protocolVersion": "2025-11-25"})
        assert "instructions" not in result
