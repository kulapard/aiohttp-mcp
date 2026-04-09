"""Version-specific response models for MCP protocol compatibility.

Each protocol version has its own set of response models containing only
the fields that existed in that version. The full models (2025-11-25)
are used internally; these are used only for serialization to older clients.
"""

from typing import Any

from pydantic import AnyUrl, BaseModel, ConfigDict

from .models import (
    LATEST_PROTOCOL_VERSION,
    Annotations,
    Implementation,
    Prompt,
    PromptArgument,
    Resource,
    ResourceTemplate,
    Tool,
    ToolAnnotations,
)

# ============================================================================
# 2025-03-26 response models
# Original spec: no title/icons/outputSchema/execution on Tool,
# no title/icons/websiteUrl/description on Implementation, etc.
# ============================================================================


class Tool_2025_03_26(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    description: str | None = None
    inputSchema: dict[str, Any]
    annotations: ToolAnnotations | None = None
    meta: dict[str, Any] | None = None


class Implementation_2025_03_26(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    version: str


class Resource_2025_03_26(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    uri: AnyUrl
    description: str | None = None
    mimeType: str | None = None
    size: int | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = None


class ResourceTemplate_2025_03_26(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    uriTemplate: str
    description: str | None = None
    mimeType: str | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = None


class Prompt_2025_03_26(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    description: str | None = None
    arguments: list[PromptArgument] | None = None
    meta: dict[str, Any] | None = None


# ============================================================================
# 2025-06-18 response models
# Adds: title, outputSchema, ResourceLink content type, structuredContent
# Still missing: icons, execution (Tool), icons (Implementation)
# ============================================================================


class Tool_2025_06_18(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    title: str | None = None
    description: str | None = None
    inputSchema: dict[str, Any]
    outputSchema: dict[str, Any] | None = None
    annotations: ToolAnnotations | None = None
    meta: dict[str, Any] | None = None


class Implementation_2025_06_18(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    title: str | None = None
    version: str
    websiteUrl: str | None = None


class Resource_2025_06_18(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    title: str | None = None
    uri: AnyUrl
    description: str | None = None
    mimeType: str | None = None
    size: int | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = None


class ResourceTemplate_2025_06_18(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    title: str | None = None
    uriTemplate: str
    description: str | None = None
    mimeType: str | None = None
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = None


class Prompt_2025_06_18(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    title: str | None = None
    description: str | None = None
    arguments: list[PromptArgument] | None = None
    meta: dict[str, Any] | None = None


# ============================================================================
# Version model registry
# ============================================================================

# Maps (model_class, version) -> versioned_model_class
_VERSION_MODELS: dict[tuple[type[BaseModel], str], type[BaseModel]] = {
    # 2025-03-26
    (Tool, "2025-03-26"): Tool_2025_03_26,
    (Implementation, "2025-03-26"): Implementation_2025_03_26,
    (Resource, "2025-03-26"): Resource_2025_03_26,
    (ResourceTemplate, "2025-03-26"): ResourceTemplate_2025_03_26,
    (Prompt, "2025-03-26"): Prompt_2025_03_26,
    # 2025-06-18
    (Tool, "2025-06-18"): Tool_2025_06_18,
    (Implementation, "2025-06-18"): Implementation_2025_06_18,
    (Resource, "2025-06-18"): Resource_2025_06_18,
    (ResourceTemplate, "2025-06-18"): ResourceTemplate_2025_06_18,
    (Prompt, "2025-06-18"): Prompt_2025_06_18,
}


def dump_for_version(obj: BaseModel, version: str) -> dict[str, Any]:
    """Serialize a pydantic model using the appropriate version-specific model.

    For the latest version, dumps directly. For older versions, validates the
    data through a version-specific model that only contains supported fields.
    """
    if version == LATEST_PROTOCOL_VERSION:
        return obj.model_dump(mode="json", by_alias=True, exclude_none=True)

    versioned_cls = _VERSION_MODELS.get((type(obj), version))
    if versioned_cls is None:
        # No version-specific model — dump as-is (e.g. TextContent, ErrorData)
        return obj.model_dump(mode="json", by_alias=True, exclude_none=True)

    # Convert through the versioned model to drop unsupported fields
    raw = obj.model_dump(by_alias=True)
    versioned = versioned_cls.model_validate(raw)
    return versioned.model_dump(mode="json", by_alias=True, exclude_none=True)
