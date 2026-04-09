"""Tool, Resource, and Prompt registries for MCP server.

Manages registration, listing, and execution of MCP primitives.
Replaces FastMCP's internal tool/resource/prompt management.
"""

import inspect
import json as _json_module
import logging
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import AnyUrl

from .context import Context, RequestContext, find_context_kwarg, get_current_context
from .func_metadata import FuncMetadata, func_metadata
from .models import (
    Annotations,
    Content,
    GetPromptResult,
    Icon,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    ResourceTemplate,
    TextContent,
    TextResourceContents,
    Tool,
    ToolAnnotations,
)

logger = logging.getLogger(__name__)


class ToolError(Exception):
    """Raised when a tool execution fails."""


# ---------------------------------------------------------------------------
# Internal definitions
# ---------------------------------------------------------------------------


@dataclass
class ToolDef:
    fn: Callable[..., Any]
    name: str
    title: str | None
    description: str
    fn_metadata: FuncMetadata
    is_async: bool
    context_kwarg: str | None
    annotations: ToolAnnotations | None = None
    icons: list[Icon] | None = None
    meta: dict[str, Any] | None = None
    structured_output: bool | None = None


@dataclass
class ResourceDef:
    fn: Callable[..., Any]
    uri: str
    name: str
    title: str | None
    description: str | None
    mime_type: str | None
    is_template: bool
    is_async: bool
    context_kwarg: str | None
    icons: list[Icon] | None = None
    annotations: Annotations | None = None
    uri_params: list[str] = field(default_factory=list)


@dataclass
class PromptDef:
    fn: Callable[..., Any]
    name: str
    title: str | None
    description: str | None
    is_async: bool
    context_kwarg: str | None
    icons: list[Icon] | None = None


# ---------------------------------------------------------------------------
# URI template matching
# ---------------------------------------------------------------------------

_URI_PARAM_RE = re.compile(r"\{(\w+)\}")


def _extract_uri_params(uri_template: str) -> list[str]:
    """Extract parameter names from a URI template like 'echo://{message}'."""
    return _URI_PARAM_RE.findall(uri_template)


def _is_uri_template(uri: str) -> bool:
    return bool(_URI_PARAM_RE.search(uri))


def _match_uri(uri_template: str, uri: str) -> dict[str, str] | None:
    """Match a URI against a template, returning extracted params or None."""
    pattern = _URI_PARAM_RE.sub(r"(?P<\\1>[^/]+)", re.escape(uri_template))
    pattern = pattern.replace(r"\{", "{").replace(r"\}", "}")
    # The re.escape + sub dance can get tricky, let's do it simply:
    regex_parts = []
    last_end = 0
    for m in _URI_PARAM_RE.finditer(uri_template):
        regex_parts.append(re.escape(uri_template[last_end : m.start()]))
        regex_parts.append(f"(?P<{m.group(1)}>[^/]+)")
        last_end = m.end()
    regex_parts.append(re.escape(uri_template[last_end:]))
    full_pattern = "^" + "".join(regex_parts) + "$"

    match = re.match(full_pattern, uri)
    if match:
        return match.groupdict()
    return None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class Registry:
    """Registry for MCP tools, resources, and prompts."""

    def __init__(
        self,
        *,
        warn_on_duplicate_tools: bool = True,
        warn_on_duplicate_resources: bool = True,
        warn_on_duplicate_prompts: bool = True,
    ) -> None:
        self._tools: dict[str, ToolDef] = {}
        self._resources: dict[str, ResourceDef] = {}
        self._prompts: dict[str, PromptDef] = {}
        self._warn_on_duplicate_tools = warn_on_duplicate_tools
        self._warn_on_duplicate_resources = warn_on_duplicate_resources
        self._warn_on_duplicate_prompts = warn_on_duplicate_prompts

    # -- Tool registration --------------------------------------------------

    def register_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        icons: list[Icon] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
    ) -> None:
        tool_name = name or fn.__name__
        tool_description = description or fn.__doc__ or ""

        if tool_name in self._tools and self._warn_on_duplicate_tools:
            logger.warning("Tool '%s' is already registered, overwriting", tool_name)

        ctx_kwarg = find_context_kwarg(fn)
        skip_names = (ctx_kwarg,) if ctx_kwarg else ()

        meta_obj = func_metadata(fn, skip_names=skip_names)
        is_async = inspect.iscoroutinefunction(fn)

        self._tools[tool_name] = ToolDef(
            fn=fn,
            name=tool_name,
            title=title,
            description=tool_description,
            fn_metadata=meta_obj,
            is_async=is_async,
            context_kwarg=ctx_kwarg,
            annotations=annotations,
            icons=icons,
            meta=meta,
            structured_output=structured_output,
        )

    def remove_tool(self, name: str) -> None:
        if name not in self._tools:
            raise ValueError(f"Unknown tool: {name}")
        del self._tools[name]

    async def list_tools(self) -> list[Tool]:
        tools: list[Tool] = []
        for td in self._tools.values():
            schema = td.fn_metadata.arg_model.clean_schema()
            tools.append(
                Tool(
                    name=td.name,
                    title=td.title,
                    description=td.description,
                    inputSchema=schema,
                    icons=td.icons,
                    annotations=td.annotations,
                )
            )
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[Content]:
        td = self._tools.get(name)
        if td is None:
            raise ToolError(f"Unknown tool: {name}")

        extra_args: dict[str, Any] | None = None
        if td.context_kwarg:
            try:
                ctx = get_current_context()
            except ValueError:
                ctx = Context(request_context=RequestContext())
            extra_args = {td.context_kwarg: ctx}

        try:
            result = await td.fn_metadata.call_fn_with_arg_validation(
                fn=td.fn,
                fn_is_async=td.is_async,
                arguments_to_validate=arguments,
                arguments_to_pass_directly=extra_args,
            )
        except ToolError:
            raise
        except Exception as e:
            raise ToolError(str(e)) from e

        return _convert_to_content(result)

    # -- Resource registration ----------------------------------------------

    def register_resource(
        self,
        fn: Callable[..., Any],
        uri: str,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
        icons: list[Icon] | None = None,
        annotations: Annotations | None = None,
    ) -> None:
        resource_name = name or fn.__name__
        is_template = _is_uri_template(uri)
        uri_params = _extract_uri_params(uri) if is_template else []

        if uri in self._resources and self._warn_on_duplicate_resources:
            logger.warning("Resource '%s' is already registered, overwriting", uri)

        ctx_kwarg = find_context_kwarg(fn)
        is_async = inspect.iscoroutinefunction(fn)

        self._resources[uri] = ResourceDef(
            fn=fn,
            uri=uri,
            name=resource_name,
            title=title,
            description=description or fn.__doc__ or "",
            mime_type=mime_type,
            is_template=is_template,
            is_async=is_async,
            context_kwarg=ctx_kwarg,
            icons=icons,
            annotations=annotations,
            uri_params=uri_params,
        )

    async def list_resources(self) -> list[Resource]:
        resources: list[Resource] = []
        for rd in self._resources.values():
            if not rd.is_template:
                resources.append(
                    Resource(
                        uri=AnyUrl(rd.uri),
                        name=rd.name,
                        title=rd.title,
                        description=rd.description,
                        mimeType=rd.mime_type,
                        icons=rd.icons,
                        annotations=rd.annotations,
                    )
                )
        return resources

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        templates: list[ResourceTemplate] = []
        for rd in self._resources.values():
            if rd.is_template:
                templates.append(
                    ResourceTemplate(
                        uriTemplate=rd.uri,
                        name=rd.name,
                        title=rd.title,
                        description=rd.description,
                        mimeType=rd.mime_type,
                        icons=rd.icons,
                        annotations=rd.annotations,
                    )
                )
        return templates

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[TextResourceContents]:
        uri_str = str(uri)

        # Try exact match first (static resources)
        if uri_str in self._resources:
            rd = self._resources[uri_str]
            return await self._call_resource(rd, {})

        # Try template matching
        for rd in self._resources.values():
            if rd.is_template:
                params = _match_uri(rd.uri, uri_str)
                if params is not None:
                    return await self._call_resource(rd, params)

        raise ValueError(f"Unknown resource: {uri_str}")

    async def _call_resource(self, rd: ResourceDef, params: dict[str, str]) -> Iterable[TextResourceContents]:
        kwargs = dict(params)
        if rd.context_kwarg:
            try:
                kwargs[rd.context_kwarg] = get_current_context()
            except ValueError:
                pass

        if rd.is_async:
            result = await rd.fn(**kwargs)
        else:
            result = rd.fn(**kwargs)

        content = str(result)
        return [
            TextResourceContents(
                uri=AnyUrl(rd.uri),
                text=content,
                mimeType=rd.mime_type or "text/plain",
            )
        ]

    # -- Prompt registration ------------------------------------------------

    def register_prompt(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        icons: list[Icon] | None = None,
    ) -> None:
        prompt_name = name or fn.__name__
        if prompt_name in self._prompts and self._warn_on_duplicate_prompts:
            logger.warning("Prompt '%s' is already registered, overwriting", prompt_name)

        ctx_kwarg = find_context_kwarg(fn)
        is_async = inspect.iscoroutinefunction(fn)

        self._prompts[prompt_name] = PromptDef(
            fn=fn,
            name=prompt_name,
            title=title,
            description=description or fn.__doc__ or "",
            is_async=is_async,
            context_kwarg=ctx_kwarg,
            icons=icons,
        )

    async def list_prompts(self) -> list[Prompt]:
        prompts: list[Prompt] = []
        for pd in self._prompts.values():
            # Extract arguments from function signature
            sig = inspect.signature(pd.fn)
            args: list[PromptArgument] = []
            for param in sig.parameters.values():
                if pd.context_kwarg and param.name == pd.context_kwarg:
                    continue
                args.append(
                    PromptArgument(
                        name=param.name,
                        required=param.default is inspect.Parameter.empty,
                    )
                )

            prompts.append(
                Prompt(
                    name=pd.name,
                    title=pd.title,
                    description=pd.description,
                    arguments=args if args else None,
                    icons=pd.icons,
                )
            )
        return prompts

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        pd = self._prompts.get(name)
        if pd is None:
            raise ValueError(f"Unknown prompt: {name}")

        kwargs = dict(arguments or {})
        if pd.context_kwarg:
            try:
                kwargs[pd.context_kwarg] = get_current_context()
            except ValueError:
                pass

        if pd.is_async:
            result = await pd.fn(**kwargs)
        else:
            result = pd.fn(**kwargs)

        # Convert result to PromptMessage
        if isinstance(result, GetPromptResult):
            return result
        if isinstance(result, list):
            return GetPromptResult(messages=result)

        # Simple string result -> user message
        text = str(result)
        return GetPromptResult(
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(text=text),
                )
            ]
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _convert_to_content(result: Any) -> list[Content]:
    """Convert a tool function result to a list of Content blocks."""
    if isinstance(result, list):
        # Check if it's already a list of Content
        if result and isinstance(result[0], TextContent):
            return result
        # Convert each item
        return [_single_to_content(item) for item in result]

    return [_single_to_content(result)]


def _single_to_content(item: Any) -> Content:
    """Convert a single value to a Content block."""
    if isinstance(item, TextContent):
        return item
    # Default: convert to text
    if isinstance(item, str):
        return TextContent(text=item)
    if isinstance(item, dict):
        return TextContent(text=_json_module.dumps(item))

    return TextContent(text=str(item))
