"""Function introspection for generating tool parameter schemas.

Inspects function signatures and builds Pydantic models to generate
JSON Schema for MCP tool inputSchema. Ported from FastMCP's func_metadata.
"""

import inspect
import json
from collections.abc import Awaitable, Callable, Sequence
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, WithJsonSchema, create_model
from pydantic.fields import FieldInfo
from pydantic.json_schema import GenerateJsonSchema


class InvalidSignature(Exception):
    """Raised when a function has an invalid signature for MCP tool use."""


class _CleanSchemaGenerator(GenerateJsonSchema):
    """JSON Schema generator that omits the root 'title' added by pydantic."""

    def generate(self, schema: Any, mode: str = "validation") -> dict[str, Any]:
        json_schema = super().generate(schema, mode=mode)
        json_schema.pop("title", None)
        json_schema.pop("description", None)
        return json_schema


class ArgModelBase(BaseModel):
    """Base model for dynamically generated argument models."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @classmethod
    def clean_schema(cls) -> dict[str, Any]:
        """Generate JSON Schema without pydantic artifacts (title, description)."""
        return cls.model_json_schema(schema_generator=_CleanSchemaGenerator)

    def model_dump_one_level(self) -> dict[str, Any]:
        """Return a dict of the model's fields, one level deep.

        Sub-models are kept as pydantic models, not recursively dumped.
        """
        kwargs: dict[str, Any] = {}
        for field_name, field_info in self.__class__.model_fields.items():
            value = getattr(self, field_name)
            output_name = field_info.alias if field_info.alias else field_name
            kwargs[output_name] = value
        return kwargs


class FuncMetadata(BaseModel):
    """Metadata about a function including its argument model for validation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    arg_model: Annotated[type[ArgModelBase], WithJsonSchema(None)]

    async def call_fn_with_arg_validation(
        self,
        fn: Callable[..., Any | Awaitable[Any]],
        fn_is_async: bool,
        arguments_to_validate: dict[str, Any],
        arguments_to_pass_directly: dict[str, Any] | None,
    ) -> Any:
        """Call the function with validated arguments."""
        arguments_pre_parsed = self._pre_parse_json(arguments_to_validate)
        arguments_parsed_model = self.arg_model.model_validate(arguments_pre_parsed)
        arguments_parsed_dict = arguments_parsed_model.model_dump_one_level()
        arguments_parsed_dict |= arguments_to_pass_directly or {}

        if fn_is_async:
            return await fn(**arguments_parsed_dict)
        else:
            return fn(**arguments_parsed_dict)

    def _pre_parse_json(self, data: dict[str, Any]) -> dict[str, Any]:
        """Pre-parse string values that should be JSON.

        Handles cases like '["a", "b"]' being passed as a string instead of a list.
        """
        new_data = data.copy()

        key_to_field_info: dict[str, FieldInfo] = {}
        for field_name, field_info in self.arg_model.model_fields.items():
            key_to_field_info[field_name] = field_info
            if field_info.alias:
                key_to_field_info[field_info.alias] = field_info

        for data_key, data_value in data.items():
            if data_key not in key_to_field_info:
                continue
            field_info = key_to_field_info[data_key]
            if isinstance(data_value, str) and field_info.annotation is not str:
                try:
                    pre_parsed = json.loads(data_value)
                except json.JSONDecodeError:
                    continue
                if isinstance(pre_parsed, str | int | float):
                    continue
                new_data[data_key] = pre_parsed

        return new_data


def func_metadata(
    func: Callable[..., Any],
    skip_names: Sequence[str] = (),
) -> FuncMetadata:
    """Extract metadata from a function, including a pydantic model for its parameters.

    Args:
        func: The function to introspect.
        skip_names: Parameter names to exclude (e.g., context parameters).

    Returns:
        FuncMetadata with arg_model for validation and schema generation.
    """
    try:
        sig = inspect.signature(func, eval_str=True)
    except NameError as e:
        raise InvalidSignature(f"Unable to evaluate type annotations for {func.__name__!r}") from e

    dynamic_pydantic_model_params: dict[str, Any] = {}

    for param in sig.parameters.values():
        if param.name.startswith("_"):
            raise InvalidSignature(f"Parameter {param.name} of {func.__name__} cannot start with '_'")
        if param.name in skip_names:
            continue

        annotation = param.annotation if param.annotation is not inspect.Parameter.empty else Any
        field_name = param.name
        field_kwargs: dict[str, Any] = {}
        field_metadata: list[Any] = []

        if param.annotation is inspect.Parameter.empty:
            field_metadata.append(WithJsonSchema({"title": param.name, "type": "string"}))

        # Avoid shadowing BaseModel attributes
        if hasattr(BaseModel, field_name) and callable(getattr(BaseModel, field_name)):
            field_kwargs["alias"] = field_name
            field_name = f"field_{field_name}"

        annotated_type = Annotated[(annotation, *field_metadata, Field(**field_kwargs))]  # type: ignore[valid-type]

        if param.default is not inspect.Parameter.empty:
            dynamic_pydantic_model_params[field_name] = (annotated_type, param.default)
        else:
            dynamic_pydantic_model_params[field_name] = annotated_type

    arguments_model = create_model(
        f"{func.__name__}Arguments",
        __base__=ArgModelBase,
        **dynamic_pydantic_model_params,
    )

    return FuncMetadata(arg_model=arguments_model)
