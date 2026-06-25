# Feature 1: Structured Return Types + `outputSchema`

## Problem

Returning a Pydantic model or dataclass from a tool calls `str(model)` producing an ugly repr. The `Tool.outputSchema` field exists in the protocol model but is never populated.

## Before

```python
@mcp.tool()
async def get_user(user_id: str) -> str:
    user = await db.get(user_id)
    return json.dumps({"name": user.name, "email": user.email})  # manual serialization
```

## After

```python
from pydantic import BaseModel

class UserResult(BaseModel):
    name: str
    email: str

@mcp.tool()
async def get_user(user_id: str) -> UserResult:
    return UserResult(name="Alice", email="a@b.com")
    # Auto-serialized to JSON, outputSchema auto-generated
```

Works with dataclasses too:

```python
import dataclasses

@dataclasses.dataclass
class UserResult:
    name: str
    email: str

@mcp.tool()
async def get_user(user_id: str) -> UserResult:
    return UserResult(name="Alice", email="a@b.com")
    # Same: auto-serialized to JSON, outputSchema auto-generated
```

**Note:** Structured types already work as **input** parameters (Pydantic handles this today):

```python
import dataclasses
from pydantic import BaseModel

@dataclasses.dataclass
class UserData:
    name: str
    email: str
    age: int = 25

class UserResult(BaseModel):
    id: str
    name: str
    email: str

@mcp.tool()
async def create_user(data: UserData) -> UserResult:
    user = await db.create(data.name, data.email, data.age)
    return UserResult(id=user.id, name=user.name, email=user.email)
    # Input: dataclass validated from dict/JSON automatically (works today)
    # Output: BaseModel auto-serialized to JSON + outputSchema generated (this feature)
```

## Design

Use Pydantic's `TypeAdapter` for both BaseModel and dataclass support:

- **Schema generation**: `TypeAdapter(annotation).json_schema()` — works for both
- **Serialization**: `TypeAdapter(annotation).dump_json(item)` — works for both
- **Detection**: Check if return annotation is a BaseModel subclass OR `dataclasses.is_dataclass`

Storing a `TypeAdapter` on `ToolDef` gives one unified path instead of separate isinstance checks at serialization time.

## Changes

### `aiohttp_mcp/protocol/registry.py`

1. **`ToolDef` dataclass** — Add fields:
   ```python
   output_schema: dict[str, Any] | None = None
   output_adapter: TypeAdapter | None = None  # for serialization
   ```

2. **`register_tool()`** — After creating FuncMetadata, inspect the return annotation:
   ```python
   import dataclasses
   from pydantic import TypeAdapter

   sig = inspect.signature(fn)
   return_annotation = sig.return_annotation
   output_schema = None
   output_adapter = None

   if return_annotation is not inspect.Parameter.empty:
       is_model = isinstance(return_annotation, type) and issubclass(return_annotation, BaseModel)
       is_dc = dataclasses.is_dataclass(return_annotation)
       if is_model or is_dc:
           adapter = TypeAdapter(return_annotation)
           output_schema = adapter.json_schema()
           output_adapter = adapter
   ```

3. **`list_tools()`** — Pass `outputSchema=td.output_schema` when constructing `Tool()`.

4. **`_single_to_content()`** — No changes needed here. Serialization happens in `call_tool()` instead, where we have access to the `ToolDef` and its adapter:
   ```python
   # In call_tool(), after getting the result:
   if td.output_adapter is not None and not isinstance(result, (str, dict, list, *_CONTENT_TYPES)):
       json_bytes = td.output_adapter.dump_json(result)
       return [TextContent(text=json_bytes.decode())]
   return _convert_to_content(result)
   ```

### Imports needed

```python
import dataclasses
from pydantic import BaseModel, TypeAdapter  # both already dependencies
```

## Complexity

**S (Small)** — All changes in one file. `TypeAdapter` does the heavy lifting.

## Test Plan

- Test tool returning `BaseModel` → verify `TextContent` has proper JSON (not repr)
- Test tool returning `dataclass` → verify `TextContent` has proper JSON
- Test `list_tools()` → verify `outputSchema` populated for BaseModel return type
- Test `list_tools()` → verify `outputSchema` populated for dataclass return type
- Test tool returning `str`/`dict` → verify no `outputSchema`, behavior unchanged
- Test tool with no return annotation → verify no `outputSchema`
- Test tool returning `BaseModel` with nested types → verify correct schema
- Test tool returning `dataclass` with default values → verify schema includes defaults
