# Feature 2: Content Return Helpers (`Image`, `Audio`)

## Problem

Returning non-text content requires manual base64 encoding and constructing protocol-level `ImageContent`/`AudioContent` objects. This is too verbose for a common operation.

## Before

```python
import base64
from aiohttp_mcp.protocol.models import ImageContent

@mcp.tool()
async def generate_chart(query: str) -> ImageContent:
    png_bytes = await render_chart(query)
    return ImageContent(
        data=base64.b64encode(png_bytes).decode("ascii"),
        mimeType="image/png",
    )
```

## After

```python
from aiohttp_mcp import Image

@mcp.tool()
async def generate_chart(query: str) -> Image:
    return Image(data=await render_chart(query), mime_type="image/png")
```

## Changes

### New file: `aiohttp_mcp/content.py`

```python
import dataclasses

@dataclasses.dataclass(frozen=True, slots=True)
class Image:
    """Helper for returning image content from tools.

    Accepts raw bytes — base64 encoding is handled automatically.
    """
    data: bytes
    mime_type: str = "image/png"

@dataclasses.dataclass(frozen=True, slots=True)
class Audio:
    """Helper for returning audio content from tools.

    Accepts raw bytes — base64 encoding is handled automatically.
    """
    data: bytes
    mime_type: str = "audio/wav"
```

### `aiohttp_mcp/protocol/registry.py` — `_single_to_content()`

Add isinstance checks before the `str(item)` fallback:

```python
if isinstance(item, Image):
    return ImageContent(
        data=base64.b64encode(item.data).decode("ascii"),
        mimeType=item.mime_type,
    )
if isinstance(item, Audio):
    return AudioContent(
        data=base64.b64encode(item.data).decode("ascii"),
        mimeType=item.mime_type,
    )
```

### `aiohttp_mcp/__init__.py`

Export `Image` and `Audio`.

## Complexity

**S (Small)** — One new file with simple dataclasses, two isinstance checks in existing function.

## Test Plan

- Test tool returning `Image(data=b"png", mime_type="image/png")` → verify `ImageContent` with correct base64
- Test tool returning `Audio(data=b"wav")` → verify `AudioContent` with correct base64
- Test default mime types
- Verify existing return types (str, dict, list) still work unchanged
