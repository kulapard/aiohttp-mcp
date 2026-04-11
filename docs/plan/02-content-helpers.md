# Feature 2: Content Return Helpers

## Problem

Returning non-text content requires manual base64 encoding and constructing protocol-level `ImageContent`/`AudioContent` objects. Too verbose for a common operation.

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
from aiohttp_mcp import PNG

@mcp.tool()
async def generate_chart(query: str) -> PNG:
    return PNG(data=await render_chart(query))
```

## API

Specific classes for common formats (no `mime_type` parameter needed):

```python
from aiohttp_mcp import PNG, JPEG, GIF, WAV, MP3, PDF

# Images
PNG(data=b"...")        # image/png
JPEG(data=b"...")       # image/jpeg
GIF(data=b"...")        # image/gif

# Audio
WAV(data=b"...")        # audio/wav
MP3(data=b"...")        # audio/mpeg

# Documents (returned as EmbeddedResource with blob)
PDF(data=b"...")        # application/pdf
```

Generic classes for rare/custom formats:

```python
from aiohttp_mcp import Image, Audio, Blob

Image(data=b"...", mime_type="image/webp")
Audio(data=b"...", mime_type="audio/ogg")
Blob(data=b"...", mime_type="application/zip")  # any binary content
```

## Changes

### New file: `aiohttp_mcp/content.py`

```python
import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class Image:
    """Image content from raw bytes. Base64 encoding is handled automatically."""
    data: bytes
    mime_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class Audio:
    """Audio content from raw bytes. Base64 encoding is handled automatically."""
    data: bytes
    mime_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class PNG(Image):
    mime_type: str = "image/png"


@dataclasses.dataclass(frozen=True, slots=True)
class JPEG(Image):
    mime_type: str = "image/jpeg"


@dataclasses.dataclass(frozen=True, slots=True)
class GIF(Image):
    mime_type: str = "image/gif"


@dataclasses.dataclass(frozen=True, slots=True)
class WAV(Audio):
    mime_type: str = "audio/wav"


@dataclasses.dataclass(frozen=True, slots=True)
class MP3(Audio):
    mime_type: str = "audio/mpeg"


@dataclasses.dataclass(frozen=True, slots=True)
class Blob:
    """Binary content returned as EmbeddedResource. Base64 encoding is handled automatically."""
    data: bytes
    mime_type: str
    uri: str = "blob://result"


@dataclasses.dataclass(frozen=True, slots=True)
class PDF(Blob):
    mime_type: str = "application/pdf"
```

### `aiohttp_mcp/protocol/registry.py` — `_single_to_content()`

Add three isinstance checks before the `str(item)` fallback (subclasses match automatically):

```python
import base64

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
if isinstance(item, Blob):
    return EmbeddedResource(
        resource=BlobResourceContents(
            uri=AnyUrl(item.uri),
            blob=base64.b64encode(item.data).decode("ascii"),
            mimeType=item.mime_type,
        )
    )
```

### `aiohttp_mcp/__init__.py`

Export `Image`, `Audio`, `Blob`, `PNG`, `JPEG`, `GIF`, `WAV`, `MP3`, `PDF`.

## Complexity

**S (Small)** — One new file with simple classes, three isinstance checks in existing function. Subclasses inherit the isinstance check for free.

## Test Plan

- Test `PNG(data=b"...")` → verify `ImageContent` with `mimeType="image/png"` and correct base64
- Test `JPEG(data=b"...")` → verify `mimeType="image/jpeg"`
- Test `GIF(data=b"...")` → verify `mimeType="image/gif"`
- Test `WAV(data=b"...")` → verify `AudioContent` with `mimeType="audio/wav"`
- Test `MP3(data=b"...")` → verify `mimeType="audio/mpeg"`
- Test `Image(data=b"...", mime_type="image/webp")` → verify custom mime type
- Test `Audio(data=b"...", mime_type="audio/ogg")` → verify custom mime type
- Test `PDF(data=b"...")` → verify `EmbeddedResource` with `BlobResourceContents`, `mimeType="application/pdf"`
- Test `Blob(data=b"...", mime_type="application/zip")` → verify custom blob mime type
- Test `Blob` with custom `uri` parameter
- Verify existing return types (str, dict, list) still work unchanged
