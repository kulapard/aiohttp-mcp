import pytest

from aiohttp_mcp import AiohttpMCP


@pytest.fixture
def anyio_backend() -> str:
    """Return the backend name for anyio. Test only against asyncio. Trio is not supported."""
    return "asyncio"


@pytest.fixture
def mcp() -> AiohttpMCP:
    return AiohttpMCP()
