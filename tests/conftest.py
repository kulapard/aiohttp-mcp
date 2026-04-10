import pytest

from aiohttp_mcp import AiohttpMCP


@pytest.fixture
def mcp() -> AiohttpMCP:
    return AiohttpMCP()
