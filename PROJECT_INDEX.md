# Project Index: aiohttp-mcp

**Generated:** 2025-12-15

**Version:** 0.6.1

**Description:** Tools for building Model Context Protocol (MCP) servers on top of aiohttp

---

## 📁 Project Structure

```
aiohttp-mcp/
├── aiohttp_mcp/          # Core library package
│   ├── __init__.py       # Public API exports
│   ├── core.py           # AiohttpMCP main class
│   ├── app.py            # AppBuilder and routing
│   ├── transport.py      # SSE transport implementation
│   ├── streamable_http.py      # Streamable HTTP transport
│   ├── streamable_http_manager.py  # Session management
│   ├── types.py          # Type exports and Context
│   └── utils/            # Utilities
│       ├── __init__.py
│       └── discover.py   # Module discovery
├── examples/             # Example implementations
│   ├── server.py         # Basic MCP server
│   ├── server_auth.py    # Authentication patterns
│   ├── server_context.py # Context usage demo
│   ├── server_custom.py  # Custom handlers
│   ├── server_subapp.py  # Sub-application integration
│   ├── server_streamable_http.py  # Streamable transport
│   └── client.py         # Client example
├── tests/                # Test suite
│   ├── conftest.py       # Pytest configuration
│   ├── utils.py          # Test utilities
│   ├── test_core.py      # Core functionality tests
│   ├── test_app.py       # App builder tests
│   ├── test_transport.py # SSE transport tests
│   ├── test_streamable_transport.py  # Streamable transport tests
│   ├── test_discover.py  # Discovery tests
│   └── test_request_context.py  # Request context tests
├── pyproject.toml        # Project configuration
├── README.md             # Main documentation
├── CLAUDE.md             # Claude Code instructions
├── Makefile              # Development commands
└── .github/              # CI/CD workflows
```

---

## 🚀 Entry Points

### Main Package
- **Path:** `aiohttp_mcp/__init__.py`
- **Exports:** `AiohttpMCP`, `AppBuilder`, `Context`, `TransportMode`, `build_mcp_app`, `setup_mcp_subapp`

### Server Examples
- **Basic Server:** `examples/server.py` - Simple MCP server with tools
- **Auth Server:** `examples/server_auth.py` - Authentication patterns
- **Context Server:** `examples/server_context.py` - Lifespan & request context usage
- **Custom Server:** `examples/server_custom.py` - Advanced custom handlers
- **Streamable Server:** `examples/server_streamable_http.py` - Production transport mode

### Client
- **Path:** `examples/client.py`
- **Purpose:** Demonstrates MCP client usage with SSE transport

### Tests
- **Command:** `uv run pytest`
- **Coverage:** Branch coverage enabled
- **Configuration:** `pyproject.toml` (pytest.ini_options)

---

## 📦 Core Modules

### Module: AiohttpMCP
- **Path:** `aiohttp_mcp/core.py:29`
- **Purpose:** Main class wrapping FastMCP with aiohttp integration
- **Key Methods:**
  - `tool()` - Decorator for registering tools
  - `resource()` - Decorator for registering resources
  - `prompt()` - Decorator for registering prompts
  - `list_tools()`, `call_tool()` - Tool management
  - `list_resources()`, `read_resource()` - Resource management
  - `list_prompts()`, `get_prompt()` - Prompt management
- **Properties:**
  - `server` - Access to underlying MCP Server
  - `event_store` - Optional EventStore for resumability
  - `app` - aiohttp Application instance

### Module: AppBuilder
- **Path:** `aiohttp_mcp/app.py:27`
- **Purpose:** Builds aiohttp applications with MCP capabilities
- **Key Methods:**
  - `build()` - Create standalone or sub-application
  - `setup_routes()` - Configure GET/POST routes
  - `sse_handler()` - Handle SSE connections
  - `message_handler()` - Handle POST messages
  - `streamable_http_handler()` - Handle streamable HTTP requests
- **Transport Modes:**
  - `TransportMode.SSE` - Default SSE transport
  - `TransportMode.STREAMABLE_HTTP` - Production-grade transport

### Module: SSEServerTransport
- **Path:** `aiohttp_mcp/transport.py`
- **Purpose:** Server-Sent Events transport implementation
- **Key Features:**
  - Persistent SSE connections
  - Message queue management
  - Session lifecycle handling

### Module: StreamableHTTPSessionManager
- **Path:** `aiohttp_mcp/streamable_http_manager.py`
- **Purpose:** Advanced session management for streamable transport
- **Key Features:**
  - Stateful and stateless modes
  - EventStore integration for resumability
  - GET/POST/DELETE endpoints
  - Production-ready session handling

### Module: Context
- **Path:** `aiohttp_mcp/types.py:2` (re-exported from mcp.server.fastmcp)
- **Purpose:** Provides access to request context in tools
- **Properties:**
  - `request_context.request` - aiohttp Request object (headers, cookies, client IP)
  - `request_context.lifespan_context` - Shared resources from lifespan
- **Use Cases:**
  - Authentication (headers, tokens)
  - User identity tracking
  - Request metadata access

### Module: discover
- **Path:** `aiohttp_mcp/utils/discover.py`
- **Purpose:** Auto-discovery of decorated MCP functions
- **Key Function:** `discover_modules(package_names)` - Find and load tools/resources/prompts

---

## 🔧 Configuration Files

### pyproject.toml
- **Purpose:** Project metadata, dependencies, build config
- **Sections:**
  - `[project]` - Package metadata (name, version, dependencies)
  - `[dependency-groups]` - Development dependencies
  - `[tool.mypy]` - Type checking configuration (strict mode)
  - `[tool.ruff]` - Linting and formatting rules
  - `[tool.pytest.ini_options]` - Test configuration with coverage
  - `[tool.coverage.report]` - Coverage exclusions

### Makefile
- **Purpose:** Development workflow shortcuts
- **Key Targets:**
  - `make lint` - Run pre-commit hooks and mypy
  - `make clean` - Remove build artifacts
  - `make test` - Run pytest with coverage

### .pre-commit-config.yaml
- **Purpose:** Git pre-commit hooks
- **Hooks:** Code formatting, linting, security checks

### GitHub Workflows
- **CI:** `.github/workflows/*.yml` - Automated testing and checks
- **Publish:** Automated PyPI publishing

---

## 📚 Documentation

### README.md
- **Topics:**
  - Installation (uv, pip)
  - Quick Start guide
  - Basic server setup
  - Sub-application integration
  - Streamable transport usage
  - Client example
  - Development setup

### CLAUDE.md
- **Purpose:** Instructions for Claude Code assistant
- **Topics:**
  - Development commands (test, lint, build)
  - Architecture overview
  - Context patterns (lifespan, request)
  - Integration patterns
  - Transport modes comparison
  - Testing guidelines

---

## 🧪 Test Coverage

- **Unit Tests:** 9 test files
- **Test Framework:** pytest + pytest-cov + pytest-sugar
- **Coverage Type:** Branch coverage enabled
- **Coverage Report:** Terminal output with skip-covered
- **Key Test Areas:**
  - Core functionality (test_core.py)
  - App building (test_app.py)
  - SSE transport (test_transport.py)
  - Streamable transport (test_streamable_transport.py)
  - Request context (test_request_context.py)
  - Module discovery (test_discover.py)

---

## 🔗 Key Dependencies

### Production
- **aiohttp** (>=3.9.0, <4.0.0) - Async HTTP server/client framework
- **aiohttp-sse** (>=2.2.0, <3.0.0) - Server-Sent Events support
- **anyio** (>=4.9.0, <5.0.0) - Async compatibility layer
- **mcp** (>=1.11.0, <2.0.0) - Model Context Protocol implementation

### Development
- **mypy** (>=1.15.0) - Static type checking
- **pytest** (>=8.3.5) - Testing framework
- **pytest-cov** (>=6.1.1) - Coverage plugin
- **httpx** (>=0.28.1) - HTTP client for testing
- **anthropic** (>=0.49.0) - Anthropic API client

---

## 📝 Quick Start

### 1. Installation
```bash
uv add aiohttp-mcp
# or: pip install aiohttp-mcp
```

### 2. Create Simple Server
```bash
# Run basic example
python examples/server.py

# Run with streamable transport
python examples/server_streamable_http.py
```

### 3. Test Integration
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=aiohttp_mcp

# Run specific test file
uv run pytest tests/test_core.py
```

### 4. Lint & Type Check
```bash
# Run all checks
make lint

# Type check only
uv run mypy .
```

---

## 🏗️ Architecture Patterns

### Standalone MCP Server
Use `build_mcp_app()` to create a complete aiohttp application:
```python
app = build_mcp_app(mcp, path="/mcp")
web.run_app(app)
```

### Sub-Application Integration
Use `setup_mcp_subapp()` to integrate into existing aiohttp apps:
```python
app = web.Application()
setup_mcp_subapp(app, mcp, prefix="/mcp")
```

### Transport Modes
- **SSE (default):** Real-time streaming, single-instance deployments
- **STREAMABLE_HTTP:** Advanced session management, multi-instance support, EventStore integration

### Context Patterns
- **Lifespan Context:** Share resources across all tools (DB pools, config)
- **Request Context:** Access per-request data (auth headers, user identity)

---

## 📊 Project Statistics

- **Python Files:** 25 (excluding .venv)
- **Total Lines:** ~4,946 (including tests)
- **Core Files:** 8 (aiohttp_mcp package)
- **Example Files:** 7
- **Test Files:** 9
- **Python Support:** 3.10, 3.11, 3.12, 3.13, 3.14
- **License:** MIT

---

## 🔍 Key Features

1. **Easy Integration** - Seamless aiohttp web app integration
2. **Dual Transport** - SSE and Streamable HTTP modes
3. **Type Safety** - Full type hints with mypy strict mode
4. **Production Ready** - EventStore support, session management
5. **Flexible Routing** - Standalone or sub-application deployment
6. **Context Support** - Lifespan and request context patterns
7. **Auto Discovery** - Automatic tool/resource/prompt discovery
8. **Async First** - Built on asyncio/aiohttp foundation

---

## 📖 Additional Resources

- **GitHub:** https://github.com/kulapard/aiohttp-mcp
- **PyPI:** https://pypi.org/project/aiohttp-mcp
- **MCP Docs:** https://modelcontextprotocol.io/
- **aiohttp Docs:** https://docs.aiohttp.org/

---

**Index Size:** ~3.5KB
**Token Reduction:** ~94% (vs. reading all source files)
