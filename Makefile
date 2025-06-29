.PHONY: install build clean publish test lint env

# Load environment variables from .env file if it exists
-include .env
export

all: test lint

# Create and activate virtual environment
venv:
	uv venv
	@echo "Activate with: source .venv/bin/activate"

# Generate .env file from template if it doesn't exist
env-file:
	@if [ -f .env ]; then \
		echo "Error: .env file already exists. Please edit it directly."; \
		exit 1; \
	else \
		cp .env.example .env; \
		echo "Created .env file from template. Please edit it with your PyPI token."; \
	fi

# Install the package
install:
	uv add .

# Build the package
build:
	uv build

# Clean build artifacts
clean:
	rm -rf `find . -name __pycache__`
	rm -f `find . -type f -name '*.py[co]' `
	rm -f `find . -type f -name '*~' `
	rm -f `find . -type f -name '.*~' `
	rm -rf `find . -name ".cache"`
	rm -rf `find . -name ".pytest_cache"`
	rm -rf `find . -name ".mypy_cache"`
	rm -rf `find . -name ".ruff_cache"`
	rm -rf htmlcov
	rm -rf *.egg-info
	rm -f .coverage
	rm -f .coverage.*
	rm -rf build
	rm -rf dist

# Publish to PyPI (requires PyPI token in .env file)
publish:
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Run 'make env' to create it from template."; \
		exit 1; \
	fi
	uv build
	uv publish

# Run tests
test:
	uv run pytest

cov-dev:
	@uv run pytest --cov-report=html
	@open -n "file://`pwd`/htmlcov/index.html"

# Run linting
lint: pre-commit mypy

mypy:
	uv run mypy .

pre-commit:
	uv run pre-commit run --all-files

pre-commit-update:
	uv run pre-commit autoupdate

# Create a new release
release: clean build publish

# Show help
help:
	@echo "Available commands:"
	@echo "  make venv       - Create virtual environment"
	@echo "  make env        - Generate .env file from template (if not exists)"
	@echo "  make install    - Install the package using uv add"
	@echo "  make build      - Build the package using uv build"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make publish    - Publish to PyPI (requires UV_PUBLISH_TOKEN in .env)"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linting"
	@echo "  make format     - Format code"
	@echo "  make release    - Create a new release (clean, build, publish)"
	@echo ""
	@echo "Example runners:"
	@echo "  make run-server              - Run basic MCP server"
	@echo "  make run-server-custom       - Run custom MCP server"
	@echo "  make run-server-subapp       - Run MCP sub-application server"
	@echo "  make run-server-streamable   - Run Streamable HTTP MCP server"
	@echo "  make run-client              - Run MCP client"
	@echo "  make run-inspector           - Run MCP inspector"

run-inspector:
	npx @modelcontextprotocol/inspector

run-client:
	uv run examples/client.py

run-server:
	uv run examples/server.py

run-server-custom:
	uv run examples/server_custom.py

run-server-subapp:
	uv run examples/server_subapp.py

run-server-streamable:
	uv run examples/server_streamable_http.py
