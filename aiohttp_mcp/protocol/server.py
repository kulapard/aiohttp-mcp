"""Native MCP JSON-RPC dispatch engine.

Replaces mcp.server.lowlevel.Server - reads SessionMessage from a stream,
dispatches to handlers, and writes responses back.
"""

import asyncio
import logging
from typing import Any

from .context import Context, RequestContext, set_current_context
from .messages import ServerMessageMetadata, SessionMessage
from .models import (
    INTERNAL_ERROR,
    LATEST_PROTOCOL_VERSION,
    METHOD_NOT_FOUND,
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorData,
    Implementation,
    InitializeResult,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    PromptsCapability,
    ResourcesCapability,
    ServerCapabilities,
    ToolsCapability,
)
from .registry import Registry, ToolError
from .streams import StreamReader, StreamWriter
from .versions import dump_for_version

logger = logging.getLogger(__name__)


class MCPServer:
    """Native MCP protocol server with JSON-RPC dispatch.

    Reads SessionMessage objects from a read stream, dispatches JSON-RPC
    methods to registered handlers, and writes responses to a write stream.
    """

    def __init__(
        self,
        name: str | None = None,
        version: str = "1.0.0",
        instructions: str | None = None,
        registry: Registry | None = None,
    ) -> None:
        self.name = name or "aiohttp-mcp"
        self.version = version
        self.instructions = instructions
        self.registry = registry or Registry()

    async def run(  # noqa: C901
        self,
        read_stream: StreamReader[SessionMessage | Exception],
        write_stream: StreamWriter[SessionMessage],
        raise_exceptions: bool = False,
    ) -> None:
        """Main dispatch loop - reads messages and dispatches to handlers."""
        negotiated_version = LATEST_PROTOCOL_VERSION

        async def send_response(
            msg: JSONRPCResponse | JSONRPCError,
            metadata: ServerMessageMetadata | None = None,
        ) -> None:
            session_msg = SessionMessage(
                message=JSONRPCMessage(root=msg),
                metadata=metadata,
            )
            await write_stream.send(session_msg)

        async def send_error(
            request_id: str | int,
            code: int,
            message: str,
            metadata: ServerMessageMetadata | None = None,
        ) -> None:
            await send_response(
                JSONRPCError(
                    id=request_id,
                    error=ErrorData(code=code, message=message),
                ),
                metadata=metadata,
            )

        async def handle_message(session_message: SessionMessage) -> None:  # noqa: C901
            nonlocal negotiated_version

            message = session_message.message
            request_context_data = None
            if session_message.metadata and isinstance(session_message.metadata, ServerMessageMetadata):
                request_context_data = session_message.metadata.request_context

            root = message.root

            # Handle notifications (no response needed)
            if isinstance(root, JSONRPCNotification):
                if root.method == "notifications/initialized":
                    logger.debug("Client sent initialized notification")
                elif root.method == "notifications/cancelled":
                    logger.debug("Received cancellation notification")
                else:
                    logger.debug("Received notification: %s", root.method)
                return

            # Handle responses from client (rare, for server-initiated requests)
            if isinstance(root, JSONRPCResponse | JSONRPCError):
                logger.debug("Received client response/error for id=%s", root.id)
                return

            # Handle requests
            if not isinstance(root, JSONRPCRequest):
                return

            request_id = root.id
            method = root.method
            params = root.params or {}

            # Build response metadata
            response_metadata = ServerMessageMetadata(
                related_request_id=request_id,
                request_context=request_context_data,
            )

            try:
                if method == "initialize":
                    result, negotiated_version = self._handle_initialize(params)
                    await send_response(
                        JSONRPCResponse(id=request_id, result=result),
                        metadata=response_metadata,
                    )
                    return

                if method == "ping":
                    await send_response(
                        JSONRPCResponse(id=request_id, result={}),
                        metadata=response_metadata,
                    )
                    return

                # Set context for tool/resource/prompt calls
                async def _send_notification(method_name: str, params: dict[str, Any] | None) -> None:
                    notif = JSONRPCNotification(method=method_name, params=params)
                    msg = SessionMessage(
                        message=JSONRPCMessage(root=notif),
                        metadata=ServerMessageMetadata(related_request_id=request_id),
                    )
                    await write_stream.send(msg)

                ctx: Context = Context(
                    RequestContext(
                        request_id=request_id,
                        request=request_context_data,
                    ),
                    send_notification=_send_notification,
                    read_resource=self.registry.read_resource,
                )
                set_current_context(ctx)

                try:
                    result = await self._dispatch(method, params, negotiated_version)
                    await send_response(
                        JSONRPCResponse(id=request_id, result=result),
                        metadata=response_metadata,
                    )
                finally:
                    set_current_context(None)

            except _MethodNotFoundError as e:
                await send_error(
                    request_id,
                    METHOD_NOT_FOUND,
                    str(e),
                    metadata=response_metadata,
                )

            except Exception as e:
                logger.exception("Error handling request %s: %s", method, e)
                if raise_exceptions:
                    raise
                await send_error(
                    request_id,
                    INTERNAL_ERROR,
                    str(e),
                    metadata=response_metadata,
                )

        # Main message loop
        async with asyncio.TaskGroup() as tg:
            async for message in read_stream:
                if isinstance(message, Exception):
                    logger.error("Received exception from stream: %s", message)
                    if raise_exceptions:
                        raise message
                    continue

                tg.create_task(handle_message(message))

    def _handle_initialize(self, params: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Handle the initialize request. Returns (result_dict, negotiated_version)."""
        client_version = params.get("protocolVersion", LATEST_PROTOCOL_VERSION)

        # Negotiate version: use client's version if supported, else our latest
        if client_version in SUPPORTED_PROTOCOL_VERSIONS:
            negotiated_version = client_version
        else:
            negotiated_version = LATEST_PROTOCOL_VERSION

        capabilities = ServerCapabilities(
            prompts=PromptsCapability(listChanged=True),
            resources=ResourcesCapability(subscribe=False, listChanged=True),
            tools=ToolsCapability(listChanged=True),
        )

        server_info = Implementation(
            name=self.name,
            version=self.version,
        )

        result = InitializeResult(
            protocolVersion=negotiated_version,
            capabilities=capabilities,
            serverInfo=server_info,
            instructions=self.instructions,
        )

        # Serialize with version-aware field handling
        result_dict = result.model_dump(by_alias=True, exclude_none=True)
        result_dict["serverInfo"] = dump_for_version(server_info, negotiated_version)

        return result_dict, negotiated_version

    async def _dispatch(self, method: str, params: dict[str, Any], version: str) -> dict[str, Any]:
        """Dispatch a JSON-RPC method to the appropriate handler."""
        if method == "tools/list":
            tools = await self.registry.list_tools()
            return {"tools": [dump_for_version(t, version) for t in tools]}

        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments", {})

            try:
                content = await self.registry.call_tool(name, arguments)
                return {
                    "content": [dump_for_version(c, version) for c in content],
                    "isError": False,
                }
            except ToolError as e:
                logger.warning("Tool '%s' execution error: %s", name, e)
                return {
                    "content": [{"type": "text", "text": str(e)}],
                    "isError": True,
                }

        elif method == "resources/list":
            resources = await self.registry.list_resources()
            return {"resources": [dump_for_version(r, version) for r in resources]}

        elif method == "resources/read":
            uri = params.get("uri", "")
            contents = await self.registry.read_resource(uri)
            return {
                "contents": [dump_for_version(c, version) for c in contents],
            }

        elif method == "resources/templates/list":
            templates = await self.registry.list_resource_templates()
            return {"resourceTemplates": [dump_for_version(t, version) for t in templates]}

        elif method == "prompts/list":
            prompts = await self.registry.list_prompts()
            return {"prompts": [dump_for_version(p, version) for p in prompts]}

        elif method == "prompts/get":
            name = params.get("name", "")
            arguments = params.get("arguments")
            result = await self.registry.get_prompt(name, arguments)
            return dump_for_version(result, version)

        else:
            raise _MethodNotFoundError(f"Method not found: {method}")


class _MethodNotFoundError(Exception):
    """Internal error for unknown methods."""

    pass
