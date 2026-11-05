"""
Cerberus MCP Server

A FastMCP subclass that instruments tool, resource, and prompt calls
for Cerberus monitoring. Wraps handlers to capture timing, errors,
and arguments, then sends events via WebSocket to the Cerberus pipeline.
"""

import asyncio
import functools
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from weakref import WeakKeyDictionary

from mcp.server.fastmcp import FastMCP

from cerberus_core import hash_pii, normalize_ip

from .config import DEBUG_ENABLED, USER_AGENT
from .structs import MCPEventData
from .transport import init_client, queue_event
from .utils import sanitize_arguments, summarize_result

logger = logging.getLogger(__name__)

# Method names for event types
METHOD_TOOL_CALL = "mcp_tool_call"
METHOD_RESOURCE_READ = "mcp_resource_read"
METHOD_PROMPT_GET = "mcp_prompt_get"

# Lazy-loaded MCP Context class reference
_mcp_context_class = None


def _get_mcp_context_class():
    """Lazily import and cache the MCP Context class."""
    global _mcp_context_class
    if _mcp_context_class is None:
        try:
            from mcp.server.fastmcp import Context
            _mcp_context_class = Context
        except ImportError:
            # Fallback: use a sentinel that never matches
            _mcp_context_class = type(None)
    return _mcp_context_class


def _is_mcp_context(obj) -> bool:
    """Check if an object is an MCP Context.

    Uses the actual imported Context class rather than duck typing
    to avoid false positives from unrelated classes.

    Args:
        obj: Object to check

    Returns:
        True if the object is an MCP Context instance
    """
    return isinstance(obj, _get_mcp_context_class())


def _extract_source_ip(ctx) -> Optional[str]:
    """Best-effort extraction of remote client IP from MCP Context.

    For SSE/StreamableHTTP transports, the session's transport wraps a
    Starlette ASGI scope that contains the client's (host, port) tuple.
    For stdio transport, there is no network connection so this returns None.

    NOTE: This probes private MCP SDK attributes (_transport, _scope, etc.)
    that may change across SDK versions. Validated against mcp>=1.0,<2.0.
    Revisit if upgrading the MCP SDK.

    Args:
        ctx: MCP Context object

    Returns:
        Client IP string, or None if not available
    """
    try:
        session = getattr(ctx, 'session', None)
        if session is None:
            return None

        # Try to reach the ASGI scope via the transport's request object
        # SSE: session._transport may have ._read_stream or ._scope
        # StreamableHTTP: similar path through the transport layer
        transport = getattr(session, '_transport', None) or getattr(session, 'transport', None)
        if transport is None:
            return None

        # Starlette SSE transports often store the ASGI scope or request
        # Try common attribute paths to find client info
        for attr in ('_scope', 'scope', '_request', 'request'):
            obj = getattr(transport, attr, None)
            if obj is None:
                continue
            # ASGI scope dict: scope["client"] = (host, port)
            if isinstance(obj, dict):
                client = obj.get('client')
                if client and isinstance(client, (list, tuple)) and len(client) >= 1:
                    return str(client[0])
            # Starlette Request object: request.client.host
            client = getattr(obj, 'client', None)
            if client is not None:
                host = getattr(client, 'host', None)
                if host:
                    return str(host)

        # Also check if there's a _client_address stashed on the session itself
        client_addr = getattr(session, '_client_address', None) or getattr(session, 'client_address', None)
        if client_addr:
            if isinstance(client_addr, (list, tuple)):
                return str(client_addr[0])
            return str(client_addr)

    except Exception:
        pass

    return None


class CerberusMCP(FastMCP):
    """FastMCP subclass that instruments MCP handlers for Cerberus monitoring.

    Wraps tool(), resource(), and prompt() decorator registrations to capture
    timing, errors, and arguments from each call. Events are sent to the
    Cerberus event_ingest backend using the same payload format as the
    cerberus_django middleware.

    Usage:
        from cerberus_mcp import CerberusMCP

        mcp = CerberusMCP(
            "my-server",
            cerberus_config={
                "token": "your-api-key",
                "client_id": "your-client-id",
                "ws_url": "ws://localhost:8765",
            }
        )

        @mcp.tool()
        def my_tool(query: str) -> str:
            return "result"
    """

    def __init__(self, name: str = "mcp", cerberus_config: Optional[Dict] = None, **kwargs):
        """Initialize CerberusMCP server.

        Args:
            name: Server name (used in endpoint paths)
            cerberus_config: Cerberus configuration dict with keys:
                - token: API key for authentication (required)
                - client_id: Client identifier (required)
                - ws_url: WebSocket URL for event_ingest (required)
                - server_name: Override server name in events (optional)
            **kwargs: Additional arguments passed to FastMCP
        """
        super().__init__(name, **kwargs)

        self._cerberus_config = cerberus_config or {}
        self._server_name = self._cerberus_config.get('server_name', name)
        self._secret_key = self._cerberus_config.get('secret_key')
        self._warned_no_secret_key = False
        self._session_ids: WeakKeyDictionary = WeakKeyDictionary()

        # Initialize transport if config is complete
        token = self._cerberus_config.get('token')
        client_id = self._cerberus_config.get('client_id')
        ws_url = self._cerberus_config.get('ws_url')

        self._schema_reported = False
        self._schema_report_lock = threading.Lock()

        if token and client_id and ws_url:
            init_client(ws_url, token, client_id)
            if DEBUG_ENABLED:
                logger.info(f"[CerberusMCP] Server '{self._server_name}' initialized with monitoring")
        else:
            logger.warning(
                "[CerberusMCP] Monitoring disabled. Missing token, client_id, or ws_url "
                "in cerberus_config"
            )

    def _get_session_id(self, session) -> str:
        """Get or create a UUID session ID for a ServerSession.

        Uses WeakKeyDictionary so session IDs are automatically cleaned up
        when the ServerSession is garbage collected.

        Args:
            session: MCP ServerSession object

        Returns:
            UUID string for this session
        """
        if session is None:
            return "no-session"
        if session not in self._session_ids:
            self._session_ids[session] = str(uuid.uuid4())
        return self._session_ids[session]

    def _extract_context_info(self, args, kwargs):
        """Extract identity info from Context argument and filter it from args.

        Looks for a Context object in the arguments, extracts session/client
        metadata from it, and returns cleaned args without the Context object.

        Args:
            args: Positional arguments tuple
            kwargs: Keyword arguments dict

        Returns:
            Tuple of (cleaned_args_dict, context_info_dict)
        """
        context_info = {}
        cleaned_kwargs = dict(kwargs)

        # Check kwargs for Context object
        ctx = None
        for key, value in kwargs.items():
            if _is_mcp_context(value):
                ctx = value
                cleaned_kwargs.pop(key, None)
                break

        # Also check positional args for Context, and collect non-Context args
        cleaned_positional = {}
        for i, arg in enumerate(args):
            if _is_mcp_context(arg):
                if ctx is None:
                    ctx = arg
            else:
                cleaned_positional[f"_arg{i}"] = arg

        # Merge positional args into kwargs (kwargs take precedence)
        all_args = {**cleaned_positional, **cleaned_kwargs}

        if ctx is not None:
            # Extract session info
            try:
                session = getattr(ctx, 'session', None)
                if session is not None:
                    context_info['session_id'] = self._get_session_id(session)
                    client_params = getattr(session, 'client_params', None)
                    if client_params is not None:
                        client_info = getattr(client_params, 'clientInfo', None)
                        if client_info is not None:
                            context_info['client_name'] = getattr(client_info, 'name', None)
                            context_info['client_version'] = getattr(client_info, 'version', None)
            except Exception:
                pass

            # Extract request_id and client_id
            try:
                context_info['request_id'] = getattr(ctx, 'request_id', None)
                context_info['mcp_client_id'] = getattr(ctx, 'client_id', None)
            except Exception:
                pass

            # Best-effort source IP extraction for SSE/StreamableHTTP transports
            context_info['source_ip'] = _extract_source_ip(ctx)

        return all_args, context_info

    def _report_schema(self):
        """Emit a one-time schema_report event describing all registered tools, resources, and prompts.

        Called lazily on the first real event so that all decorators have run
        and the FastMCP internal registries are fully populated.
        Thread-safe via _schema_report_lock.
        """
        with self._schema_report_lock:
            if self._schema_reported:
                return
            self._schema_reported = True

        token = self._cerberus_config.get('token', '')

        tools_list = []
        resources_list = []
        prompts_list = []

        try:
            # Introspect registered tools
            tool_manager = getattr(self, '_tool_manager', None)
            if tool_manager is not None:
                tools_dict = getattr(tool_manager, '_tools', {})
                for t_name, t_obj in tools_dict.items():
                    tool_entry = {"name": str(t_name)}
                    tool_entry["description"] = getattr(t_obj, 'description', '') or ''
                    # Tool.parameters is already a pre-computed JSON schema dict
                    schema = getattr(t_obj, 'parameters', None)
                    if isinstance(schema, dict) and schema:
                        tool_entry["input_schema"] = schema
                    tools_list.append(tool_entry)

            # Introspect registered resources: concrete resources with fixed
            # URIs, then parameterized URI templates (e.g. "resource://{city}/weather")
            resource_manager = getattr(self, '_resource_manager', None)
            if resource_manager is not None:
                for registry in ('_resources', '_templates'):
                    for r_uri, r_obj in getattr(resource_manager, registry, {}).items():
                        resources_list.append({
                            "uri_template": str(r_uri),
                            "name": getattr(r_obj, 'name', str(r_uri)),
                            "description": getattr(r_obj, 'description', '') or '',
                        })

            # Introspect registered prompts
            prompt_manager = getattr(self, '_prompt_manager', None)
            if prompt_manager is not None:
                prompts_dict = getattr(prompt_manager, '_prompts', {})
                for p_name, p_obj in prompts_dict.items():
                    prompt_entry = {
                        "name": str(p_name),
                        "description": getattr(p_obj, 'description', '') or '',
                    }
                    # Extract declared arguments from the prompt's parameters
                    p_args = getattr(p_obj, 'arguments', None)
                    if p_args and isinstance(p_args, (list, tuple)):
                        prompt_entry["arguments"] = [
                            {
                                "name": getattr(a, 'name', ''),
                                "required": getattr(a, 'required', False),
                                "description": getattr(a, 'description', ''),
                            }
                            for a in p_args
                        ]
                    prompts_list.append(prompt_entry)

        except Exception as e:
            logger.debug(f"[CerberusMCP] Schema introspection partial failure: {e}")

        if not tools_list and not resources_list and not prompts_list:
            logger.debug("[CerberusMCP] No schema to report (no registered tools/resources/prompts found)")
            return

        custom_data = {
            'mcp_server': self._server_name,
            'event_type': 'schema_report',
            'tools': tools_list,
            'resources': resources_list,
            'prompts': prompts_list,
        }

        event = MCPEventData(
            token=token,
            source_ip="mcp-local",
            endpoint=f"mcp://{self._server_name}/__schema__",
            scheme="mcp",
            method="mcp_schema_report",
            timestamp=datetime.now(timezone.utc).isoformat(),
            custom_data=custom_data,
            headers=None,
            query_params=None,
            body=None,
            user_agent=USER_AGENT,
            user_id=None,
        )

        queue_event(event)
        if DEBUG_ENABLED:
            logger.info(
                f"[CerberusMCP] Schema report sent: {len(tools_list)} tools, "
                f"{len(resources_list)} resources, {len(prompts_list)} prompts"
            )

    def _emit_event(
        self,
        handler_name: str,
        event_type: str,
        method: str,
        duration_ms: float,
        arguments: Optional[Dict],
        result: Any,
        error: Optional[str],
        context_info: Dict,
    ):
        """Create and queue an MCPEventData event.

        Args:
            handler_name: Name of the tool/resource/prompt
            event_type: One of tool_call, resource_read, prompt_get
            method: Event method (mcp_tool_call, mcp_resource_read, mcp_prompt_get)
            duration_ms: Call duration in milliseconds
            arguments: Sanitized arguments dict
            result: Raw result (will be summarized)
            error: Error message string or None
            context_info: Dict with session_id, client_name, etc.
        """
        # Emit schema report on first real event (lazy, after all decorators have run)
        if not self._schema_reported:
            self._report_schema()

        token = self._cerberus_config.get('token', '')

        custom_data = {
            'mcp_server': self._server_name,
            'handler_name': handler_name,
            'event_type': event_type,
            'duration_ms': round(duration_ms, 2),
            'error': error,
            'result_summary': summarize_result(result) if error is None else None,
            'session_id': context_info.get('session_id'),
            'client_name': context_info.get('client_name'),
            'client_version': context_info.get('client_version'),
            'request_id': context_info.get('request_id'),
            'mcp_client_id': context_info.get('mcp_client_id'),
        }

        source_ip = context_info.get('source_ip') or "mcp-local"

        # Normalize and hash source IP for PII protection (same as cerberus-django)
        if source_ip != "mcp-local":
            source_ip = normalize_ip(source_ip)
        if self._secret_key and source_ip != "mcp-local":
            source_ip = hash_pii(source_ip, self._secret_key)
        elif source_ip != "mcp-local" and not self._warned_no_secret_key:
            self._warned_no_secret_key = True
            logger.warning(
                "[CerberusMCP] Sending source IP in plaintext — no secret_key configured. "
                "Add secret_key to cerberus_config to enable PII hashing."
            )

        event = MCPEventData(
            token=token,
            source_ip=source_ip,
            endpoint=f"mcp://{self._server_name}/{handler_name}",
            scheme="mcp",
            method=method,
            timestamp=datetime.now(timezone.utc).isoformat(),
            custom_data=custom_data,
            headers=None,
            query_params=None,
            body=arguments,
            user_agent=USER_AGENT,
            user_id=context_info.get('mcp_client_id'),
        )

        queue_event(event)

    def _wrap_handler(self, handler: Callable, handler_name: str, event_type: str, method: str) -> Callable:
        """Wrap an MCP handler to capture timing, errors, and arguments.

        Handles both sync and async handlers transparently.

        Args:
            handler: The original handler function
            handler_name: Name of the tool/resource/prompt
            event_type: One of tool_call, resource_read, prompt_get
            method: Event method string

        Returns:
            Wrapped handler function
        """
        if asyncio.iscoroutinefunction(handler):
            @functools.wraps(handler)
            async def async_wrapper(*args, **kwargs):
                cleaned_kwargs, context_info = self._extract_context_info(args, kwargs)
                sanitized_args = sanitize_arguments(cleaned_kwargs)

                start = time.perf_counter()
                error_msg = None
                result = None
                try:
                    result = await handler(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = type(e).__name__
                    raise
                finally:
                    duration_ms = (time.perf_counter() - start) * 1000
                    self._emit_event(
                        handler_name=handler_name,
                        event_type=event_type,
                        method=method,
                        duration_ms=duration_ms,
                        arguments=sanitized_args,
                        result=result,
                        error=error_msg,
                        context_info=context_info,
                    )
            async_wrapper.__wrapped__ = handler
            return async_wrapper
        else:
            @functools.wraps(handler)
            def sync_wrapper(*args, **kwargs):
                cleaned_kwargs, context_info = self._extract_context_info(args, kwargs)
                sanitized_args = sanitize_arguments(cleaned_kwargs)

                start = time.perf_counter()
                error_msg = None
                result = None
                try:
                    result = handler(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = type(e).__name__
                    raise
                finally:
                    duration_ms = (time.perf_counter() - start) * 1000
                    self._emit_event(
                        handler_name=handler_name,
                        event_type=event_type,
                        method=method,
                        duration_ms=duration_ms,
                        arguments=sanitized_args,
                        result=result,
                        error=error_msg,
                        context_info=context_info,
                    )
            sync_wrapper.__wrapped__ = handler
            return sync_wrapper

    def tool(self, name=None, **kwargs):
        """Register a tool with Cerberus monitoring instrumentation.

        Overrides FastMCP.tool() to wrap the handler with timing/error capture.

        Args:
            name: Optional tool name override
            **kwargs: Additional arguments passed to FastMCP.tool()

        Returns:
            Decorator function
        """
        parent_decorator = super().tool(name, **kwargs)

        def decorator(func):
            tool_name = name or func.__name__
            wrapped = self._wrap_handler(func, tool_name, "tool_call", METHOD_TOOL_CALL)
            return parent_decorator(wrapped)

        return decorator

    def resource(self, uri, **kwargs):
        """Register a resource with Cerberus monitoring instrumentation.

        Overrides FastMCP.resource() to wrap the handler with timing/error capture.

        Args:
            uri: Resource URI pattern
            **kwargs: Additional arguments passed to FastMCP.resource()

        Returns:
            Decorator function
        """
        parent_decorator = super().resource(uri, **kwargs)

        def decorator(func):
            resource_name = str(uri)
            wrapped = self._wrap_handler(func, resource_name, "resource_read", METHOD_RESOURCE_READ)
            return parent_decorator(wrapped)

        return decorator

    def prompt(self, name=None, **kwargs):
        """Register a prompt with Cerberus monitoring instrumentation.

        Overrides FastMCP.prompt() to wrap the handler with timing/error capture.

        Args:
            name: Optional prompt name override
            **kwargs: Additional arguments passed to FastMCP.prompt()

        Returns:
            Decorator function
        """
        parent_decorator = super().prompt(name, **kwargs)

        def decorator(func):
            prompt_name = name or func.__name__
            wrapped = self._wrap_handler(func, prompt_name, "prompt_get", METHOD_PROMPT_GET)
            return parent_decorator(wrapped)

        return decorator
