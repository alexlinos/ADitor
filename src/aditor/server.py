"""Unified MCP server for Active Directory.

A single low-level MCP :class:`~mcp.server.lowlevel.Server` driven by the one
tool registry (:mod:`aditor.registry`). It serves either:

* ``stdio``  -- the classic MCP stdio transport, or
* ``http``   -- streamable-HTTP mounted at ``/activedirectory-mcp`` on port 8813.

Both transports expose exactly the same tool set, because both are built from
``registry.TOOLS``. Selecting a transport is a ``--transport {stdio,http}``
flag; the default is ``http`` to preserve the behaviour of the server that was
actually run in production (streamable-HTTP on :8813).
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from typing import Any, Dict, List, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from .config.loader import load_config, validate_config
from .core.ldap_manager import LDAPManager
from .core.logging import setup_logging
from .registry import TOOLS, Tools

SERVER_NAME = "ActiveDirectoryMCP"
SERVER_VERSION = "0.1.0"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8813
DEFAULT_PATH = "/activedirectory-mcp"


class ActiveDirectoryMCPServer:
    """Single Active Directory MCP server over stdio or streamable-HTTP."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        transport: str = "http",
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        path: str = DEFAULT_PATH,
    ):
        """
        Initialize the server.

        Args:
            config_path: Path to configuration file.
            transport: ``"stdio"`` or ``"http"``.
            host: Bind host for the HTTP transport.
            port: Bind port for the HTTP transport.
            path: Mount path for the HTTP transport (trailing slash is added by
                Starlette's ``Mount``; clients must use the trailing slash).
        """
        # Route the root logger to stderr before anything logs, so stdout stays
        # clean for the MCP stdio protocol.
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s - %(message)s",
            stream=sys.stderr,
        )

        self.transport = transport
        self.host = host
        self.port = port
        self.path = path

        # Load and validate configuration.
        self.config = load_config(config_path)
        validate_config(self.config)

        # Full logging (replaces the basic config above).
        self.logger = setup_logging(self.config.logging)

        # LDAP manager. ``active_directory.organizational_units`` is wired in by
        # the config loader so tools can resolve default OUs.
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance,
        )

        # Test connection on startup (non-fatal).
        self._test_initial_connection()

        # Instantiate the tool bundle from the single registry.
        self.tools = Tools.from_ldap(self.ldap_manager)

        # Back-compat attribute aliases (used by tests and external callers).
        self.user_tools = self.tools.user
        self.group_tools = self.tools.group
        self.computer_tools = self.tools.computer
        self.ou_tools = self.tools.ou
        self.security_tools = self.tools.security
        self.gpo_tools = self.tools.gpo

        # Build the low-level MCP server (list_tools / call_tool from TOOLS).
        self._tools: List[types.Tool] = []
        self._tool_handlers: Dict[str, Any] = {}
        self.mcp = self._build_server()

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #
    def _test_initial_connection(self) -> None:
        """Test initial LDAP connection (logs only; never fatal)."""
        try:
            self.logger.info("Testing initial LDAP connection...")
            connection_info = self.ldap_manager.test_connection()
            if connection_info.get("connected"):
                self.logger.info(
                    f"Successfully connected to {connection_info.get('server')}:{connection_info.get('port')}"
                )
                if connection_info.get("search_test"):
                    self.logger.info("LDAP search test passed")
                else:
                    self.logger.warning("LDAP search test failed")
            else:
                self.logger.error(f"Initial connection failed: {connection_info.get('error')}")
        except Exception as e:
            self.logger.error(f"Connection test error: {e}")

    def _build_server(self) -> Server:
        """Build the low-level MCP server from the registry."""
        server = Server(SERVER_NAME)

        # Materialise the registry once. These two structures are the single
        # source the server exposes; the drift-guard test asserts they match
        # ``registry.TOOLS`` name-for-name.
        self._tools = [
            types.Tool(name=spec.name, description=spec.description, inputSchema=spec.input_schema)
            for spec in TOOLS
        ]
        self._tool_handlers = {spec.name: spec.handler for spec in TOOLS}

        @server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return self._tools

        @server.call_tool()
        async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            handler = self._tool_handlers.get(name)
            if handler is None:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}, indent=2))]
            try:
                result = handler(self.tools, arguments or {})
                # Tool classes already return a list of MCP content objects;
                # system handlers return a plain dict/list to serialise.
                if isinstance(result, list):
                    return result
                return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
            except Exception as e:
                self.logger.error(f"Tool {name} error: {e}")
                return [types.TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]

        return server

    # ------------------------------------------------------------------ #
    # Transports
    # ------------------------------------------------------------------ #
    async def _run_stdio(self) -> None:
        """Serve over the stdio transport."""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.mcp.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name=SERVER_NAME,
                    server_version=SERVER_VERSION,
                    capabilities=self.mcp.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    def build_http_app(self):
        """Build the Starlette app that serves the low-level server over
        streamable-HTTP.

        This mirrors what the MCP SDK's FastMCP ``streamable_http_app`` builds:
        a :class:`StreamableHTTPSessionManager` wrapping this server, mounted at
        ``self.path``. Because it is a Starlette ``Mount``, a request to the bare
        path 307-redirects to the trailing-slash form -- identical to the
        previous FastMCP-based endpoint.
        """
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        from starlette.applications import Starlette
        from starlette.routing import Mount
        from starlette.types import Receive, Scope, Send

        session_manager = StreamableHTTPSessionManager(
            app=self.mcp,
            event_store=None,
            json_response=False,
            stateless=False,
        )

        async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
            await session_manager.handle_request(scope, receive, send)

        return Starlette(
            debug=False,
            routes=[Mount(self.path, app=handle_streamable_http)],
            lifespan=lambda app: session_manager.run(),
        )

    def _run_http(self) -> None:
        """Serve over the streamable-HTTP transport via uvicorn."""
        import uvicorn

        app = self.build_http_app()
        uvicorn.run(
            app,
            host=self.host,
            port=self.port,
            log_level=self.config.logging.level.lower(),
        )

    # ------------------------------------------------------------------ #
    # Entry
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Start serving on the configured transport (blocks)."""
        try:
            self.logger.info(f"Starting {SERVER_NAME} server (transport={self.transport})...")
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")
            self.logger.info(f"Base DN: {self.config.active_directory.base_dn}")

            if self.transport == "http":
                self.logger.info(f"HTTP endpoint: http://{self.host}:{self.port}{self.path}/")
                # uvicorn installs its own signal handlers.
                self._run_http()
            else:
                self._install_stdio_signal_handlers()
                asyncio.run(self._run_stdio())
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            self.ldap_manager.disconnect()
            sys.exit(1)

    def _install_stdio_signal_handlers(self) -> None:
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            self.ldap_manager.disconnect()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


def main() -> None:
    """Main entry point for the console script (``aditor.server:main``)."""
    parser = argparse.ArgumentParser(description="Active Directory MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="http",
        help="Transport to serve on (default: http)",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"HTTP bind host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"HTTP bind port (default: {DEFAULT_PORT})")
    parser.add_argument("--path", default=DEFAULT_PATH, help=f"HTTP mount path (default: {DEFAULT_PATH})")
    parser.add_argument("--config", default=None, help="Path to configuration file (else $AD_MCP_CONFIG)")
    args = parser.parse_args()

    config_path = args.config or os.getenv("AD_MCP_CONFIG")
    if not config_path:
        print("Configuration required: pass --config or set AD_MCP_CONFIG")
        sys.exit(1)

    try:
        server = ActiveDirectoryMCPServer(
            config_path=config_path,
            transport=args.transport,
            host=args.host,
            port=args.port,
            path=args.path,
        )
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
