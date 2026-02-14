"""
PyGhidra-based MCP Bridge for AI Repository Integration.

This script uses PyGhidra (Ghidra 12.0+) to provide an external AI agent
with programmatic access to Ghidra's analysis capabilities. It exposes a lightweight
HTTP JSON API that allows AI systems to query decompilation data, perform reverse
engineering tasks, and execute scripted operations within Ghidra.

Key differences from Ghidrathon version:
- Uses PyGhidra instead of Ghidrathon (official support)
- Starts JVM from Python (not vice versa)
- No dependency on analyzeHeadless -postScript
- Better support for multi-threading

Entry point: main()
"""

import importlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.request import urlopen
from urllib.parse import urlparse, parse_qs

# Add /app to sys.path for module imports
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Import PyGhidra before any Ghidra imports
import pyghidra

from utils.logging_config import get_log_file_path, log_debug, log_info

HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8803"))
MCP_PORT = int(os.environ.get("GHIDRA_MCP_SSE_PORT", "8804"))

_server_instance: Optional["ThreadingHTTPServer"] = None
_server_thread: Optional[threading.Thread] = None

# Cache Ghidra context (PyGhidra style)
_ghidra_project = None
_current_program = None
_mock_state = None


class MockGhidraState:
    """
    Mock GhidraState object for API compatibility.

    In PyGhidra mode, we don't have the same state object as Ghidrathon,
    so we create a lightweight mock that provides the same interface.
    """
    def __init__(self, project, program):
        self._project = project
        self._program = program

    def getCurrentProgram(self):
        """Get current program (compatible with Ghidrathon API)."""
        return self._program

    def getProject(self):
        """Get Ghidra project."""
        return self._project

    def getCurrentAddress(self):
        """Get current address (returns None in headless mode)."""
        return None

    def getCurrentSelection(self):
        """Get current selection (returns None in headless mode)."""
        return None

    def getCurrentHighlight(self):
        """Get current highlight (returns None in headless mode)."""
        return None

    def getTool(self):
        """Get current tool (returns None in headless mode)."""
        return None


def _init_ghidra_project():
    """
    Initialize Ghidra using PyGhidra and load the project.

    This replaces the analyzeHeadless approach.
    """
    global _ghidra_project, _current_program, _mock_state

    print("[PyGhidra-MCP-Bridge] Initializing PyGhidra...")

    # Start Ghidra (this initializes the JVM and Ghidra Application)
    pyghidra.start(verbose=True)
    print("[PyGhidra-MCP-Bridge] ✓ PyGhidra started successfully")

    # Import Ghidra APIs (must be after pyghidra.start())
    from ghidra.base.project import GhidraProject

    # Get project configuration from environment
    project_mode = os.environ.get("PROJECT_MODE", "local")
    project_path = os.environ.get("PROJECT_PATH", "/ghidra-projects")
    project_name = os.environ.get("PROJECT_NAME", "default")

    print(f"[PyGhidra-MCP-Bridge] Loading project: {project_name}")
    print(f"[PyGhidra-MCP-Bridge] Mode: {project_mode}")
    print(f"[PyGhidra-MCP-Bridge] Path: {project_path}")

    if project_mode == "local":
        # Open or create local project
        _ghidra_project = GhidraProject.openProject(
            project_path,
            project_name,
            restore=True  # Create if doesn't exist
        )
        print(f"[PyGhidra-MCP-Bridge] ✓ Project opened: {project_name}")

        # Try to open the first program in the project
        # In headless mode, we need to specify which binary to analyze
        root_folder = _ghidra_project.getProjectData().getRootFolder()
        program_files = list(root_folder.getFiles())

        if program_files:
            # Open first program
            program_file = program_files[0]
            program_name = program_file.getName()
            _current_program = _ghidra_project.openProgram("/", program_name, False)
            print(f"[PyGhidra-MCP-Bridge] ✓ Program loaded: {program_name}")
        else:
            print("[PyGhidra-MCP-Bridge] ⚠ No programs found in project")
            print("[PyGhidra-MCP-Bridge] ⚠ You can import binaries via API or manually")
            _current_program = None

    elif project_mode == "server":
        # Ghidra Server mode with SSH key authentication
        server_host = os.environ.get("GHIDRA_SERVER_HOST", "localhost")
        server_port = int(os.environ.get("GHIDRA_SERVER_PORT", "13100"))
        server_user = os.environ.get("GHIDRA_SERVER_USER", "")
        server_keystore = os.environ.get("GHIDRA_SERVER_KEYSTORE", "")  # Path to SSH private key

        print(f"[PyGhidra-MCP-Bridge] Connecting to Ghidra Server: {server_host}:{server_port}")
        print(f"[PyGhidra-MCP-Bridge] User: {server_user if server_user else '(anonymous)'}")
        print(f"[PyGhidra-MCP-Bridge] Authentication: {'SSH key (' + server_keystore + ')' if server_keystore else 'Anonymous'}")

        try:
            from ghidra.framework.client import ClientUtil, HeadlessClientAuthenticator
            from java.lang import System
            from javax.net.ssl import HttpsURLConnection, SSLContext
            from java.security import SecureRandom
            import jpype

            # Disable SSL hostname verification for Docker networking (host.docker.internal)
            # This is needed because the server's SSL certificate contains "localhost"
            # but Docker connects via "host.docker.internal"

            # Create a trust manager that accepts all certificates using JProxy
            @jpype.JImplements("javax.net.ssl.X509TrustManager")
            class AllTrustManager:
                @jpype.JOverride
                def checkClientTrusted(self, chain, authType):
                    pass
                @jpype.JOverride
                def checkServerTrusted(self, chain, authType):
                    pass
                @jpype.JOverride
                def getAcceptedIssuers(self):
                    return None

            # Create a hostname verifier that accepts all hostnames using JProxy
            @jpype.JImplements("javax.net.ssl.HostnameVerifier")
            class AllHostnameVerifier:
                @jpype.JOverride
                def verify(self, hostname, session):
                    return True

            # Install the permissive trust manager and hostname verifier
            sc = SSLContext.getInstance("TLS")
            trust_managers = jpype.JArray(jpype.JClass("javax.net.ssl.TrustManager"))([AllTrustManager()])
            sc.init(None, trust_managers, SecureRandom())

            # Set SSL factory for HTTPS URLs
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
            HttpsURLConnection.setDefaultHostnameVerifier(AllHostnameVerifier())

            # CRITICAL: Set default SSLContext globally for all SSL connections (including SSLSocket)
            # This is needed for Ghidra's ClientUtil.getRepositoryServer() which uses SSLSocket
            SSLContext.setDefault(sc)

            # Also disable endpoint identification for SSL sockets
            from javax.net.ssl import SSLParameters
            System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3")
            System.setProperty("https.protocols", "TLSv1.2,TLSv1.3")

            print(f"[PyGhidra-MCP-Bridge] ✓ SSL hostname verification disabled globally for Docker compatibility")

            # Install headless authenticator with SSH key authentication
            # IMPORTANT: No password prompts - only SSH key authentication
            if server_user and server_keystore:
                # SSH key authentication mode
                print(f"[PyGhidra-MCP-Bridge] Installing headless authenticator with SSH key")
                print(f"[PyGhidra-MCP-Bridge] Keystore: {server_keystore}")

                # Verify keystore file exists
                if not os.path.exists(server_keystore):
                    raise FileNotFoundError(f"SSH keystore not found: {server_keystore}")

                # Install authenticator with keystore, NO password prompts
                HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
                    server_user,
                    server_keystore,
                    False  # CRITICAL: Never prompt for password
                )
                print(f"[PyGhidra-MCP-Bridge] ✓ SSH key authenticator installed")

            elif server_user and not server_keystore:
                # User specified but no keystore - this is an error
                raise ValueError(
                    "GHIDRA_SERVER_USER specified but GHIDRA_SERVER_KEYSTORE not set. "
                    "SSH key authentication required. Password authentication has been removed."
                )
            else:
                # Anonymous access mode
                print(f"[PyGhidra-MCP-Bridge] Installing headless authenticator for anonymous access")
                HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
                    None, None, False  # No password prompt for anonymous mode
                )

            # Connect to Ghidra Server (already authenticated via HeadlessClientAuthenticator)
            server_handle = ClientUtil.getRepositoryServer(server_host, server_port, True)

            # Check connection status
            if not server_handle.isConnected():
                raise Exception(f"Failed to establish server connection - isConnected() returned False")

            print(f"[PyGhidra-MCP-Bridge] ✓ Connected to server")
            print(f"[PyGhidra-MCP-Bridge] Server user: {server_handle.getUser()}")

            # List available repositories
            repos = server_handle.getRepositoryNames()
            print(f"[PyGhidra-MCP-Bridge] Available repositories: {list(repos) if repos else '(none)'}")

            # Open repository (default to root "/")
            repo_name = os.environ.get("GHIDRA_SERVER_REPO", "")
            if not repo_name and repos and len(repos) > 0:
                repo_name = repos[0]
                print(f"[PyGhidra-MCP-Bridge] Using first repository: {repo_name}")

            if repo_name:
                repo_handle = server_handle.getRepository(repo_name)
                print(f"[PyGhidra-MCP-Bridge] ✓ Opened repository: {repo_name}")

                # List projects in repository
                items = repo_handle.getItemList("/")
                print(f"[PyGhidra-MCP-Bridge] Repository items: {len(items) if items else 0}")

                # Try to open the specified project
                if project_name and project_name != "default":
                    try:
                        # Open project from server
                        project_item = repo_handle.getItem("/", project_name)
                        if project_item:
                            # TODO: Open program from server project
                            print(f"[PyGhidra-MCP-Bridge] ✓ Found project: {project_name}")
                            _current_program = None
                            print("[PyGhidra-MCP-Bridge] ⚠ Server mode: Program opening not yet fully implemented")
                        else:
                            print(f"[PyGhidra-MCP-Bridge] ⚠ Project not found: {project_name}")
                            _current_program = None
                    except Exception as e:
                        print(f"[PyGhidra-MCP-Bridge] ⚠ Error opening project: {e}")
                        _current_program = None
                else:
                    print("[PyGhidra-MCP-Bridge] ⚠ No project specified (PROJECT_NAME)")
                    _current_program = None

                # Create a minimal project handle for API compatibility
                # Note: This is a simplified implementation
                _ghidra_project = None  # Server mode doesn't use local GhidraProject
            else:
                print("[PyGhidra-MCP-Bridge] ⚠ No repositories found on server")
                _current_program = None
                _ghidra_project = None

        except Exception as e:
            print(f"[PyGhidra-MCP-Bridge] ✗ Failed to connect to server: {e}")
            import traceback
            traceback.print_exc()
            raise

    else:
        raise ValueError(f"Invalid PROJECT_MODE: {project_mode} (must be 'local' or 'server')")

    # Create mock state object for API compatibility
    _mock_state = MockGhidraState(_ghidra_project, _current_program)

    return _mock_state


def _discover_and_load_api_modules():
    """
    自动发现并加载 api/ 和 api_v*/ 目录下所有模块。
    模块使用 @route 装饰器自动注册路由。
    """
    # Ensure script directory is in sys.path (PyGhidra may reset it)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # 先 reload api 包本身，确保使用最新版本
    import api
    importlib.reload(api)
    from api import clear_routes, get_route_list

    # 清空现有路由
    clear_routes()

    reloaded = []
    errors = []

    # 收集所有 API 目录: api/ + api_v*/
    api_dirs = []

    # 主目录 api/
    main_api_dir = os.path.join(script_dir, "api")
    if os.path.isdir(main_api_dir):
        api_dirs.append(("api", main_api_dir))

    # 版本化目录 api_v1/, api_v2/, ...
    for entry in sorted(os.listdir(script_dir)):
        if entry.startswith("api_v") and os.path.isdir(os.path.join(script_dir, entry)):
            api_dirs.append((entry, os.path.join(script_dir, entry)))

    # 加载每个目录下的模块
    for package_name, api_dir in api_dirs:
        for filename in sorted(os.listdir(api_dir)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue

            module_name = f"{package_name}.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                importlib.reload(module)
                reloaded.append(module_name)
            except Exception as e:
                errors.append(f"{module_name}: {e}")

    return {
        "success": len(errors) == 0,
        "reloaded": reloaded,
        "routes": get_route_list(),
        "errors": errors if errors else None
    }


def _cache_ghidra_context():
    """Initialize PyGhidra and load API modules."""
    global _mock_state

    # Initialize PyGhidra and load project
    _mock_state = _init_ghidra_project()

    # Load API modules
    result = _discover_and_load_api_modules()
    if not result.get("success"):
        print(f"[PyGhidra-MCP-Bridge] Warning: Failed to load some API modules: {result.get('errors')}")

    return result.get("routes", [])


class GhidraRequestHandler(BaseHTTPRequestHandler):
    server_version = "PyGhidraMCP/1.0"

    def _send_json(self, payload: Dict[str, Any], status: int = 200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length) if length else b""
        try:
            return json.loads(data.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def log_message(self, format: str, *args: Any) -> None:
        # Log HTTP requests to file
        try:
            log_debug("HTTP %s", format % args)
        except Exception:
            pass

    def do_GET(self):
        """Handle GET requests."""
        from api import dispatch_route

        # Special system routes
        if self.path == "/_reload":
            result = _discover_and_load_api_modules()
            self._send_json(result)
            return

        if self.path == "/_shutdown":
            self._send_json({"success": True, "message": "Shutdown requested"})
            # Shutdown in background thread
            def shutdown():
                time.sleep(0.5)
                if _server_instance:
                    _server_instance.shutdown()
            threading.Thread(target=shutdown, daemon=True).start()
            return

        # Dispatch to API routes
        try:
            # Parse URL to separate path and query string
            parsed = urlparse(self.path)
            path = parsed.path
            query_params = parse_qs(parsed.query)
            # Convert query params to single values (instead of lists)
            params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

            # Pass mock state to route handlers
            result = dispatch_route(path, _mock_state, params)
            if result is not None:
                self._send_json(result)
            else:
                self._send_json({"error": f"Unknown route: {path}"}, 404)
        except Exception as exc:
            log_debug(f"Error handling GET {self.path}: {exc}")
            self._send_json({"error": str(exc)}, 500)

    def do_POST(self):
        """Handle POST requests."""
        from api import dispatch_route

        try:
            # Read JSON body
            body = self._read_json()

            # Dispatch to API routes (pass body as query params)
            result = dispatch_route(self.path, _mock_state, body)
            if result is not None:
                self._send_json(result)
            else:
                self._send_json({"error": f"Unknown route: {self.path}"}, 404)
        except Exception as exc:
            log_debug(f"Error handling POST {self.path}: {exc}")
            self._send_json({"error": str(exc)}, 500)


def start_server(host: str = HOST, port: int = PORT):
    """Start the HTTP API server."""
    global _server_instance, _server_thread

    # Try to find available port
    for attempt in range(10):
        try:
            server = ThreadingHTTPServer((host, port), GhidraRequestHandler)
            _server_instance = server

            # Start server in daemon thread
            def run():
                server.serve_forever()

            _server_thread = threading.Thread(target=run, daemon=True)
            _server_thread.start()

            return server, port
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"[PyGhidra-MCP-Bridge] Port {port} in use, trying {port + 1}...")
                port += 1
            else:
                raise

    raise RuntimeError(f"Could not find available port after 10 attempts")


def _start_mcp_server(host: str, port: int, http_port: int):
    """Start MCP SSE Proxy as subprocess."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mcp_script = os.path.join(script_dir, "scripts", "mcp_sse_proxy.py")

    if not os.path.exists(mcp_script):
        print(f"[PyGhidra-MCP-Bridge] Warning: MCP SSE script not found: {mcp_script}")
        return None

    # Start MCP server as subprocess
    for attempt in range(10):
        try:
            cmd = [
                sys.executable,
                mcp_script,
                "--host", host,
                "--port", str(port),
                "--http-port", str(http_port)
            ]

            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )

            # Wait a bit to ensure it started
            time.sleep(1)
            return port
        except Exception as e:
            if attempt < 9:
                port += 1
            else:
                print(f"[PyGhidra-MCP-Bridge] Warning: Failed to start MCP server: {e}")
                return None

    return None


def _print_startup_banner(host: str, port: int, mcp_port: Optional[int], routes: list):
    """Print startup information."""
    print("\n")
    print("=" * 60)
    print("  Ghidra MCP Bridge - PyGhidra Edition")
    print("=" * 60)

    # Server URLs
    http_url = f"http://{host}:{port}"
    print(f"HTTP API:   {http_url}")
    if mcp_port:
        print(f"MCP SSE:    http://{host}:{mcp_port}/sse")

    # Log file
    print(f"Log file:   {get_log_file_path()}")

    # Program info
    if _current_program:
        name = _current_program.getName()
        lang = _current_program.getLanguage()
        arch = lang.getProcessor().toString()
        bits = lang.getDefaultSpace().getSize() * 8
        func_count = _current_program.getFunctionManager().getFunctionCount()
        print(f"Program:    {name} ({arch}/{bits}-bit, {func_count} functions)")
    else:
        print(f"Program:    (No program loaded)")

    # API routes
    print(f"API Routes: {len(routes)} endpoints loaded")

    print("=" * 60)
    print(f"Try: {http_url}/api/basic_info")
    print("=" * 60)
    print("\n")


def main():
    """Main entry point for PyGhidra mode."""
    try:
        # Initialize Ghidra and load API modules
        print("[PyGhidra-MCP-Bridge] Starting...")
        routes = _cache_ghidra_context()

        # Start HTTP API server
        srv, actual_port = start_server(host=HOST, port=PORT)

        # Start MCP SSE Proxy
        actual_mcp_port = _start_mcp_server(host=HOST, port=MCP_PORT, http_port=actual_port)

        # Print startup banner
        _print_startup_banner(HOST, actual_port, actual_mcp_port, routes)

        # Keep main thread alive
        print("[PyGhidra-MCP-Bridge] Server running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[PyGhidra-MCP-Bridge] Shutting down...")
            if _server_instance:
                _server_instance.shutdown()

        return srv
    except Exception as exc:
        print(f"[PyGhidra-MCP-Bridge] Failed to start server: {exc}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
