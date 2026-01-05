"""
Ghidra MCP Bridge server for Ghidrathon.

Starts a small HTTP JSON API (http.server) inside Ghidra so an external
agent can query decompilation data and perform scripted edits.
Handlers are split into mcp_apis/* for clarity.

Entry point is main(script_globals); no side effects at import time.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

try:
    import ghidra_builtins as _ghidra_builtins  # type: ignore
except Exception:  # noqa: BLE001 - optional outside Ghidra
    _ghidra_builtins = None

import mcp_apis.common as common

HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8803"))

_server_instance: Optional["ThreadingHTTPServer"] = None
_server_thread: Optional[threading.Thread] = None
_handlers_loaded = False

# Cache Ghidra context at startup since it's not available during HTTP requests
_cached_program = None
_cached_address = None


def _cache_ghidra_context():
    """Cache Ghidra context at startup when functions are available."""
    global _cached_program, _cached_address

    try:
        _cached_program = currentProgram()
        print(f"[Ghidra-MCP-Bridge] Cached program: {_cached_program.getName() if _cached_program else None}")
    except:
        _cached_program = None
        print("[Ghidra-MCP-Bridge] Failed to cache currentProgram")

    try:
        _cached_address = currentAddress()
        print(f"[Ghidra-MCP-Bridge] Cached address: {_cached_address}")
    except:
        _cached_address = None
        print("[Ghidra-MCP-Bridge] Failed to cache currentAddress")




class GhidraRequestHandler(BaseHTTPRequestHandler):
    server_version = "GhidraMCP/0.2"

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
        except Exception as exc:  # noqa: BLE001 - propagate parsing issues
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - required signature
        # Keep console noise minimal inside Ghidra.
        return

    def do_GET(self):
        try:
            if self.path == "/api/status":
                # Direct implementation using cached values
                if _cached_program:
                    return self._send_json({
                        "status": "ok",
                        "program": _cached_program.getName(),
                        "currentAddress": str(_cached_address) if _cached_address else None,
                    })
                else:
                    return self._send_json({"error": "No program cached"}, status=500)
            if self.path.startswith("/api/function/"):
                addr_token = self.path.split("/api/function/", 1)[1]
                return self._send_json(common.get_function_payload(addr_token))
            self._send_json({"error": "Not Found"}, status=404)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc)}, status=500)

    def do_POST(self):
        try:
            if self.path == "/api/comment":
                return self._send_json(common.add_comment(self._read_json()))
            if self.path == "/api/rename/variable":
                return self._send_json(common.rename_variable(self._read_json()))
            if self.path == "/api/rename/function":
                return self._send_json(common.rename_function(self._read_json()))
            if self.path == "/api/search":
                return self._send_json(common.run_search(self._read_json()))
            self._send_json({"error": "Not Found"}, status=404)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc)}, status=500)


class _ThreadedServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _load_handlers_once():
    """Lazy import of API handlers after context is set."""
    global _handlers_loaded
    if _handlers_loaded:
        return
    from mcp_apis.comment_api import add_comment  # noqa: F401
    from mcp_apis.function_api import get_function_payload  # noqa: F401
    from mcp_apis.rename_fn_api import rename_function  # noqa: F401
    from mcp_apis.rename_var_api import rename_variable  # noqa: F401
    from mcp_apis.search_api import run_search  # noqa: F401
    from mcp_apis.status_api import handle_status  # noqa: F401

    # Re-export on common so handler can access through common.*
    common.add_comment = add_comment
    common.get_function_payload = get_function_payload
    common.rename_function = rename_function
    common.rename_variable = rename_variable
    common.run_search = run_search
    common.handle_status = handle_status
    _handlers_loaded = True


def start_server(host: str = HOST, port: int = PORT):
    """Start the HTTP server as a daemon thread to keep GUI responsive."""
    global _server_instance, _server_thread
    if _server_instance:
        return _server_instance
    _load_handlers_once()
    last_err = None
    chosen_port = port
    for _ in range(100):
        try:
            _server_instance = _ThreadedServer((host, chosen_port), GhidraRequestHandler)
            break
        except OSError as err:
            last_err = err
            chosen_port += 1
            continue
    else:
        raise RuntimeError(f"Failed to bind after 100 attempts starting from {port}: {last_err}")

    _server_thread = threading.Thread(
        target=_server_instance.serve_forever,
        name="GhidraMCPServer",
        daemon=True,
    )
    _server_thread.start()
    print(f"[Ghidra-MCP-Bridge] Listening on http://{host}:{chosen_port}")
    return _server_instance


def stop_server():
    global _server_instance, _server_thread
    if _server_instance:
        _server_instance.shutdown()
        _server_instance.server_close()
        _server_instance = None
        _server_thread = None


def main(script_globals: Dict[str, Any] | None = None, host: str = HOST, port: int = PORT):
    """
    Entry point for Script Manager or headless use.
    Pass in globals() so we can capture currentProgram/currentAddress/state explicitly.
    """
    if script_globals is None:
        script_globals = {}
    try:
        if hasattr(common, "set_context"):
            common.set_context(script_globals)
        _cache_ghidra_context()
        common._cached_program_ref = _cached_program
        common._cached_address_ref = _cached_address
        srv = start_server(host=host, port=port)
        print(f"[Ghidra-MCP-Bridge] Server started on {host}:{port}")
        return srv
    except Exception as exc:  # noqa: BLE001
        print(f"[Ghidra-MCP-Bridge] Failed to start server: {exc}")
        raise


# Auto-start on import for Script Manager convenience.
try:
    if hasattr(common, "set_context"):
        common.set_context(globals())
    common.debug_log_context("server-init-import")

    print("[Ghidra-MCP-Bridge] Caching Ghidra context for HTTP requests...")
    _cache_ghidra_context()

    # Share cached context with common module
    try:
        common._cached_program_ref = _cached_program
        common._cached_address_ref = _cached_address
    except Exception as e:
        print(f"[Ghidra-MCP-Bridge] Failed to set cached variables: {e}")

    start_server()
    print(f"[Ghidra-MCP-Bridge] Server auto-started on http://{HOST}:{PORT}")
except Exception as _auto_exc:  # noqa: BLE001
    print(f"[Ghidra-MCP-Bridge] Auto-start failed: {_auto_exc}")
