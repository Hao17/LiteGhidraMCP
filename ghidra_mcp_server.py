"""
Ghidrathon-based MCP Bridge for AI Repository Integration.

This script runs inside Ghidra via Ghidrathon to provide an external AI agent
with programmatic access to Ghidra's analysis capabilities. It exposes a lightweight
HTTP JSON API that allows AI systems to query decompilation data, perform reverse
engineering tasks, and execute scripted operations within Ghidra.

Designed to serve as a bridge between AI repositories and Ghidra, enabling
automated binary analysis, symbol management, and code understanding workflows.
API handlers are modularized in mcp_apis/* for maintainability.

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
_cached_location = None
_cached_selection = None
_cached_highlight = None
_cached_monitor = None
_cached_state = None
_cached_script = None


def _run_test_script():
    """使用script().runScript()执行test_script.py"""
    try:
        _cached_script.runScript("test_script.py")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _cache_ghidra_context():
    """Cache Ghidra context at startup when functions are available."""
    global _cached_program, _cached_address, _cached_location, _cached_selection, _cached_highlight, _cached_monitor, _cached_state, _cached_script

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

    try:
        _cached_location = currentLocation()
        print(f"[Ghidra-MCP-Bridge] Cached location: {_cached_location}")
    except:
        _cached_location = None
        print("[Ghidra-MCP-Bridge] Failed to cache currentLocation")

    try:
        _cached_selection = currentSelection()
        print(f"[Ghidra-MCP-Bridge] Cached selection: {_cached_selection}")
    except:
        _cached_selection = None
        print("[Ghidra-MCP-Bridge] Failed to cache currentSelection")

    try:
        _cached_highlight = currentHighlight()
        print(f"[Ghidra-MCP-Bridge] Cached highlight: {_cached_highlight}")
    except:
        _cached_highlight = None
        print("[Ghidra-MCP-Bridge] Failed to cache currentHighlight")

    try:
        _cached_monitor = monitor()
        print(f"[Ghidra-MCP-Bridge] Cached monitor: {_cached_monitor}")
    except:
        _cached_monitor = None
        print("[Ghidra-MCP-Bridge] Failed to cache monitor")

    try:
        _cached_state = state()
        print(f"[Ghidra-MCP-Bridge] Cached state: {_cached_state}")
    except:
        _cached_state = None
        print("[Ghidra-MCP-Bridge] Failed to cache state")

    try:
        _cached_script = script()
        print(f"[Ghidra-MCP-Bridge] Cached script: {_cached_script}")
    except:
        _cached_script = None
        print("[Ghidra-MCP-Bridge] Failed to cache script")




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
                return self._send_json(common.handle_status())
            if self.path == "/api/test_context" or self.path == "/api/test-context":
                if hasattr(common, 'test_context'):
                    return self._send_json(common.test_context())
                else:
                    return self._send_json({
                        "error": "test_context function not found in common module - this should be injected at startup",
                        "available": [x for x in dir(common) if not x.startswith('_')],
                        "note": "If you see this message, there was a problem with function injection during server startup"
                    })
            if self.path == "/api/debug/import_sources" or self.path == "/api/debug/import-sources":
                if hasattr(common, 'get_import_debug_info'):
                    return self._send_json(common.get_import_debug_info())
                else:
                    # Try to import directly from the module
                    try:
                        from mcp_apis.common import get_import_debug_info
                        return self._send_json(get_import_debug_info())
                    except ImportError as e:
                        return self._send_json({
                            "error": "get_import_debug_info function not found",
                            "details": str(e),
                            "available_functions": [x for x in dir(common) if not x.startswith('_')],
                            "has_function_in_module": hasattr(__import__('mcp_apis.common', fromlist=['get_import_debug_info']), 'get_import_debug_info')
                        })
            if self.path == "/api/test/script_execution" or self.path == "/api/test/script-execution":
                if hasattr(common, 'test_script_based_access'):
                    return self._send_json(common.test_script_based_access())
                else:
                    return self._send_json({
                        "error": "test_script_based_access function not found in common module",
                        "note": "This function tests script.runScript() based API access"
                    })
            if self.path == "/api/execute/test_script" or self.path == "/api/execute/test-script":
                if hasattr(common, 'execute_script_with_context'):
                    result = common.execute_script_with_context("test_script.py")
                    return self._send_json(result)
                else:
                    return self._send_json({
                        "error": "execute_script_with_context function not found in common module"
                    })
            # 新路由：使用exec()方式执行测试脚本，直接在注入了Ghidra上下文的环境中运行
            if self.path == "/api/run/test_script" or self.path == "/api/run/test-script":
                return self._send_json(_run_test_script())
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

    # Manually inject test_context and debug functions if they're missing (Ghidrathon cache workaround)
    if not hasattr(common, 'test_context'):
        print("[Ghidra-MCP-Bridge] Manually injecting test_context function due to Ghidrathon cache issue")
        try:
            # Create a temporary test_context function
            def temp_test_context():
                import sys
                from typing import Dict, Any

                result: Dict[str, Any] = {
                    "timestamp": str(__import__("time").time()),
                    "test_results": {"manual_injection": True},
                    "errors": [],
                    "import_debug": {
                        "flat_api_available": getattr(common, '_FLAT_API_AVAILABLE', False),
                        "cache_issue": "Ghidrathon cache prevented normal function loading",
                        "manual_injection_used": True
                    },
                    "summary": "manual_injection_mode"
                }

                # Test basic functions that should be available
                try:
                    prog = common.get_program()
                    result["test_results"]["get_program_success"] = prog is not None
                    if prog:
                        result["test_results"]["program_name"] = prog.getName()
                except Exception as e:
                    result["errors"].append(f"get_program() failed: {str(e)}")
                    result["test_results"]["get_program_success"] = False

                try:
                    addr = common.get_current_address()
                    result["test_results"]["get_current_address_success"] = addr is not None
                    if addr:
                        result["test_results"]["current_address"] = str(addr)
                except Exception as e:
                    result["errors"].append(f"get_current_address() failed: {str(e)}")
                    result["test_results"]["get_current_address_success"] = False

                # Test the three new direct access methods we added
                try:
                    if hasattr(common, 'get_program_direct'):
                        prog_direct = common.get_program_direct()
                        result["test_results"]["get_program_direct_success"] = prog_direct is not None
                        if prog_direct:
                            result["test_results"]["get_program_direct_name"] = prog_direct.getName()
                    else:
                        result["test_results"]["get_program_direct_success"] = False
                        result["errors"].append("get_program_direct function not available due to cache issue")
                except Exception as e:
                    result["test_results"]["get_program_direct_success"] = False
                    result["errors"].append(f"get_program_direct() failed: {str(e)}")

                try:
                    if hasattr(common, 'get_program_simple'):
                        prog_simple = common.get_program_simple()
                        result["test_results"]["get_program_simple_success"] = prog_simple is not None
                        if prog_simple:
                            result["test_results"]["get_program_simple_name"] = prog_simple.getName()
                    else:
                        result["test_results"]["get_program_simple_success"] = False
                        result["errors"].append("get_program_simple function not available due to cache issue")
                except Exception as e:
                    result["test_results"]["get_program_simple_success"] = False
                    result["errors"].append(f"get_program_simple() failed: {str(e)}")

                # Check if any Ghidra Flat API functions were successfully injected to common module
                flat_api_functions = ['currentProgram', 'currentAddress', 'currentLocation', 'currentSelection', 'currentHighlight', 'monitor', 'state', 'script']
                injected_functions = {}
                for func_name in flat_api_functions:
                    injected_functions[func_name] = hasattr(common, func_name)

                result["test_results"]["injected_flat_api_functions"] = injected_functions
                result["test_results"]["total_injected_flat_api"] = sum(injected_functions.values())

                # Test if we can call injected currentProgram directly
                if hasattr(common, 'currentProgram'):
                    try:
                        prog_injected = common.currentProgram()
                        result["test_results"]["direct_currentProgram_call_success"] = prog_injected is not None
                        if prog_injected:
                            result["test_results"]["direct_currentProgram_name"] = prog_injected.getName()
                    except Exception as e:
                        result["test_results"]["direct_currentProgram_call_success"] = False
                        result["errors"].append(f"Direct currentProgram() call failed: {str(e)}")
                else:
                    result["test_results"]["direct_currentProgram_call_success"] = False
                    result["errors"].append("currentProgram not injected to common module")

                # Test script-based access if available
                try:
                    if hasattr(common, 'test_script_based_access'):
                        script_test_result = common.test_script_based_access()
                        result["test_results"]["script_based_access"] = script_test_result
                    else:
                        result["test_results"]["script_based_access"] = {
                            "error": "test_script_based_access function not available due to cache issue"
                        }
                except Exception as e:
                    result["test_results"]["script_based_access"] = {
                        "error": f"test_script_based_access() failed: {str(e)}"
                    }

                # Check available functions
                result["available_functions"] = [x for x in dir(common) if not x.startswith('_') and callable(getattr(common, x, None))]

                return result

            common.test_context = temp_test_context
            print("[Ghidra-MCP-Bridge] Successfully injected temporary test_context function")

        except Exception as e:
            print(f"[Ghidra-MCP-Bridge] Failed to inject temporary test_context: {e}")
    else:
        print("[Ghidra-MCP-Bridge] test_context function found normally")

    # Check debug function availability
    if not hasattr(common, 'get_import_debug_info'):
        print("[Ghidra-MCP-Bridge] Warning: get_import_debug_info not found in common module")

        # Create a simplified debug info function
        def temp_debug_info():
            return {
                "error": "get_import_debug_info not loaded due to Ghidrathon cache issue",
                "manual_injection": True,
                "available_functions": [x for x in dir(common) if not x.startswith('_') and callable(getattr(common, x, None))],
                "cache_issue": "Ghidrathon module caching prevented normal loading"
            }

        common.get_import_debug_info = temp_debug_info
        print("[Ghidra-MCP-Bridge] Injected temporary get_import_debug_info function")
    else:
        print("[Ghidra-MCP-Bridge] get_import_debug_info function successfully loaded")

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


def _inject_flat_api_to_common():
    """主动注入Ghidra Flat API函数到common模块的全局命名空间"""
    try:
        # 获取当前脚本的全局变量
        script_globals = globals()

        # 要注入的Ghidra Flat API函数列表
        flat_api_functions = [
            'currentProgram', 'currentAddress', 'currentLocation', 'currentSelection',
            'currentHighlight', 'monitor', 'state', 'script'
        ]

        injected_count = 0
        for func_name in flat_api_functions:
            if func_name in script_globals:
                func = script_globals[func_name]
                if callable(func) or func is not None:
                    # 直接注入到common模块的全局命名空间
                    setattr(common, func_name, func)
                    injected_count += 1
                    print(f"[Ghidra-MCP-Bridge] Injected {func_name} to common module")

        print(f"[Ghidra-MCP-Bridge] Successfully injected {injected_count} Flat API functions to common module")
        return injected_count > 0

    except Exception as e:
        print(f"[Ghidra-MCP-Bridge] Failed to inject Flat API to common: {e}")
        return False


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

        # 尝试主动注入Flat API到common模块
        _inject_flat_api_to_common()

        _cache_ghidra_context()
        common._cached_program_ref = _cached_program
        common._cached_address_ref = _cached_address
        common._cached_location_ref = _cached_location
        common._cached_selection_ref = _cached_selection
        common._cached_highlight_ref = _cached_highlight
        common._cached_monitor_ref = _cached_monitor
        common._cached_state_ref = _cached_state
        common._cached_script_ref = _cached_script
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

    # 尝试主动注入Flat API到common模块（自动启动时）
    _inject_flat_api_to_common()

    print("[Ghidra-MCP-Bridge] Caching Ghidra context for HTTP requests...")
    _cache_ghidra_context()

    # Share cached context with common module
    try:
        common._cached_program_ref = _cached_program
        common._cached_address_ref = _cached_address
        common._cached_location_ref = _cached_location
        common._cached_selection_ref = _cached_selection
        common._cached_highlight_ref = _cached_highlight
        common._cached_monitor_ref = _cached_monitor
        common._cached_state_ref = _cached_state
        common._cached_script_ref = _cached_script
    except Exception as e:
        print(f"[Ghidra-MCP-Bridge] Failed to set cached variables: {e}")

    start_server()
    print(f"[Ghidra-MCP-Bridge] Server auto-started on http://{HOST}:{PORT}")
except Exception as _auto_exc:  # noqa: BLE001
    print(f"[Ghidra-MCP-Bridge] Auto-start failed: {_auto_exc}")
