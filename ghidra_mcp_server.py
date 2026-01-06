"""
Ghidrathon-based MCP Bridge for AI Repository Integration.

This script runs inside Ghidra via Ghidrathon to provide an external AI agent
with programmatic access to Ghidra's analysis capabilities. It exposes a lightweight
HTTP JSON API that allows AI systems to query decompilation data, perform reverse
engineering tasks, and execute scripted operations within Ghidra.

Designed to serve as a bridge between AI repositories and Ghidra, enabling
automated binary analysis, symbol management, and code understanding workflows.

Entry point is main(script_globals); no side effects at import time.
"""

import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8803"))

_server_instance: Optional["ThreadingHTTPServer"] = None
_server_thread: Optional[threading.Thread] = None

# Cache Ghidra context at startup
_cached_script = None
_cached_state = None

# Import API modules (state passing pattern)
import api.basic_info as basic_info_api
import api.search as search_api


def _run_script_by_path(script_path: str, extra_args: list = None):
    """
    通用脚本执行函数：使用script().runScript()执行指定路径的脚本。

    Args:
        script_path: 脚本路径（相对于Ghidra脚本目录）
        extra_args: 额外的参数列表

    Returns:
        脚本执行结果的JSON对象
    """
    # 生成带时间戳的临时文件路径
    timestamp = int(time.time() * 1000)  # 毫秒级时间戳
    result_filename = f"ghidra_script_result_{timestamp}.json"
    result_filepath = os.path.join(tempfile.gettempdir(), result_filename)

    # 传入参数：第一个是结果文件路径，后续是额外参数
    script_args = [result_filepath] + (extra_args or [])

    start_time = time.time()
    script_executed = False
    script_error = None

    try:
        _cached_script.runScript(script_path, script_args)
        script_executed = True
    except Exception as e:
        # CancelledException 在脚本实际执行成功后仍可能抛出，忽略它
        if "CancelledException" in str(type(e).__name__) or "CancelledException" in str(e):
            script_executed = True
        else:
            script_error = str(e)

    execution_time_ms = int((time.time() - start_time) * 1000)

    if not script_executed:
        return {
            "success": False,
            "error": script_error,
            "script_path": script_path,
            "result_file": result_filepath,
            "passed_args": script_args,
            "execution_time_ms": execution_time_ms
        }

    # runScript 是同步的，执行完毕后直接读取结果文件
    if not os.path.exists(result_filepath):
        return {
            "success": False,
            "error": "Script executed but result file not found",
            "script_path": script_path,
            "result_file": result_filepath,
            "passed_args": script_args,
            "execution_time_ms": execution_time_ms,
            "note": "Script may have failed to write output"
        }

    # 读取并返回结果
    try:
        with open(result_filepath, 'r', encoding='utf-8') as f:
            script_result = json.load(f)

        # 清理临时文件
        try:
            os.remove(result_filepath)
        except OSError:
            pass  # 忽略清理失败

        return {
            "success": True,
            "script_path": script_path,
            "passed_args": script_args,
            "result_file": result_filepath,
            "script_result": script_result,
            "execution_time_ms": execution_time_ms
        }

    except json.JSONDecodeError as e:
        # 读取原始内容用于调试
        try:
            with open(result_filepath, 'r', encoding='utf-8') as f:
                raw_content = f.read()
        except:
            raw_content = "<unable to read>"

        return {
            "success": False,
            "error": f"Failed to parse result JSON: {str(e)}",
            "script_path": script_path,
            "result_file": result_filepath,
            "passed_args": script_args,
            "execution_time_ms": execution_time_ms,
            "raw_content": raw_content[:1000]  # 限制长度
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read result file: {str(e)}",
            "script_path": script_path,
            "result_file": result_filepath,
            "passed_args": script_args,
            "execution_time_ms": execution_time_ms
        }


def _run_demo_script():
    """执行 api/demo.py 演示脚本（API 开发参考样例）"""
    return _run_script_by_path("api/demo.py", ["demo_param_1", "demo_param_2", "12345"])


def _run_basic_info():
    """直接调用 basic_info_api.basic_info(state) 获取程序基础信息"""
    if _cached_state is None:
        return {"success": False, "error": "State not cached"}

    try:
        return basic_info_api.basic_info(_cached_state)
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# Search API 路由处理函数 (State Passing Pattern)
# ============================================================

def _run_search(endpoint, params):
    """
    处理 /api/search/* 请求

    路由:
        GET /api/search/functions?q=<query>&limit=100
        GET /api/search/symbols?q=<query>&type=<type>&limit=100
        GET /api/search/comments?q=<query>&type=<type>&limit=100
        GET /api/search/strings?q=<query>&encoding=<enc>&limit=100
        GET /api/search/scalars?value=<value>&size=<size>&limit=100
        GET /api/search/bytes?pattern=<pattern>&limit=100&align=1
        GET /api/search/instructions?q=<query>&limit=100
        GET /api/search/xrefs/to?address=<addr>
        GET /api/search/xrefs/from?address=<addr>
        GET /api/search/datatypes?q=<query>&limit=100
        GET /api/search/all?q=<query>&limit=50
    """
    if _cached_state is None:
        return {"success": False, "error": "State not cached"}

    query = params.get("q", "")
    limit = int(params.get("limit", "100"))

    try:
        if endpoint == "functions":
            return search_api.search_functions(_cached_state, query, limit)

        elif endpoint == "symbols":
            sym_type = params.get("type")
            return search_api.search_symbols(_cached_state, query, sym_type, limit)

        elif endpoint == "comments":
            comment_type = params.get("type")
            return search_api.search_comments(_cached_state, query, comment_type, limit)

        elif endpoint == "strings":
            encoding = params.get("encoding")
            return search_api.search_strings(_cached_state, query, encoding, limit)

        elif endpoint == "scalars":
            value = params.get("value", "")
            size = params.get("size")
            size = int(size) if size else None
            return search_api.search_scalars(_cached_state, value, size, limit)

        elif endpoint == "bytes":
            pattern = params.get("pattern", "")
            align = int(params.get("align", "1"))
            return search_api.search_bytes(_cached_state, pattern, limit, align)

        elif endpoint == "instructions":
            return search_api.search_instructions(_cached_state, query, limit)

        elif endpoint == "xrefs/to":
            address = params.get("address", "")
            return search_api.search_xrefs_to(_cached_state, address)

        elif endpoint == "xrefs/from":
            address = params.get("address", "")
            return search_api.search_xrefs_from(_cached_state, address)

        elif endpoint == "datatypes":
            return search_api.search_data_types(_cached_state, query, limit)

        elif endpoint == "all":
            limit = int(params.get("limit", "50"))
            return search_api.search_all(_cached_state, query, limit)

        else:
            return {"success": False, "error": f"Unknown search endpoint: {endpoint}"}

    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# API v1 路由处理函数
# ============================================================

def _handle_v1_search(command, params):
    """
    处理 /api/v1/search 请求

    路由:
        GET /api/v1/search?q=<query>           - 搜索全部（函数+符号+字符串）
        GET /api/v1/search/functions?q=<query> - 仅搜索函数
        GET /api/v1/search/strings?q=<query>   - 仅搜索字符串

    参数:
        q: 搜索关键词
        limit: (可选) 结果数量限制，默认50
    """
    query = params.get("q", "")
    limit = params.get("limit", "50")

    if command in ("", "all"):
        return _run_script_by_path("api_v1/search.py", ["all", query, limit])
    elif command == "functions":
        return _run_script_by_path("api_v1/search.py", ["functions", query, limit])
    elif command == "strings":
        return _run_script_by_path("api_v1/search.py", ["strings", query, limit])
    else:
        return {"success": False, "error": f"Unknown search command: {command}"}


def _parse_query_params(query_string):
    """解析URL查询参数"""
    params = {}
    if not query_string:
        return params
    for pair in query_string.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            # URL解码
            from urllib.parse import unquote
            params[unquote(key)] = unquote(value)
    return params


def _cache_ghidra_context():
    """Cache Ghidra script and state objects at startup."""
    global _cached_script, _cached_state

    try:
        _cached_script = script()
        print(f"[Ghidra-MCP-Bridge] Cached script: {_cached_script}")
    except:
        _cached_script = None
        print("[Ghidra-MCP-Bridge] Failed to cache script")

    try:
        _cached_state = state()
        print(f"[Ghidra-MCP-Bridge] Cached state: {_cached_state}")
    except:
        _cached_state = None
        print("[Ghidra-MCP-Bridge] Failed to cache state")


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
        except Exception as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console noise minimal inside Ghidra.
        return

    def do_GET(self):
        try:
            # 解析路径和查询参数
            path = self.path
            query_string = ""
            if "?" in path:
                path, query_string = path.split("?", 1)
            params = _parse_query_params(query_string)

            # ============================================================
            # 基础 API 路由
            # ============================================================

            # 演示脚本（API 开发参考样例）
            if path == "/api/demo":
                return self._send_json(_run_demo_script())

            # 程序基础信息
            if path == "/api/basic_info":
                return self._send_json(_run_basic_info())

            # ============================================================
            # Search API 路由: /api/search/<endpoint>
            # ============================================================
            if path.startswith("/api/search/"):
                # 提取 endpoint: /api/search/functions -> functions
                # 支持多级: /api/search/xrefs/to -> xrefs/to
                endpoint = path[12:]  # len("/api/search/") = 12
                return self._send_json(_run_search(endpoint, params))

            # ============================================================
            # API v1 路由: /api/v1/<module>/<command>
            # ============================================================
            if path.startswith("/api/v1/search"):
                # /api/v1/search 或 /api/v1/search/<command>
                if path == "/api/v1/search":
                    command = ""
                else:
                    command = path[15:]  # len("/api/v1/search/") = 15
                return self._send_json(_handle_v1_search(command, params))

            # 404
            self._send_json({"error": "Not Found", "path": path}, status=404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)

    def do_POST(self):
        try:
            self._send_json({"error": "Not Found"}, status=404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)


class _ThreadedServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_server(host: str = HOST, port: int = PORT):
    """Start the HTTP server as a daemon thread to keep GUI responsive."""
    global _server_instance, _server_thread
    if _server_instance:
        return _server_instance
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
        _cache_ghidra_context()
        srv = start_server(host=host, port=port)
        print(f"[Ghidra-MCP-Bridge] Server started on {host}:{port}")
        return srv
    except Exception as exc:
        print(f"[Ghidra-MCP-Bridge] Failed to start server: {exc}")
        raise


# Auto-start on import for Script Manager convenience.
try:
    print("[Ghidra-MCP-Bridge] Caching Ghidra context for HTTP requests...")
    _cache_ghidra_context()
    start_server()
    print(f"[Ghidra-MCP-Bridge] Server auto-started on http://{HOST}:{PORT}")
except Exception as _auto_exc:
    print(f"[Ghidra-MCP-Bridge] Auto-start failed: {_auto_exc}")
