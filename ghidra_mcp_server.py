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

# Cache Ghidra script object at startup for runScript() calls
_cached_script = None


def _run_test_script():
    """
    使用script().runScript()执行test_script.py，并返回脚本执行结果。

    实现方式：
    1. 生成带时间戳的临时文件路径
    2. 将临时文件路径作为第一个参数传入脚本
    3. 脚本同步执行后将结果写入该文件
    4. runScript返回后直接读取结果文件

    注意：runScript() 是同步调用，会等待子脚本执行完成后才返回，
    即使抛出 CancelledException 也是在执行完毕后。

    Returns:
        脚本执行结果的JSON对象
    """
    # 生成带时间戳的临时文件路径
    timestamp = int(time.time() * 1000)  # 毫秒级时间戳
    result_filename = f"ghidra_script_result_{timestamp}.json"
    result_filepath = os.path.join(tempfile.gettempdir(), result_filename)

    # 传入参数：第一个是结果文件路径，后续是测试参数
    test_args = [result_filepath, "test_param_1", "test_param_2", "12345"]

    start_time = time.time()
    script_executed = False
    script_error = None

    try:
        _cached_script.runScript("test_script.py", test_args)
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
            "result_file": result_filepath,
            "passed_args": test_args,
            "execution_time_ms": execution_time_ms
        }

    # runScript 是同步的，执行完毕后直接读取结果文件
    if not os.path.exists(result_filepath):
        return {
            "success": False,
            "error": "Script executed but result file not found",
            "result_file": result_filepath,
            "passed_args": test_args,
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
            "passed_args": test_args,
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
            "result_file": result_filepath,
            "passed_args": test_args,
            "execution_time_ms": execution_time_ms,
            "raw_content": raw_content[:1000]  # 限制长度
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read result file: {str(e)}",
            "result_file": result_filepath,
            "passed_args": test_args,
            "execution_time_ms": execution_time_ms
        }


def _cache_ghidra_context():
    """Cache Ghidra script object at startup for runScript() calls."""
    global _cached_script

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
        except Exception as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console noise minimal inside Ghidra.
        return

    def do_GET(self):
        try:
            if self.path == "/api/run/test_script" or self.path == "/api/run/test-script":
                return self._send_json(_run_test_script())
            self._send_json({"error": "Not Found"}, status=404)
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
