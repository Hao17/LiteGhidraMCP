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

import importlib
import json
import os
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.request import urlopen
from urllib.error import URLError

HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8803"))

_server_instance: Optional["ThreadingHTTPServer"] = None
_server_thread: Optional[threading.Thread] = None

# Cache Ghidra context at startup
_cached_script = None
_cached_state = None


def _discover_and_load_api_modules():
    """
    自动发现并加载 api/ 目录下所有模块。
    模块使用 @route 装饰器自动注册路由。
    """
    # 先 reload api 包本身，确保使用最新版本
    import api
    importlib.reload(api)
    from api import clear_routes, get_route_list

    # 清空现有路由
    clear_routes()

    reloaded = []
    errors = []

    # 获取 api/ 目录路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    api_dir = os.path.join(script_dir, "api")

    if not os.path.isdir(api_dir):
        return {"success": False, "error": f"API directory not found: {api_dir}"}

    # 扫描并加载所有 .py 文件
    for filename in sorted(os.listdir(api_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        module_name = f"api.{filename[:-3]}"
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


def _handle_api_request(path, params):
    """
    统一处理 API 请求。
    根据已注册的路由调用对应的 handler。

    Args:
        path: 请求路径，如 "/api/basic_info"
        params: URL 查询参数字典

    Returns:
        dict 或 None（None 表示路由未找到）
    """
    from api import get_routes

    if _cached_state is None:
        return {"success": False, "error": "State not cached"}

    routes = get_routes()

    if path not in routes:
        return None  # 404

    handler = routes[path]["handler"]

    # 自动转换参数类型
    converted_params = {}
    for key, value in params.items():
        # 尝试转换为整数
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            converted_params[key] = int(value)
        else:
            converted_params[key] = value

    try:
        return handler(_cached_state, **converted_params)
    except TypeError as e:
        # 参数不匹配时的错误处理
        return {"success": False, "error": f"Invalid parameters: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


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
    except:
        _cached_script = None
        print("[Ghidra-MCP-Bridge] Warning: Failed to cache script")

    try:
        _cached_state = state()
    except:
        _cached_state = None
        print("[Ghidra-MCP-Bridge] Warning: Failed to cache state")

    # 自动加载 API 模块
    result = _discover_and_load_api_modules()
    if result.get("success"):
        routes = result.get("routes", [])
        print(f"[Ghidra-MCP-Bridge] Loaded {len(routes)} API routes")
    else:
        print(f"[Ghidra-MCP-Bridge] Warning: Failed to load some API modules: {result.get('errors')}")


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
            # 系统管理路由 (根目录) - 保持硬编码
            # ============================================================

            # 热重载 API 模块
            if path == "/_reload":
                result = _discover_and_load_api_modules()
                print(f"[Ghidra-MCP-Bridge] API modules reloaded: {result}")
                return self._send_json(result)

            # 关闭服务器
            if path == "/_shutdown":
                def delayed_shutdown():
                    time.sleep(0.1)
                    stop_server()
                threading.Thread(target=delayed_shutdown, daemon=True).start()
                return self._send_json({"success": True, "message": "Server shutting down"})

            # 演示脚本（使用 runScript 模式，保持硬编码）
            if path == "/api/demo":
                return self._send_json(_run_demo_script())

            # ============================================================
            # 动态 API 路由 - 通过装饰器自动注册
            # ============================================================
            result = _handle_api_request(path, params)
            if result is not None:
                return self._send_json(result)

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
        return _server_instance, port
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
    return _server_instance, chosen_port


def stop_server():
    global _server_instance, _server_thread
    if _server_instance:
        _server_instance.shutdown()
        _server_instance.server_close()
        _server_instance = None
        _server_thread = None


def _print_startup_banner(host: str, port: int):
    """打印启动横幅和 Quick Start 提示"""
    base_url = f"http://{host}:{port}"
    print(f"[Ghidra-MCP-Bridge] ═══════════════════════════════════════════════════════════")
    print(f"[Ghidra-MCP-Bridge] Server started: {base_url}")
    print(f"[Ghidra-MCP-Bridge] ───────────────────────────────────────────────────────────")
    print(f"[Ghidra-MCP-Bridge] Quick Start:")
    print(f"[Ghidra-MCP-Bridge]   {base_url}/api/basic_info")
    print(f"[Ghidra-MCP-Bridge]   {base_url}/api/search/functions?q=main")
    print(f"[Ghidra-MCP-Bridge]   {base_url}/_shutdown")
    print(f"[Ghidra-MCP-Bridge] ═══════════════════════════════════════════════════════════")


def main(script_globals: Dict[str, Any] | None = None, host: str = HOST, port: int = PORT):
    """
    Entry point for Script Manager or headless use.
    Pass in globals() so we can capture currentProgram/currentAddress/state explicitly.
    """
    if script_globals is None:
        script_globals = {}
    try:
        _cache_ghidra_context()
        srv, actual_port = start_server(host=host, port=port)
        _print_startup_banner(host, actual_port)
        return srv
    except Exception as exc:
        print(f"[Ghidra-MCP-Bridge] Failed to start server: {exc}")
        raise


def _check_existing_server(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    检测指定端口是否已有 Ghidra-MCP-Bridge 服务器在运行。
    通过尝试连接并检查响应头来确认。
    """
    try:
        url = f"http://{host}:{port}/api/basic_info"
        with urlopen(url, timeout=timeout) as resp:
            server_header = resp.headers.get("Server", "")
            return "GhidraMCP" in server_header
    except:
        return False


def _trigger_reload(host: str, port: int, timeout: float = 2.0) -> bool:
    """
    触发已运行服务器的热重载。
    返回 True 表示成功触发。
    """
    try:
        url = f"http://{host}:{port}/_reload"
        with urlopen(url, timeout=timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("success", False)
    except Exception as e:
        print(f"[Ghidra-MCP-Bridge] Reload request failed: {e}")
        return False


def auto_start_or_reload(host: str = HOST, port: int = PORT):
    """
    智能启动逻辑：
    - 如果目标端口已有 Ghidra-MCP-Bridge 服务器在运行，触发热重载
    - 否则启动新服务器
    """
    # 先缓存 Ghidra 上下文
    print("[Ghidra-MCP-Bridge] Caching Ghidra context...")
    _cache_ghidra_context()

    # 检测是否已有服务器在运行
    if _check_existing_server(host, port):
        print(f"[Ghidra-MCP-Bridge] Existing server detected, triggering reload...")
        if _trigger_reload(host, port):
            print(f"[Ghidra-MCP-Bridge] API modules reloaded successfully")
            return None  # 不返回服务器实例，因为我们没有启动新的
        else:
            print(f"[Ghidra-MCP-Bridge] Reload failed, existing server may be unresponsive")
            return None

    # 没有已存在的服务器，启动新的
    try:
        srv, actual_port = start_server(host=host, port=port)
        _print_startup_banner(host, actual_port)
        return srv
    except Exception as exc:
        print(f"[Ghidra-MCP-Bridge] Failed to start server: {exc}")
        raise


# Auto-start on import for Script Manager convenience.
try:
    auto_start_or_reload()
except Exception as _auto_exc:
    print(f"[Ghidra-MCP-Bridge] Auto-start failed: {_auto_exc}")
