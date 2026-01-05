# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Ghidrathon-based MCP (Model Context Protocol) Bridge that runs inside Ghidra to provide AI systems with programmatic access to Ghidra's reverse engineering capabilities. The bridge exposes a lightweight HTTP JSON API for automated binary analysis and code understanding workflows.

## Architecture

### Core Components

- **`ghidra_mcp_server.py`**: Main HTTP server that runs inside Ghidra via Ghidrathon. Caches `state` object at startup and imports API modules directly.

- **`api/`**: API 模块目录，包含所有可调用的 API 实现：
  - **`demo.py`**: API 开发参考样例（使用 runScript 模式）
  - **`basic_info.py`**: 获取当前程序基础信息（使用 state 传递模式）

- **`api_v1/`**: v1 版本 API 模块目录

### Key Design Patterns

**State Passing Pattern (推荐)**: 服务器启动时缓存 `state` 对象，API 模块通过 `import` 导入后直接调用，传入 `state` 参数。

```python
# 服务器端
import api.basic_info as basic_info_api
result = basic_info_api.basic_info(_cached_state)

# API 模块
def basic_info(state):
    prog = state.getCurrentProgram()
    return {"name": prog.getName(), ...}
```

**Script Execution Pattern (兼容)**: 使用 `script.runScript()` 执行脚本，通过临时文件传递结果。仅用于 demo.py 等测试脚本。

## Development Commands

### Running the Bridge
```bash
# Inside Ghidra CodeBrowser: Execute ghidra_mcp_server.py via Ghidrathon
# Server auto-starts and logs: "Listening on http://HOST:PORT"

# Headless mode:
analyzeHeadless <projDir> <projName> -import <binary> -scriptPath . -postScript ghidra_mcp_server.py

# Environment variables:
# GHIDRA_MCP_HOST (default: 127.0.0.1)
# GHIDRA_MCP_PORT (default: 8803)
```

### API Testing
```bash
# 运行演示脚本
curl http://127.0.0.1:8803/api/demo

# 获取程序基础信息
curl http://127.0.0.1:8803/api/basic_info
```

## Code Conventions

**Language**: Python 3 with Ghidrathon runtime
**Indentation**: 4 spaces
**Type Hints**: Used where practical

**API Endpoints**:
- `GET /api/demo` - 执行演示脚本，用于测试
- `GET /api/basic_info` - 获取当前程序的基础信息
- `GET /api/v1/search?q=<query>` - 搜索函数和字符串

**Error Handling**: Minimal logging to avoid Ghidra console noise, but preserve error context in API responses

## Adding New API Endpoints

使用 State 传递模式添加新 API：

1. 在 `api/` 目录创建新模块，定义接收 `state` 参数的函数：
```python
# api/my_api.py
def my_function(state):
    prog = state.getCurrentProgram()
    # ... 业务逻辑
    return {"success": True, "data": ...}
```

2. 在 `ghidra_mcp_server.py` 中导入并添加路由：
```python
import api.my_api as my_api

def _run_my_api():
    if _cached_state is None:
        return {"success": False, "error": "State not cached"}
    return my_api.my_function(_cached_state)

# 在 do_GET 中添加路由
if path == "/api/my_api":
    return self._send_json(_run_my_api())
```

**State 对象可用方法**:
- `state.getCurrentProgram()` - 当前程序
- `state.getCurrentAddress()` - 当前地址
- `state.getCurrentSelection()` - 当前选择
- `state.getCurrentHighlight()` - 当前高亮
- `state.getTool()` - 当前工具

## Security Configuration

**Default binding**: `127.0.0.1:8803` (localhost only)
**Authentication**: None (designed for local AI agent access)
**Threading**: Daemon threads only to preserve Ghidra GUI responsiveness
**Dependencies**: Minimal footprint using only Ghidra stdlib plus standard Python libraries

## Troubleshooting

If encountering issues:
1. Check that program is loaded in Ghidra before starting server
2. Verify `_cached_state` is successfully cached in startup logs
3. Ensure API module files are in Ghidra's script path

The bridge handles both GUI and headless modes with appropriate threading models for each environment.
