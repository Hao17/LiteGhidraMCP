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
  - **`search.py`**: 搜索 API（使用 state 传递模式），支持多种搜索类型
  - **`view.py`**: 查看 API，提供反编译和反汇编功能
  - **`status.py`**: 服务器状态 API，用于验证热重载是否生效

- **`api_v1/`**: v1 版本 API 模块目录

### Key Design Patterns

**装饰器路由模式 (推荐)**: 使用 `@route` 装饰器声明 API 路由，服务器自动发现并注册。

```python
# api/my_api.py
from api import route

@route("/api/my_api")
def my_function(state, q="", limit=100):
    prog = state.getCurrentProgram()
    return {"success": True, "data": ...}
```

- 服务器启动时自动扫描 `api/` 目录下所有模块
- 调用 `/_reload` 热重载时自动发现新增的 API
- URL 参数自动映射到函数参数

**Script Execution Pattern (兼容)**: 使用 `script.runScript()` 执行脚本，通过临时文件传递结果。仅用于 demo.py 等测试脚本。

## Development Commands

### Running the Bridge
```bash
# Inside Ghidra CodeBrowser: Execute ghidra_mcp_server.py via Ghidrathon
# - 首次执行：启动服务器，日志显示 "Server started on http://HOST:PORT"
# - 再次执行：自动检测已运行的服务器，触发热重载，日志显示 "API modules reloaded"

# Headless mode:
analyzeHeadless <projDir> <projName> -import <binary> -scriptPath . -postScript ghidra_mcp_server.py

# Environment variables:
# GHIDRA_MCP_HOST (default: 127.0.0.1)
# GHIDRA_MCP_PORT (default: 8803)

# 手动热重载 API 模块（无需在 Ghidra 中重新执行脚本）
curl http://127.0.0.1:8803/_reload

# 关闭服务器
curl http://127.0.0.1:8803/_shutdown
```

### API Testing
```bash
# 运行演示脚本
curl http://127.0.0.1:8803/api/demo

# 获取程序基础信息
curl http://127.0.0.1:8803/api/basic_info

# Search API 测试
curl "http://127.0.0.1:8803/api/search/functions?q=main&limit=10"
curl "http://127.0.0.1:8803/api/search/symbols?q=*printf*"
curl "http://127.0.0.1:8803/api/search/strings?q=error"
curl "http://127.0.0.1:8803/api/search/bytes?pattern=48 8b ?? 90&limit=20"
curl "http://127.0.0.1:8803/api/search/instructions?q=call"
curl "http://127.0.0.1:8803/api/search/xrefs/to?address=0x401000"
curl "http://127.0.0.1:8803/api/search/datatypes?q=*struct*"
curl "http://127.0.0.1:8803/api/search/all?q=init"

# View API 测试
curl "http://127.0.0.1:8803/api/view/decompile?name=main"
curl "http://127.0.0.1:8803/api/view/decompile?address=0x401000"
curl "http://127.0.0.1:8803/api/view/disassemble?name=main&limit=50"
curl "http://127.0.0.1:8803/api/view/disassemble?address=0x401000"
```

## Code Conventions

**Language**: Python 3 with Ghidrathon runtime
**Indentation**: 4 spaces
**Type Hints**: Used where practical

**System Routes** (根目录):
- `GET /_reload` - 热重载所有 API 模块（无需重启服务器）
- `GET /_shutdown` - 关闭服务器

**Status API**:
- `GET /api/status` - 查看服务器状态和模块加载时间（验证热重载）

**API Endpoints**:
- `GET /api/demo` - 执行演示脚本，用于测试
- `GET /api/basic_info` - 获取当前程序的基础信息

**View API** (`/api/view/*`):
- `GET /api/view/decompile?address=<addr>` - 反编译函数为 C 伪代码
- `GET /api/view/decompile?name=<name>&timeout=30` - 按函数名反编译
- `GET /api/view/disassemble?address=<addr>&limit=500` - 获取函数汇编代码
- `GET /api/view/disassemble?name=<name>&limit=500` - 按函数名获取汇编

**Search API** (`/api/search/*`):
- `GET /api/search/functions?q=<query>&limit=100` - 搜索函数名
- `GET /api/search/symbols?q=<query>&type=<type>&limit=100` - 搜索符号（支持通配符 `*` `?`）
- `GET /api/search/comments?q=<query>&type=<type>&limit=100` - 搜索注释（type: EOL/PRE/POST/PLATE/REPEATABLE）
- `GET /api/search/strings?q=<query>&encoding=<enc>&limit=100` - 搜索字符串
- `GET /api/search/scalars?value=<value>&size=<size>&limit=100` - 搜索立即数/标量
- `GET /api/search/bytes?pattern=<pattern>&limit=100&align=1` - 搜索字节模式（如 `48 8b ?? 90`）
- `GET /api/search/instructions?q=<query>&limit=100` - 搜索汇编指令文本
- `GET /api/search/xrefs/to?address=<addr>` - 搜索引用到某地址的交叉引用
- `GET /api/search/xrefs/from?address=<addr>` - 搜索从某地址发出的引用
- `GET /api/search/datatypes?q=<query>&limit=100` - 搜索数据类型
- `GET /api/search/all?q=<query>&limit=50` - 聚合搜索（函数+符号+字符串）

**Legacy API** (`/api/v1/*`):
- `GET /api/v1/search?q=<query>` - 旧版搜索（使用 runScript 模式）

**Error Handling**: Minimal logging to avoid Ghidra console noise, but preserve error context in API responses

## Adding New API Endpoints

使用 `@route` 装饰器添加新 API（**无需修改服务器代码**）：

1. 在 `api/` 目录创建新模块：
```python
# api/my_api.py
from api import route

@route("/api/my_api")
def my_function(state, param1="", param2=None, limit=100):
    """
    我的 API 功能描述。

    路由: GET /api/my_api?param1=xxx&limit=50
    """
    prog = state.getCurrentProgram()
    # ... 业务逻辑
    return {"success": True, "data": ...}

# 一个文件可以定义多个路由
@route("/api/my_api/detail")
def my_detail(state, address=""):
    # ...
    return {"success": True, ...}
```

2. 热重载使新 API 生效：
```bash
curl http://127.0.0.1:8803/_reload
```

**参数约定**:
- 第一个参数必须是 `state`（Ghidra 状态对象）
- 后续参数从 URL query 自动注入
- 参数应提供默认值，如 `q=""`, `limit=100`
- 整数字符串会自动转换为 int 类型

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
