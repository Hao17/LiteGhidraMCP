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
  - **`symbol_tree.py`**: Symbol Tree API，提供符号树结构查看功能
  - **`comment.py`**: Comment API，设置/删除注释

- **`api_v1/`**: v1 版本 API 模块目录（面向 AI 的聚合接口）：
  - **`search.py`**: 统一搜索 API，支持智能类型推断
  - **`view.py`**: 统一查看 API，支持批量查询和同时返回反编译/汇编
  - **`list.py`**: 统一列表 API，提供类似 ls 的符号浏览功能

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

# Symbol Tree API 测试
curl "http://127.0.0.1:8803/api/symbol_tree/namespaces"
curl "http://127.0.0.1:8803/api/symbol_tree/namespace?name=std"
curl "http://127.0.0.1:8803/api/symbol_tree/namespace/tree?depth=2"
curl "http://127.0.0.1:8803/api/symbol_tree/classes"
curl "http://127.0.0.1:8803/api/symbol_tree/class?name=MyClass"
curl "http://127.0.0.1:8803/api/symbol_tree/functions?namespace=std"
curl "http://127.0.0.1:8803/api/symbol_tree/function?name=main"
curl "http://127.0.0.1:8803/api/symbol_tree/labels"
curl "http://127.0.0.1:8803/api/symbol_tree/globals"
curl "http://127.0.0.1:8803/api/symbol_tree/imports?library=kernel32"
curl "http://127.0.0.1:8803/api/symbol_tree/exports"

# Comment API 测试
curl "http://127.0.0.1:8803/api/comment/set?address=0x401000&type=EOL&text=测试注释"
curl "http://127.0.0.1:8803/api/comment/set?name=main&type=PLATE&text=主函数说明"
curl "http://127.0.0.1:8803/api/comment/set?address=0x401000&type=EOL&text="  # 删除注释

# V1 List API 测试
curl "http://127.0.0.1:8803/api/v1/list"
curl "http://127.0.0.1:8803/api/v1/list?q=init*"
curl "http://127.0.0.1:8803/api/v1/list?types=all&limit=20"
curl "http://127.0.0.1:8803/api/v1/list?types=functions,classes"
curl "http://127.0.0.1:8803/api/v1/list?start=0x401000&end=0x402000"
curl "http://127.0.0.1:8803/api/v1/list?types=imports&library=kernel32"
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

**Symbol Tree API** (`/api/symbol_tree/*`) - 符号树结构查看:
- `GET /api/symbol_tree/namespaces?limit=100` - 列出顶级命名空间
- `GET /api/symbol_tree/namespace?name=<ns>&limit=100` - 获取命名空间子项（支持路径如 `std::vector`）
- `GET /api/symbol_tree/namespace/tree?name=<ns>&depth=3&limit=500` - 获取命名空间树形结构
- `GET /api/symbol_tree/classes?q=<query>&limit=100` - 列出类
- `GET /api/symbol_tree/class?name=<class>` - 获取类成员（方法、字段）
- `GET /api/symbol_tree/functions?q=<query>&namespace=<ns>&limit=100` - 列出函数（带命名空间）
- `GET /api/symbol_tree/function?name=<name>` 或 `?address=<addr>` - 获取函数内部符号（参数、局部变量、标签）
- `GET /api/symbol_tree/labels?q=<query>&limit=100` - 列出标签
- `GET /api/symbol_tree/globals?q=<query>&limit=100` - 列出全局变量
- `GET /api/symbol_tree/imports?library=<lib>&limit=100` - 列出导入符号
- `GET /api/symbol_tree/exports?limit=100` - 列出导出符号

**Comment API** (`/api/comment/*`) - 注释操作:
- `GET /api/comment/set?address=<addr>&type=<type>&text=<text>` - 设置注释
- `GET /api/comment/set?name=<name>&type=<type>&text=<text>` - 按函数名设置入口点注释
- 参数 `type`: EOL(默认)/PRE/POST/PLATE/REPEATABLE
- 删除注释: `text=` (空字符串)

**V1 API** (`/api/v1/*`) - 面向 AI 的聚合接口:

所有 V1 API 默认返回 compact 格式（数组 + `_schema`），可通过 `verbose=true` 获取完整 dict 格式。

- `GET /api/v1/search?q=<query>&types=auto&limit=20&verbose=false` - 统一搜索（支持智能类型推断）
  - `types`: `auto`(智能推断) / `all` / 逗号分隔（如 `functions,symbols,strings`）
  - `verbose`: `true` 返回完整 dict，默认 compact 数组格式
- `GET /api/v1/view?q=<query>&type=both&timeout=30&limit=500&verbose=false` - 统一查看（支持批量查询）
  - `q`: 函数名或地址，逗号分隔支持批量（如 `main,init,0x401000`）
  - `type`: `both`(默认) / `decompile` / `disassemble`
  - `verbose`: `true` 返回完整 dict，默认 compact info 数组格式
- `GET /api/v1/list?q=<query>&types=auto&limit=100&verbose=false` - 统一列表（类似 ls 的符号浏览）
  - `q`: 名称过滤（支持通配符 `*` `?`）
  - `types`: `auto`(默认=functions) / `all` / 逗号分隔（如 `functions,classes,imports`）
  - `start`/`end`: 地址范围过滤（如 `start=0x401000&end=0x402000`）
  - `library`: imports 的库名过滤（如 `library=kernel32`）
  - `verbose`: `true` 返回完整 dict，默认 compact 数组格式
  - 支持类型: functions, classes, namespaces, labels, globals, imports, exports

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
