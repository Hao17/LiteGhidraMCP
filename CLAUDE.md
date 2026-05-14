# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+ to provide AI systems with programmatic access to Ghidra's reverse engineering capabilities. The bridge exposes a lightweight HTTP JSON API for automated binary analysis and code understanding workflows.

## Architecture

### Core Components

- **`ghidra_mcp_server.py`**: GUI mode HTTP server, runs inside Ghidra via Script Manager. Caches `state` object at startup and imports API modules directly.

- **`docker_only_ghidra_mcp_server.py`**: Docker/Headless mode server, runs via PyGhidra CLI. Handles server connection, SSH key auth, and headless analysis. **Do not run in Ghidra GUI Script Manager** — it expects container paths (`/ghidra-projects/...`) and will fail.

- **`api/`**: API 模块目录，包含所有可调用的 API 实现：
  - **`demo.py`**: API 开发参考样例（使用 runScript 模式）
  - **`basic_info.py`**: 获取当前程序基础信息（使用 state 传递模式）
  - **`search.py`**: 搜索 API（使用 state 传递模式），支持多种搜索类型
  - **`view.py`**: 查看 API，提供反编译和反汇编功能
  - **`status.py`**: 服务器状态 API，用于验证热重载是否生效
  - **`symbol_tree.py`**: Symbol Tree API，提供符号树结构查看功能
  - **`comment.py`**: Comment API，设置/删除注释
  - **`rename.py`**: Rename API，重命名函数、变量、参数、标签、数据类型、命名空间等
  - **`datatype.py`**: DataType API，数据类型设置、创建、管理和 C 头文件解析
  - **`program.py`**: Program API，程序枚举与导入；运行时切换已废弃
  - **`version.py`**: Version API，版本管理 commit/log/rollback/revert（仅 Ghidra Server 模式）
  - **`checkout.py`**: Checkout Manager，写操作自动 checkout/save/checkin 生命周期（仅 Headless 模式）
  - **`memory.py`**: Memory API，读取任意地址的原始字节数据

- **`api_v1/`**: v1 版本 API 模块目录（面向 AI 的聚合接口）：
  - **`overview.py`**: 二进制全景概览 API，一次调用返回元数据、内存布局、统计、关键函数、导入导出、字符串
  - **`search.py`**: 统一搜索 API，支持智能类型推断
  - **`view.py`**: 统一查看 API，支持批量查询和同时返回反编译/汇编
  - **`list.py`**: 统一列表 API，提供类似 ls 的符号浏览功能
  - **`edit.py`**: 统一编辑 API，支持批量重命名、类型设置、注释操作

- **`scripts/`**: 独立脚本目录：
  - **`mcp_sse_proxy.py`**: MCP SSE 代理服务器，作为独立子进程运行，通过 HTTP API 与 Ghidra 通信
  - **`mcp_stdio.py`**: MCP stdio 模式脚本，用于本地 Claude Desktop 调试
  - **`test_mcp.py`**: MCP 和 HTTP API 测试脚本
  - **`admin_bootstrap.py`**: 以 `bridgectl` SSH 身份执行的一次性服务器管理脚本（`create-repo`/`list-repos`），由 `gmcp server repo create` 通过 `docker run --entrypoint python3` 调用
  - **`exec_runner.py`**: `/api/v1/exec` 的 Python in-process 执行运行时，自动序列化 `result` 与捕获 stdout（Java/headless 路径已移除——见下方 `/api/v1/exec` 段落）

- **`cli/`**: `gmcp` 命令行实现（`pip install -e .` 后通过 `pyproject.toml` 的 `[project.scripts]` 暴露为 `gmcp`）：
  - **`main.py`**: Click 入口，组装所有子命令
  - **`commands/server.py`**: `gmcp server {up,down,restart,logs,clean,users,add-user,reset-password,repos,migrate-acl,repo {create,delete,grant,revoke,list}}`
  - **`commands/client.py`**: `gmcp client {start,stop,clean,logs}`（ephemeral UUID 身份、ACL grant/revoke、客户端会话文件维护）
  - **`commands/stack.py`**: `gmcp up` / `gmcp down`（一键 server+client 1）
  - **`commands/install.py`**: `gmcp install skill {claude-code,codex,cursor,copilot}` 与 `gmcp install mcp {claude-code,claude-desktop,coco}`
  - **`commands/build.py`** / **`commands/dev.py`**: `gmcp build` / `gmcp rebuild` / `gmcp dev {up,reload,health,test,shell,logs}`
  - **`commands/info.py`** / **`commands/status.py`** / **`commands/troubleshoot.py`**: `gmcp info` / `gmcp versions` / `gmcp switch-version` / `gmcp status` / `gmcp troubleshoot`
  - **`config.py`**: `.env` 解析、数据目录布局（`GHIDRA_DATA_DIR/<version>/{server,client/N,ssh,imports}`）
  - **`docker.py`**: `docker compose` 与 `docker exec` 包装（注入 env_overrides、project name）
  - **`ports.py`**: 客户端端口计算公式 `N → HTTP 8800+(N-1)*10+3, SSE +1`
  - **`output.py`**: 终端彩色输出辅助

- **`utils/`**: 服务器进程内共享工具（被 `ghidra_mcp_server.py` / `docker_only_ghidra_mcp_server.py` 导入）：
  - **`logging_config.py`**: 集中日志配置，文件 handler 写入 `tempdir/ghidra_mcp_bridge.log`（10MB × 3 滚动），用于守护线程在 Ghidra 控制台失效后的可观测性
  - **`project_loader.py`**: 通过 `PROJECT_MODE` / `PROJECT_PATH` / `GHIDRA_SERVER_*` 环境变量解析项目配置，校验本地 `.gpr`/`.rep` 文件存在性

- **`skills/`**: AI Skill 文档（由 `gmcp install skill` 写入到目标项目）：
  - **`SKILL.md`**: AI Skill 的工作流文档（推荐 AI 首次接入项目时阅读）

- **`examples/`**: 端到端样例
  - **`api-usage/curl-examples.sh`**: 所有 HTTP API 的 curl 调用合集
  - **`mcp/{claude-config.json,coco-config.json}`**: Claude Desktop / Coco 的 MCP 配置参考

- **`docker/`**: 镜像与 compose 配置（`Dockerfile`、`docker-compose.{yml,server,client,dev}.yml`、`entrypoint.sh`、`init-ghidra-server.sh`、`server.conf`、`Makefile`、`healthcheck.sh`、`troubleshoot.sh`、`verify-setup.sh`，深度说明见 `docker/ARCHITECTURE.md`、`docker/QUICKSTART.md`、`docker/ISSUES.md`）

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

**GUI prerequisites (one-time setup):**

`ghidra_mcp_server.py` only runs under **PyGhidra**, not Ghidrathon/Jython. Launch Ghidra via the dedicated entrypoint and install Bridge deps into the PyGhidra venv:

```bash
# 1. Launch Ghidra with PyGhidra (creates the venv on first run)
<ghidra_install>/support/pyghidraRun         # macOS/Linux
<ghidra_install>\support\pyghidraRun.bat     # Windows

# 2. Install mcp/uvicorn/httpx INTO THE PYGHIDRA VENV (not system Python)
#    venv path: ~/Library/ghidra/ghidra_<VER>_PUBLIC/venv/ (macOS)
#               ~/.config/ghidra/ghidra_<VER>_PUBLIC/venv/ (Linux)
#               %APPDATA%\ghidra\ghidra_<VER>_PUBLIC\venv\ (Windows)
~/Library/ghidra/ghidra_12.0.3_PUBLIC/venv/bin/python3 -m pip install -r requirements.txt
```

**Symptom of skipping step 2:** banner prints `MCP proxy failed to start` + `ModuleNotFoundError: No module named 'mcp'`; HTTP API still serves on 8803 but SSE on 8804 is dead.

**Running:**

```bash
# Inside Ghidra CodeBrowser: Execute ghidra_mcp_server.py via PyGhidra
# - 首次执行：启动服务器，日志显示 "HTTP Server: http://HOST:PORT" + "Current Loaded Program: ..."
# - 再次执行：每次 Run 都会新开一对端口（端口冲突自动 +1）；旧实例不会自动停。
#   要清理可 curl http://127.0.0.1:8803/_shutdown，或用 /_reload 走热重载而不重启。

# Headless / Docker mode: don't use analyzeHeadless. Instead invoke the
# standalone entrypoint directly (it self-initializes via pyghidra.start()):
#   python3 docker_only_ghidra_mcp_server.py
# In the Docker image this is `docker/entrypoint.sh`'s last line.

# Environment variables:
# GHIDRA_MCP_HOST (default: 127.0.0.1)
# GHIDRA_MCP_PORT (default: 8803)
# GHIDRA_MCP_SSE_PORT (default: 8804) - MCP SSE server port
# PROGRAM_NAME (default: "") - specify program name or repository path at startup (empty = first available)

# 手动热重载 API 模块（无需在 Ghidra 中重新执行脚本）
curl http://127.0.0.1:8803/_reload

# 关闭服务器
curl http://127.0.0.1:8803/_shutdown
```

### MCP (Model Context Protocol) Support

服务器启动时会同时启动 HTTP API (8803) 和 MCP SSE Proxy (8804) 两个服务。

MCP SSE 作为独立子进程运行（`scripts/mcp_sse_proxy.py`），通过 HTTP API 与 Ghidra 通信，实现 MCP 协议支持：

```
┌─────────────────┐     SSE       ┌─────────────────┐     HTTP      ┌─────────────────┐
│  Claude Desktop │ ◄───────────► │ mcp_sse_proxy   │ ◄───────────► │  Ghidra Bridge  │
│                 │               │   (subprocess)  │               │  (HTTP Server)  │
└─────────────────┘               └─────────────────┘               └─────────────────┘
```

**Dependencies:**
```bash
pip install mcp uvicorn httpx
```

**Claude Desktop Configuration:**

在 `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) 或 `~/.config/claude/settings.json` (Linux) 添加:
```json
{
  "mcpServers": {
    "ghidra": {
      "type": "sse",
      "url": "http://127.0.0.1:8804/sse"
    }
  }
}
```

**Available MCP Tools:**
- `ghidra_overview`: 二进制全景概览（推荐首次调用），返回元数据、内存布局、统计、关键函数、导入导出、字符串
- `ghidra_search`: 统一搜索 (functions, symbols, strings, xrefs, etc.)
- `ghidra_view`: 反编译/反汇编/内存查看
- `ghidra_list`: 符号列表浏览
- `ghidra_edit`: 统一编辑 (rename, datatype, comment)
- `ghidra_version`: 版本历史与回滚（log/rollback/revert）— 仅 Server 模式下条件注册；写操作已自动 commit，无需手动提交

**MCP stdio Mode (for local debugging):**

除了 SSE 模式，还提供独立的 stdio 模式脚本 `scripts/mcp_stdio.py`，用于本地 Claude Desktop 调试。

stdio 模式作为独立进程运行，通过 HTTP API 与 Ghidra Bridge 通信：

```
┌─────────────────┐     stdio      ┌─────────────────┐     HTTP      ┌─────────────────┐
│  Claude Desktop │ ◄────────────► │   mcp_stdio.py  │ ◄───────────► │  Ghidra Bridge  │
└─────────────────┘                └─────────────────┘               └─────────────────┘
```

Claude Desktop 配置 (stdio 模式):
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/opt/homebrew/anaconda3/envs/ghidra/bin/python",
      "args": ["/path/to/Bridge/scripts/mcp_stdio.py", "--port", "8803"]
    }
  }
}
```

命令行参数:
- `--host`: Ghidra Bridge 主机地址 (默认: 127.0.0.1)
- `--port`: Ghidra Bridge HTTP API 端口 (默认: 8803，需与 Ghidra 中显示的端口一致)

**SSE vs stdio 模式对比:**

| 特性 | SSE 模式 | stdio 模式 |
|------|----------|------------|
| 进程 | Ghidra 自动启动子进程 | 手动配置独立进程 |
| 配置 | `"url": "http://...sse"` | `"command": "python"` |
| 调试 | 查看子进程日志 | 可用 IDE 调试 |
| 性能 | 通过 HTTP 代理 | 通过 HTTP 代理 |
| 适用场景 | 生产使用（推荐） | 本地开发调试 |

### API Testing
```bash
# 基础
curl http://127.0.0.1:8803/api/basic_info

# Search
curl "http://127.0.0.1:8803/api/search/functions?q=main&limit=10"
curl "http://127.0.0.1:8803/api/search/xrefs/to?address=0x401000"

# View
curl "http://127.0.0.1:8803/api/view/decompile?name=main"
curl "http://127.0.0.1:8803/api/view/disassemble?name=main&limit=50"

# Memory
curl "http://127.0.0.1:8803/api/memory/read?address=0x611&length=256"
curl "http://127.0.0.1:8803/api/memory/read?address=0x611&length=256&format=u8"

# Symbol Tree
curl "http://127.0.0.1:8803/api/symbol_tree/function?name=main"
curl "http://127.0.0.1:8803/api/symbol_tree/classes"

# Comment
curl "http://127.0.0.1:8803/api/comment/set?address=0x401000&type=EOL&text=test"

# Rename (Decompiler 级别 - 推荐)
curl "http://127.0.0.1:8803/api/rename/decompiler/variable?function=main&var_name=local_8&new_name=counter"
curl "http://127.0.0.1:8803/api/rename/function_signature?function=FUN_00401000&signature=int%20main(int%20argc,%20char%20**argv)"

# DataType
curl "http://127.0.0.1:8803/api/datatype/set/return?function=main&type=int"
curl "http://127.0.0.1:8803/api/datatype/parse/c?code=typedef%20struct%20{%20int%20x;%20int%20y;%20}%20Point;"

# V1 API（面向 AI 聚合接口）
curl http://127.0.0.1:8803/api/v1/overview
curl "http://127.0.0.1:8803/api/v1/overview?verbose=true"
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"
curl "http://127.0.0.1:8803/api/v1/view?q=main"
curl "http://127.0.0.1:8803/api/v1/view?q=0x611&type=memory&limit=256"
curl "http://127.0.0.1:8803/api/v1/list?types=functions,classes"
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" \
  -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}'
# V1 Edit 批量操作
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" \
  -d '{"actions": [{"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}, {"action": "comment.set", "name": "main", "type": "PLATE", "text": "Main entry"}]}'
```

## Code Conventions

**Language**: Python 3 with PyGhidra runtime (Ghidra 12.0+)
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

**Rename API** (`/api/rename/*`) - 重命名操作:

*Listing 级别*（修改数据库符号，可能不影响反编译视图）:
- `GET /api/rename/function?address=<addr>&new_name=<name>` - 重命名函数（按地址）
- `GET /api/rename/function?name=<old>&new_name=<new>` - 重命名函数（按名称）
- `GET /api/rename/variable?function=<func>&var_name=<old>&new_name=<new>` - 重命名局部变量
- `GET /api/rename/variable?function_address=<addr>&var_name=<old>&new_name=<new>` - 按函数地址定位
- `GET /api/rename/parameter?function=<func>&param=<idx|name>&new_name=<new>` - 重命名函数参数
- `GET /api/rename/global?address=<addr>&new_name=<name>` - 重命名全局变量（按地址）
- `GET /api/rename/global?name=<old>&new_name=<new>` - 重命名全局变量（按名称）
- `GET /api/rename/label?address=<addr>&new_name=<name>` - 重命名标签
- `GET /api/rename/datatype?name=<old>&new_name=<new>` - 重命名数据类型（按名称）
- `GET /api/rename/datatype?path=<path>&new_name=<new>` - 重命名数据类型（按路径）
- `GET /api/rename/namespace?name=<old>&new_name=<new>` - 重命名命名空间/类（支持路径如 `std::MyClass`）

*Decompiler 级别*（推荐，修改反编译视图中的变量名）:
- `GET /api/rename/decompiler/variable?function=<func>&var_name=<old>&new_name=<new>` - 重命名反编译器变量
- `GET /api/rename/decompiler/variable?function_address=<addr>&var_name=<old>&new_name=<new>&timeout=30` - 按函数地址定位
- `GET /api/rename/decompiler/parameter?function=<func>&param=<idx|name>&new_name=<new>` - 重命名反编译器参数
- `GET /api/rename/decompiler/split?function=<func>&var_name=<old>&use_address=<addr>&new_name=<new>` - 拆分变量（Split out as new variable）
- `GET /api/rename/decompiler/variable/instances?function=<func>&var_name=<name>` - 列出变量的所有使用点（用于确定拆分位置）

*函数签名修改*（一次性设置完整函数签名）:
- `GET /api/rename/function_signature?function=<func>&signature=<c_signature>` - 通过 C 签名字符串修改函数签名
  - 支持函数名、返回类型、调用约定、参数（类型+名称）一次性设置
  - 签名格式: `int main(int argc, char **argv)` 或 `int __stdcall MessageBoxA(HWND hWnd, ...)`
  - 支持的调用约定: `__stdcall`, `__cdecl`, `__fastcall`, `__thiscall`, `__vectorcall`

> **注意**: Listing 级别的 `variable/parameter` 操作的是底层存储单元（栈变量、寄存器变量），
> 反编译器可能会将多个底层变量聚合为一个逻辑变量，导致修改不生效。
> 推荐使用 `decompiler/*` 系列 API，直接操作反编译视图中显示的变量。
>
> **Split 功能**: 当编译器复用同一寄存器存储不同逻辑变量时（如循环计数器后被复用为返回值），
> 可使用 `split` API 将特定使用点拆分为独立变量。注意：仅支持寄存器变量，栈变量暂不支持。

**DataType API** (`/api/datatype/*`) - 数据类型操作:

*类型设置*（设置变量/参数/返回值的类型）:
- `GET /api/datatype/set/return?function=<name>&type=<type>` - 设置函数返回类型
- `GET /api/datatype/set/parameter?function=<name>&param=<idx|name>&type=<type>` - 设置函数参数类型
- `GET /api/datatype/set/decompiler/variable?function=<name>&var_name=<var>&type=<type>` - 设置反编译器变量类型（推荐）
- `GET /api/datatype/set/decompiler/parameter?function=<name>&param=<idx|name>&type=<type>` - 设置反编译器参数类型（推荐）
- `GET /api/datatype/set/global?address=<addr>&type=<type>` - 设置全局变量类型
- `GET /api/datatype/set/field?struct=<name>&field=<idx|name>&type=<type>` - 设置结构体字段类型

*类型创建*:
- `GET /api/datatype/create/struct?name=<name>&category=/&packing=0&fields=<json>` - 创建结构体
  - `fields` JSON: `[{"name": "x", "type": "int", "comment": "..."}]`
- `GET /api/datatype/create/enum?name=<name>&category=/&size=4&members=<json>` - 创建枚举
  - `members` JSON: `{"OK": 0, "ERROR": 1}` 或 `[{"name": "OK", "value": 0}]`
- `GET /api/datatype/create/typedef?name=<name>&base_type=<type>&category=/` - 创建 typedef
- `GET /api/datatype/create/union?name=<name>&category=/&members=<json>` - 创建联合体
  - `members` JSON: `[{"name": "i", "type": "int"}]`
- `GET /api/datatype/create/funcdef?name=<name>&return_type=void&params=<json>&calling_convention=` - 创建函数定义（函数指针）
  - `params` JSON: `[{"name": "ctx", "type": "void *"}]`

*类型管理*:
- `GET /api/datatype/struct/field/add?struct=<name>&type=<type>&name=<name>&at=-1` - 添加结构体字段
- `GET /api/datatype/struct/field/delete?struct=<name>&field=<idx|name>` - 删除结构体字段
- `GET /api/datatype/struct/field/modify?struct=<name>&field=<idx|name>&new_name=&new_type=&new_comment=` - 修改结构体字段
- `GET /api/datatype/enum/member/add?enum=<name>&name=<name>&value=<value>` - 添加枚举成员
- `GET /api/datatype/enum/member/delete?enum=<name>&name=<name>` - 删除枚举成员
- `GET /api/datatype/delete?path=<path>` 或 `?name=<name>` - 删除数据类型
- `GET /api/datatype/copy?source=<path>&dest_category=/&new_name=` - 复制数据类型
- `GET /api/datatype/move?source=<path>&dest_category=/` - 移动数据类型

*C 代码解析*:
- `GET /api/datatype/parse/c?code=<urlencoded_c>&category=/` - 解析 C 代码创建类型
  - 支持 struct、typedef、enum 定义

*类型查询*:
- `GET /api/datatype/info?name=<name>` 或 `?path=<path>` - 获取数据类型详细信息
- `GET /api/datatype/list?category=/&q=<query>&limit=100` - 列出数据类型（支持通配符）

*类型导出*:
- `GET /api/datatype/export/c` - 导出全部类型为 C header
- `GET /api/datatype/export/c?category=<path>` - 导出指定类别
  - 注意：函数声明不会导出（Ghidra 限制），除非是 function pointer typedef

> **类型字符串格式**: 支持内置类型（`int`, `char`, `void`, `float`, `double` 等）、指针（`int *`, `char **`）、数组（`int[10]`, `char[256]`）、路径（`/MyCategory/MyStruct`）

**Memory API** (`/api/memory/*`) - 内存读取:
- `GET /api/memory/read?address=<addr>&length=256&format=hex` - 读取原始字节
  - `format`: `hex`(默认) / `base64` / `ascii` / `u8` / `u16le` / `u16be` / `u32le` / `u32be` / `u64le` / `u64be`
  - `length`: 最大 16384 (16KB)

**Program API** (`/api/program/*`) - 程序枚举/导入（运行时切换已废弃）:
- `GET /api/program/list` - 列出当前项目/仓库中的所有程序（包含 `active` 标记）
- `GET /api/program/open?name=<name>` - 已废弃，不需要；请在启动时通过 `PROGRAM_NAME` / `BINARY` 指定程序名或仓库路径
- `GET /api/program/import?path=<path>&name=<name>&analyze=true` - 导入 binary 到项目

> **环境变量**:
> - `PROGRAM_NAME` - 启动时指定要打开的程序名称或仓库路径，未设置则默认打开第一个程序
> - `IMPORT_BINARY_NAME` - 启动时自动从 `/import/` 目录导入的 binary 名称（Docker Client 模式）

**Version API** (`/api/version/*`) - 版本管理（仅 Ghidra Server 共享项目模式）:
- `GET /api/version/log?limit=50&diff=<n>` - 版本历史；`diff=N` 时附带与版本 N 的差异
- `GET /api/version/commit?comment=<msg>` - 保存并提交版本（自动独占 checkout）
  - 错误码 `merge_required`: 服务器有更新版本，需先 rollback 再重新修改提交
  - 错误码 `checkout_conflict`: 其他用户持有独占 checkout
- `GET /api/version/rollback` - 丢弃未提交修改，回退到最近一次 commit
- `GET /api/version/revert?version=<n>` - 回退到指定版本，永久删除之后的所有版本（**破坏性**）

> **注意**: 非 Server 模式（GUI 本地项目）调用会返回错误。
> MCP proxy 启动时自动检测，不支持时不注册 `ghidra_version` tool。
> Commit 使用独占 checkout，同一 binary 同时只有一个写入者。

### 版本管理与协作模式

Bridge 在两种运行模式下对写操作（rename、comment、datatype 等）的版本管理行为不同：

**Headless 模式（Docker/PyGhidra）— 自动 checkout/commit**

写操作自动完成 checkout/save，通过 idle timer 延迟 checkin，MCP 使用者无需手动管理版本：

```
首次写操作 → ensure_checkout(exclusive=True) → handler → auto_save(prog.save + 重置 timer)
后续写操作 → 已 checked out → handler → auto_save(prog.save + 重置 timer)
最后一次写操作后 5 秒无新写入 → timer 触发 → checkin(keepCheckedOut=False) → 释放 checkout
```

- 连续的写操作共享同一次 checkout，idle timer 不断重置，最终产生一个 commit
- `@route` 装饰器通过 `writes=True` 标记写操作路由，`dispatch_route` 自动包裹 checkout/save middleware
- `POST /api/v1/edit` 和 `POST /api/v1/exec`（`readonly=False`）在 `do_POST` 中包裹
- 非 Server 模式（本地项目）所有 checkout/save 函数为 no-op
- 成功的写操作返回结果中附带 `_saved` 字段
- `ghidra_version(action="log")` 调用前会自动 flush 未提交的修改
- `ghidra_version` tool 仍可用于查看历史（log）、回滚（rollback）、回退（revert）

**GUI 模式（Ghidra CodeBrowser）— 用户管理**

GUI 模式下 checkout/checkin 由用户通过 Ghidra 界面管理，Bridge 不干预：

- `checkout.py` 通过检测 `docker_only_ghidra_mcp_server` 模块是否加载来判断运行模式
- GUI 模式下 `_get_domain_file()` 返回 `None`，所有 checkout/commit 函数为 no-op
- 写操作正常执行（startTransaction → modify → endTransaction），但不触发 checkout/commit
- 用户需通过 Ghidra GUI 的 Project 菜单手动 checkout、save、checkin

**写操作路由标记**:

```python
@route("/api/rename/function", writes=True)  # 写操作，自动 checkout/commit（Headless）
@route("/api/search/functions")              # 读操作，无 checkout/commit
```

写操作模块: `rename.py`(11), `comment.py`(1), `datatype.py`(20), `program.py`(1 import)

**V1 API** (`/api/v1/*`) - 面向 AI 的聚合接口:

所有 V1 API 默认返回 compact 格式（数组 + `_schema`），可通过 `verbose=true` 获取完整 dict 格式。

- `GET /api/v1/overview?top_funcs=20&top_strings=30&verbose=false` - 二进制全景概览（推荐首次调用）
  - `top_funcs`: 返回的关键函数数量（默认 20，按 xref 数 + 用户命名加分排序）
  - `top_strings`: 返回的关键字符串数量（默认 30，按信息量评分排序）
  - 返回: metadata, segments, statistics, entry_points, top_functions, imports_by_library, exports, notable_strings
- `GET /api/v1/search?q=<query>&types=auto&limit=20&verbose=false` - 统一搜索（支持智能类型推断）
  - `types`: `auto`(智能推断) / `all` / 逗号分隔（如 `functions,symbols,strings`）
  - `verbose`: `true` 返回完整 dict，默认 compact 数组格式
- `GET /api/v1/view?q=<query>&type=both&timeout=30&limit=500&verbose=false` - 统一查看（支持批量查询）
  - `q`: 函数名或地址，逗号分隔支持批量（如 `main,init,0x401000`）；当 `type=header` 时作为 category 过滤
  - `type`: `both`(默认) / `decompile` / `disassemble` / `header` / `memory`
    - `header`: 导出程序数据类型为 C header 格式，`q` 参数作为 category 路径（默认 "/" 导出全部）
    - `memory`: 读取起始地址处的原始字节，`q` 为地址，`limit` 为长度
  - `verbose`: `true` 返回完整 dict，默认 compact info 数组格式
- `GET /api/v1/list?q=<query>&types=auto&limit=100&verbose=false` - 统一列表（类似 ls 的符号浏览）
  - `q`: 名称过滤（支持通配符 `*` `?`）
  - `types`: `auto`(默认=functions) / `all` / 逗号分隔（如 `functions,classes,imports`）
  - `start`/`end`: 地址范围过滤（如 `start=0x401000&end=0x402000`）
  - `library`: imports 的库名过滤（如 `library=kernel32`）
  - `verbose`: `true` 返回完整 dict，默认 compact 数组格式
  - 支持类型: functions, classes, namespaces, labels, globals, imports, exports, datatypes
- `POST /api/v1/edit` - 统一编辑接口（rename + datatype + comment）
  - 请求体: `{"action": "<action>", ...params}` 单操作
  - 批量: `{"actions": [{...}, {...}]}` 多操作
  - `verbose`: `true` 返回详细输入输出
  - **Rename actions**: `rename.function`, `rename.variable`, `rename.parameter`, `rename.global`, `rename.label`, `rename.datatype`, `rename.namespace`, `rename.decompiler.variable`, `rename.decompiler.parameter`, `rename.decompiler.split`, `rename.function_signature`
  - **DataType set**: `datatype.set.return`, `datatype.set.parameter`, `datatype.set.decompiler.variable`, `datatype.set.decompiler.parameter`, `datatype.set.global`, `datatype.set.field`
  - **DataType parse**: `datatype.parse.c` - 通过 C 代码创建类型（struct/enum/typedef/union/funcdef）
  - **Comment**: `comment.set`

- `POST /api/v1/exec` - 任意脚本执行（POST-only，不走 `@route` 装饰器，由 `do_POST` 直接处理）
  - 请求体: `{"code": "<source>", "language": "python", "readonly": true, "timeout": 120}`
  - **仅支持 `language=python`**：in-process 直接 `exec()` 用户代码，注入 Ghidra Flat API 全局变量（`currentProgram`、`toAddr`、`getFunctionAt` 等）。GUI 模式经 `scripts/exec_runner.py` 走 `runScript`；Headless 模式在 `_exec_python_inprocess` 内部直接 exec，不再走子进程。用户脚本里的 `result` 变量被 JSON 序列化返回，print 输出抓到 `stdout`
  - 历史上的 `language=java`（`analyzeHeadless` 子进程）已移除——子进程跟 MCP client 抢同一个 binary 的 exclusive checkout，handoff 路径有 race；写场景请用 `ghidra_edit` 批量 `actions` 或 `language=python`
  - `readonly=false`: 由 `do_POST` 包裹 `ensure_checkout` + `auto_save`，与 `/api/v1/edit` 相同的 checkout/commit 生命周期
  - MCP proxy 暴露此端点供 `ghidra_exec` 工具调用（`mcp_sse_proxy.py`、`mcp_stdio.py`）

**Error Handling**: Minimal logging to avoid Ghidra console noise, but preserve error context in API responses

## Adding New API Endpoints

使用 `@route` 装饰器添加新 API（**无需修改服务器代码**）：

1. 在 `api/` 目录创建新模块：
```python
# api/my_api.py
from api import route

@route("/api/my_api")
def my_function(state, param1="", param2=None, limit=100):
    """读操作示例。"""
    prog = state.getCurrentProgram()
    # ... 业务逻辑
    return {"success": True, "data": ...}

# 写操作：添加 writes=True，Headless 模式下自动 checkout/commit
@route("/api/my_api/update", writes=True)
def my_update(state, name="", new_name=""):
    """写操作示例。"""
    prog = state.getCurrentProgram()
    tx_id = prog.startTransaction("My Update")
    try:
        # ... 修改操作
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return {"success": False, "error": str(e)}
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
- 修改程序数据的路由须标记 `writes=True`，Headless 模式下自动 checkout/commit

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

### Jep "No Jep instance available on current thread" Error

**重要**: 当遇到 `No Jep instance available on current thread` 错误时，**这通常不是真正的线程问题**，而是以下两种情况之一：

1. **Java 类名大小写错误** - Ghidra 的 Java 类名区分大小写
   - 错误示例: `from ghidra.program.model.data import Typedef` (小写 d)
   - 正确示例: `from ghidra.program.model.data import TypeDef` (大写 D)
   - 参考 commit: `caa2a0f` (Fix TypeDef class name)

2. **热重载时的 Java 类导入问题** - 热重载 (`/_reload`) 在 HTTP 工作线程上执行，无法通过 Jep 导入新的 Java 类
   - **解决方案**: 使用 `sys.modules` 缓存机制，确保 Java 类在主线程（服务器启动时）导入并缓存
   - 参考实现 (`api/datatype.py`):
   ```python
   # Cache CParser in sys.modules to survive hot reloads on worker threads
   import sys
   _CPARSER_CACHE_KEY = '_ghidra_api_datatype_cparser'
   if _CPARSER_CACHE_KEY not in sys.modules:
       from ghidra.app.util.cparser.C import CParser as _CParser
       sys.modules[_CPARSER_CACHE_KEY] = _CParser
   CParser = sys.modules[_CPARSER_CACHE_KEY]
   ```

**诊断步骤**:
1. 首先检查 Java 类名拼写和大小写是否正确（查阅 Ghidra API 文档）
2. 如果类名正确，检查导入是否在函数内部（lazy import）
3. 将 lazy import 改为模块级导入，并使用 `sys.modules` 缓存
4. 重启 Ghidra 服务器（在主线程执行模块加载）验证修复

## Docker Deployment

单一镜像通过 `RUN_MODE` 环境变量控制运行模式（`SERVER` / `CLIENT`）。

### 权限模型（admin-owned）

仓库始终由 admin 创建并拥有 `+a`，客户端是被显式授权的二等公民：

| 用户类型 | 注册方式 | 默认权限 |
|---|---|---|
| **password admin**（如 `syec`） | `gmcp server up` 首次或 `gmcp server add-user` | 所有 repo +a，GUI 用 |
| **`bridgectl`**（SSH） | `gmcp server up` 自动生成 SSH key | 所有 repo +a，仅供 `gmcp` CLI 自动化（如创建 repo） |
| **客户端身份**（SSH） | `gmcp client start` 时生成 UUID 或 `--user <name>` | 仅 `gmcp server repo grant` 显式授予的 repo |

ACL sync loop（每 5s）维护：①password 用户始终 `+a`；②`bridgectl` 始终 `+a`；③其他 SSH 用户只看 `/repos/.bridge-acl.conf` 显式 grants。客户端容器不再有 `createRepository` 权限——不存在的 repo 由 admin 通过 `gmcp server repo create` 走 `bridgectl` 创建。

### 快速启动

```bash
pip install -e .          # 安装 gmcp CLI

# 1) 启动 Server（首次自动创建 .env + bridgectl SSH key + 注册管理员）
gmcp server up

# 2) admin 创建 repo（必须；client 不能自己建）
gmcp server repo create myproj

# 3) 启动 Client（默认生成 ephemeral UUID 身份，自动 +w grant）
gmcp client start 1 --repo myproj --binary-file ~/alpha.bin
gmcp client start 1 --repo myproj --binary 38.1.0/alpha                            # 仓库路径
gmcp client start 2 --repo myproj --user alice                                     # 显式身份

# 停止
gmcp client stop 1    # 不释放身份；UUID 留在 .bridge-acl.conf，再次 start 会重生成新 UUID
gmcp down             # 全部停止
```

**首次启动流程**:
1. `gmcp server up` 自动创建 `docker/.env`（默认 `GHIDRA_DATA_DIR=~/ghidra-data`）
2. 在 `${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/ssh/clients/bridgectl/` 生成自动化身份 SSH key
3. 启动 Ghidra Server（端口 13100）
4. 交互式注册管理员用户（用户名 + 密码），用于 Ghidra GUI 访问
5. ACL sync loop（每 5 秒）将 admin 和 `bridgectl` 授权到所有 repo

**连接 Ghidra GUI**: File → New Project → Shared Project → `localhost:13100` → 使用注册的管理员用户名

### 常用命令

```bash
# Server 管理
gmcp server up / down / restart / logs
gmcp server users                                 # 列出用户
gmcp server add-user <name>                       # 添加 password 管理员
gmcp server repos                                 # 列出仓库 + ACL（svrAdmin -list --users）
gmcp server clean                                 # 删除所有数据
gmcp server migrate-acl                           # 清理遗留 bridge-N 用户（一次性）

# Repo 管理（admin-owned，必须 admin 操作）
gmcp server repo create <name>                    # 通过 bridgectl 创建
gmcp server repo delete <name>                    # 停 server → rm -rf → 重启
gmcp server repo grant <user> <repo> +w           # 授权（写入 .bridge-acl.conf）
gmcp server repo revoke <user> <repo>             # 撤销（同时 svrAdmin -revoke）
gmcp server repo list                             # 显示 repo + 显式 grants

# Client 管理
gmcp client start N --repo <repo> [--user <name>] [--binary <name>] [--binary-file <path>]
gmcp client stop N / logs N

# 一键操作
gmcp up --repo <name> --binary <name>   # 启动 Server + Client 1
gmcp down                               # 停止全部

# 信息和调试
gmcp info                                                  # 当前配置（GHIDRA_VERSION、数据目录、端口）
gmcp versions                                              # 列出 GHIDRA_DATA_DIR 下已安装版本
gmcp switch-version <ver>                                  # 切换 GHIDRA_VERSION（写入 docker/.env）
gmcp status                                                # 探测 server + 所有 client 的容器/端口/HTTP/basic_info
gmcp troubleshoot check                                    # 诊断问题（端口冲突、Docker 状态、SSH key 等）

# 镜像与开发模式
gmcp build                                                 # docker compose build
gmcp rebuild                                               # down -v + build + up -d
gmcp dev up / dev reload / dev health / dev test / dev shell / dev logs

# AI 集成（向当前项目安装 Skill，或向 AI 客户端配置 MCP）
gmcp install -d <dir> skill claude-code                    # → <dir>/.claude/commands/
gmcp install -d <dir> skill codex                          # → <dir>/AGENTS.md
gmcp install -d <dir> skill cursor                         # → <dir>/.cursor/rules/ghidra-mcp.md
gmcp install -d <dir> skill copilot                        # → <dir>/.github/copilot-instructions.md
gmcp install mcp claude-code [--client N]                  # 写入 claude mcp（自动按 N 计算端口）
gmcp install mcp claude-desktop                            # 写入 claude_desktop_config.json
gmcp install mcp coco                                      # 调用 coco mcp add-json
```

**Makefile 替代方式**（从 `docker/` 目录执行）:
```bash
make server-up                 # 同 gmcp server up（首次也会注册管理员）
make client N=1 REPO=test BINARY=test_alpha
make client N=2 REPO=test BINARY=modules/test_beta BINARY_FILE=~/beta.bin
make client-stop N=1
make down-separated
```

### 参数和端口

- `--repo` / `REPO`（必选）：Ghidra Server 仓库名
- `--binary` / `BINARY`（推荐）：要打开的程序名或仓库路径
- `--binary-file` / `BINARY_FILE`（可选）：主机上的 binary 文件路径，自动导入到 repo
- **端口计算**: Client N → HTTP 8800+(N-1)*10+3, SSE +1（如 N=1→8803/8804, N=2→8813/8814）

### 设计原则

- MCP Tools 保持不变，纯分析工具，不包含 program 管理
- Client 生命周期由 `gmcp` CLI 或 Makefile 管理
- 程序在启动时通过 `--binary` / `PROGRAM_NAME` 绑定；运行时切换不需要
- Program API 仅保留枚举/导入能力，不暴露为 MCP tool

详细架构、数据持久化和部署说明见 `docker/ARCHITECTURE.md` 和 `docker/QUICKSTART.md`。

## CLI Development (`cli/` and `pyproject.toml`)

`gmcp` 是项目内置的 Python Click CLI，源码全部在 `cli/`：

- `pip install -e .` 后通过 `pyproject.toml` 的 `[project.scripts] gmcp = "cli.main:cli"` 暴露
- 单一 `requires-python >=3.10`；运行时只依赖 `click>=8.1`（极简，避免污染调用者环境）
- 可选 extra `[bridge]` 列出服务器侧需要的 `mcp`/`uvicorn`/`httpx`，但 CLI 本身不依赖它们
- 添加新子命令的标准流程：在 `cli/commands/<name>.py` 写 Click command 或 group，然后在 `cli/main.py` `cli.add_command(...)` 注册
- 与 Docker 交互统一走 `cli/docker.py`（不要直接调 `subprocess.run("docker compose ...")`，避免遗漏 env_overrides / project name）
- 端口计算只走 `cli/ports.py:client_ports(n)`，写死 N→端口公式在多个地方会漂移

## Logging and Observability

服务器进程同时把日志写到两个地方（见 `utils/logging_config.py`）：

- **Ghidra 控制台**：主线程 `print(...)`（GUI 模式可见、Docker Headless 模式重定向到容器 stdout）
- **滚动文件**：`tempdir/ghidra_mcp_bridge.log`（10MB × 3 backup），所有守护线程写入。在 GUI 模式下 Script 执行结束后控制台失效，文件日志是唯一的诊断入口。位置：
  - macOS: `/var/folders/.../T/ghidra_mcp_bridge.log`（或 `$TMPDIR`）
  - Linux: `/tmp/ghidra_mcp_bridge.log`
  - Docker 容器: `/tmp/ghidra_mcp_bridge.log`

调试时常用 `tail -F $(python3 -c "import tempfile,os;print(os.path.join(tempfile.gettempdir(),'ghidra_mcp_bridge.log'))")`。

## Further Reading

- **`skills/SKILL.md`** — `gmcp install skill` 写入的 AI 工作流说明（首次接入项目时建议先读）
- **`docker/ARCHITECTURE.md`** — 单镜像 `RUN_MODE` 双模、数据卷布局、网络拓扑
- **`docker/QUICKSTART.md`** — Server/Client/Local-Project 三种部署模式的最短路径
- **`docker/ISSUES.md`** — 已知问题与变通方案
- **`examples/api-usage/curl-examples.sh`** — 全部 HTTP API 的 curl 调用合集（最快的"这个 API 怎么用"查询入口）
- **`examples/mcp/`** — Claude Desktop / Coco 的 MCP 配置示例
- **`README.md`** / **`README_ZH.md`** — 用户视角的 Quick Start 与功能高亮
