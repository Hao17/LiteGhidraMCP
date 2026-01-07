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
  - **`rename.py`**: Rename API，重命名函数、变量、参数、标签、数据类型、命名空间等
  - **`datatype.py`**: DataType API，数据类型设置、创建、管理和 C 头文件解析

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

# Rename API 测试 (Listing 级别)
curl "http://127.0.0.1:8803/api/rename/function?address=0x401000&new_name=my_main"
curl "http://127.0.0.1:8803/api/rename/function?name=FUN_00401000&new_name=main"
curl "http://127.0.0.1:8803/api/rename/variable?function=main&var_name=local_8&new_name=counter"
curl "http://127.0.0.1:8803/api/rename/parameter?function=main&param=0&new_name=argc"
curl "http://127.0.0.1:8803/api/rename/global?address=0x404000&new_name=g_config"
curl "http://127.0.0.1:8803/api/rename/label?address=0x401050&new_name=loop_start"
curl "http://127.0.0.1:8803/api/rename/datatype?name=struct_1&new_name=ConfigStruct"
curl "http://127.0.0.1:8803/api/rename/namespace?name=Class1&new_name=MyClass"

# Rename API 测试 (Decompiler 级别 - 推荐)
curl "http://127.0.0.1:8803/api/rename/decompiler/variable?function=main&var_name=local_8&new_name=counter"
curl "http://127.0.0.1:8803/api/rename/decompiler/variable?function_address=0x401000&var_name=uVar1&new_name=result"
curl "http://127.0.0.1:8803/api/rename/decompiler/parameter?function=main&param=0&new_name=argc"
curl "http://127.0.0.1:8803/api/rename/decompiler/parameter?function=main&param=param_1&new_name=argv"

# Split Variable API 测试 (拆分变量)
curl "http://127.0.0.1:8803/api/rename/decompiler/variable/instances?function=main&var_name=uVar1"  # 先查看使用点
curl "http://127.0.0.1:8803/api/rename/decompiler/split?function=main&var_name=uVar1&use_address=0x401050&new_name=result"

# V1 List API 测试
curl "http://127.0.0.1:8803/api/v1/list"
curl "http://127.0.0.1:8803/api/v1/list?q=init*"
curl "http://127.0.0.1:8803/api/v1/list?types=all&limit=20"
curl "http://127.0.0.1:8803/api/v1/list?types=functions,classes"
curl "http://127.0.0.1:8803/api/v1/list?start=0x401000&end=0x402000"
curl "http://127.0.0.1:8803/api/v1/list?types=imports&library=kernel32"

# V1 Edit API 测试 (POST)
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}'
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"action": "datatype.set.return", "function": "main", "type": "int"}'
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"action": "rename.decompiler.variable", "function": "main", "var_name": "local_8", "new_name": "counter"}'
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"action": "comment.set", "address": "0x401000", "type": "EOL", "text": "Entry point"}'
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"action": "datatype.create.struct", "name": "Point", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "int"}]}'
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"action": "datatype.parse.c", "code": "typedef struct { int x; int y; } Point;"}'
# V1 Edit API 批量操作
curl -X POST http://127.0.0.1:8803/api/v1/edit -H "Content-Type: application/json" -d '{"actions": [{"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}, {"action": "datatype.set.return", "function": "main", "type": "int"}, {"action": "comment.set", "name": "main", "type": "PLATE", "text": "Main entry"}]}'

# DataType API 测试 - 类型设置
curl "http://127.0.0.1:8803/api/datatype/set/return?function=main&type=int"
curl "http://127.0.0.1:8803/api/datatype/set/parameter?function=main&param=0&type=int"
curl "http://127.0.0.1:8803/api/datatype/set/decompiler/variable?function=main&var_name=local_8&type=int"
curl "http://127.0.0.1:8803/api/datatype/set/decompiler/parameter?function=main&param=0&type=char **"
curl "http://127.0.0.1:8803/api/datatype/set/global?address=0x404000&type=int"
curl "http://127.0.0.1:8803/api/datatype/set/field?struct=MyStruct&field=0&type=int"

# DataType API 测试 - 类型创建
curl "http://127.0.0.1:8803/api/datatype/create/struct?name=Point&fields=[{\"name\":\"x\",\"type\":\"int\"},{\"name\":\"y\",\"type\":\"int\"}]"
curl "http://127.0.0.1:8803/api/datatype/create/enum?name=Status&members={\"OK\":0,\"ERROR\":1}"
curl "http://127.0.0.1:8803/api/datatype/create/typedef?name=DWORD&base_type=uint"
curl "http://127.0.0.1:8803/api/datatype/create/union?name=Value&members=[{\"name\":\"i\",\"type\":\"int\"},{\"name\":\"f\",\"type\":\"float\"}]"
curl "http://127.0.0.1:8803/api/datatype/create/funcdef?name=CallbackFn&return_type=void&params=[{\"name\":\"ctx\",\"type\":\"void *\"}]"

# DataType API 测试 - 类型管理
curl "http://127.0.0.1:8803/api/datatype/struct/field/add?struct=Point&type=int&name=z"
curl "http://127.0.0.1:8803/api/datatype/struct/field/delete?struct=Point&field=z"
curl "http://127.0.0.1:8803/api/datatype/struct/field/modify?struct=Point&field=x&new_name=x_pos"
curl "http://127.0.0.1:8803/api/datatype/enum/member/add?enum=Status&name=PENDING&value=2"
curl "http://127.0.0.1:8803/api/datatype/enum/member/delete?enum=Status&name=PENDING"
curl "http://127.0.0.1:8803/api/datatype/delete?name=OldStruct"
curl "http://127.0.0.1:8803/api/datatype/copy?source=/Point&dest_category=/Geometry&new_name=Point2D"
curl "http://127.0.0.1:8803/api/datatype/move?source=/Point&dest_category=/Geometry"

# DataType API 测试 - C 解析
curl "http://127.0.0.1:8803/api/datatype/parse/c?code=typedef%20struct%20{%20int%20x;%20int%20y;%20}%20Point;"

# DataType API 测试 - 查询
curl "http://127.0.0.1:8803/api/datatype/info?name=Point"
curl "http://127.0.0.1:8803/api/datatype/list?category=/&limit=50"
curl "http://127.0.0.1:8803/api/datatype/list?q=*Struct*"

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

> **注意**: Listing 级别的 `variable/parameter` 操作的是底层存储单元（栈变量、寄存器变量），
> 反编译器可能会将多个底层变量聚合为一个逻辑变量，导致修改不生效。
> 推荐使用 `decompiler/*` 系列 API，直接操作反编译视图中显示的变量。
>
> **Split 功能**: 当编译器复用同一寄存器存储不同逻辑变量时（如循环计数器后被复用为返回值），
> 可使用 `split` API 将特定使用点拆分为独立变量。注意：仅支持寄存器变量，栈变量暂不支持。

**Bookmark API**: 不提供支持。原因：
1. Comment 和 Label 已覆盖标记需求（EOL/PRE/POST/PLATE 注释 + 自定义标签）
2. AI 工作流通过地址/符号名直接定位，不依赖用户态的书签导航机制

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

> **类型字符串格式**: 支持内置类型（`int`, `char`, `void`, `float`, `double` 等）、指针（`int *`, `char **`）、数组（`int[10]`, `char[256]`）、路径（`/MyCategory/MyStruct`）

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
  - 支持类型: functions, classes, namespaces, labels, globals, imports, exports, datatypes
- `POST /api/v1/edit` - 统一编辑接口（rename + datatype + comment）
  - 请求体: `{"action": "<action>", ...params}` 单操作
  - 批量: `{"actions": [{...}, {...}]}` 多操作
  - `verbose`: `true` 返回详细输入输出
  - **Rename actions**: `rename.function`, `rename.variable`, `rename.parameter`, `rename.global`, `rename.label`, `rename.datatype`, `rename.namespace`, `rename.decompiler.variable`, `rename.decompiler.parameter`, `rename.decompiler.split`
  - **DataType set**: `datatype.set.return`, `datatype.set.parameter`, `datatype.set.decompiler.variable`, `datatype.set.decompiler.parameter`, `datatype.set.global`, `datatype.set.field`
  - **DataType create**: `datatype.create.struct`, `datatype.create.enum`, `datatype.create.typedef`, `datatype.create.union`, `datatype.create.funcdef`
  - **DataType manage**: `datatype.struct.field.add`, `datatype.struct.field.delete`, `datatype.struct.field.modify`, `datatype.enum.member.add`, `datatype.enum.member.delete`, `datatype.delete`, `datatype.parse.c`
  - **Comment**: `comment.set`

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
