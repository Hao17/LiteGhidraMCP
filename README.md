# Ghidra MCP Bridge

基于 Ghidrathon 的 MCP (Model Context Protocol) Bridge，在 Ghidra 内部运行，为 AI 系统提供对 Ghidra 逆向工程能力的编程访问。

## Claude Desktop 配置

### 前置条件

1. 在 Ghidra 中通过 Ghidrathon 执行 `ghidra_mcp_server.py` 启动服务器
2. 确认服务器已启动（日志显示 `Server started on http://127.0.0.1:8803`）

### 方式一：SSE 模式（推荐）

SSE 模式作为 Ghidra 内置线程运行，直接访问 Ghidra API，性能更好。

编辑 Claude Desktop 配置文件：
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/claude/settings.json`

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8804/sse"
    }
  }
}
```

### 方式二：stdio 模式（调试用）

stdio 模式作为独立 Python 进程运行，通过 HTTP API 与 Ghidra Bridge 通信，便于本地调试。

```
┌─────────────────┐     stdio      ┌─────────────────┐     HTTP      ┌─────────────────┐
│  Claude Desktop │ ◄────────────► │   mcp_stdio.py  │ ◄───────────► │  Ghidra Bridge  │
└─────────────────┘                └─────────────────┘               └─────────────────┘
```

配置示例：

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

**参数说明：**
- `command`: Python 解释器路径（需安装 `mcp` 库）
- `--host`: Ghidra Bridge 主机地址（默认: `127.0.0.1`）
- `--port`: Ghidra Bridge HTTP API 端口（默认: `8803`）

**依赖安装：**
```bash
pip install mcp
```

### SSE vs stdio 模式对比

| 特性 | SSE 模式 | stdio 模式 |
|------|----------|------------|
| 进程 | Ghidra 内置线程 | 独立 Python 进程 |
| 配置 | `"url": "http://...sse"` | `"command": "python"` |
| 调试 | 无法直接调试 | 可用 IDE 调试 |
| 性能 | 直接访问 Ghidra API | 通过 HTTP 代理 |
| 适用场景 | 生产使用 | 本地开发调试 |

## 可用 MCP 工具

- `ghidra_search`: 统一搜索（函数、符号、字符串、交叉引用等）
- `ghidra_view`: 反编译/反汇编查看
- `ghidra_list`: 符号列表浏览
- `ghidra_edit`: 统一编辑（重命名、类型设置、注释）
- `ghidra_basic_info`: 获取程序基本信息

## 环境变量

- `GHIDRA_MCP_HOST`: HTTP API 主机地址（默认: `127.0.0.1`）
- `GHIDRA_MCP_PORT`: HTTP API 端口（默认: `8803`）
- `GHIDRA_MCP_SSE_PORT`: MCP SSE 服务器端口（默认: `8804`）
