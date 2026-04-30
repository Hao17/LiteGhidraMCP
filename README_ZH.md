# Ghidra MCP Bridge

[English](README.md) | 简体中文

> **版本说明**：
> - **当前分支 (main)**：Ghidra 12.0+ / PyGhidra 版本
> - **Ghidra 11.x 用户**：请切换到 [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) 分支或使用 [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

基于 PyGhidra 的 MCP (Model Context Protocol) Bridge，在 Ghidra 12.0+ 内部运行，为 AI 系统提供对 Ghidra 逆向工程能力的编程访问。

### 亮点

- **6 个聚合 MCP 工具** — 统一入口，模式分发到 50+ API，无工具膨胀。
- **版本控制 + AI/人类协作** — 多个 AI Agent 与人类分析师通过 Ghidra Server 协同分析同一 binary，完整版本历史。
- **多 binary 跨文件分析** — 同一项目下启动多个 Client 分析不同 binary。适用于 VMP 脱壳、DLL-EXE 交互追踪、多模块固件等场景。
- **GUI、Headless、Docker** — 同一套 API 代码支持所有模式。Docker Server-Client 支持 AI 全自主分析。

## 快速开始指引

**推荐：Docker 部署（一条命令）** ⭐
- → [Docker Server-Client 模式](#docker-部署)：AI + GUI 协作，每客户端独立用户隔离
- 一条命令启动，自动生成 SSH 密钥
- 适合生产环境、团队协作、多 AI Agent 场景

**替代方案：GUI 模式**
- → [在 Ghidra GUI 中运行](#gui-模式)：直接在 Ghidra 中运行脚本
- 无需 Docker，最适合单人分析工作

启动后，→ [配置 AI 客户端](#配置-ai-客户端) 连接你的 AI 工具。

---

## Docker 部署

### Separated Server-Client 模式 ⭐ 推荐

AI（Docker）+ GUI（人工）协作，一条命令部署。每个 Client 启动时绑定一个 REPO/BINARY（程序名或仓库路径），运行时不支持切换。

> **Apple Silicon / ARM 主机注意**：
> Ghidra 官方发布包目前不包含 `linux_arm_64` 的反编译器二进制。Docker 运行 Bridge 时应使用 `linux/amd64`；本仓库的 compose 默认已固定为该平台，避免出现 `Could not find decompiler executable`。

```bash
cd docker/

# 首次配置
cp .env.example .env
vim .env  # 设置 GHIDRA_DATA_DIR（如 ~/ghidra-data）

# 启动 Server
make server-up

# 启动 Client（REPO 必选，BINARY 推荐）
make client-up REPO=test BINARY=my_binary                       # 打开已有 binary
make client-up REPO=test BINARY=38.1.0/my_binary               # 按仓库路径打开 binary
make client-up REPO=test BINARY=my_binary BINARY_FILE=~/a.bin  # 导入并打开

# 第二个客户端，使用不同端口 (8813/8814)
make client2-up REPO=test BINARY=modules/other_binary
```

**启动后：**
- Ghidra Server 在端口 `13100` 启动，`root` 用户（随机密码在日志中）
- 每个客户端自动生成 SSH 密钥并注册为 `bridge-<N>`
- 仓库 `mcp-projects` 自动创建
- HTTP API: `http://localhost:8803`，MCP SSE: `http://localhost:8804/sse`

**连接 Ghidra GUI：**

1. File → New Project → **Shared Project**
2. Server: `localhost:13100`
3. User: `root`，**取消勾选** "Use PKI authentication"
4. Password: 从 `make server-logs` 获取（查找 `root (password): ...`）
5. Repository: `mcp-projects`

**常用命令：**

```bash
make server-logs      # 查看 Server 日志（root 密码在这里）
make server-users     # 列出已注册用户
make client-logs      # 查看 Client 日志
make down-separated   # 停止所有服务
make server-clean     # 删除所有数据（破坏性操作）
```

**详细指南**: [docker/QUICKSTART.md](docker/QUICKSTART.md#separated-server-client-mode-recommended-for-aigui-collaboration)

### 本地项目模式（仅自动化）

将本地 `.gpr` 项目挂载到 Docker 中。**GUI 无法同时打开该项目。**

```bash
cd docker && cp .env.example .env
# 编辑 .env: 设置 HOST_PROJECT_PATH、PROJECT_NAME、PROJECT_MODE=local
docker-compose up -d
```

### 外部 Ghidra Server

连接已有的 Ghidra Server，使用 `PROJECT_MODE=server`。详见 [docker/QUICKSTART.md](docker/QUICKSTART.md)。

---

## GUI 模式

**环境要求：** Ghidra 12.0+ 和 `pip install -r requirements.txt`

1. 在 Ghidra CodeBrowser 中打开一个二进制文件
2. 打开 Script Manager (`Window` → `Script Manager`)
3. **添加脚本路径**（首次使用）：点击 "Manage Script Directories"（文件夹图标）→ `+` → 选择项目根目录 → OK
4. 运行 `ghidra_mcp_server.py`
5. 确认日志中显示：
   ```
   Server started on http://127.0.0.1:8803
   MCP SSE server started on http://127.0.0.1:8804
   ```

---

## 配置 AI 客户端

启动 Bridge（Docker 或 GUI）后，将 AI 客户端连接到 MCP SSE 端点。

默认端点: `http://localhost:8804/sse`（Docker）或 `http://127.0.0.1:8804/sse`（GUI）

### 可用 MCP 工具

- **ghidra_overview**: 二进制全景概览 — 元数据、内存布局、统计、关键函数、导入导出、字符串（推荐首次调用）
- **ghidra_search**: 搜索函数、符号、字符串、交叉引用等
- **ghidra_view**: 反编译/反汇编/内存查看
- **ghidra_list**: 符号列表浏览
- **ghidra_edit**: 统一编辑（重命名、类型设置、注释）
- **ghidra_version**: 版本管理 — commit/log/rollback/revert（仅 Server 模式，条件注册）

### Coco

```bash
coco mcp add-json ghidra '{"type": "sse", "url": "http://127.0.0.1:8804/sse"}'
```

### Claude Desktop

编辑配置文件（macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`）：

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

保存后重启 Claude Desktop。

### Claude Code

```bash
claude mcp add --transport sse ghidra http://127.0.0.1:8804/sse
```

---

## 高级选项

### HTTP API

```bash
curl http://127.0.0.1:8803/api/v1/overview
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"
curl "http://127.0.0.1:8803/api/v1/view?q=main&type=decompile"
curl "http://127.0.0.1:8803/api/memory/read?address=0x401000&length=256"
```

完整 API 文档参见 [CLAUDE.md](CLAUDE.md)。

### 环境变量

```bash
export GHIDRA_MCP_HOST=127.0.0.1      # HTTP API 主机（默认: 127.0.0.1）
export GHIDRA_MCP_PORT=8803           # HTTP API 端口（默认: 8803）
export GHIDRA_MCP_SSE_PORT=8804       # MCP SSE 端口（默认: 8804）
export PROGRAM_NAME=""                # 启动时打开的程序名或仓库路径（默认: 第一个可用程序）
```

### 多程序同时分析

在不同 Ghidra 实例中使用不同端口，然后在 AI 客户端配置多个 MCP 服务器：

```json
{
  "mcpServers": {
    "ghidra-binary1": { "type": "sse", "url": "http://127.0.0.1:8804/sse" },
    "ghidra-binary2": { "type": "sse", "url": "http://127.0.0.1:8806/sse" }
  }
}
```

## 项目结构

```
Bridge/
├── ghidra_mcp_server.py           # GUI 模式服务器（Ghidra Script Manager）
├── docker_only_ghidra_mcp_server.py  # Docker/Headless 模式服务器（PyGhidra）— 切勿在 GUI Script Manager 运行
├── api/                           # API 模块（basic_info, search, view, memory, comment, rename, datatype, version, ...）
├── api_v1/                        # AI 友好聚合 API（overview, search, view, list, edit）
├── scripts/
│   ├── mcp_sse_proxy.py           # MCP SSE 代理（子进程）
│   └── mcp_stdio.py               # MCP stdio 模式（独立进程）
└── docker/                        # Docker 部署（Server-Client 模式）
```

## 故障排查

**服务器无法启动？**
- 确认已在 Ghidra CodeBrowser 中打开二进制文件
- 确认使用的是 Ghidra 12.0+（内置 PyGhidra 支持）

**AI 客户端无法连接？**
- 确认服务器已启动（检查 Ghidra Console 输出或 Docker 日志）
- 确认端口号正确（SSE 默认 8804）
- 重启客户端（Claude Desktop / Coco / Claude Code）

## 开发

详细的 API 开发指南和架构说明请参见 [CLAUDE.md](CLAUDE.md)。
