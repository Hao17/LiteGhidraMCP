# Ghidra MCP Bridge

[English](README.md) | 简体中文

> **版本说明**：
> - **当前分支 (main)**：Ghidra 12.0+ / PyGhidra 版本
> - **Ghidra 11.x 用户**：请切换到 [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) 分支或使用 [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

基于 PyGhidra 的 MCP (Model Context Protocol) Bridge，在 Ghidra 12.0+ 内部运行，为 AI 系统提供对 Ghidra 逆向工程能力的编程访问。

### 亮点

- **7 个 MCP 工具** — 统一入口，模式分发到 50+ API，无工具膨胀。
- **版本控制 + AI/人类协作** — 多个 AI Agent 与人类分析师通过 Ghidra Server 协同分析同一 binary，完整版本历史。
- **多 binary 跨文件分析** — 同一项目下启动多个 Client 分析不同 binary。适用于 VMP 脱壳、DLL-EXE 交互追踪、多模块固件等场景。
- **AI 友好** — 克隆仓库、安装 Skill，然后让 Claude Code / Codex 帮你完成一切 — 启动 Server、拉起 Client、配置 MCP、开始分析。

---

## 快速开始指引

### 让 AI 帮你搞定 ⭐

```bash
git clone https://github.com/Hao17/LiteGhidraMCP.git && cd LiteGhidraMCP
pip install -e .
gmcp install -d . skill claude-code   # 或: codex / cursor / copilot
```

然后告诉你的 AI：

> *"帮我分析 ~/Downloads/firmware.bin"*

它知道如何启动 Server、导入 binary、配置 MCP、开始分析。

### 手动部署

**Docker Server-Client 模式**（推荐）
- → [Docker 部署](#docker-部署)：AI + GUI 协作，多客户端
- 一条命令启动，自动生成 SSH 密钥，交互式注册管理员

**GUI 模式**（无需 Docker）
- → [GUI 模式](#gui-模式)：直接在 Ghidra 中运行脚本
- 最适合单人分析工作

手动部署后，→ [连接 AI](#连接-ai) 接入 MCP。

---

## Docker 部署

### 安装 CLI

```bash
pip install -e .
```

安装后即可使用 `gmcp` 命令管理所有 Docker 操作。运行 `gmcp --help` 查看可用命令。

### Separated Server-Client 模式 ⭐ 推荐

AI（Docker）+ GUI（人工）协作，一条命令部署。每个 Client 启动时绑定一个 REPO/BINARY（程序名或仓库路径），运行时不支持切换。

> **Apple Silicon / ARM 主机注意**：
> Ghidra 官方发布包目前不包含 `linux_arm_64` 的反编译器二进制。Docker 运行 Bridge 时应使用 `linux/amd64`；本仓库的 compose 默认已固定为该平台，避免出现 `Could not find decompiler executable`。

```bash
# 启动 Server（首次运行自动创建配置并提示注册管理员用户）
gmcp server up

# 启动 Client（--repo 必选，--binary 推荐）
gmcp client start 1 --repo test --binary my_binary                          # 打开已有 binary
gmcp client start 1 --repo test --binary 38.1.0/my_binary                  # 按仓库路径打开 binary
gmcp client start 1 --repo test --binary my_binary --binary-file ~/a.bin   # 导入并打开

# 第二个客户端，使用不同端口 (8813/8814)
gmcp client start 2 --repo test --binary modules/other_binary

# 或一条命令启动 Server + Client 1
gmcp up --repo test --binary my_binary
```

#### 启动后

- Ghidra Server 在端口 `13100` 启动
- **仅首次启动**：提示注册管理员用户（用户名 + 密码），用于 GUI 访问。此后所有新建仓库自动授权给该管理员。
- 每个客户端自动生成 SSH 密钥并注册为 `bridge-<N>`
- 仓库在首个客户端连接时自动创建
- HTTP API: `http://localhost:8803`，MCP SSE: `http://localhost:8804/sse`

#### 连接 Ghidra GUI

1. File → New Project → **Shared Project**
2. Server: `localhost:13100`
3. User: 你注册的管理员用户名（或 `root`），**取消勾选** "Use PKI authentication"
4. Password: 注册时设置的密码（`root` 的密码在 `gmcp server logs` 中查找）
5. 选择一个仓库

#### 常用命令

```bash
gmcp server logs         # 查看 Server 日志
gmcp server users        # 列出已注册用户
gmcp server add-user x   # 添加新用户（交互式设置密码）
gmcp client logs 1       # 查看 Client 1 日志
gmcp client list         # 列出所有运行中的客户端
gmcp down                # 停止所有服务（Server + 全部 Client）
gmcp server clean        # 删除所有数据（破坏性操作，下次启动重新注册管理员）
gmcp info                # 查看当前配置
gmcp troubleshoot check  # 诊断问题
```

> **详细指南**: [docker/QUICKSTART.md](docker/QUICKSTART.md)

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

**环境要求：** Ghidra 12.0+（脚本依赖 PyGhidra 运行时，默认 Jython/Java 环境下无法运行）。

### 1. 用 PyGhidra 启动 Ghidra

脚本必须在 **PyGhidra** 插件下加载。使用 Ghidra 自带的专用启动器：

```bash
# macOS / Linux
<ghidra_install>/support/pyghidraRun

# Windows
<ghidra_install>\support\pyghidraRun.bat
```

首次启动会创建一个独立的 Python venv（不在 Ghidra 安装目录里）：

| 系统 | 默认 venv 位置 |
|---|---|
| macOS | `~/Library/ghidra/ghidra_<版本>_PUBLIC/venv/` |
| Linux | `~/.config/ghidra/ghidra_<版本>_PUBLIC/venv/` |
| Windows | `%APPDATA%\ghidra\ghidra_<版本>_PUBLIC\venv\` |

如果之前没用 PyGhidra 启动过、或 venv 已损坏，直接删掉该目录后重新运行 `pyghidraRun` 即可重建。

### 2. 把 Bridge 依赖装到 PyGhidra venv

Bridge 会拉起一个 SSE 代理子进程，它需要 `mcp`、`uvicorn`、`httpx`。三个包必须装进 **PyGhidra venv**（不是系统 Python）：

```bash
# macOS 示例 —— 版本号根据自己的安装调整
~/Library/ghidra/ghidra_12.0.3_PUBLIC/venv/bin/python3 -m pip install -r requirements.txt
```

验证：

```bash
~/Library/ghidra/ghidra_12.0.3_PUBLIC/venv/bin/python3 -c "from mcp.server.fastmcp import FastMCP; import uvicorn, httpx"
```

### 3. 运行脚本

1. 在 Ghidra CodeBrowser 中打开一个二进制文件
2. 打开 Script Manager (`Window` → `Script Manager`)
3. **添加脚本路径**（首次使用）：点击 "Manage Script Directories"（文件夹图标）→ `+` → 选择本项目根目录 → OK
4. 运行 `ghidra_mcp_server.py`（**不要**运行 `docker_only_ghidra_mcp_server.py`，那是 Docker 专用，在 GUI 下会因容器路径报错）
5. 确认 Script 控制台显示：

   ```
   [Ghidra-MCP-Bridge] HTTP Server: http://127.0.0.1:8803
   [Ghidra-MCP-Bridge] MCP Server:  http://127.0.0.1:8804/sse
   [Ghidra-MCP-Bridge] Current Loaded Program: <name> (...)
   ```

   如果看到 `MCP proxy failed to start` 配 `ModuleNotFoundError: No module named 'mcp'`，说明第 2 步漏装或装到了错误的 Python。

---

## 连接 AI

### 安装 Skill（推荐）

Skill 会教会你的 AI 完整工作流 — 如何启停 Docker 服务、配置 MCP 连接、使用所有 Ghidra MCP 工具。安装后 AI 可以自主管理一切。

```bash
# 在你的项目目录下运行（-d 指定目标项目）
gmcp install -d . skill claude-code    # Claude Code → .claude/commands/
gmcp install -d . skill codex          # OpenAI Codex → AGENTS.md
gmcp install -d . skill cursor         # Cursor → .cursor/rules/ghidra-mcp.md
gmcp install -d . skill copilot        # GitHub Copilot → .github/copilot-instructions.md
```

> Skill 涵盖内容：[skills/SKILL.md](skills/SKILL.md)

### 配置 MCP 连接

如果只需要将 AI 客户端连接到已运行的 Bridge 实例：

```bash
gmcp install mcp claude-code        # Claude Code
gmcp install mcp claude-desktop     # Claude Desktop
gmcp install mcp coco               # Coco

# 多客户端（根据 Client N 自动计算端口）
gmcp install mcp claude-code --client 2   # → ghidra-2，端口 8814
```

<details>
<summary>手动 MCP 配置</summary>

**Claude Code:**

```bash
claude mcp add --transport sse ghidra http://127.0.0.1:8804/sse
```

**Claude Desktop**（macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`）：

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

**Coco:**

```bash
coco mcp add-json ghidra '{"type": "sse", "url": "http://127.0.0.1:8804/sse"}'
```

默认端点：`http://127.0.0.1:8804/sse`。多客户端：Client N → 端口 `8800+(N-1)*10+4`。

</details>

### MCP 工具

| 工具 | 说明 |
|------|------|
| **ghidra_overview** | 二进制全景概览 — 元数据、内存布局、关键函数、导入导出、字符串 |
| **ghidra_search** | 搜索函数、符号、字符串、交叉引用、字节、指令 |
| **ghidra_view** | 反编译/反汇编/内存查看 |
| **ghidra_list** | 符号列表浏览（函数、类、导入、导出等） |
| **ghidra_edit** | 重命名、设置数据类型、添加注释（支持批量） |
| **ghidra_exec** | 执行自定义 Python/Java 脚本，完整访问 Ghidra API |
| **ghidra_version** | 版本历史/回滚/回退（仅 Server 模式） |

---

## 高级选项

### HTTP API

```bash
curl http://127.0.0.1:8803/api/v1/overview
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"
curl "http://127.0.0.1:8803/api/v1/view?q=main&type=decompile"
curl "http://127.0.0.1:8803/api/memory/read?address=0x401000&length=256"
```

> 完整 API 文档参见 [CLAUDE.md](CLAUDE.md)。

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
    "ghidra-binary2": { "type": "sse", "url": "http://127.0.0.1:8814/sse" }
  }
}
```

---

## 项目结构

```
Bridge/
├── ghidra_mcp_server.py              # GUI 模式服务器（Ghidra Script Manager）
├── docker_only_ghidra_mcp_server.py  # Docker/Headless 模式服务器（PyGhidra）— 切勿在 GUI 运行
├── api/                              # API 模块（basic_info, search, view, memory, comment, rename, datatype, version, ...）
├── api_v1/                           # AI 友好聚合 API（overview, search, view, list, edit）
├── cli/                              # gmcp CLI（pip install -e .）
├── scripts/
│   ├── mcp_sse_proxy.py              # MCP SSE 代理（子进程）
│   └── mcp_stdio.py                  # MCP stdio 模式（独立进程）
├── skills/                           # AI Skill 文档（SKILL.md，由 `gmcp install skill` 写入）
├── utils/                            # 共享工具模块
└── docker/                           # Docker 部署（Server-Client 模式）
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

> 详细的 API 开发指南和架构说明请参见 [CLAUDE.md](CLAUDE.md)。
