# Ghidra MCP Bridge

[English](README_EN.md) | 简体中文

基于 Ghidrathon 的 MCP (Model Context Protocol) Bridge，在 Ghidra 内部运行，为 AI 系统提供对 Ghidra 逆向工程能力的编程访问。

## 前置要求

### 1. Ghidra
推荐版本：**Ghidra 11.0+**

下载地址：https://ghidra-sre.org/

### 2. Ghidrathon
Ghidrathon 是 Ghidra 的 Python 3 脚本插件，本项目依赖它运行。

**安装步骤：**
1. 访问 [Ghidrathon Releases](https://github.com/mandiant/Ghidrathon/releases)
2. 下载最新版本的 `.zip` 文件（如 `ghidrathon-4.0.0.zip`）
3. 在 Ghidra 中: `File` → `Install Extensions...`
4. 点击 `+` 号，选择下载的 `.zip` 文件
5. 重启 Ghidra

**验证安装：**
- 打开 Ghidra CodeBrowser
- `Window` → `Script Manager`
- 确认可以看到 Python 3 脚本支持

### 3. Python 环境配置（用于 MCP 和 Claude Desktop）

**强烈建议使用虚拟环境：**

```bash
# 创建虚拟环境
python3 -m venv ghidra-env

# 激活虚拟环境
# macOS/Linux:
source ghidra-env/bin/activate
# Windows:
# ghidra-env\Scripts\activate

# 安装依赖
pip install -r requirements.txt
```

**配置 Ghidrathon 使用虚拟环境：**

安装完依赖后，需要告诉 Ghidrathon 使用这个虚拟环境：

```bash
# 运行 Ghidrathon 配置脚本
python3 -m ghidrathon.configure
```

按照提示输入：
1. **Ghidra 安装路径**（如 `/Applications/ghidra_11.0_PUBLIC/`）
2. **Python 解释器路径**（虚拟环境中的 Python，如 `/path/to/ghidra-env/bin/python3`）

配置完成后，重启 Ghidra 使配置生效。

## 快速开始

### 部署方式选择

**本地开发模式**（Ghidra GUI + Python 脚本）：
- ✅ 适合逆向工程师日常使用
- ✅ 可与 Ghidra GUI 交互
- ✅ 支持代码热重载
- 📖 见下方 "本地开发" 章节

**Docker 无头模式**（Headless + API 服务）：
- ✅ 适合持续运行的 AI 协作
- ✅ 容器化部署，易于管理
- ✅ 支持 Ghidra Shared Project 多用户协作
- 📖 见下方 "Docker 部署" 章节

---

## 本地开发

### 1. 启动 Ghidra Bridge

1. 在 Ghidra CodeBrowser 中打开一个二进制文件
2. 打开 Script Manager (`Window` → `Script Manager`)
3. **添加脚本路径**（首次使用需要）：
   - 点击 Script Manager 右上角的 **"Manage Script Directories"** 按钮（文件夹图标）
   - 点击 `+` 号
   - 选择本项目的根目录（包含 `ghidra_mcp_server.py` 的目录）
   - 点击 OK
4. 在 Script Manager 中找到并运行 `ghidra_mcp_server.py`
5. 确认日志中显示：
   ```
   Server started on http://127.0.0.1:8803
   MCP SSE server started on http://127.0.0.1:8804
   ```

**热重载：** 再次执行脚本会自动触发 API 模块重载，无需重启服务器。

### 2. 配置 AI 客户端

根据你使用的 AI 客户端选择对应的配置方式：

#### Coco

建议内网使用 gemini-pro 模型。

```bash
coco mcp add-json ghidra '{"type": "sse", "url": "http://127.0.0.1:8804/sse"}'
```

#### Claude Desktop

编辑 Claude Desktop 配置文件：
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/settings.json`

单个程序配置：

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8804/sse"
    }
  }
}
```

**多程序同时分析**（可在不同 Ghidra 实例中配置不同端口）：

```json
{
  "mcpServers": {
    "ghidra-sdk_v1": {
      "url": "http://127.0.0.1:8804/sse"
    },
    "ghidra-sdk_v2": {
      "url": "http://127.0.0.1:8806/sse"
    }
  }
}
```

保存后重启 Claude Desktop，即可使用 Ghidra 工具。

#### Claude Code

```bash
claude mcp add --transport sse ghidra-init1 http://127.0.0.1:8804/sse
```

## 可用工具

配置成功后，AI 客户端将自动获得以下 Ghidra 工具：

- **ghidra_search**: 搜索函数、符号、字符串、交叉引用等
- **ghidra_view**: 反编译/反汇编查看
- **ghidra_list**: 符号列表浏览（类似 ls）
- **ghidra_edit**: 统一编辑（重命名、类型设置、注释）
- **ghidra_basic_info**: 获取程序基本信息

## 环境变量（可选）

可通过环境变量自定义端口：

```bash
export GHIDRA_MCP_HOST=127.0.0.1      # HTTP API 主机（默认: 127.0.0.1）
export GHIDRA_MCP_PORT=8803           # HTTP API 端口（默认: 8803）
export GHIDRA_MCP_SSE_PORT=8804       # MCP SSE 端口（默认: 8804）
```

**多程序同时分析：**

如需同时分析多个二进制文件，可在不同 Ghidra 实例中使用不同端口：

```bash
# 第一个 Ghidra 实例（分析 sdk_v1）
export GHIDRA_MCP_PORT=8803
export GHIDRA_MCP_SSE_PORT=8804

# 第二个 Ghidra 实例（分析 sdk_v2）
export GHIDRA_MCP_PORT=8805
export GHIDRA_MCP_SSE_PORT=8806
```

然后在 AI 客户端配置文件中添加多个 MCP 服务器（参考上面的 Claude Desktop 多程序配置示例）。

## HTTP API

Bridge 同时提供 HTTP JSON API，可用于测试或集成其他工具：

```bash
# 获取程序基本信息
curl http://127.0.0.1:8803/api/basic_info

# 搜索函数
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"

# 反编译函数
curl "http://127.0.0.1:8803/api/v1/view?q=main&type=decompile"

# 重命名函数
curl -X POST http://127.0.0.1:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}'

# 热重载 API 模块
curl http://127.0.0.1:8803/_reload

# 关闭服务器
curl http://127.0.0.1:8803/_shutdown
```

完整 API 文档参见 [CLAUDE.md](CLAUDE.md)。

---

## Docker 部署

Docker 模式运行 Ghidra 无头服务器 + MCP Bridge，适合作为持续运行的 AI 协作服务。

### 特性

- **无头运行**：无需 GUI，纯 API 访问
- **容器化**：一键启动，易于管理
- **项目模式**：
  - **本地模式**：挂载本地 Ghidra shared project（volume）
  - **服务器模式**：连接到 Ghidra Server（多用户协作）
- **健康检查**：自动监控和重启
- **日志持久化**：容器重启后日志保留

### 快速开始

#### 1. 构建镜像

```bash
cd docker
docker build -f Dockerfile -t ghidra-mcp-bridge:latest ..
```

#### 2. 选择部署模式

**本地项目模式**（推荐新手）：

```bash
cd examples/docker/local-project

# 编辑 .env 文件，配置你的项目路径
nano .env

# 启动服务
docker-compose up -d
```

`.env` 配置示例：

```bash
# 主机上的 Ghidra 项目路径
HOST_PROJECT_PATH=/Users/username/ghidra-projects/my_binary

# 项目名称（必须与 .gpr 文件名匹配）
PROJECT_NAME=my_binary

# 端口配置
GHIDRA_MCP_PORT=8803
GHIDRA_MCP_SSE_PORT=8804
```

**Ghidra Server 模式**（团队协作）：

```bash
cd examples/docker/ghidra-server

# 编辑 .env 文件，配置服务器连接
nano .env

# 启动服务
docker-compose up -d
```

`.env` 配置示例：

```bash
PROJECT_MODE=server
GHIDRA_SERVER_HOST=ghidra-server.local
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=analyst
PROJECT_NAME=shared_project
```

#### 3. 验证部署

```bash
# 查看容器状态
docker ps

# 查看日志
docker logs ghidra-mcp-bridge

# 测试 API
curl http://localhost:8803/api/status
curl http://localhost:8803/api/basic_info
```

#### 4. 配置 AI 客户端

与本地模式相同，连接到 `http://localhost:8804/sse`（如果使用默认端口）。

### 架构说明

**本地项目模式**：

```
┌─────────────────────────────┐
│  Ghidra Shared Project      │
│  (Host Volume)              │
└──────────┬──────────────────┘
           │ bind mount
┌──────────v──────────────────┐
│  Docker Container           │
│  - Ghidra Headless          │
│  - MCP Bridge               │
│  - HTTP API :8803           │
│  - MCP SSE  :8804           │
└─────────────────────────────┘
```

**服务器模式**：

```
┌─────────────────────────────┐
│  Ghidra Server              │
│  (Network)                  │
└──────────┬──────────────────┘
           │ TCP :13100
┌──────────v──────────────────┐
│  Docker Container           │
│  - Connects to server       │
│  - MCP Bridge               │
│  - HTTP API :8803           │
│  - MCP SSE  :8804           │
└─────────────────────────────┘
```

### 多用户协作

Docker 实例可作为"协作者"连接到外部 Ghidra shared project：

```
┌───────────────┐         ┌───────────────┐
│ Ghidra GUI    │         │ Docker Bridge │
│ (用户手动分析) │         │ (AI 自动分析)  │
└───────┬───────┘         └───────┬───────┘
        │                         │
        v                         v
┌───────────────────────────────────────┐
│     Ghidra Shared Project             │
│     (共享文件系统或 Ghidra Server)     │
└───────────────────────────────────────┘
```

- **Ghidra GUI** 用于手动交互式分析
- **Docker Bridge** 提供 AI 访问，自动化任务
- 双方修改通过项目同步机制共享

### 详细文档

- **部署指南**: [`docs/setup/docker-deployment.md`](docs/setup/docker-deployment.md)
- **架构设计**: [`docs/architecture/docker-architecture.md`](docs/architecture/docker-architecture.md)
- **示例配置**: [`examples/docker/`](examples/docker/)

---

## 高级选项

### stdio 模式（本地调试）

如需在 IDE 中调试 MCP 服务器，可使用 stdio 模式：

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/ghidra-env/bin/python",
      "args": ["/path/to/Bridge/scripts/mcp_stdio.py", "--port", "8803"]
    }
  }
}
```

**注意：** `command` 应指向虚拟环境中的 Python 解释器路径。

stdio 模式作为独立进程运行，通过 HTTP API 与 Ghidra 通信，便于断点调试。

## 项目结构

```
Bridge/
├── ghidra_mcp_server.py    # 主服务器（在 Ghidra 中运行）
├── api/                    # 原始 API 模块
│   ├── search.py
│   ├── view.py
│   ├── rename.py
│   └── ...
├── api_v1/                 # AI 友好聚合 API
│   ├── search.py
│   ├── view.py
│   ├── list.py
│   └── edit.py
└── scripts/
    ├── mcp_sse_proxy.py    # MCP SSE 代理（子进程）
    └── mcp_stdio.py        # MCP stdio 模式（独立进程）
```

## 故障排查

**服务器无法启动？**
- 确认已在 Ghidra CodeBrowser 中打开二进制文件
- 确认 Ghidrathon 已正确安装并重启 Ghidra
- 确认 Ghidrathon 已通过 `python3 -m ghidrathon.configure` 配置虚拟环境

**AI 客户端无法连接？**
- 确认服务器已启动（检查 Ghidra Console 输出）
- 确认配置文件中的端口号正确（SSE 默认 8804）
- 重启客户端（Claude Desktop / Coco / Claude Code）

**API 修改未生效？**
- 执行热重载：`curl http://127.0.0.1:8803/_reload`
- 或在 Ghidra 中再次运行 `ghidra_mcp_server.py`

## 开发

详细的 API 开发指南和架构说明请参见 [CLAUDE.md](CLAUDE.md)。
