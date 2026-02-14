# Ghidra MCP Bridge

[English](README.md) | 简体中文

> **版本说明**：
> - **当前分支 (main)**：Ghidra 12.0+ / PyGhidra 版本
> - **Ghidra 11.x 用户**：请切换到 [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) 分支或使用 [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

基于 PyGhidra 的 MCP (Model Context Protocol) Bridge，在 Ghidra 12.0+ 内部运行，为 AI 系统提供对 Ghidra 逆向工程能力的编程访问。

## 快速开始指引

**普通用户：从 GUI 模式开始**
- → [在 Ghidra GUI 中运行 MCP](#快速开始)：最简单的设置，直接在 Ghidra 中运行脚本
- 无需 Docker，无需复杂配置
- 适合学习和日常分析工作

**专业逆向工程师：**

如需生产级部署或团队协作，查看 [Docker 部署](#docker-部署) 章节：
- 容器化部署选项
- 本地项目模式（仅自动化）
- Ghidra Server 模式（AI + GUI 协作）

---

## 快速开始

**环境要求：**
- Ghidra 12.0+（下载：https://ghidra-sre.org/）
- Python 依赖：`pip install -r requirements.txt`

> **注意**：使用 Ghidra 12.0+ 内置的 PyGhidra。Docker 模式无需本地安装，所有依赖已包含在容器中。

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

### 2. 可用工具

配置成功后，AI 客户端将自动获得以下 Ghidra 工具：

- **ghidra_search**: 搜索函数、符号、字符串、交叉引用等
- **ghidra_view**: 反编译/反汇编查看
- **ghidra_list**: 符号列表浏览（类似 ls）
- **ghidra_edit**: 统一编辑（重命名、类型设置、注释）
- **ghidra_basic_info**: 获取程序基本信息

### 3. 配置 AI 客户端

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

## Docker 部署

Docker 模式运行 Ghidra 无头服务器 + MCP Bridge，基于 Ghidra 12.0+ 的 PyGhidra。

### 部署选项对比

| 特性 | 本地 GUI | Docker + 本地项目 | Docker + Ghidra Server |
|------|---------|------------------|----------------------|
| **使用场景** | 日常分析 | 仅自动化 | 生产环境/协作 |
| **部署方式** | Ghidra GUI | Docker 容器 | Docker 容器 |
| **Ghidra 来源** | 本地安装 | 容器化 | 容器化 |
| **项目来源** | GUI 打开 | 卷挂载 (.gpr) | Ghidra Server |
| **AI + GUI 同时使用** | 不适用 | **否 - GUI 被锁定** | **是 - 完全协作** |
| **持久化** | 会话级 | 卷挂载 | Server 存储 |
| **并发访问** | 单用户 | 容器锁定 | 多用户安全 |
| **版本控制** | 否 | 否 | 内置 |
| **用户隔离** | 否 | 否 | 独立会话 |
| **容器重启** | 不适用 | 需重新挂载 | 自动恢复 |

> **重要限制**：
> - **本地项目模式**使用非共享项目 - Docker 容器**锁定**项目，**GUI 无法同时打开**
> - **Server 模式**使用共享项目 - Docker（AI 分析师）和 GUI（人工分析师）可**并行工作**

### 选择部署场景

**当前可用模式**（通过 `PROJECT_MODE` 环境变量配置）：

1. **本地项目** (`PROJECT_MODE=local`)：挂载本地 .gpr 文件
   - 适用于：纯自动化，无需 GUI 交互
   - 限制：Docker 锁定项目，GUI 无法同时打开

2. **Ghidra Server** (`PROJECT_MODE=server`)：连接 Ghidra Server（生产环境推荐）
   - 适用于：AI + 人工协作，团队工作，生产部署
   - 优势：AI 和 GUI 可协同工作，持久化存储，版本控制

**未来计划模式**（尚未实现）：

3. **本地 Ghidra 实例** (`PROJECT_MODE=host-ghidra`)：使用宿主机的 Ghidra 安装
   - 将支持：访问现有插件和脚本
   - 状态：尚未实现

---

### 选项 1：本地项目连接（仅自动化）

**关键限制**：非共享项目 - **Docker 锁定项目，GUI 无法同时打开！**

- 适用于：纯自动化，无需 GUI 交互
- 不适用于：AI-人工协作，手动审查

**1. 准备 Ghidra 项目**

在 Ghidra GUI 中创建并分析项目（首次使用）：

```bash
# 项目目录结构示例
/path/to/ghidra-projects/my_binary/
├── my_binary.gpr          # 项目配置文件
└── my_binary.rep/         # 项目仓库目录
```

**2. 构建 PyGhidra 镜像**

```bash
docker build -f docker/Dockerfile.pyghidra -t ghidra-bridge:pyghidra .
```

**3. 配置环境变量**

```bash
cd docker
cp .env.example .env
# 编辑 .env，设置 HOST_PROJECT_PATH 和 PROJECT_NAME
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

**4. 启动服务**

```bash
docker-compose -f docker/docker-compose.pyghidra.yml up -d
```

**5. 验证部署**

```bash
# 查看日志
docker logs -f ghidra-mcp-bridge-pyghidra

# 测试 API
curl http://localhost:8803/api/basic_info
curl "http://localhost:8803/api/search/functions?q=main"

# 测试 MCP
curl http://localhost:8804/sse
```

**6. 配置 AI 客户端**

与本地模式相同，连接到 `http://localhost:8804/sse`。

#### 架构说明

```
┌─────────────────────────────┐
│  Ghidra Shared Project      │
│  (Host Volume)              │
└──────────┬──────────────────┘
           │ bind mount
┌──────────v──────────────────┐
│  Docker Container           │
│  - Ghidra 12.0 + PyGhidra   │
│  - MCP Bridge               │
│  - HTTP API :8803           │
│  - MCP SSE  :8804           │
└─────────────────────────────┘
```

#### 详细文档

- **快速开始指南**: [`docker/QUICKSTART.pyghidra.md`](docker/QUICKSTART.pyghidra.md)
- **Dockerfile**: [`docker/Dockerfile.pyghidra`](docker/Dockerfile.pyghidra)
- **Compose 配置**: [`docker/docker-compose.pyghidra.yml`](docker/docker-compose.pyghidra.yml)

---

### 选项 2：Ghidra Server 连接 - 生产环境推荐

**唯一能够同时使用 AI（Docker）+ GUI（人工）的方式！**

**配置：** 在 `.env` 中设置 `PROJECT_MODE=server` + 配置 Server 连接变量

**为什么连接 Ghidra Server？**

使用 Ghidra Server（共享项目）提供专业的协作架构：

**相比本地项目：**
- **Docker 和 GUI 可以协同工作**（本地项目会锁定文件）
- **持久化存储**（数据在容器删除后仍保留）
- **版本控制**（内置冲突解决）
- **多用户安全**（AI 分析师 + 人工分析师作为独立用户）

**额外优势：**
- **权限隔离**：追踪哪些修改来自 AI，哪些来自人工
- **并发安全**：多个 AI 代理 + 人工分析师可并行工作
- **容器重启安全**：所有数据在 Server 中，容器只是客户端

#### 标准协作架构

在这个架构中，Ghidra Server 是**中心协调者**，MCP Bridge 和 GUI 都是**平等的客户端用户**：

```
┌─────────────────────────────────────────────────┐
│           Ghidra Server (Docker)                │
│                                                 │
│  Repository: /repos/my_project                  │
│  - 持久化存储（Volume 挂载）                     │
│  - 版本控制和冲突管理                           │
│  - 用户权限管理                                 │
└────────┬──────────────────────┬─────────────────┘
         │                      │
         │ User: "ai_analyst"   │ User: "human_analyst"
         │ (AI 分析师)           │ (人工分析师)
         v                      v
┌────────────────────┐  ┌──────────────────────┐
│  MCP Bridge        │  │  Ghidra GUI          │
│  (Docker)          │  │  (本地/远程)          │
│                    │  │                      │
│  - AI 驱动分析     │  │  - 交互式逆向        │
│  - 自动化重命名    │  │  - 手动审查和标注    │
│  - 批量处理        │  │  - 可视化调试        │
│                    │  │                      │
│  HTTP API :8803    │  │                      │
│  MCP SSE  :8804    │  │                      │
└────────────────────┘  └──────────────────────┘
         │                      │
         v                      v
   AI 客户端              分析师工作站
  (Claude Desktop)       (交互式操作)
```

**工作流程**：
1. **Ghidra Server** 管理共享仓库 `/repos/my_project`
2. **MCP Bridge 用户** (`ai_analyst`) - AI 驱动的自动化分析
   - 通过 MCP 工具执行批量重命名、类型推断
   - 自动标注函数、变量、数据结构
   - 响应 AI 客户端的分析请求
3. **GUI 用户** (`human_analyst`) - 人工分析师
   - 审查 AI 的分析结果
   - 手动调试和深度分析
   - 可视化交叉引用和控制流
4. **双向同步** - 两个用户的修改通过 Server 实时同步

**优势**：
- AI 和人工分析师可**并行工作**，互不干扰
- Server 自动处理**版本冲突**（如两者同时修改同一函数）
- **权责分离**：可追踪哪些修改来自 AI，哪些来自人工
- **容器重启不丢失数据**：所有状态保存在 Server 持久化存储

#### 部署步骤

**1. 生成 SSH 密钥（用于 Server 认证）**

为 AI 分析师（MCP Bridge）和人工分析师分别生成密钥：

```bash
mkdir -p ~/.ghidra

# AI 分析师密钥（MCP Bridge 使用）
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/ai_analyst_key -N ""

# 人工分析师密钥（GUI 使用）
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/human_analyst_key -N ""
```

**2. 创建 docker-compose.yml**

```yaml
version: '3.8'

services:
  ghidra-server:
    image: blacktop/ghidra:12.0-server
    container_name: ghidra-server
    ports:
      - "13100-13102:13100-13102"
    volumes:
      - ./ghidra-repos:/repos:rw           # 仓库持久化
      - ./ghidra-config:/ghidra/.ghidraServer:rw  # 配置持久化
    environment:
      - MAXMEM=4G
      - GHIDRA_USERS=ai_analyst human_analyst  # 两个独立用户
    restart: unless-stopped

  ghidra-bridge:
    image: ghidra-bridge:pyghidra
    depends_on:
      - ghidra-server
    environment:
      - PROJECT_MODE=server
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_PORT=13100
      - GHIDRA_SERVER_USER=ai_analyst        # AI 分析师用户
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
      - GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key
    volumes:
      - ~/.ghidra/ai_analyst_key:/root/.ghidra/ssh_key:ro  # AI 分析师密钥
      - ./logs:/app/logs:rw
    ports:
      - "8803:8803"
      - "8804:8804"
    restart: unless-stopped
```

**3. 配置 Ghidra Server 用户（首次启动后）**

```bash
# 启动 Server
docker-compose up -d ghidra-server

# 进入 Server 容器
docker exec -it ghidra-server /bin/bash

# 添加 AI 分析师用户
ghidra-server-admin add-user ai_analyst
# 将 ~/.ghidra/ai_analyst_key.pub 内容添加到 authorized_keys

# 添加人工分析师用户
ghidra-server-admin add-user human_analyst
# 将 ~/.ghidra/human_analyst_key.pub 内容添加到 authorized_keys

# 创建共享仓库
ghidra-server-admin create-repository /shared

# 授予两个用户访问权限
ghidra-server-admin grant-access /shared ai_analyst
ghidra-server-admin grant-access /shared human_analyst

exit
```

**4. 启动 MCP Bridge 服务**

```bash
# 启动 Bridge（AI 分析师）
docker-compose up -d ghidra-bridge

# 查看日志
docker logs -f ghidra-bridge
```

**5. 配置 GUI 用户（人工分析师）连接到 Server**

在分析师的工作站上配置 Ghidra GUI：

```bash
# 1. 在 Ghidra GUI 中创建 Server 连接
# File → New Project → Shared Project

# 2. 配置 Server 连接信息：
Server Name:    ghidra-server  (或 localhost:13100)
Port Number:    13100
User ID:        human_analyst
Repository:     /shared
Project Name:   my_project

# 3. 配置 SSH 认证
# 将 ~/.ghidra/human_analyst_key 配置到 Ghidra 的 SSH 设置中
```

**6. 验证双用户协作**

```bash
# 测试 AI 分析师（MCP Bridge）
curl http://localhost:8803/api/basic_info
# 应该显示连接到 Server 的项目信息，User: ai_analyst

# 在 GUI 中测试人工分析师
# 打开 Ghidra GUI → 连接到 Server → 打开 my_project
# 状态栏应显示：Connected as human_analyst

# 测试协作：GUI 中重命名一个函数
# 在 MCP 中查看：curl "http://localhost:8803/api/search/functions?q=new_name"
# 应该能看到 GUI 的修改

# 测试反向：通过 MCP 重命名函数
curl -X POST http://localhost:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "ai_renamed_func"}'

# 在 GUI 中刷新，应该能看到 AI 的修改
```

#### 数据持久化验证

**关键优势**：Server 模式下，即使删除所有容器（包括 Bridge 和 Server），数据仍完整保留。

```bash
# 1. 通过 MCP 做一些修改
curl -X POST http://localhost:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "comment.set", "name": "main", "type": "PLATE", "text": "AI analyzed"}'

# 2. 停止并删除所有容器
docker-compose down

# 3. 验证数据持久化
ls -la ./ghidra-repos/shared/
# 应该看到完整的仓库结构

# 4. 重新启动（数据自动恢复）
docker-compose up -d

# 5. 验证修改仍然存在
curl "http://localhost:8803/api/v1/view?q=main&type=decompile"
# 应该能看到之前添加的注释 "AI analyzed"

# 6. GUI 用户重新连接
# Ghidra GUI → 连接到 Server → 打开项目
# 所有历史修改（AI + 人工）都完整保留
```

**持久化存储说明**：
- **仓库数据**：`./ghidra-repos/` → Server 容器的 `/repos`
- **Server 配置**：`./ghidra-config/` → Server 容器的 `/.ghidraServer`
- **Bridge 日志**：`./logs/` → Bridge 容器的 `/app/logs`

删除容器只是删除运行时状态，所有分析数据都保存在宿主机 volume 中。

#### 多 AI Agent 协作（高级场景）

可以部署多个 MCP Bridge 实例，每个作为独立的 AI 分析师，分工协作：

```yaml
services:
  ghidra-server:
    # ... (同上)
    environment:
      - GHIDRA_USERS=ai_code_analyst ai_vuln_analyst human_analyst

  # AI Agent 1: 代码分析专家
  bridge-code-analyst:
    image: ghidra-bridge:pyghidra
    container_name: bridge-code-analyst
    environment:
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_USER=ai_code_analyst
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
    volumes:
      - ~/.ghidra/ai_code_analyst_key:/root/.ghidra/ssh_key:ro
    ports:
      - "8803:8803"  # MCP for code analysis
      - "8804:8804"

  # AI Agent 2: 漏洞分析专家
  bridge-vuln-analyst:
    image: ghidra-bridge:pyghidra
    container_name: bridge-vuln-analyst
    environment:
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_USER=ai_vuln_analyst
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
    volumes:
      - ~/.ghidra/ai_vuln_analyst_key:/root/.ghidra/ssh_key:ro
    ports:
      - "8805:8803"  # MCP for vulnerability analysis
      - "8806:8804"
```

**使用场景**：
- `ai_code_analyst`：专注于函数识别、重命名、类型推断
- `ai_vuln_analyst`：专注于漏洞模式搜索、危险函数标注
- `human_analyst`：审查 AI 结果，深度分析关键逻辑

**Claude Desktop 配置（多 Agent）**：
```json
{
  "mcpServers": {
    "ghidra-code": {
      "url": "http://localhost:8804/sse"
    },
    "ghidra-vuln": {
      "url": "http://localhost:8806/sse"
    }
  }
}
```

所有 Agent 的修改通过 Server 同步，可在 GUI 中统一查看。

#### 详细配置

参考示例：[`examples/docker/ghidra-server/docker-compose.pyghidra.yml`](examples/docker/ghidra-server/docker-compose.pyghidra.yml)

---

## 高级选项

### HTTP API

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

# 关闭服务器
curl http://127.0.0.1:8803/_shutdown
```

完整 API 文档参见 [CLAUDE.md](CLAUDE.md)。

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

### 环境变量

自定义服务器端口（可选）：

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

然后在 AI 客户端中配置多个 MCP 服务器（参考上面的 Claude Desktop 多程序配置示例）。

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
- 确认使用的是 Ghidra 12.0+（内置 PyGhidra 支持）

**AI 客户端无法连接？**
- 确认服务器已启动（检查 Ghidra Console 输出）
- 确认配置文件中的端口号正确（SSE 默认 8804）
- 重启客户端（Claude Desktop / Coco / Claude Code）

## 开发

详细的 API 开发指南和架构说明请参见 [CLAUDE.md](CLAUDE.md)。
