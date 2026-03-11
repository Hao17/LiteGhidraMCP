# Docker Architecture

## Unified Image Design

本项目使用**单一镜像**（`ghidra-mcp-bridge:latest`）通过**环境变量控制**实现多种运行模式。

### Run Modes

通过 `RUN_MODE` 环境变量控制：

#### 1. SERVER Mode (`RUN_MODE=SERVER`)

**用途：** 作为 Ghidra Server 运行，提供共享项目服务

**启动命令：**
```bash
cd docker
make server-up
# 或
docker-compose -f docker-compose.server.yml up -d
```

**关键配置：**
```yaml
environment:
  - RUN_MODE=SERVER
  - GHIDRA_SERVER_PORT=13100
  - MAXMEM=4G
```

**运行内容：**
- 启动 Ghidra Server (`/opt/ghidra/server/ghidraSvr`)
- 监听端口 13100
- 管理共享项目仓库 (`/repos`)
- 支持多用户、多客户端连接

---

#### 2. CLIENT Mode (`RUN_MODE=CLIENT`, 默认)

**用途：** 作为 MCP Bridge Client 运行，连接 Server 并提供 MCP API

**启动命令：**
```bash
cd docker
make client-up
# 或
docker-compose -f docker-compose.client.yml up -d
```

**关键配置：**
```yaml
environment:
  - RUN_MODE=CLIENT  # 可省略，默认值
  - PROJECT_MODE=server
  - GHIDRA_SERVER_HOST=ghidra-server
  - GHIDRA_SERVER_PORT=13100
  - GHIDRA_SERVER_USER=bridge
  - GHIDRA_SERVER_REPO=/mcp-projects
  - GHIDRA_MCP_PORT=8803
  - GHIDRA_MCP_SSE_PORT=8804
```

**运行内容：**
- 连接到 Ghidra Server
- 启动 HTTP API (8803) 和 MCP SSE (8804)
- 提供 AI 访问接口

---

## Architecture Diagram

```
┌────────────────────────────────────────────────────────┐
│  ghidra-mcp-bridge:latest (Unified Image)             │
│                                                        │
│  Dockerfile:                                           │
│    - Ghidra 12.0.3                                     │
│    - Python 3 + PyGhidra                               │
│    - MCP Bridge Code (api/, scripts/)                 │
│                                                        │
│  entrypoint.sh:                                        │
│    if RUN_MODE=SERVER → ghidraSvr console              │
│    else                → python ghidra_mcp_server.py   │
└────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┴──────────────┐
                │                            │
        RUN_MODE=SERVER              RUN_MODE=CLIENT
                │                            │
                v                            v
    ┌───────────────────────┐    ┌──────────────────────┐
    │  Ghidra Server        │    │  MCP Bridge Client   │
    │  Port: 13100          │◄───│  HTTP: 8803          │
    │  /repos (volumes)     │    │  MCP:  8804          │
    └───────────────────────┘    └──────────────────────┘
                │                            │
                │                            v
                │                   ┌──────────────────┐
                │                   │  AI Client       │
                │                   │  (Claude, etc.)  │
                │                   └──────────────────┘
                v
       ┌───────────────────┐
       │  Ghidra GUI       │
       │  (Human Analyst)  │
       └───────────────────┘
```

## Benefits of Unified Image

✅ **统一维护：** 只需维护一个 Dockerfile
✅ **版本一致：** Server 和 Client 使用完全相同的 Ghidra 版本
✅ **减少依赖：** 不依赖第三方镜像（如 blacktop/ghidra）
✅ **灵活部署：** 同一个镜像可部署为不同角色
✅ **便于调试：** Server 和 Client 环境完全一致

## Quick Start

### 一键启动 Server + Client

```bash
cd docker
make up-separated
```

### 分步启动（更多控制）

```bash
cd docker

# 1. 构建镜像
make build

# 2. 启动 Server
make server-up

# 3. 启动 Client
make client-up

# 4. 查看日志
make logs-separated
```

### 多客户端部署

```bash
# Client 1 (8803/8804)
make client-up

# Client 2 (8813/8814)
make client2-up

# Client 3 (自定义端口)
CLIENT_CONTAINER_NAME=ghidra-mcp-bridge-client-3 \
CLIENT_MCP_PORT=8823 \
CLIENT_MCP_SSE_PORT=8824 \
CLIENT_LOG_DIR=./logs/client-3 \
docker-compose -f docker-compose.client.yml up -d
```

## Environment Variables Reference

### SERVER Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `RUN_MODE` | `CLIENT` | Set to `SERVER` for server mode |
| `GHIDRA_SERVER_PORT` | `13100` | Server listening port |
| `MAXMEM` | `4G` | Maximum memory for server |

### CLIENT Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `RUN_MODE` | `CLIENT` | Can be omitted |
| `PROJECT_MODE` | `local` | Set to `server` for server connection |
| `GHIDRA_SERVER_HOST` | `ghidra-server` | Server hostname |
| `GHIDRA_SERVER_PORT` | `13100` | Server port |
| `GHIDRA_SERVER_USER` | - | Server username |
| `GHIDRA_SERVER_REPO` | - | Repository path |
| `GHIDRA_SERVER_KEYSTORE` | - | SSH private key path |
| `GHIDRA_MCP_HOST` | `0.0.0.0` | API bind address |
| `GHIDRA_MCP_PORT` | `8803` | HTTP API port |
| `GHIDRA_MCP_SSE_PORT` | `8804` | MCP SSE port |

## Migration from blacktop/ghidra

如果你之前使用 `blacktop/ghidra:12.0-server`，现在已经完全替换为自己的镜像。

**旧配置（已移除）：**
```yaml
services:
  ghidra-server:
    image: blacktop/ghidra:12.0-server  # ❌ 外部依赖
```

**新配置（当前）：**
```yaml
services:
  ghidra-server:
    image: ghidra-mcp-bridge:latest     # ✅ 自己的镜像
    environment:
      - RUN_MODE=SERVER                 # ✅ 通过环境变量控制
```

**优势：**
- 不再需要下载外部镜像
- Server 和 Client 使用相同的 Ghidra 版本
- 完全自主可控的构建过程

---

## Data Persistence (Version-Isolated Storage)

### 版本隔离存储设计

本项目采用**版本隔离存储**方案，实现代码和数据完全分离：

**数据目录结构：**
```
${GHIDRA_DATA_DIR}/                # 用户指定的数据根目录（如 ~/ghidra-data）
├── 12.0.3/                        # 版本目录（每个版本独立存储）
│   ├── repos/                     # Ghidra Server 项目仓库
│   ├── config/                    # Server 配置和日志
│   ├── client-config/             # Client 配置（缓存、偏好设置等）
│   └── ssh/                       # SSH keys（Server 和 Client 共享）
├── 12.0.4/                        # 其他版本的数据
│   ├── repos/
│   ├── config/
│   ├── client-config/
│   └── ssh/
└── logs/                          # 日志（按版本分离）
    ├── 12.0.3/
    │   ├── client-1/
    │   └── client-2/
    └── 12.0.4/
```

### Persistent Directories

**Server 端：**

| Directory | Purpose | Mount Path | Priority |
|-----------|---------|------------|----------|
| `/repos` | 项目仓库、用户数据、版本历史 | `${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/repos` | 🔴 Critical |
| `/root/.ghidraServer` | Server 配置和日志 | `${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/config` | 🟡 Recommended |

**Client 端：**

| Directory | Purpose | Mount Path | Priority |
|-----------|---------|------------|----------|
| `/root/.ghidra/` | Client 配置（缓存、偏好设置、状态） | `${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/client-config` | 🟡 Recommended |
| `/root/.ghidra/ssh_key` | SSH 私钥（从 Server ssh 目录自动注入） | `${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/ssh/ssh_key` | 🔴 Critical |

### Key Files in `/repos`

```
/repos/
├── .users/                    # User authentication data
│   ├── <username>/
│   │   └── authorized_keys   # SSH public keys
│   └── users                 # User list
│
├── /<repo_name>/             # Project repository
│   ├── .indexes/            # Path-to-ID mapping
│   ├── ~admin/              # Repository metadata
│   ├── _<hex_id>/           # Project files
│   │   └── ~*.db/
│   │       └── changesets/  # Version history ⭐
│   └── checkout.dat
```

**Critical Notes:**
- `changesets/` - 包含所有版本历史，删除会丢失版本控制
- `~admin/` - 仓库元数据，损坏会导致仓库无法打开
- `.users/` - 用户认证数据，删除会导致无法登录

### Directory Details

**`/repos` - Server 项目仓库：**
```
repos/
├── .users/                    # 用户认证数据
│   ├── bridge/
│   │   └── authorized_keys   # SSH 公钥
├── /mcp-projects/            # 项目仓库
│   ├── ~admin/              # 仓库元数据
│   └── changesets/          # 版本历史
```

**`/root/.ghidraServer` - Server 配置：**
```
config/
├── server.log               # 服务器日志
├── server.conf              # 服务器配置
└── 运行时状态文件
```

**`/root/.ghidra` - Client 配置：**
```
client-config/
├── preferences/             # 用户偏好设置
│   ├── CodeBrowser/
│   ├── decompiler/
│   └── analysis/
├── cache/                   # 反编译缓存
│   └── decompiler_cache/
├── extensions/              # 扩展插件
├── known_servers            # 已知服务器列表
├── recent_projects          # 最近项目
└── .lock                    # 锁文件
```

**`ssh/` - SSH 密钥对（Server 自动生成）：**
```
ssh/
├── ssh_key              # 私钥（Client 自动挂载使用）
└── ssh_key.pub          # 公钥（Server 自动安装到 /repos/.users/）
```

### Current Configuration

已在 `docker-compose.server.yml` 中正确配置：

```yaml
# Server container
volumes:
  - ${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/repos:/repos:rw
  - ${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/ssh:/ssh:rw
  - ${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/config:/root/.ghidraServer:rw
```

Server 启动时自动完成初始化（SSH 密钥生成、用户创建、仓库创建），无需 init 容器。

已在 `docker-compose.client.yml` 中正确配置：

```yaml
# Client container
volumes:
  # Client 配置目录（完整）
  - ${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/client-config:/root/.ghidra:rw

  # SSH key（从 Server ssh 目录自动注入，只读）
  - ${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/ssh/ssh_key:/root/.ghidra/ssh_key:ro

  # 日志
  - ${GHIDRA_DATA_DIR}/logs/${GHIDRA_VERSION}/client-${CLIENT_ID:-1}:/app/logs:rw
```

### 配置步骤

1. **首次设置：**
```bash
cd docker
cp .env.example .env
vim .env  # 设置 GHIDRA_DATA_DIR=~/ghidra-data
make info  # 验证配置
```

2. **启动服务：**
```bash
make up-separated  # 自动初始化数据目录
```

3. **查看配置：**
```bash
make info          # 显示当前版本和数据路径
make list-versions # 列出所有版本
```

4. **切换版本：**
```bash
make switch-version  # 交互式切换
# 或直接编辑 .env 修改 GHIDRA_VERSION
```

### 优势

✅ **代码数据分离：** 项目目录保持纯净，只有代码
✅ **版本隔离：** 每个版本独立存储，互不影响
✅ **灵活存储位置：** 可放在大容量磁盘、NAS、云盘
✅ **便于备份：** 集中管理，备份整个数据目录即可

### Future Iterations (TODO)

- [ ] 实现自动备份机制
- [ ] 添加 Volume 监控和告警
- [ ] 支持跨版本数据迁移
- [ ] Volume 大小限制和清理策略
