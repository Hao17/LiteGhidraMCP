# Headless Ghidra Server Authentication Guide

本文档介绍如何在 Docker 容器中使用 headless Ghidra 连接到 Ghidra Server，包括非交互式密码认证配置。

## 概述

Ghidra headless 模式支持以下几种非交互式认证方法：

1. **密码管道 (Password Piping)** - 通过 stdin 传递密码 ✅ **推荐用于 Docker**
2. **SSH/PKI 密钥** - 使用密钥文件认证
3. **匿名访问** - 无需认证（需 Server 支持）

## 方案 1：密码管道认证（推荐）

### 工作原理

通过 `echo $PASSWORD | analyzeHeadless ... -p` 将密码从 stdin 传递给 Ghidra。

### Docker 配置

#### 1. 配置环境变量

编辑 `examples/docker/ghidra-server/.env`：

```bash
# ========================================
# Ghidra Server Mode Configuration
# ========================================

# Server Configuration
GHIDRA_MCP_HOST=0.0.0.0
GHIDRA_MCP_PORT=8803
GHIDRA_MCP_SSE_PORT=8804

# Project Configuration
PROJECT_MODE=server

# Ghidra Server Connection
GHIDRA_SERVER_HOST=localhost         # 或 Docker 网络中的服务名
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=bridge
GHIDRA_SERVER_REPO=/                 # Repository 路径

# Non-interactive password authentication
GHIDRA_SERVER_PASSWORD=bridge123

# Project name on the server
PROJECT_NAME=my_project

# Logging
LOG_LEVEL=INFO
LOG_DIR=/app/logs
```

#### 2. 启动容器

```bash
cd examples/docker/ghidra-server
docker-compose up -d
```

#### 3. 验证连接

```bash
# 查看日志
docker logs ghidra-mcp-bridge-server

# 测试 API
curl http://localhost:8803/api/basic_info
```

### 手动命令行使用

如果不使用 Docker Compose，可以直接运行：

```bash
# 使用环境变量
export GHIDRA_SERVER_PASSWORD="bridge123"

echo "$GHIDRA_SERVER_PASSWORD" | analyzeHeadless \
  ghidra://localhost:13100/ \
  my_project \
  -connect bridge \
  -p \
  -scriptPath /path/to/Bridge \
  -postScript ghidra_mcp_server.py
```

或者一行命令：

```bash
echo "bridge123" | analyzeHeadless \
  ghidra://localhost:13100/ \
  my_project \
  -connect bridge \
  -p \
  -scriptPath . \
  -postScript ghidra_mcp_server.py
```

## 方案 2：SSH 密钥认证（高安全性）

### 1. 生成 SSH 密钥对

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/id_rsa -N ""
```

### 2. 在 Ghidra Server 上配置公钥

将 `~/.ghidra/id_rsa.pub` 内容添加到 Server 的用户配置中。

### 3. 使用密钥连接

```bash
analyzeHeadless \
  ghidra://localhost:13100/ \
  my_project \
  -connect bridge \
  -keystore ~/.ghidra/id_rsa \
  -scriptPath . \
  -postScript ghidra_mcp_server.py
```

### Docker 密钥挂载

```yaml
# docker-compose.yml
services:
  ghidra-bridge:
    volumes:
      - ~/.ghidra/id_rsa:/root/.ghidra/id_rsa:ro
    environment:
      - GHIDRA_SERVER_KEYSTORE=/root/.ghidra/id_rsa
```

修改 `entrypoint.sh` 支持密钥认证：

```bash
if [ -n "$GHIDRA_SERVER_KEYSTORE" ]; then
    GHIDRA_CMD="$GHIDRA_CMD -keystore $GHIDRA_SERVER_KEYSTORE"
fi
```

## 方案 3：Docker Secrets（生产环境推荐）

### 1. 创建 Docker Secret

```bash
echo "bridge123" | docker secret create ghidra_server_password -
```

### 2. 修改 docker-compose.yml

```yaml
version: '3.8'

services:
  ghidra-bridge:
    image: ghidra-mcp-bridge
    secrets:
      - ghidra_server_password
    environment:
      - GHIDRA_SERVER_PASSWORD_FILE=/run/secrets/ghidra_server_password

secrets:
  ghidra_server_password:
    external: true
```

### 3. 修改 entrypoint.sh 读取 Secret

```bash
# Read password from Docker secret if provided
if [ -n "$GHIDRA_SERVER_PASSWORD_FILE" ] && [ -f "$GHIDRA_SERVER_PASSWORD_FILE" ]; then
    GHIDRA_SERVER_PASSWORD=$(cat "$GHIDRA_SERVER_PASSWORD_FILE")
    echo "Loaded password from Docker secret"
fi
```

## 常见问题排查

### 问题 1：密码认证失败

**错误信息**:
```
Connection refused: ghidra://localhost:13100/
Failed to connect to server
```

**解决方法**:
1. 检查 Server 是否运行：`netstat -an | grep 13100`
2. 验证用户名密码是否正确
3. 检查 Repository 是否存在

### 问题 2：Docker 容器无法连接 Host Server

**错误信息**:
```
java.net.ConnectException: Connection refused
```

**解决方法**:

使用 Docker 网络配置：

```bash
# macOS/Linux: 使用 host.docker.internal
GHIDRA_SERVER_HOST=host.docker.internal

# 或使用 Docker bridge 网络
docker network create ghidra-network
```

### 问题 3：密码包含特殊字符

如果密码包含 `$`, `"`, `!` 等特殊字符，需要转义：

```bash
# 使用单引号
echo 'pass$word!' | analyzeHeadless ...

# 或环境变量
export GHIDRA_SERVER_PASSWORD='pass$word!'
```

## 安全最佳实践

1. **不要将密码硬编码在 Dockerfile 中**
2. **使用 Docker Secrets 或 Kubernetes Secrets** 存储敏感信息
3. **优先使用 SSH/PKI 密钥认证** 而非密码
4. **限制 `.env` 文件权限**:
   ```bash
   chmod 600 .env
   ```
5. **不要提交 `.env` 到版本控制**（已在 `.gitignore` 中）

## 参考资料

- [Headless Analyzer README](https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html)
- [HeadlessClientAuthenticator API](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/HeadlessClientAuthenticator.html)
- [PasswordClientAuthenticator API](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/PasswordClientAuthenticator.html)
- [Docker Ghidra Examples](https://github.com/blacktop/docker-ghidra)

## 测试命令

### 测试 Server 连接

```bash
# 测试端口连通性
nc -zv localhost 13100

# 测试认证
echo "bridge123" | analyzeHeadless \
  ghidra://localhost:13100/ \
  test_project \
  -connect bridge \
  -p \
  -import /bin/ls \
  -deleteProject
```

### 测试 MCP Bridge API

```bash
# 等待容器启动
sleep 10

# 测试基本信息 API
curl http://localhost:8803/api/basic_info

# 测试搜索 API
curl "http://localhost:8803/api/search/functions?q=main"
```

## 下一步

- [Docker 快速入门](../docker/QUICKSTART.pyghidra.md)
- [API 使用示例](../examples/api-usage/curl-examples.sh)
- [MCP 配置指南](../CLAUDE.md#mcp-model-context-protocol-support)
