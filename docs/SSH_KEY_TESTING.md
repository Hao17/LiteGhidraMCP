# Ghidra Server SSH Key 认证测试指南

## 方法 1：Ghidra GUI 测试（推荐新手）

### 步骤 1：配置 Ghidra 的 SSH Key 路径

1. 打开 **Ghidra**
2. 菜单：**Edit** → **Tool Options**
3. 在左侧树中找到：**Server** → **Server**
4. 找到配置项：**SSH Private Key File**
5. 点击右侧的 **[...]** 按钮
6. 浏览并选择：`/Users/syec/ghidra-data/12.0.3/ssh/bridge_key`
7. 点击 **OK** 保存

**重要提示**：
- 必须选择**私钥**文件（`bridge_key`），不是公钥（`bridge_key.pub`）
- 私钥必须是 **PEM 格式**（文件第一行应该是 `-----BEGIN RSA PRIVATE KEY-----`）
- 私钥权限应该是 600 或 400

### 步骤 2：创建 Shared Project 连接到服务器

1. **File** → **New Project**
2. 选择 **Shared Project**
3. 点击 **Next**

### 步骤 3：配置服务器连接

在 "Server Information" 对话框中：

```
Server Name: localhost
Port Number: 13100
```

点击 **Connect**

### 步骤 4：SSH 认证登录

在登录对话框中：

```
User ID: bridge
Password: [留空 - SSH key 认证不需要密码]
Authentication Method: PKI (会自动选择)
```

如果看到 "SSH Keystore" 或 "PKI Authentication" 选项，说明 Ghidra 检测到了你配置的 SSH key。

点击 **OK** 登录

### 步骤 5：创建或选择仓库

首次连接需要创建仓库：

1. 右键点击空白区域
2. 选择 **Create Folder**
3. 输入仓库名称（如 `/test-ssh`）
4. 在新建的文件夹中创建项目

### 预期结果

**✅ 成功**：
- 无需输入密码即可登录
- 可以看到服务器上的仓库列表
- 可以创建文件夹和项目
- 状态栏显示 "Connected to localhost:13100 as bridge"

**❌ 失败**：
- 提示 "Authentication failed"
- 提示 "Login failed"
- 要求输入密码（说明 SSH key 未生效）

---

## 方法 2：命令行测试（快速验证）

使用我创建的自动化测试脚本：

```bash
cd /path/to/Bridge
./test_ssh_connection.sh
```

这个脚本会：
1. 检查 SSH key 格式和权限
2. 使用 `analyzeHeadless` 连接服务器
3. 验证 SSH 认证是否成功
4. 显示详细的测试结果

---

## 方法 3：Python 脚本测试（高级）

如果你想测试更底层的连接，可以运行：

```bash
# 确保已安装 PyGhidra
pip install pyghidra

# 运行测试脚本
python3 << 'EOF'
import os
import pyghidra

# 配置
os.environ['GHIDRA_INSTALL_DIR'] = '/Applications/ghidra_12.0.3_PUBLIC'

# 启动 PyGhidra
pyghidra.start()

# 导入 Ghidra 类
from ghidra.framework.client import ClientUtil, HeadlessClientAuthenticator

# 配置 SSH 认证
SERVER_HOST = "localhost"
SERVER_PORT = 13100
SERVER_USER = "bridge"
SSH_KEYSTORE = "/Users/syec/ghidra-data/12.0.3/ssh/bridge_key"

print(f"Connecting to {SERVER_HOST}:{SERVER_PORT} as {SERVER_USER}")
print(f"Using SSH key: {SSH_KEYSTORE}")

# 安装 SSH 认证器
HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
    SERVER_USER,
    SSH_KEYSTORE,
    False  # 不提示密码
)

print("✓ SSH authenticator installed")

# 连接服务器
server = ClientUtil.getRepositoryServer(SERVER_HOST, SERVER_PORT, True)

# 检查连接状态
if server.isConnected():
    print(f"✓ Connected successfully!")
    print(f"  User: {server.getUser()}")
    repos = server.getRepositoryNames()
    print(f"  Repositories: {list(repos) if repos else '(none)'}")
else:
    print("✗ Connection failed")
EOF
```

---

## 故障排查

### 问题 1：提示 "Unsupported SSH Private Key"

**原因**：SSH key 格式不正确（OpenSSH 格式而非 PEM）

**解决**：
```bash
# 检查密钥格式
head -1 /Users/syec/ghidra-data/12.0.3/ssh/bridge_key

# 如果是 "-----BEGIN OPENSSH PRIVATE KEY-----"，需要重新生成
ssh-keygen -m pem -t rsa -b 2048 \
  -f /Users/syec/ghidra-data/12.0.3/ssh/bridge_key_new \
  -N "" -C "ghidra-bridge"

# 替换旧密钥
mv /Users/syec/ghidra-data/12.0.3/ssh/bridge_key_new \
   /Users/syec/ghidra-data/12.0.3/ssh/bridge_key

# 更新服务器公钥
PUB_KEY=$(cat /Users/syec/ghidra-data/12.0.3/ssh/bridge_key.pub)
docker exec ghidra-server-standalone sh -c \
  "echo '${PUB_KEY}' > /opt/ghidra/repositories/~ssh/bridge.pub"
```

### 问题 2：服务器日志显示 "SSH key not found"

**原因**：公钥未正确安装到服务器

**解决**：
```bash
# 验证服务器端公钥
docker exec ghidra-server-standalone \
  cat /opt/ghidra/repositories/~ssh/bridge.pub

# 如果不存在或内容不对，重新安装
docker exec ghidra-server-standalone sh -c \
  "cat /Users/syec/ghidra-data/12.0.3/ssh/bridge_key.pub > \
   /opt/ghidra/repositories/~ssh/bridge.pub"
```

### 问题 3：Ghidra GUI 找不到 SSH Key

**原因**：未配置 SSH Private Key File 路径

**解决**：
- Edit → Tool Options → Server → SSH Private Key File
- 设置为私钥文件的完整路径
- 重启 Ghidra

### 问题 4：服务器未启用 SSH 认证

**原因**：server.conf 缺少 `-ssh` 参数

**验证**：
```bash
docker logs ghidra-server-standalone 2>&1 | grep "SSH authentication"
# 应该看到：SSH authentication option enabled
```

**解决**：
```bash
# 检查配置
docker exec ghidra-server-standalone \
  grep "wrapper.app.parameter" /opt/ghidra/server/server.conf

# 应该包含 wrapper.app.parameter.3=-ssh
```

---

## 验证清单

在测试前，请确认：

- [ ] SSH 私钥存在：`/Users/syec/ghidra-data/12.0.3/ssh/bridge_key`
- [ ] SSH 私钥格式：PEM（`-----BEGIN RSA PRIVATE KEY-----`）
- [ ] SSH 私钥权限：600 或 400
- [ ] SSH 公钥存在：`/Users/syec/ghidra-data/12.0.3/ssh/bridge_key.pub`
- [ ] Server 端公钥已安装：`/opt/ghidra/repositories/~ssh/bridge.pub`
- [ ] Server 已启用 SSH：日志显示 "SSH authentication option enabled"
- [ ] 用户已添加到 server：`bridge` 在用户列表中
- [ ] Ghidra GUI 已配置 SSH Private Key File 路径

完成所有检查后，再进行测试。
