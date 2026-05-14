# Ghidra MCP Bridge

[English](README.md) | 简体中文

> **版本说明**：当前分支针对 Ghidra 12.0+（PyGhidra）。Ghidra 11.x 用户请切换到 [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) 分支或使用 [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag。

基于 PyGhidra 的 MCP (Model Context Protocol) Bridge，在 Ghidra 12.0+ 内部运行，为 AI 系统提供对 Ghidra 逆向能力的编程访问。

### 亮点

- **7 个 MCP 工具** — 统一入口，模式分发到 50+ API，无工具膨胀。
- **版本控制 + AI/人类协作** — 多个 AI Agent 与人类分析师通过 Ghidra Server 协同分析同一 binary，完整版本历史。
- **多 binary 跨文件分析** — 同一项目下启动多个 Client 分析不同 binary。适用于 VMP 脱壳、DLL-EXE 交互追踪、多模块固件等场景。
- **AI 友好** — 安装 Skill，让 Claude Code / Codex 启动 Server、导入 binary、配置 MCP、开始分析。

---

## 快速开始

### 让 AI 帮你搞定 ⭐

```bash
git clone https://github.com/Hao17/LiteGhidraMCP.git && cd LiteGhidraMCP
pip install -e .
gmcp install -d . skill claude-code   # 或: codex / cursor / copilot
```

然后告诉你的 AI：*"帮我分析 ~/Downloads/firmware.bin"* —— Skill 会教会它后续流程。

### Docker（推荐）

```bash
pip install -e .                                # 安装 `gmcp` CLI
gmcp server up                                  # 首次运行会提示注册管理员
gmcp server repo create test                    # admin-owned：客户端不能自行创建仓库
gmcp client start 1 --repo test --binary-file ~/firmware.bin
gmcp install mcp claude-code                    # 或: claude-desktop / coco
```

HTTP API 在 `:8803`，MCP SSE 在 `:8804/sse`。多客户端端口公式：Client N → `8800+(N-1)*10+3`（HTTP）/ `+4`（SSE）。

> **Apple Silicon / ARM 主机**：Ghidra 官方发布包没有 `linux_arm_64` 反编译器二进制；本仓库的 compose 默认固定为 `linux/amd64`，避免 `Could not find decompiler executable`。

多客户端部署、GUI 连接、本地项目模式、用户/ACL 管理 → **[docker/QUICKSTART.md](docker/QUICKSTART.md)**。

### GUI 模式（无需 Docker）

直接在 Ghidra 中运行脚本：

1. 用 PyGhidra 启动：`<ghidra_install>/support/pyghidraRun`
2. 把 Bridge 依赖装进 **PyGhidra venv**（不是系统 Python）：
   ```bash
   ~/Library/ghidra/ghidra_<版本>_PUBLIC/venv/bin/python3 -m pip install -r requirements.txt
   ```
3. Ghidra → Script Manager → 把本仓库加入脚本目录 → 运行 `ghidra_mcp_server.py`

如果看到 `MCP proxy failed to start` 配 `ModuleNotFoundError: No module named 'mcp'`，说明第 2 步装到了错误的 Python。

---

## MCP 工具

| 工具 | 说明 |
|------|------|
| **ghidra_overview** | 二进制全景概览 — 元数据、内存布局、关键函数、导入导出、字符串 |
| **ghidra_search** | 搜索函数、符号、字符串、交叉引用、字节、指令 |
| **ghidra_view** | 反编译/反汇编/内存查看 |
| **ghidra_list** | 符号列表浏览（函数、类、导入、导出等） |
| **ghidra_edit** | 重命名、设置数据类型、添加注释（支持批量） |
| **ghidra_exec** | 执行自定义 Python/Java 脚本，完整访问 Ghidra API |
| **ghidra_version** | 版本历史/回滚/回退（仅 Server 模式） |

底层 HTTP API（50+ 路由）参见 **[CLAUDE.md](CLAUDE.md)**。

---

## 进一步阅读

- **[docker/QUICKSTART.md](docker/QUICKSTART.md)** — Docker 部署、多客户端、用户/ACL 管理、故障排查
- **[skills/SKILL.md](skills/SKILL.md)** — `gmcp install skill` 写入项目的 AI 工作流文档
- **[CLAUDE.md](CLAUDE.md)** — 完整 API 参考、架构、热重载、贡献指南
