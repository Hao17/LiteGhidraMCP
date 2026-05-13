# Ghidra MCP Bridge — Known Issues & Improvements

## Issue 1: 新建 repo 时 GUI 用户无权限访问

**状态**: Fixed
**严重性**: High — 阻塞正常工作流

### 问题描述

通过 `make client N=<n> REPO=<new_repo> BINARY_FILE=<path>` 创建新 repo 时，只有 bridge-* SSH 用户被自动授权（通过 `entrypoint.sh` 的 key scanner 循环）。密码认证的 GUI 用户（如 `syec`、`admin`）不会自动获得新 repo 的访问权限。

**复现步骤**:
1. `make client N=2 REPO=baobao BINARY_FILE=/path/to/libmetasec_ml.so`
2. Client 启动成功，binary 导入成功
3. 在 Ghidra GUI 中连接 server → 看不到 `baobao` 仓库

**根因**: `entrypoint.sh` 第 124-135 行的 ACL 同步逻辑只遍历 `/ssh/clients/*/ssh_key.pub`，不包括通过 `svrAdmin -add` 或密码方式注册的用户。

### 当前 workaround

手动执行:
```bash
docker exec ghidra-server-standalone /opt/ghidra/server/svrAdmin -grant syec "+a" <repo_name>
```

### 建议修复

在 `entrypoint.sh` 的 ACL 同步循环中（第 124-135 行），除了扫描 SSH key 用户，还应从 `/repos/.users/users` 文件读取所有已注册用户并授权:

```bash
# Full ACL sync: ensure ALL registered users have access to all repos
for repo_dir in "${REPO_DIR}"/*/; do
    [ -d "$repo_dir" ] || continue
    repo_name=$(basename "$repo_dir")
    [[ "$repo_name" == ~* || "$repo_name" == .* ]] && continue

    # 1. SSH key users (existing logic)
    for pubkey in "${SSH_DIR}"/clients/*/ssh_key.pub; do
        [ -f "$pubkey" ] || continue
        username=$(basename "$(dirname "$pubkey")")
        "${SVRADMIN}" -grant "${username}" +a "${repo_name}" 2>/dev/null || true
    done

    # 2. Password-auth users (NEW: read from server user list)
    if [ -f "${REPO_DIR}/.users/users" ]; then
        while IFS= read -r username; do
            [[ -z "$username" || "$username" == bridge-* ]] && continue
            "${SVRADMIN}" -grant "${username}" +a "${repo_name}" 2>/dev/null || true
        done < "${REPO_DIR}/.users/users"
    fi
done
```

---

## Issue 2: 导入 binary 后自动分析根本没有执行

**状态**: Open
**严重性**: Critical — 导入的 binary 没有被分析，函数/字符串/交叉引用全部缺失

### 问题描述

通过 `make client N=<n> REPO=<repo> BINARY_FILE=<path>` 导入新 binary 后，Ghidra 自动分析没有实际执行。例如导入 3MB 的 `libmetasec_ml.so`（预期 ~6000+ 函数），只识别出 396 个函数（仅 ELF 导出符号），说明 Auto Analysis 完全没有运行。

### 根因

`docker_only_ghidra_mcp_server.py` 第 239-251 行的 `_import_program()` 函数中，自动分析存在两个问题：

**问题 A: 分析异常被静默吞掉**

```python
# 第 250-251 行
except Exception:
    pass  # Analysis is best-effort   ← 任何分析错误都被忽略，无日志
```

**问题 B: `startAnalysis()` 使用 `TaskMonitor.DUMMY`，是非阻塞调用**

```python
# 第 247 行
mgr.startAnalysis(TaskMonitor.DUMMY)  # ← 启动分析但不等待完成
```

`startAnalysis(TaskMonitor.DUMMY)` 只是触发分析，不会阻塞等待完成。函数返回后程序立即 `save()`（第 253 行），此时分析可能还没开始或只跑了一小部分。结合 `except Exception: pass`，即使分析启动失败也无任何反馈。

### 建议修复

```python
if analyze:
    try:
        from ghidra.app.util.importer import AutoAnalysisManager
        from ghidra.util.task import ConsoleTaskMonitor
        
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        txid = program.startTransaction("Auto-analysis")
        try:
            mgr.initializeOptions()
            mgr.reAnalyzeAll(None)
            # Use ConsoleTaskMonitor for progress output, and BLOCK until done
            monitor = ConsoleTaskMonitor()
            mgr.startAnalysis(monitor, wait=True)  # block until complete
        finally:
            program.endTransaction(txid, True)
        
        func_count = program.getFunctionManager().getFunctionCount()
        print(f"[analysis] Complete: {func_count} functions identified")
    except Exception as e:
        print(f"[analysis] WARNING: Auto-analysis failed: {e}")
        import traceback
        traceback.print_exc()
```

关键改动：
1. **不要静默吞异常** — 打印错误信息和 traceback
2. **阻塞等待分析完成** — 使用 `ConsoleTaskMonitor` 或等效的阻塞方式
3. **输出分析结果** — 打印识别到的函数数量，方便验证
4. **考虑添加超时机制** — 大 binary（>10MB）的分析可能需要数分钟

---

## Issue 3: MCP Bridge client 持有排他锁，阻塞 GUI 同时访问

**状态**: Open
**严重性**: High — GUI 和 MCP client 无法协作使用同一 binary

### 问题描述

MCP bridge client 以 checkout 方式持有 binary 的排他锁。当 client 运行时，Ghidra GUI 无法打开同一个 binary（提示锁占用）。用户必须先 `make client-stop N=<n>` 才能在 GUI 中操作。

这在实际工作流中严重影响效率：用户经常需要 MCP API 做批量搜索/反编译，同时在 GUI 中手动浏览和标注。

### 建议

- Client 应以**只读/共享**模式打开 binary，而非排他 checkout
- 或提供 `make client-release N=<n>` 命令临时释放锁而不停止容器
- 考虑 Ghidra Server 的 versioned checkout 模式，允许多用户并发

---

## Issue 4: Makefile `client` target 缺少 repo 存在性提示

**状态**: Open  
**严重性**: Low

### 问题描述

当 `REPO=<name>` 指定的仓库已存在于 Ghidra Server 上时，`make client` 不会给出任何提示，直接连接。当仓库不存在时，会自动创建。但用户无法区分是复用了已有仓库还是新建了仓库。

### 建议

在 client 启动时输出明确信息:
```
[info] Repository 'baobao' already exists on server, connecting...
# 或
[info] Creating new repository 'baobao' on server...
```
