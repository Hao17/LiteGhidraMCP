# api/version.py - Version management API (log, commit, rollback, revert)
"""
Version API - 版本管理操作（仅在 Ghidra Server 共享项目模式下可用）

提供类似 git 的精简版本管理：commit、log+diff、rollback、revert。
"""

from api import route

import sys

# Cache Java classes in sys.modules to survive hot reloads on worker threads
_CACHE_PREFIX = '_ghidra_api_version_'

_classes_to_cache = {
    'ProgramDiff': ('ghidra.program.util', 'ProgramDiff'),
    'ProgramDiffFilter': ('ghidra.program.util', 'ProgramDiffFilter'),
    'TaskMonitor': ('ghidra.util.task', 'TaskMonitor'),
    'DefaultCheckinHandler': ('ghidra.framework.data', 'DefaultCheckinHandler'),
}

for _key, (_pkg, _cls_name) in _classes_to_cache.items():
    _cache_key = _CACHE_PREFIX + _key
    if _cache_key not in sys.modules:
        try:
            _mod = __import__(_pkg, fromlist=[_cls_name])
            sys.modules[_cache_key] = getattr(_mod, _cls_name)
        except Exception:
            pass

ProgramDiff = sys.modules.get(_CACHE_PREFIX + 'ProgramDiff')
ProgramDiffFilter = sys.modules.get(_CACHE_PREFIX + 'ProgramDiffFilter')
TaskMonitor = sys.modules.get(_CACHE_PREFIX + 'TaskMonitor')
DefaultCheckinHandler = sys.modules.get(_CACHE_PREFIX + 'DefaultCheckinHandler')


def _get_program(state):
    """获取当前程序，返回 (prog, error_dict)"""
    prog = state.getCurrentProgram()
    if not prog:
        return None, {"success": False, "error": "No program loaded"}
    return prog, None


def _get_domain_file(prog):
    """获取真正的 DomainFile（通过 project root folder，避免 DomainFileProxy）。
    支持子目录结构（如 38.1.0/libmetasec_ml.so）。"""
    from ghidra_mcp_server_pyghidra import _project, _ghidra_project
    proj = _project
    if proj is None and _ghidra_project:
        proj = _ghidra_project._project
    if proj is None:
        return None
    try:
        root = proj.getProjectData().getRootFolder()
        # 1. Try root folder directly
        df = root.getFile(prog.getName())
        if df is not None:
            return df
        # 2. Use DomainFileProxy pathname to navigate to the correct subfolder
        proxy = prog.getDomainFile()
        if proxy is not None:
            pathname = proxy.getPathname()  # e.g. "/38.1.0/libmetasec_ml.so"
            if pathname and "/" in pathname.lstrip("/"):
                parts = pathname.lstrip("/").split("/")
                folder = root
                for part in parts[:-1]:
                    folder = folder.getFolder(part)
                    if folder is None:
                        break
                if folder is not None:
                    df = folder.getFile(parts[-1])
                    if df is not None:
                        return df
        # 3. Fallback: recursive search by name
        from ghidra_mcp_server_pyghidra import _collect_all_files
        for f in _collect_all_files(root):
            if f.getName() == prog.getName():
                return f
        return None
    except Exception:
        return None


def _reopen_program(df):
    """Reopen program from DomainFile after undoCheckout/revert.

    Uses getDomainObject to get a fresh handle and updates the server module state.
    """
    import ghidra_mcp_server_pyghidra as _server_mod

    proj = _server_mod._project
    if proj is None and _server_mod._ghidra_project:
        proj = _server_mod._ghidra_project._project

    new_prog = df.getDomainObject(proj, False, False, TaskMonitor.DUMMY)

    with _server_mod._program_lock:
        _server_mod._current_program = new_prog
        _server_mod._mock_state._program = new_prog


def _release_program():
    """释放当前程序（undoCheckout/revert 前必须调用）"""
    import ghidra_mcp_server_pyghidra as _server_mod
    proj = _server_mod._project
    if proj is None and _server_mod._ghidra_project:
        proj = _server_mod._ghidra_project._project
    with _server_mod._program_lock:
        if _server_mod._current_program:
            try:
                _server_mod._current_program.release(proj)
            except Exception:
                pass
            _server_mod._current_program = None
            _server_mod._mock_state._program = None


def _format_version(v):
    """格式化 Version 对象为 dict"""
    return {
        "version": v.getVersion(),
        "user": v.getUser(),
        "time": str(v.getCreateTime()),
        "comment": v.getComment(),
    }


@route("/api/version/log")
def version_log(state, limit=50, diff=0, types="all"):
    """
    获取版本历史，可选附带与指定版本的差异。

    路由: GET /api/version/log?limit=50&diff=<n>&types=all

    参数:
        limit: 最大返回版本数 (默认 50)
        diff: 与指定版本号比较差异 (0=不比较)
        types: diff 过滤类型 (默认 all)
    """
    prog, err = _get_program(state)
    if err:
        return err

    df = _get_domain_file(prog)
    if df is None or not df.isVersioned():
        return {"success": False, "error": "Program is not under version control (requires Ghidra Server mode)"}

    try:
        history = df.getVersionHistory()
    except Exception as e:
        return {"success": False, "error": f"Failed to get version history: {e}"}

    versions = []
    count = 0
    for v in history:
        if count >= int(limit):
            break
        versions.append(_format_version(v))
        count += 1

    result = {
        "success": True,
        "current_version": df.getVersion(),
        "is_checked_out": df.isCheckedOut(),
        "versions": versions,
        "total": len(history),
    }

    # Diff against specified version
    diff_ver = int(diff)
    if diff_ver > 0 and ProgramDiff is not None:
        diff_result = _compute_diff(prog, df, diff_ver, int(limit))
        if diff_result is not None:
            result["diff"] = diff_result

    return result


def _compute_diff(prog, df, target_version, limit):
    """计算当前程序与指定版本之间的差异"""
    old_prog = None
    from java.lang import Object as JavaObject
    consumer = JavaObject()
    try:
        old_prog = df.getImmutableDomainObject(
            consumer, target_version, TaskMonitor.DUMMY
        )

        prog_diff = ProgramDiff(old_prog, prog)
        diff_filter = ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS)

        diffs = prog_diff.getDifferences(diff_filter, TaskMonitor.DUMMY)

        changes = []
        if not diffs.isEmpty():
            it = diffs.getAddresses(True)
            while it.hasNext() and len(changes) < limit:
                addr = it.next()
                changes.append({"address": str(addr)})

        return {
            "compared_version": target_version,
            "change_count": diffs.getNumAddresses() if not diffs.isEmpty() else 0,
            "changes": changes,
        }

    except Exception as e:
        return {"error": f"Diff failed: {e}"}
    finally:
        if old_prog is not None:
            try:
                old_prog.release(consumer)
            except Exception:
                pass


@route("/api/version/commit")
def version_commit(state, comment=""):
    """
    保存并提交版本（自动处理 checkout）。

    路由: GET /api/version/commit?comment=<msg>

    参数:
        comment: 提交说明 (默认空)

    错误码:
        - "merge_required": 服务器有更新版本，需要先 rollback 再重新修改提交
        - "checkout_exclusive": 其他用户持有独占 checkout
        - "checkout_conflict": checkout 失败（其他用户锁定）
    """
    prog, err = _get_program(state)
    if err:
        return err

    df = _get_domain_file(prog)
    if df is None:
        df = prog.getDomainFile()
    if df is None:
        return {"success": False, "error": "No domain file associated with program"}

    commit_comment = comment if comment else "Committed via API"

    try:
        # Case 1: Not yet under version control - add to VC
        if not df.isVersioned():
            try:
                df.addToVersionControl(commit_comment, True, TaskMonitor.DUMMY)
                return {
                    "success": True,
                    "action": "added_to_version_control",
                    "comment": commit_comment,
                    "version": df.getVersion(),
                }
            except Exception as e:
                return {"success": False, "error": f"Cannot add to version control (requires Ghidra Server mode): {e}"}

        # Case 2: Versioned but not checked out - checkout (exclusive)
        if not df.isCheckedOut():
            try:
                result = df.checkout(True, TaskMonitor.DUMMY)
                if not result:
                    return {
                        "success": False,
                        "error": "Exclusive checkout failed: another user has the file checked out",
                        "error_code": "checkout_conflict",
                    }
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Checkout failed: {e}",
                    "error_code": "checkout_conflict",
                }

        # Case 3: Save local changes
        prog.save(commit_comment, TaskMonitor.DUMMY)

        # Case 4: Checkin to server (keepCheckedOut=True)
        try:
            handler = DefaultCheckinHandler(commit_comment, True, False)
            df.checkin(handler, TaskMonitor.DUMMY)
        except Exception as e:
            err_str = str(e)
            if "has not been modified since checkout" in err_str:
                return {
                    "success": True,
                    "action": "no_changes",
                    "comment": commit_comment,
                    "message": "No changes since last commit",
                    "version": df.getVersion(),
                    "is_checked_out": df.isCheckedOut(),
                }
            if "merge" in err_str.lower() or "newer version" in err_str.lower():
                return {
                    "success": False,
                    "error": f"Server has a newer version. Use rollback to discard local changes, then re-apply and commit. Detail: {e}",
                    "error_code": "merge_required",
                    "current_version": df.getVersion(),
                    "hint": "Call rollback first, then re-apply your changes on the latest version and commit again.",
                }
            raise

        return {
            "success": True,
            "action": "committed",
            "comment": commit_comment,
            "version": df.getVersion(),
            "is_checked_out": df.isCheckedOut(),
        }

    except Exception as e:
        return {"success": False, "error": f"Commit failed: {e}"}


@route("/api/version/rollback")
def version_rollback(state):
    """
    丢弃未提交修改，回退到最近一次 commit。

    路由: GET /api/version/rollback
    """
    prog, err = _get_program(state)
    if err:
        return err

    df = _get_domain_file(prog)
    if df is None:
        return {"success": False, "error": "No domain file associated with program"}

    if not df.isVersioned():
        return {"success": False, "error": "Program is not under version control"}

    if not df.isCheckedOut():
        return {"success": False, "error": "Program is not checked out, nothing to rollback"}

    try:
        prog_name = prog.getName()

        _release_program()

        # Undo checkout - discards all local changes
        df.undoCheckout(False)

        # Reopen the program (now at last committed version)
        _reopen_program(df)

        return {
            "success": True,
            "action": "rolled_back",
            "program": prog_name,
            "version": df.getVersion() if df.isVersioned() else None,
        }

    except Exception as e:
        return {"success": False, "error": f"Rollback failed: {e}"}


@route("/api/version/revert")
def version_revert(state, version=0):
    """
    回退到指定版本，永久删除该版本之后的所有版本。

    路由: GET /api/version/revert?version=<n>

    参数:
        version: 目标版本号（必须 >= 1 且 < 当前最新版本）

    注意: 这是破坏性操作！被删除的版本无法恢复。
    文件不能被任何人 checkout（包括自己），操作前会自动 undo checkout。
    """
    target = int(version)
    if target < 1:
        return {"success": False, "error": "version parameter is required and must be >= 1"}

    prog, err = _get_program(state)
    if err:
        return err

    df = _get_domain_file(prog)
    if df is None:
        return {"success": False, "error": "No domain file associated with program"}

    if not df.isVersioned():
        return {"success": False, "error": "Program is not under version control"}

    current = df.getVersion()
    if target >= current:
        return {
            "success": False,
            "error": f"Target version {target} must be less than current version {current}",
        }

    # Must release program and undo checkout before deleting versions
    prog_name = prog.getName()

    try:
        if df.isCheckedOut():
            _release_program()
            df.undoCheckout(False)

        # Delete versions from newest down to target+1
        deleted = []
        while True:
            history = df.getVersionHistory()
            latest = max(v.getVersion() for v in history)
            if latest <= target:
                break
            df.delete(latest)
            deleted.append(latest)

        # Reopen program at the target version
        _reopen_program(df)

        return {
            "success": True,
            "action": "reverted",
            "target_version": target,
            "deleted_versions": deleted,
            "current_version": df.getVersion(),
        }

    except Exception as e:
        # Try to reopen program even if revert partially failed
        try:
            _reopen_program(df)
        except Exception:
            pass
        return {"success": False, "error": f"Revert failed: {e}"}
