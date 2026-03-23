# api/version.py - Version management API (log, commit, rollback)
"""
Version API - 版本管理操作（仅在 Ghidra Server 共享项目模式下可用）

提供类似 git 的精简版本管理：commit、log+diff、rollback。
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
    """获取真正的 DomainFile（通过 project root folder，避免 DomainFileProxy）"""
    # DomainFileProxy from prog.getDomainFile() doesn't support version operations.
    # We need the real DomainFile from the project's root folder.
    from ghidra_mcp_server_pyghidra import _project, _ghidra_project
    proj = _project
    if proj is None and _ghidra_project:
        proj = _ghidra_project._project
    if proj is None:
        return None
    try:
        root = proj.getProjectData().getRootFolder()
        return root.getFile(prog.getName())
    except Exception:
        return None


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

    # Get version history
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
    consumer = JavaObject()  # Java consumer for getImmutableDomainObject
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
    """
    prog, err = _get_program(state)
    if err:
        return err

    df = _get_domain_file(prog)
    if df is None:
        # Fallback: try proxy (local mode)
        df = prog.getDomainFile()
    if df is None:
        return {"success": False, "error": "No domain file associated with program"}

    commit_comment = comment if comment else "Committed via API"

    try:
        # Case 1: Not yet under version control - add to VC
        if not df.isVersioned():
            # Try to add to version control (only works in server mode)
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

        # Case 2: Versioned but not checked out - checkout and reopen writable
        if not df.isCheckedOut():
            try:
                if not df.checkout(False, TaskMonitor.DUMMY):
                    return {"success": False, "error": "Failed to checkout file"}
            except Exception as e:
                return {"success": False, "error": f"Checkout failed: {e}"}
            # Must reopen to get writable handle
            from ghidra_mcp_server_pyghidra import _switch_program
            prog = _switch_program(prog.getName())

        # Case 3: Save local changes
        prog.save(commit_comment, TaskMonitor.DUMMY)

        # Case 4: Checkin to server (keepCheckedOut=True)
        try:
            handler = DefaultCheckinHandler(commit_comment, True, False)
            df.checkin(handler, TaskMonitor.DUMMY)
        except Exception as e:
            if "has not been modified since checkout" in str(e):
                return {
                    "success": True,
                    "action": "no_changes",
                    "comment": commit_comment,
                    "message": "No changes since last commit",
                    "version": df.getVersion(),
                    "is_checked_out": df.isCheckedOut(),
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

        # Must release/close program before undoCheckout
        from ghidra_mcp_server_pyghidra import _project, _ghidra_project, _switch_program
        import ghidra_mcp_server_pyghidra as _server_mod
        proj = _project
        if proj is None and _ghidra_project:
            proj = _ghidra_project._project

        # Release the current program
        with _server_mod._program_lock:
            if _server_mod._current_program:
                try:
                    _server_mod._current_program.release(proj)
                except Exception:
                    pass
                _server_mod._current_program = None
                _server_mod._mock_state._program = None

        # Undo checkout - discards all local changes
        df.undoCheckout(False)

        # Reopen the program (now read-only, at last committed version)
        _switch_program(prog_name)

        return {
            "success": True,
            "action": "rolled_back",
            "program": prog_name,
            "version": df.getVersion() if df.isVersioned() else None,
        }

    except Exception as e:
        return {"success": False, "error": f"Rollback failed: {e}"}
