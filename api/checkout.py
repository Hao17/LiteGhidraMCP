# api/checkout.py - Auto checkout/commit manager for Ghidra Server mode
"""
Checkout Manager - 自动为写操作处理 checkout/save/checkin 生命周期。

Server 模式下：写操作前 checkout(exclusive=True)，写操作后 save + checkin。
非 Server 模式（GUI/本地）：所有函数为 no-op，直接透传。
"""

import sys

# Cache Java classes in sys.modules to survive hot reloads on worker threads
_CACHE_PREFIX = '_ghidra_api_checkout_'

_classes_to_cache = {
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

TaskMonitor = sys.modules.get(_CACHE_PREFIX + 'TaskMonitor')
DefaultCheckinHandler = sys.modules.get(_CACHE_PREFIX + 'DefaultCheckinHandler')


def _get_domain_file(prog):
    """Get the real DomainFile for a program (headless/PyGhidra mode only).

    Returns None in GUI mode — version.py's _get_domain_file imports from
    ghidra_mcp_server_pyghidra which is not loaded in GUI mode.
    This ensures all checkout/commit functions are no-ops in GUI mode,
    where the user manages version control through the Ghidra GUI.
    """
    try:
        from api.version import _get_domain_file as _vdf
        return _vdf(prog)
    except Exception:
        return None


def is_server_versioned(state):
    """Check if the current program is under Ghidra Server version control.

    Returns True only when connected to a Ghidra Server shared project
    AND the file is versioned. Returns False for GUI/local mode.
    """
    prog = state.getCurrentProgram()
    if prog is None:
        return False
    df = _get_domain_file(prog)
    if df is None:
        return False
    try:
        return df.isVersioned()
    except Exception:
        return False


def ensure_checkout(state):
    """Acquire exclusive checkout if needed.

    Returns (success, error_dict_or_None).
    - Non-versioned: returns (True, None) immediately (no-op).
    - Already checked out: returns (True, None).
    - Checkout acquired: returns (True, None).
    - Checkout failed: returns (False, error_dict).
    """
    prog = state.getCurrentProgram()
    if prog is None:
        return True, None

    df = _get_domain_file(prog)
    if df is None:
        return True, None  # No domain file = local mode, no-op

    try:
        if not df.isVersioned():
            return True, None  # Not versioned, no checkout needed
    except Exception:
        return True, None

    if df.isCheckedOut():
        return True, None  # Already checked out

    # Acquire exclusive checkout
    try:
        result = df.checkout(True, TaskMonitor.DUMMY)
        if not result:
            return False, {
                "success": False,
                "error": "Exclusive checkout failed: another user has the file checked out",
                "error_code": "checkout_conflict",
            }
        return True, None
    except Exception as e:
        return False, {
            "success": False,
            "error": f"Checkout failed: {e}",
            "error_code": "checkout_conflict",
        }


def auto_commit(state, comment="Auto-commit via API"):
    """Save and checkin after a successful write operation.

    Returns a dict with commit info, or None if not applicable.
    - Non-versioned: returns None (no-op).
    - Not checked out: returns None (shouldn't happen after ensure_checkout).
    - Success: returns commit info dict.
    - Error: returns error info dict (but does NOT fail the operation).
    """
    prog = state.getCurrentProgram()
    if prog is None:
        return None

    df = _get_domain_file(prog)
    if df is None:
        return None

    try:
        if not df.isVersioned():
            return None
    except Exception:
        return None

    if not df.isCheckedOut():
        return None  # Not checked out, nothing to commit

    # Save local changes
    try:
        prog.save(comment, TaskMonitor.DUMMY)
    except Exception as e:
        return {"action": "save_failed", "error": str(e)}

    # Checkin to server (keepCheckedOut=False to release the lock)
    try:
        handler = DefaultCheckinHandler(comment, False, False)
        df.checkin(handler, TaskMonitor.DUMMY)
        return {
            "action": "committed",
            "comment": comment,
            "version": df.getVersion(),
        }
    except Exception as e:
        err_str = str(e)
        if "has not been modified since checkout" in err_str:
            return {
                "action": "no_changes",
                "comment": comment,
                "message": "No changes since last commit",
            }
        if "merge" in err_str.lower() or "newer version" in err_str.lower():
            return {
                "action": "merge_required",
                "comment": comment,
                "warning": f"Server has a newer version: {e}",
            }
        return {"action": "checkin_failed", "error": str(e)}
