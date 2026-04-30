# api/checkout.py - Auto checkout/commit manager for Ghidra Server mode
"""
Checkout Manager - 自动为写操作处理 checkout/save/checkin 生命周期。

Headless 模式下的写操作流程：
  1. ensure_checkout(): 首次写操作时获取 exclusive checkout
  2. handler 执行修改（startTransaction → modify → endTransaction）
  3. auto_save(): prog.save() 保存到本地，重置 idle timer
  4. idle timer 到期（无新写操作）→ checkin 并释放 checkout

连续的写操作共享同一次 checkout，idle timer 不断重置，
直到最后一次写操作后 CHECKIN_DELAY 秒无新写入才 checkin，产生一个 commit。

非 Server 模式（GUI/本地）：所有函数为 no-op，直接透传。
"""

import sys
import threading

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


# Deferred checkin timer
CHECKIN_DELAY = 5  # seconds after last write before auto-checkin
_checkin_timer = None
_checkin_lock = threading.Lock()


def _get_domain_file(prog):
    """Get the real DomainFile for a program (headless/PyGhidra mode only).

    Returns None in GUI mode — version.py's _get_domain_file imports from
    docker_only_ghidra_mcp_server which is not loaded in GUI mode.
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
    """Acquire exclusive checkout if needed, cancel any pending checkin timer.

    Returns (success, error_dict_or_None).
    - Non-versioned: returns (True, None) immediately (no-op).
    - Already checked out: returns (True, None).
    - Checkout acquired: returns (True, None).
    - Checkout failed: returns (False, error_dict).
    """
    # Cancel pending checkin to prevent race with handler execution
    _cancel_checkin_timer()

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
            # May be stale checkout from previous container — release and retry
            try:
                from docker_only_ghidra_mcp_server import _release_stale_checkout
                if _release_stale_checkout(df):
                    result = df.checkout(True, TaskMonitor.DUMMY)
            except ImportError:
                pass  # GUI mode
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


def auto_save(state, comment="Auto-commit via API"):
    """Save locally after a successful write operation, schedule deferred checkin.

    Returns a dict with save info, or None if not applicable.
    The actual checkin happens after CHECKIN_DELAY seconds of no writes.
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
        return None

    # Save local changes
    try:
        prog.save(comment, TaskMonitor.DUMMY)
    except Exception as e:
        return {"action": "save_failed", "error": str(e)}

    # Schedule deferred checkin
    _schedule_checkin(state, comment)

    return {"action": "saved", "comment": comment}


def flush_checkin(state, comment="Auto-commit via API"):
    """Force immediate checkin if checked out. Cancel any pending timer.

    Used before version log (to show latest state) and on shutdown.
    Returns commit info dict, or None if not applicable.
    """
    _cancel_checkin_timer()
    return _do_checkin(state, comment)


# ============================================================
# Internal timer management
# ============================================================

def _cancel_checkin_timer():
    """Cancel the pending deferred checkin timer."""
    global _checkin_timer
    with _checkin_lock:
        if _checkin_timer is not None:
            _checkin_timer.cancel()
            _checkin_timer = None


def _schedule_checkin(state, comment):
    """Reset the deferred checkin timer. Called after each save."""
    global _checkin_timer
    with _checkin_lock:
        if _checkin_timer is not None:
            _checkin_timer.cancel()
        _checkin_timer = threading.Timer(
            CHECKIN_DELAY, _deferred_checkin, args=[state, comment]
        )
        _checkin_timer.daemon = True
        _checkin_timer.start()


def _deferred_checkin(state, comment):
    """Timer callback: perform checkin after idle period."""
    global _checkin_timer
    with _checkin_lock:
        _checkin_timer = None

    result = _do_checkin(state, comment)

    # If checkin failed (e.g. connection lost), retry after delay
    if isinstance(result, dict) and result.get("action") == "checkin_failed":
        print(f"[PyGhidra-MCP-Bridge] Deferred checkin failed, scheduling retry in {CHECKIN_DELAY}s...")
        _schedule_checkin(state, comment)


def _do_checkin(state, comment):
    """Perform save + checkin(keepCheckedOut=False).

    Returns commit info dict, or None if not applicable.
    """
    prog = state.getCurrentProgram()
    if prog is None:
        return None

    df = _get_domain_file(prog)
    if df is None:
        return None

    try:
        if not df.isVersioned() or not df.isCheckedOut():
            return None
    except Exception:
        return None

    # Save before checkin to ensure latest state
    try:
        prog.save(comment, TaskMonitor.DUMMY)
    except Exception:
        pass  # May fail if no changes since last save, that's OK

    # Ensure server connection before checkin (reconnect if needed)
    try:
        from docker_only_ghidra_mcp_server import _ensure_server_connection
        ok, _err = _ensure_server_connection()
        if not ok:
            return {"action": "checkin_failed", "error": "Server connection lost"}
    except ImportError:
        pass  # GUI mode

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
            # No changes — undo checkout to release the lock
            try:
                df.undoCheckout(False)
            except Exception:
                pass
            return None
        if "merge" in err_str.lower() or "newer version" in err_str.lower():
            return {
                "action": "merge_required",
                "comment": comment,
                "warning": f"Server has a newer version: {e}",
            }
        return {"action": "checkin_failed", "error": str(e)}
