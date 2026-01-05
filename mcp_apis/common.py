"""Shared utilities for Ghidra MCP Bridge API handlers."""

import threading
from typing import Any, Dict, List, Optional

print("[Ghidra-MCP-Bridge][Common] Loading common module...")

try:
    import ghidra_builtins as _ghidra_builtins
except Exception:  # noqa: BLE001 - optional fallback if not present
    _ghidra_builtins = None

try:
    from __main__ import currentProgram, currentAddress, currentLocation, currentSelection, currentHighlight, monitor, state, script
    _FLAT_API_AVAILABLE = True
except ImportError:
    try:
        from ghidra_builtins import currentProgram, currentAddress, currentLocation, currentSelection, currentHighlight, monitor, state, script
        _FLAT_API_AVAILABLE = True
    except ImportError:
        _FLAT_API_AVAILABLE = False
        currentProgram = currentAddress = currentLocation = currentSelection = currentHighlight = monitor = state = script = None

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.util import SystemUtilities
from ghidra.util.task import TaskMonitor
from javax.swing import SwingUtilities

# Explicitly injected context (script globals) to avoid implicit bindings.
_CTX: Dict[str, Any] = {}

# Cached Ghidra context from main script to avoid Ghidrathon cache issues
_cached_program_ref = None
_cached_address_ref = None
_cached_location_ref = None
_cached_selection_ref = None
_cached_highlight_ref = None
_cached_monitor_ref = None
_cached_state_ref = None
_cached_script_ref = None

# Debug tracking for import sources
_import_source_log = []
_last_program_source = "unknown"
_last_address_source = "unknown"


def _log_import_source(api_name: str, source: str, value_found: bool):
    """Log where an API was successfully imported from."""
    global _import_source_log, _last_program_source, _last_address_source

    log_entry = {
        "api": api_name,
        "source": source,
        "found": value_found,
        "timestamp": str(__import__("time").time())
    }
    _import_source_log.append(log_entry)

    # Track last successful source for quick reference
    if value_found:
        if api_name == "currentProgram":
            _last_program_source = source
        elif api_name == "currentAddress":
            _last_address_source = source

    # Keep log size manageable
    if len(_import_source_log) > 50:
        _import_source_log = _import_source_log[-25:]

    print(f"[Ghidra-MCP-Bridge][Import-Debug] {api_name} from {source}: {'✓' if value_found else '✗'}")


def set_context(ctx: Dict[str, Any]):
    """Inject script-level bindings (e.g., currentProgram/currentAddress/state)."""
    _CTX.clear()
    _CTX.update(ctx)
    _log_import_source("set_context", "script_injection", len(ctx) > 0)


def set_cached_context(program, address):
    """Set cached Ghidra context from main script."""
    global _cached_program_ref, _cached_address_ref
    _cached_program_ref = program
    _cached_address_ref = address


def reset_context():
    """Clear cached context and decompiler for reuse across scripts."""
    _CTX.clear()
    global _DECOMPILER
    _DECOMPILER = None


def _fallback_binding(name: str):
    """Best-effort lookup in builtins/ghidra_builtins when context is missing."""
    builtins_obj = globals().get("__builtins__")
    if builtins_obj:
        try:
            if hasattr(builtins_obj, name):
                return getattr(builtins_obj, name)
            if isinstance(builtins_obj, dict) and name in builtins_obj:
                return builtins_obj[name]
        except Exception:
            pass
    if _ghidra_builtins and hasattr(_ghidra_builtins, name):
        return getattr(_ghidra_builtins, name)
    return None


def _resolve_callable_or_value(obj):
    if callable(obj):
        try:
            return obj()
        except Exception:
            return None
    return obj


def _refresh_context_from_ghidra():
    """Dynamically fetch current Ghidra context when _CTX is empty or outdated."""
    if _ghidra_builtins:
        try:
            # Try to get fresh context from ghidra_builtins
            current_prog = getattr(_ghidra_builtins, 'currentProgram', None)
            current_addr = getattr(_ghidra_builtins, 'currentAddress', None)
            state = getattr(_ghidra_builtins, 'state', None)

            if current_prog or state:
                fresh_ctx = {}
                if current_prog:
                    fresh_ctx['currentProgram'] = current_prog
                if current_addr:
                    fresh_ctx['currentAddress'] = current_addr
                if state:
                    fresh_ctx['state'] = state

                # Update _CTX with fresh values
                _CTX.update(fresh_ctx)
                return True
        except Exception:
            pass
    return False


def get_program_direct():
    """
    尝试直接访问currentProgram而不使用缓存的多种方法
    """
    methods_tried = []

    # 方法1：通过__main__模块
    try:
        import __main__
        if hasattr(__main__, 'currentProgram'):
            prog = __main__.currentProgram()
            if prog is not None:
                _log_import_source("currentProgram", "direct_main_module", True)
                return prog
        methods_tried.append("__main__ module: not available")
    except Exception as e:
        methods_tried.append(f"__main__ module: error {e}")

    # 方法2：通过sys.modules['__main__']
    try:
        import sys
        main_module = sys.modules.get('__main__')
        if main_module:
            for attr_name in ['currentProgram', 'getCurrentProgram']:
                if hasattr(main_module, attr_name):
                    func = getattr(main_module, attr_name)
                    prog = func() if callable(func) else func
                    if prog is not None:
                        _log_import_source("currentProgram", f"direct_sys_modules_{attr_name}", True)
                        return prog
        methods_tried.append("sys.modules['__main__']: not available")
    except Exception as e:
        methods_tried.append(f"sys.modules['__main__']: error {e}")

    # 方法3：通过ghidra_builtins
    if _ghidra_builtins:
        try:
            if hasattr(_ghidra_builtins, 'currentProgram'):
                prog = _ghidra_builtins.currentProgram()
                if prog is not None:
                    _log_import_source("currentProgram", "direct_ghidra_builtins", True)
                    return prog
        except Exception as e:
            methods_tried.append(f"ghidra_builtins: error {e}")
    else:
        methods_tried.append("ghidra_builtins: not available")

    # 方法4：通过栈帧检查
    try:
        import inspect
        frame = inspect.currentframe().f_back  # 跳过当前函数
        while frame:
            frame_globals = frame.f_globals
            if 'currentProgram' in frame_globals:
                func = frame_globals['currentProgram']
                if callable(func):
                    prog = func()
                    if prog is not None:
                        _log_import_source("currentProgram", "direct_frame_inspection", True)
                        return prog
            frame = frame.f_back
        methods_tried.append("frame inspection: no suitable frame found")
    except Exception as e:
        methods_tried.append(f"frame inspection: error {e}")

    # 方法5：检查当前模块的globals()是否被注入了
    try:
        current_globals = globals()
        if 'currentProgram' in current_globals and callable(current_globals['currentProgram']):
            prog = current_globals['currentProgram']()
            if prog is not None:
                _log_import_source("currentProgram", "direct_injected_globals", True)
                return prog
        methods_tried.append("injected globals: not available")
    except Exception as e:
        methods_tried.append(f"injected globals: error {e}")

    # 所有方法都失败了
    _log_import_source("currentProgram", f"direct_access_failed({'; '.join(methods_tried)})", False)
    return None


def get_program():
    """
    Resolve the current program from injected script bindings.
    Supports variable/callable currentProgram and state.getCurrentProgram().
    Falls back to ghidra_builtins/builtins if context was not set.
    """
    # Try to get cache directly from main module via sys.modules FIRST
    try:
        import sys
        if 'ghidra_mcp_server' in sys.modules:
            main_module = sys.modules['ghidra_mcp_server']
            if hasattr(main_module, '_cached_program') and main_module._cached_program:
                _log_import_source("currentProgram", "main_module_cache", True)
                return main_module._cached_program
        _log_import_source("currentProgram", "main_module_cache", False)
    except Exception as e:
        _log_import_source("currentProgram", f"main_module_cache_error({str(e)})", False)

    # Use cached program from common module
    global _cached_program_ref
    if _cached_program_ref is not None:
        _log_import_source("currentProgram", "common_module_cache", True)
        return _cached_program_ref
    else:
        _log_import_source("currentProgram", "common_module_cache", False)

    # Try direct flat API import if available
    if _FLAT_API_AVAILABLE and currentProgram:
        try:
            prog = _resolve_callable_or_value(currentProgram)
            if prog is not None:
                _log_import_source("currentProgram", "direct_flat_api_import", True)
                return prog
            _log_import_source("currentProgram", "direct_flat_api_import", False)
        except Exception as e:
            _log_import_source("currentProgram", f"direct_flat_api_import_error({str(e)})", False)
    else:
        _log_import_source("currentProgram", "direct_flat_api_import", False)

    # First try existing context
    prog_obj = _CTX.get("currentProgram")
    prog = _resolve_callable_or_value(prog_obj) if prog_obj else None
    if prog is not None:
        _log_import_source("currentProgram", "existing_context", True)
        return prog
    else:
        _log_import_source("currentProgram", "existing_context", False)

    # If no program found, try to refresh context from Ghidra
    refresh_success = _refresh_context_from_ghidra()
    if refresh_success:
        prog_obj = _CTX.get("currentProgram")
        prog = _resolve_callable_or_value(prog_obj) if prog_obj else None
        if prog is not None:
            _log_import_source("currentProgram", "refreshed_context", True)
            return prog
    _log_import_source("currentProgram", "refreshed_context", False)

    # Fallback to direct binding lookup
    prog_obj = _fallback_binding("currentProgram")
    prog = _resolve_callable_or_value(prog_obj)
    if prog is not None:
        _log_import_source("currentProgram", "fallback_binding", True)
        return prog
    else:
        _log_import_source("currentProgram", "fallback_binding", False)

    # Try state.getCurrentProgram() as last resort
    state_obj = None
    if _FLAT_API_AVAILABLE and state:
        try:
            state_obj = _resolve_callable_or_value(state)
        except Exception:
            pass
    if state_obj is None:
        state_obj = _CTX.get("state") or _fallback_binding("state")
    if state_obj is not None:
        try:
            prog = state_obj.getCurrentProgram()
            if prog is not None:
                _log_import_source("currentProgram", "state_getCurrentProgram", True)
                return prog
        except Exception as e:
            _log_import_source("currentProgram", f"state_getCurrentProgram_error({str(e)})", False)
    _log_import_source("currentProgram", "state_getCurrentProgram", False)

    _log_import_source("currentProgram", "ALL_METHODS_FAILED", False)
    raise RuntimeError("No program is active in Ghidra. Cache may not be set properly.")


def get_cached_context():
    """Get all cached context information."""
    # Try to get context directly from main module
    try:
        import sys
        if 'ghidra_mcp_server' in sys.modules:
            main_module = sys.modules['ghidra_mcp_server']
            if hasattr(main_module, '_context'):
                ctx = main_module._context
                return ctx.to_dict()
    except:
        pass

    # Try alternative import method
    try:
        import ghidra_mcp_server
        if hasattr(ghidra_mcp_server, '_context'):
            ctx = ghidra_mcp_server._context
            return ctx.to_dict()
    except:
        pass

    # Fallback to cached references
    global _cached_program_ref, _cached_address_ref, _cached_location_ref, _cached_selection_ref
    global _cached_highlight_ref, _cached_monitor_ref, _cached_state_ref, _cached_script_ref

    return {
        "program": _cached_program_ref.getName() if _cached_program_ref else None,
        "address": str(_cached_address_ref) if _cached_address_ref else None,
        "location": str(_cached_location_ref) if _cached_location_ref else None,
        "selection": str(_cached_selection_ref) if _cached_selection_ref else None,
        "highlight": str(_cached_highlight_ref) if _cached_highlight_ref else None,
        "monitor": str(_cached_monitor_ref) if _cached_monitor_ref else None,
        "state": str(_cached_state_ref) if _cached_state_ref else None,
        "script": str(_cached_script_ref) if _cached_script_ref else None,
    }


def get_current_address():
    # Try to get cache directly from main module via sys.modules FIRST
    try:
        import sys
        if 'ghidra_mcp_server' in sys.modules:
            main_module = sys.modules['ghidra_mcp_server']
            if hasattr(main_module, '_cached_address'):
                _log_import_source("currentAddress", "main_module_cache", main_module._cached_address is not None)
                return main_module._cached_address
        _log_import_source("currentAddress", "main_module_cache", False)
    except Exception as e:
        _log_import_source("currentAddress", f"main_module_cache_error({str(e)})", False)

    # Use cached address from common module
    global _cached_address_ref
    if _cached_address_ref is not None:
        _log_import_source("currentAddress", "common_module_cache", True)
        return _cached_address_ref
    else:
        _log_import_source("currentAddress", "common_module_cache", False)

    # Try direct flat API import if available
    if _FLAT_API_AVAILABLE and currentAddress:
        try:
            addr = _resolve_callable_or_value(currentAddress)
            if addr is not None:
                _log_import_source("currentAddress", "direct_flat_api_import", True)
                return addr
            _log_import_source("currentAddress", "direct_flat_api_import", False)
        except Exception as e:
            _log_import_source("currentAddress", f"direct_flat_api_import_error({str(e)})", False)
    else:
        _log_import_source("currentAddress", "direct_flat_api_import", False)

    # First try existing context
    addr_obj = _CTX.get("currentAddress")
    addr = _resolve_callable_or_value(addr_obj) if addr_obj else None
    if addr is not None:
        _log_import_source("currentAddress", "existing_context", True)
        return addr
    else:
        _log_import_source("currentAddress", "existing_context", False)

    # If no address found, try to refresh context from Ghidra
    refresh_success = _refresh_context_from_ghidra()
    if refresh_success:
        addr_obj = _CTX.get("currentAddress")
        addr = _resolve_callable_or_value(addr_obj) if addr_obj else None
        if addr is not None:
            _log_import_source("currentAddress", "refreshed_context", True)
            return addr
    _log_import_source("currentAddress", "refreshed_context", False)

    # Fallback to direct binding lookup
    addr_obj = _fallback_binding("currentAddress")
    addr = _resolve_callable_or_value(addr_obj)
    if addr is not None:
        _log_import_source("currentAddress", "fallback_binding", True)
        return addr
    else:
        _log_import_source("currentAddress", "fallback_binding", False)

    _log_import_source("currentAddress", "ALL_METHODS_FAILED", False)
    return addr


def parse_address(addr_text: str):
    if addr_text is None:
        raise ValueError("Address text is missing.")
    if addr_text.lower() == "current":
        cur = get_current_address()
        if cur is None:
            raise RuntimeError("currentAddress is not available.")
        return cur
    factory = get_program().getAddressFactory()
    cleaned = addr_text.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    addr = factory.getAddress(cleaned)
    if addr is None:
        raise ValueError(f"Unable to parse address: {addr_text}")
    return addr


def run_in_ui(func):
    if SystemUtilities.isInHeadlessMode():
        return func()
    result_holder: Dict[str, Any] = {}
    error_holder: Dict[str, BaseException] = {}

    def runner():
        try:
            result_holder["value"] = func()
        except BaseException as exc:  # noqa: BLE001 - preserve original
            error_holder["error"] = exc

    SwingUtilities.invokeAndWait(runner)
    if "error" in error_holder:
        raise error_holder["error"]
    return result_holder.get("value")


PROGRAM_LOCK = threading.RLock()


def transaction(description: str, func):
    prog = get_program()

    def body():
        tx_id = prog.startTransaction(description)
        success = False
        try:
            result = func()
            success = True
            return result
        finally:
            prog.endTransaction(tx_id, success)

    with PROGRAM_LOCK:
        if SystemUtilities.isInHeadlessMode():
            return body()
        return run_in_ui(body)


class DecompilerHelper:
    """Wraps DecompInterface with a lock for thread-safe reuse."""

    def __init__(self):
        self._iface = DecompInterface()
        self._lock = threading.Lock()
        opts = DecompileOptions()
        self._iface.setOptions(opts)
        self._iface.setSimplificationStyle("decompile")
        self._iface.openProgram(get_program())

    def decompile(self, function):
        with self._lock:
            results = self._iface.decompileFunction(
                function, 30, TaskMonitor.DUMMY
            )
            if not results.decompileCompleted():
                msg = results.getErrorMessage()
                raise RuntimeError(f"Decompile failed: {msg}")
            return results


_DECOMPILER: DecompilerHelper | None = None


def get_decompiler() -> DecompilerHelper:
    """Lazily initialize decompiler to avoid failing when no program is open."""
    global _DECOMPILER
    if _DECOMPILER is None:
        _DECOMPILER = DecompilerHelper()
    return _DECOMPILER


def decompile_function(function) -> Dict[str, Any]:
    results = get_decompiler().decompile(function)
    decomp = results.getDecompiledFunction()
    return {
        "signature": decomp.getSignature(),
        "pseudo_c": decomp.getC(),
        "warnings": results.getErrorMessage() or "",
    }


def collect_instructions(function) -> List[Dict[str, Any]]:
    listing = get_program().getListing()
    instructions = []
    iterator = listing.getInstructions(function.getBody(), True)
    while iterator.hasNext():
        instr = iterator.next()
        try:
            raw_bytes = instr.getBytes()
            byte_str = " ".join(f"{b & 0xFF:02x}" for b in raw_bytes) if raw_bytes else ""
        except Exception:
            byte_str = ""
        instructions.append(
            {
                "address": str(instr.getAddress()),
                "mnemonic": instr.getMnemonicString(),
                "instruction": str(instr),
                "bytes": byte_str,
            }
        )
    return instructions


def find_variable(func, name: str):
    for param in func.getParameters():
        if param.getName() == name:
            return param
    for var in func.getLocalVariables():
        if var.getName() == name:
            return var
    return None


def debug_log_context(tag: str = "startup"):
    """Print current program/address context for troubleshooting."""
    prog = _resolve_callable_or_value(_CTX.get("currentProgram"))
    addr = _resolve_callable_or_value(_CTX.get("currentAddress"))
    headless = SystemUtilities.isInHeadlessMode()
    prog_name = prog.getName() if prog else None
    print(
        f"[Ghidra-MCP-Bridge][Context][{tag}] "
        f"program={prog_name} addr={addr} headless={headless} "
        f"context_keys={list(_CTX.keys())}"
    )


def test_context():
    """Test and diagnose context access for debugging purposes."""
    import sys

    result: Dict[str, Any] = {
        "timestamp": str(sys.modules.get("time", type("", (), {"time": lambda: "unknown"}))().time() if hasattr(sys.modules.get("time", None), "time") else "unknown"),
        "test_results": {},
        "errors": [],
        "import_debug": {
            "flat_api_available": _FLAT_API_AVAILABLE,
            "last_program_source": _last_program_source,
            "last_address_source": _last_address_source,
            "recent_import_log": _import_source_log[-10:] if len(_import_source_log) > 0 else [],
            "import_log_count": len(_import_source_log)
        },
        "summary": "unknown"
    }

    # Test 1: Main module access
    try:
        main_module = sys.modules.get('ghidra_mcp_server')
        result["test_results"]["main_module_exists"] = main_module is not None

        if main_module:
            result["test_results"]["main_cached_program"] = hasattr(main_module, '_cached_program') and main_module._cached_program is not None
            result["test_results"]["main_cached_address"] = hasattr(main_module, '_cached_address') and main_module._cached_address is not None

            if hasattr(main_module, '_cached_program') and main_module._cached_program:
                try:
                    # Test safe method call
                    program_name = main_module._cached_program.getName()
                    result["test_results"]["program_getName_success"] = True
                    result["test_results"]["program_name"] = program_name
                except Exception as e:
                    result["test_results"]["program_getName_success"] = False
                    result["errors"].append(f"getName() failed: {str(e)}")
        else:
            result["errors"].append("Main module not found")
    except Exception as e:
        result["errors"].append(f"Main module test failed: {str(e)}")

    # Test 2: Common module cached references
    try:
        global _cached_program_ref, _cached_address_ref
        result["test_results"]["common_cached_program_ref"] = _cached_program_ref is not None
        result["test_results"]["common_cached_address_ref"] = _cached_address_ref is not None
    except Exception as e:
        result["errors"].append(f"Common cache test failed: {str(e)}")

    # Test 3: Context dictionary
    try:
        result["test_results"]["ctx_keys"] = list(_CTX.keys())
        result["test_results"]["ctx_has_program"] = "currentProgram" in _CTX
        result["test_results"]["ctx_has_address"] = "currentAddress" in _CTX
    except Exception as e:
        result["errors"].append(f"Context dict test failed: {str(e)}")

    # Test 4: Try get_program() function
    try:
        prog = get_program()
        result["test_results"]["get_program_success"] = True
        result["test_results"]["get_program_type"] = str(type(prog))
        try:
            prog_name = prog.getName()
            result["test_results"]["get_program_getName_success"] = True
            result["test_results"]["get_program_name"] = prog_name
        except Exception as e:
            result["test_results"]["get_program_getName_success"] = False
            result["errors"].append(f"get_program().getName() failed: {str(e)}")
    except Exception as e:
        result["test_results"]["get_program_success"] = False
        result["errors"].append(f"get_program() failed: {str(e)}")

    # Test 5: Try get_current_address() function
    try:
        addr = get_current_address()
        result["test_results"]["get_current_address_success"] = True
        result["test_results"]["get_current_address_type"] = str(type(addr)) if addr else "None"
        result["test_results"]["get_current_address_str"] = str(addr) if addr else None
    except Exception as e:
        result["test_results"]["get_current_address_success"] = False
        result["errors"].append(f"get_current_address() failed: {str(e)}")

    # Test 6: Try get_program_direct() function (pure direct access, no cache)
    try:
        prog_direct = get_program_direct()
        result["test_results"]["get_program_direct_success"] = prog_direct is not None
        result["test_results"]["get_program_direct_type"] = str(type(prog_direct)) if prog_direct else "None"
        if prog_direct:
            try:
                prog_direct_name = prog_direct.getName()
                result["test_results"]["get_program_direct_name"] = prog_direct_name
            except Exception as e:
                result["errors"].append(f"get_program_direct().getName() failed: {str(e)}")
    except Exception as e:
        result["test_results"]["get_program_direct_success"] = False
        result["errors"].append(f"get_program_direct() failed: {str(e)}")

    # Test 7: Try get_program_simple() function (injected function access)
    try:
        prog_simple = get_program_simple()
        result["test_results"]["get_program_simple_success"] = prog_simple is not None
        result["test_results"]["get_program_simple_type"] = str(type(prog_simple)) if prog_simple else "None"
        if prog_simple:
            try:
                prog_simple_name = prog_simple.getName()
                result["test_results"]["get_program_simple_name"] = prog_simple_name
            except Exception as e:
                result["errors"].append(f"get_program_simple().getName() failed: {str(e)}")
    except Exception as e:
        result["test_results"]["get_program_simple_success"] = False
        result["errors"].append(f"get_program_simple() failed: {str(e)}")

    # Test 8: Check if Ghidra Flat API functions were injected into this module
    try:
        flat_api_functions = ['currentProgram', 'currentAddress', 'currentLocation', 'currentSelection', 'currentHighlight', 'monitor', 'state', 'script']
        injected_functions = {}
        injected_callable_functions = {}

        for func_name in flat_api_functions:
            # Check if function exists in current module
            injected_functions[func_name] = func_name in globals()

            # Check if function is callable
            if func_name in globals():
                try:
                    func = globals()[func_name]
                    injected_callable_functions[func_name] = callable(func)

                    # Try to call currentProgram if it exists and is callable
                    if func_name == 'currentProgram' and callable(func):
                        try:
                            prog_injected = func()
                            result["test_results"]["injected_currentProgram_call_success"] = prog_injected is not None
                            if prog_injected:
                                result["test_results"]["injected_currentProgram_name"] = prog_injected.getName()
                        except Exception as e:
                            result["test_results"]["injected_currentProgram_call_success"] = False
                            result["errors"].append(f"injected currentProgram() call failed: {str(e)}")
                except Exception as e:
                    injected_callable_functions[func_name] = False
                    result["errors"].append(f"checking {func_name} callable failed: {str(e)}")
            else:
                injected_callable_functions[func_name] = False

        result["test_results"]["injected_functions"] = injected_functions
        result["test_results"]["injected_callable_functions"] = injected_callable_functions
        result["test_results"]["total_injected_functions"] = sum(injected_functions.values())
        result["test_results"]["total_callable_injected_functions"] = sum(injected_callable_functions.values())

    except Exception as e:
        result["errors"].append(f"Injected functions test failed: {str(e)}")

    # Determine overall status
    if len(result["errors"]) == 0:
        result["summary"] = "all_tests_passed"
    elif result["test_results"].get("get_program_success") and result["test_results"].get("get_current_address_success"):
        result["summary"] = "basic_functions_work"
    else:
        result["summary"] = "critical_failures"

    return result


def get_import_debug_info():
    """Get detailed import source debugging information."""
    result = {
        "flat_api_status": {
            "available": _FLAT_API_AVAILABLE,
            "currentProgram_callable": callable(currentProgram) if currentProgram else False,
            "currentAddress_callable": callable(currentAddress) if currentAddress else False,
            "currentProgram_exists": currentProgram is not None,
            "currentAddress_exists": currentAddress is not None,
        },
        "last_successful_sources": {
            "program": _last_program_source,
            "address": _last_address_source
        },
        "import_log": {
            "total_attempts": len(_import_source_log),
            "recent_entries": _import_source_log[-15:] if len(_import_source_log) > 0 else [],
            "success_rate_by_source": {}
        },
        "cache_status": {
            "main_module_cache": {
                "program": None,
                "address": None
            },
            "common_module_cache": {
                "program": _cached_program_ref is not None,
                "address": _cached_address_ref is not None
            }
        },
        "context_status": {
            "ctx_keys": list(_CTX.keys()),
            "ctx_has_program": "currentProgram" in _CTX,
            "ctx_has_address": "currentAddress" in _CTX
        }
    }

    # Try to get main module cache status
    try:
        import sys
        if 'ghidra_mcp_server' in sys.modules:
            main_module = sys.modules['ghidra_mcp_server']
            result["cache_status"]["main_module_cache"]["program"] = hasattr(main_module, '_cached_program') and main_module._cached_program is not None
            result["cache_status"]["main_module_cache"]["address"] = hasattr(main_module, '_cached_address') and main_module._cached_address is not None
    except:
        pass

    # Calculate success rates by source
    if _import_source_log:
        sources = {}
        for entry in _import_source_log:
            source = entry["source"]
            if source not in sources:
                sources[source] = {"success": 0, "total": 0}
            sources[source]["total"] += 1
            if entry["found"]:
                sources[source]["success"] += 1

        for source, stats in sources.items():
            if stats["total"] > 0:
                result["import_log"]["success_rate_by_source"][source] = {
                    "rate": round(stats["success"] / stats["total"], 2),
                    "success_count": stats["success"],
                    "total_count": stats["total"]
                }

    return result


print("[Ghidra-MCP-Bridge][Common] get_import_debug_info function defined successfully")

def get_program_simple():
    """
    简化版本：尝试直接调用currentProgram()而不使用缓存
    如果主脚本成功注入了函数，这应该可以直接工作
    """
    try:
        # 检查是否被注入了currentProgram函数
        if hasattr(__import__('mcp_apis.common', fromlist=['currentProgram']), 'currentProgram'):
            func = getattr(__import__('mcp_apis.common', fromlist=['currentProgram']), 'currentProgram')
            if callable(func):
                prog = func()
                _log_import_source("currentProgram", "simple_injected_call", prog is not None)
                return prog

        # 回退到检查当前模块全局变量
        if 'currentProgram' in globals() and callable(globals()['currentProgram']):
            prog = globals()['currentProgram']()
            _log_import_source("currentProgram", "simple_globals_call", prog is not None)
            return prog

        _log_import_source("currentProgram", "simple_access_failed", False)
        return None
    except Exception as e:
        _log_import_source("currentProgram", f"simple_access_error({str(e)})", False)
        return None


__all__ = [
    "CodeUnit",
    "SourceType",
    "get_program",
    "get_program_direct",
    "get_program_simple",
    "get_current_address",
    "get_cached_context",
    "parse_address",
    "transaction",
    "decompile_function",
    "collect_instructions",
    "find_variable",
    "get_decompiler",
    "debug_log_context",
    "test_context",
    "get_import_debug_info",
    "set_context",
    "set_cached_context",
    "reset_context",
]

# Debug: Confirm key functions are defined
print(f"[Ghidra-MCP-Bridge][Common] Module loaded successfully")
print(f"[Ghidra-MCP-Bridge][Common] test_context defined: {'test_context' in globals()}")
print(f"[Ghidra-MCP-Bridge][Common] get_import_debug_info defined: {'get_import_debug_info' in globals()}")
print(f"[Ghidra-MCP-Bridge][Common] Available functions: {[x for x in globals().keys() if callable(globals()[x]) and not x.startswith('_')]}")
