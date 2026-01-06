"""
V1 View API - Unified View for AI/MCP Tools

State Passing Pattern - 面向 AI 的统一查看接口，支持批量查询。

=== 设计目标 ===
- 一个工具解决所有查看需求，减少 AI 调用多个工具带来的可靠性下降
- 默认同时返回反编译和汇编，为 AI 提供完整上下文
- 支持批量查询，一次请求查看多个函数

=== 使用方式 ===
    import api_v1.view as v1_view
    result = v1_view.view(state, q="main,init", type="both")

路由: GET /api/v1/view?q=<query>&type=<type>&timeout=30&limit=500
"""

from api import route
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


# ============================================================
# Response Helpers
# ============================================================

def _ok(data):
    """Construct success response"""
    return {"success": True, "data": data}


def _err(message):
    """Construct error response"""
    return {"success": False, "error": message}


def _get_prog(state):
    """Get current program from state"""
    prog = state.getCurrentProgram()
    if prog is None:
        return None, _err("No program loaded")
    return prog, None


# ============================================================
# Function Resolution
# ============================================================

def _resolve_function(prog, query):
    """
    Resolve function by address or name.

    Args:
        prog: Ghidra program object
        query: Function name or address (0x... format)

    Returns:
        (function, error_message) - success returns (func, None)
    """
    fm = prog.getFunctionManager()
    q = query.strip()

    # Try as address first (0x prefix or pure hex 8+ chars)
    if q.lower().startswith("0x") or (len(q) >= 8 and all(c in '0123456789abcdefABCDEF' for c in q)):
        try:
            addr_str = q if q.lower().startswith("0x") else "0x" + q
            addr = prog.getAddressFactory().getAddress(addr_str)
            if addr is None:
                return None, f"Invalid address format: {q}"
            func = fm.getFunctionContaining(addr)
            if func:
                return func, None
            return None, f"No function at address: {q}"
        except Exception as e:
            return None, f"Address parse error: {str(e)}"

    # Try as function name
    for func in fm.getFunctions(True):
        if func.getName() == q:
            return func, None

    return None, f"Function not found: {q}"


# ============================================================
# Decompile Function
# ============================================================

def _decompile_function(decomp, func, timeout):
    """
    Decompile a single function.

    Args:
        decomp: DecompInterface instance (reused)
        func: Ghidra function object
        timeout: Decompilation timeout in seconds

    Returns:
        (c_code, error_message) - success returns (code, None)
    """
    try:
        monitor = ConsoleTaskMonitor()
        results = decomp.decompileFunction(func, int(timeout), monitor)

        if not results.decompileCompleted():
            error_msg = results.getErrorMessage()
            return None, f"Decompilation failed: {error_msg}"

        decomp_func = results.getDecompiledFunction()
        if decomp_func is None:
            return None, "Decompilation returned no result"

        return decomp_func.getC(), None
    except Exception as e:
        return None, f"Decompile error: {str(e)}"


# ============================================================
# Disassemble Function
# ============================================================

def _disassemble_function(prog, func, limit):
    """
    Disassemble a single function.

    Args:
        prog: Ghidra program object
        func: Ghidra function object
        limit: Maximum instructions to return

    Returns:
        list of instruction dicts
    """
    listing = prog.getListing()
    instructions = []
    limit_int = int(limit)

    func_body = func.getBody()

    for instr in listing.getInstructions(func_body, True):
        if len(instructions) >= limit_int:
            break

        # Get instruction bytes
        instr_bytes = instr.getBytes()
        bytes_hex = ''.join('%02x' % (b & 0xff) for b in instr_bytes)

        # Get operands
        operands_list = []
        for i in range(instr.getNumOperands()):
            op_repr = instr.getDefaultOperandRepresentation(i)
            if op_repr:
                operands_list.append(op_repr)

        instructions.append({
            "address": str(instr.getAddress()),
            "bytes": bytes_hex,
            "mnemonic": instr.getMnemonicString(),
            "operands": ", ".join(operands_list)
        })

    return instructions


# ============================================================
# View Single Function
# ============================================================

def _view_single_function(prog, decomp, func, view_type, timeout, limit):
    """
    View a single function with specified type.

    Args:
        prog: Ghidra program object
        decomp: DecompInterface instance (can be None if not needed)
        func: Ghidra function object
        view_type: "both", "decompile", or "disassemble"
        timeout: Decompilation timeout
        limit: Max instructions

    Returns:
        dict with function info and view results
    """
    func_body = func.getBody()
    result = {
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "signature": str(func.getSignature()),
        "size": func_body.getNumAddresses() if func_body else 0,
    }

    # Decompile if needed
    if view_type in ("both", "decompile"):
        if decomp:
            c_code, err = _decompile_function(decomp, func, timeout)
            if err:
                result["decompiled"] = None
                result["decompile_error"] = err
            else:
                result["decompiled"] = c_code
        else:
            result["decompiled"] = None
            result["decompile_error"] = "Decompiler not available"

    # Disassemble if needed
    if view_type in ("both", "disassemble"):
        instructions = _disassemble_function(prog, func, limit)
        result["instructions"] = instructions
        result["instruction_count"] = len(instructions)

    return result


# ============================================================
# Main View Function
# ============================================================

@route("/api/v1/view")
def view(state, q="", type="both", timeout=30, limit=500):
    """
    Unified view API for decompilation and disassembly.

    Args:
        state: Ghidra GhidraState object
        q: Query - function name or address, comma-separated for batch
        type: View type - "both" (default), "decompile", "disassemble"
        timeout: Decompilation timeout in seconds (default 30)
        limit: Max instructions per function (default 500)

    Returns:
        dict: Aggregated view results for all queried functions
    """
    prog, err = _get_prog(state)
    if err:
        return err

    if not q or not q.strip():
        return _err("Query parameter 'q' is required")

    # Validate view type
    view_type = type.lower()
    if view_type not in ("both", "decompile", "disassemble"):
        return _err(f"Invalid type: {type}. Valid: both, decompile, disassemble")

    # Parse query - support comma-separated batch queries
    queries = [item.strip() for item in q.split(",") if item.strip()]
    if not queries:
        return _err("No valid queries provided")

    # Initialize decompiler if needed
    decomp = None
    if view_type in ("both", "decompile"):
        decomp = DecompInterface()
        decomp.openProgram(prog)

    try:
        functions = []
        errors = []

        for query in queries:
            func, resolve_err = _resolve_function(prog, query)
            if resolve_err:
                errors.append({"query": query, "error": resolve_err})
                continue

            func_result = _view_single_function(
                prog, decomp, func, view_type, timeout, limit
            )
            func_result["query"] = query
            functions.append(func_result)

        # Build summary
        summary = {
            "requested": len(queries),
            "found": len(functions),
            "failed": len(errors),
        }

        return _ok({
            "query": q,
            "view_type": view_type,
            "functions": functions,
            "summary": summary,
            "errors": errors if errors else None,
        })

    finally:
        if decomp:
            decomp.dispose()
