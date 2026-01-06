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
# Compact Mode Schema
# ============================================================

COMPACT_SCHEMA = {
    "info": ["name", "address", "signature", "size"],
}


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
        query: Function name or address (0x... format or pure hex)

    Returns:
        (function, error_message) - success returns (func, None)
    """
    fm = prog.getFunctionManager()
    q = str(query).strip()  # 确保是字符串

    # 判断是否为地址：
    # 1. 带 0x 前缀
    # 2. 纯十六进制字符且长度 >= 5 (避免短函数名如 "F0" 误判)
    is_address = q.lower().startswith("0x") or (
        len(q) >= 5 and all(c in '0123456789abcdefABCDEF' for c in q)
    )

    if is_address:
        try:
            addr_str = q if q.lower().startswith("0x") else "0x" + q
            addr = prog.getAddressFactory().getAddress(addr_str)
            if addr is None:
                return None, f"Invalid address format: {q}"
            func = fm.getFunctionContaining(addr)
            if func:
                return func, None
            # 地址有效但无函数，继续尝试作为函数名
        except Exception:
            pass  # 地址解析失败，继续尝试作为函数名

    # Try as function name
    for func in fm.getFunctions(True):
        if func.getName() == q:
            return func, None

    # 如果是地址格式但没找到函数，返回明确错误
    if is_address:
        return None, f"No function at address: {q}"

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
        (lines_list, error_message) - success returns (list of "lineno: code", None)
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

        # 获取原始代码并按行处理
        raw_code = decomp_func.getC()
        if not raw_code:
            return None, "Decompilation returned empty result"

        # 分割为行并添加行号
        lines = raw_code.split('\n')
        # 过滤掉首尾空行，但保留中间的空行
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()

        # 格式化为 "行号: 代码" 格式
        numbered_lines = []
        for i, line in enumerate(lines, 1):
            numbered_lines.append(f"{i}: {line}")

        return numbered_lines, None
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
        list of formatted instruction strings like "00100004 200f013c     aui        at,zero,0xf200000"
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

        # Format: "address bytes     mnemonic   operands"
        # 地址带0x前缀，字节16位左对齐，助记符10位左对齐，操作数
        addr_str = "0x" + str(instr.getAddress())
        mnemonic = instr.getMnemonicString()
        operands = ",".join(operands_list)

        formatted = f"{addr_str} {bytes_hex:<16} {mnemonic:<10} {operands}"
        instructions.append(formatted)

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
        "address": "0x" + str(func.getEntryPoint()),
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
def view(state, q="", type="both", timeout=30, limit=500, verbose=""):
    """
    Unified view API for decompilation and disassembly.

    Args:
        state: Ghidra GhidraState object
        q: Query - function name or address, comma-separated for batch
        type: View type - "both" (default), "decompile", "disassemble"
        timeout: Decompilation timeout in seconds (default 30)
        limit: Max instructions per function (default 500)
        verbose: Output format:
               - "" (default): Compact format with info array
               - "true"/"1": Verbose dict format with all fields

    Returns:
        dict: Aggregated view results for all queried functions

    路由: GET /api/v1/view?q=<query>&type=<type>&timeout=30&limit=500&verbose=<bool>
    """
    prog, err = _get_prog(state)
    if err:
        return err

    # 强制转为字符串，防止纯数字被服务器参数解析转为 int
    q = str(q) if q else ""

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

    # Parse verbose parameter
    is_verbose = str(verbose).lower() in ("true", "1", "yes")

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

            if is_verbose:
                # Verbose mode: keep full dict format
                func_result["query"] = query
                functions.append(func_result)
            else:
                # Compact mode: use info array for metadata
                compact_result = {
                    "info": [
                        func_result["name"],
                        func_result["address"],
                        func_result["signature"],
                        func_result["size"],
                    ]
                }
                # Add decompiled code if present
                if "decompiled" in func_result:
                    compact_result["decompiled"] = func_result["decompiled"]
                if "decompile_error" in func_result:
                    compact_result["decompile_error"] = func_result["decompile_error"]
                # Add instructions if present
                if "instructions" in func_result:
                    compact_result["instructions"] = func_result["instructions"]
                functions.append(compact_result)

        # Build response
        if is_verbose:
            response = {
                "functions": functions,
                "summary": {
                    "requested": len(queries),
                    "found": len(functions),
                    "failed": len(errors),
                },
            }
        else:
            response = {
                "functions": functions,
                "_schema": COMPACT_SCHEMA,
            }

        # Only include errors if present
        if errors:
            response["errors"] = errors

        return _ok(response)

    finally:
        if decomp:
            decomp.dispose()
