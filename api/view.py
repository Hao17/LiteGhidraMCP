"""
查看 API - 提供反编译和反汇编功能

- decompile: 获取函数的 C 伪代码
- disassemble: 获取函数的汇编代码
"""

from api import route
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


# ============================================================
# 辅助函数
# ============================================================

def _make_success(data):
    """构造成功响应"""
    return {"success": True, **data}


def _make_error(message):
    """构造错误响应"""
    return {"success": False, "error": message}


def _get_program(state):
    """从 state 获取当前程序"""
    prog = state.getCurrentProgram()
    if prog is None:
        return None, _make_error("No program loaded")
    return prog, None


def _resolve_function(state, address="", name=""):
    """
    根据地址或名称查找函数

    Args:
        state: Ghidra state 对象
        address: 函数地址 (十六进制字符串，如 "0x401000")
        name: 函数名

    Returns:
        (function, error_response) - 成功返回 (func, None)，失败返回 (None, error_dict)
    """
    prog, err = _get_program(state)
    if err:
        return None, err

    fm = prog.getFunctionManager()

    # 优先使用地址查找
    if address:
        try:
            addr = prog.getAddressFactory().getAddress(address)
            if addr is None:
                return None, _make_error(f"Invalid address format: {address}")
            func = fm.getFunctionContaining(addr)
            if func:
                return func, None
            return None, _make_error(f"No function at address: {address}")
        except Exception as e:
            return None, _make_error(f"Address parse error: {str(e)}")

    # 按名称查找
    if name:
        for func in fm.getFunctions(True):
            if func.getName() == name:
                return func, None
        return None, _make_error(f"Function not found: {name}")

    return None, _make_error("Must provide 'address' or 'name' parameter")


# ============================================================
# 反编译 API
# ============================================================

@route("/api/view/decompile")
def decompile(state, address="", name="", timeout=30):
    """
    反编译函数为 C 伪代码

    路由: GET /api/view/decompile?address=0x401000
          GET /api/view/decompile?name=main

    参数:
        address: 函数地址 (十六进制)
        name: 函数名
        timeout: 反编译超时秒数 (默认 30)

    返回:
        {
            "success": true,
            "function": {"name": "...", "address": "...", "signature": "..."},
            "decompiled": "C code..."
        }
    """
    func, err = _resolve_function(state, address, name)
    if err:
        return err

    prog = state.getCurrentProgram()

    # 初始化反编译器
    decomp = DecompInterface()
    decomp.openProgram(prog)

    try:
        # 执行反编译
        monitor = ConsoleTaskMonitor()
        timeout_int = int(timeout)
        results = decomp.decompileFunction(func, timeout_int, monitor)

        if not results.decompileCompleted():
            error_msg = results.getErrorMessage()
            return _make_error(f"Decompilation failed: {error_msg}")

        decomp_func = results.getDecompiledFunction()
        if decomp_func is None:
            return _make_error("Decompilation returned no result")

        c_code = decomp_func.getC()

        return _make_success({
            "function": {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature())
            },
            "decompiled": c_code
        })
    finally:
        decomp.dispose()


# ============================================================
# 反汇编 API
# ============================================================

@route("/api/view/disassemble")
def disassemble(state, address="", name="", limit=500):
    """
    获取函数汇编代码

    路由: GET /api/view/disassemble?address=0x401000
          GET /api/view/disassemble?name=main&limit=100

    参数:
        address: 函数地址 (十六进制)
        name: 函数名
        limit: 最大指令数 (默认 500)

    返回:
        {
            "success": true,
            "function": {"name": "...", "address": "...", "size": 123},
            "instructions": [
                {"address": "0x401000", "bytes": "55", "mnemonic": "PUSH", "operands": "RBP"},
                ...
            ],
            "count": 50
        }
    """
    func, err = _resolve_function(state, address, name)
    if err:
        return err

    prog = state.getCurrentProgram()
    listing = prog.getListing()

    instructions = []
    limit_int = int(limit)

    # 遍历函数体内的所有指令
    func_body = func.getBody()

    for instr in listing.getInstructions(func_body, True):
        if len(instructions) >= limit_int:
            break

        # 获取指令字节
        instr_bytes = instr.getBytes()
        bytes_hex = ''.join('%02x' % (b & 0xff) for b in instr_bytes)

        # 获取操作数
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

    return _make_success({
        "function": {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func_body.getNumAddresses()
        },
        "instructions": instructions,
        "count": len(instructions)
    })
