# api/rename.py
"""Rename API - 重命名函数、变量、参数、标签、数据类型、命名空间等"""

from api import route
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
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
    """获取当前程序"""
    prog = state.getCurrentProgram()
    if not prog:
        return None, _make_error("No program loaded")
    return prog, None


def _parse_address(prog, addr_str):
    """解析地址字符串"""
    try:
        addr = prog.getAddressFactory().getAddress(addr_str)
        if addr is None:
            return None, _make_error(f"Invalid address: {addr_str}")
        return addr, None
    except Exception as e:
        return None, _make_error(f"Address parse error: {str(e)}")


def _find_function(state, address="", name=""):
    """
    查找函数。

    Returns:
        (prog, func, error) 三元组
    """
    prog, err = _get_program(state)
    if err:
        return None, None, err

    fm = prog.getFunctionManager()
    func = None

    if address:
        addr, err = _parse_address(prog, address)
        if err:
            return None, None, err
        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
    elif name:
        for f in fm.getFunctions(True):
            if f.getName() == name:
                func = f
                break
    else:
        return None, None, _make_error("Must provide 'address' or 'name'")

    if func is None:
        return None, None, _make_error(f"Function not found: {address or name}")

    return prog, func, None


# ============================================================
# 函数重命名
# ============================================================

@route("/api/rename/function")
def rename_function(state, address="", name="", new_name=""):
    """
    重命名函数。

    路由: GET /api/rename/function?address=0x401000&new_name=main
          GET /api/rename/function?name=FUN_00401000&new_name=main

    参数:
        address: 函数地址 (与 name 二选一)
        name: 当前函数名 (与 address 二选一)
        new_name: 新函数名 (必填)
    """
    if not new_name:
        return _make_error("new_name is required")

    prog, func, err = _find_function(state, address, name)
    if err:
        return err

    old_name = func.getName()
    entry_addr = func.getEntryPoint()

    tx_id = prog.startTransaction("Rename Function")
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename function: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "address": str(entry_addr),
        "type": "function"
    })


# ============================================================
# 局部变量重命名
# ============================================================

@route("/api/rename/variable")
def rename_variable(state, function="", function_address="", var_name="", new_name=""):
    """
    重命名函数内的局部变量。

    路由: GET /api/rename/variable?function=main&var_name=local_8&new_name=counter
          GET /api/rename/variable?function_address=0x401000&var_name=local_8&new_name=counter

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        var_name: 当前变量名 (必填)
        new_name: 新变量名 (必填)
    """
    if not var_name:
        return _make_error("var_name is required")
    if not new_name:
        return _make_error("new_name is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    # 查找局部变量
    target_var = None
    for var in func.getLocalVariables():
        if var.getName() == var_name:
            target_var = var
            break

    if target_var is None:
        return _make_error(f"Variable not found: {var_name} in function {func.getName()}")

    old_name = target_var.getName()

    tx_id = prog.startTransaction("Rename Variable")
    try:
        target_var.setName(new_name, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename variable: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "function": func.getName(),
        "function_address": str(func.getEntryPoint()),
        "type": "variable"
    })


# ============================================================
# 参数重命名
# ============================================================

@route("/api/rename/parameter")
def rename_parameter(state, function="", function_address="", param="", new_name=""):
    """
    重命名函数参数。

    路由: GET /api/rename/parameter?function=main&param=0&new_name=argc
          GET /api/rename/parameter?function=main&param=param_1&new_name=argv

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        param: 参数索引(0,1,2...)或当前参数名 (必填)
        new_name: 新参数名 (必填)
    """
    if not param and param != 0:
        return _make_error("param is required (index or name)")
    if not new_name:
        return _make_error("new_name is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    params = func.getParameters()
    target_param = None

    # 尝试作为索引解析
    try:
        param_index = int(param)
        if 0 <= param_index < len(params):
            target_param = params[param_index]
    except (ValueError, TypeError):
        # 作为名称查找
        for p in params:
            if p.getName() == str(param):
                target_param = p
                break

    if target_param is None:
        return _make_error(f"Parameter not found: {param} in function {func.getName()}")

    old_name = target_param.getName()
    ordinal = target_param.getOrdinal()

    tx_id = prog.startTransaction("Rename Parameter")
    try:
        target_param.setName(new_name, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename parameter: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "ordinal": ordinal,
        "function": func.getName(),
        "function_address": str(func.getEntryPoint()),
        "type": "parameter"
    })


# ============================================================
# 全局变量重命名
# ============================================================

@route("/api/rename/global")
def rename_global(state, address="", name="", new_name=""):
    """
    重命名全局变量。

    路由: GET /api/rename/global?address=0x404000&new_name=g_config
          GET /api/rename/global?name=DAT_00404000&new_name=g_config

    参数:
        address: 全局变量地址 (与 name 二选一)
        name: 当前全局变量名 (与 address 二选一)
        new_name: 新名称 (必填)
    """
    if not new_name:
        return _make_error("new_name is required")

    prog, err = _get_program(state)
    if err:
        return err

    st = prog.getSymbolTable()
    target_sym = None
    target_addr = None

    if address:
        addr, err = _parse_address(prog, address)
        if err:
            return err
        target_addr = addr
        # 查找该地址的符号
        for sym in st.getSymbols(addr):
            sym_type = sym.getSymbolType()
            if sym_type == SymbolType.GLOBAL_VAR or sym_type == SymbolType.GLOBAL or sym_type == SymbolType.LABEL:
                target_sym = sym
                break
    elif name:
        # 按名称查找
        for sym in st.getAllSymbols(True):
            if sym.getName() == name:
                sym_type = sym.getSymbolType()
                if sym_type == SymbolType.GLOBAL_VAR or sym_type == SymbolType.GLOBAL or sym_type == SymbolType.LABEL:
                    target_sym = sym
                    target_addr = sym.getAddress()
                    break
    else:
        return _make_error("Must provide 'address' or 'name'")

    if target_sym is None:
        return _make_error(f"Global symbol not found: {address or name}")

    old_name = target_sym.getName()

    tx_id = prog.startTransaction("Rename Global")
    try:
        target_sym.setName(new_name, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename global: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "address": str(target_addr),
        "type": "global"
    })


# ============================================================
# 标签重命名
# ============================================================

@route("/api/rename/label")
def rename_label(state, address="", new_name=""):
    """
    重命名标签。

    路由: GET /api/rename/label?address=0x401050&new_name=loop_start

    参数:
        address: 标签地址 (必填)
        new_name: 新标签名 (必填)
    """
    if not address:
        return _make_error("address is required")
    if not new_name:
        return _make_error("new_name is required")

    prog, err = _get_program(state)
    if err:
        return err

    addr, err = _parse_address(prog, address)
    if err:
        return err

    st = prog.getSymbolTable()
    target_sym = None

    # 查找该地址的标签符号
    for sym in st.getSymbols(addr):
        if sym.getSymbolType() == SymbolType.LABEL:
            target_sym = sym
            break

    # 如果没有标签，尝试获取主符号
    if target_sym is None:
        primary = st.getPrimarySymbol(addr)
        if primary and primary.getSymbolType() == SymbolType.LABEL:
            target_sym = primary

    if target_sym is None:
        return _make_error(f"Label not found at address: {address}")

    old_name = target_sym.getName()

    tx_id = prog.startTransaction("Rename Label")
    try:
        target_sym.setName(new_name, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename label: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "address": str(addr),
        "type": "label"
    })


# ============================================================
# 数据类型重命名
# ============================================================

@route("/api/rename/datatype")
def rename_datatype(state, name="", path="", new_name=""):
    """
    重命名数据类型。

    路由: GET /api/rename/datatype?name=struct_1&new_name=ConfigStruct
          GET /api/rename/datatype?path=/MyCategory/struct_1&new_name=ConfigStruct

    参数:
        name: 数据类型名称 (与 path 二选一)
        path: 数据类型完整路径，如 /MyCategory/struct_1 (与 name 二选一)
        new_name: 新名称 (必填)
    """
    if not new_name:
        return _make_error("new_name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    target_dt = None

    if path:
        # 按路径查找
        from ghidra.program.model.data import DataTypePath
        try:
            dt_path = DataTypePath(path)
            target_dt = dtm.getDataType(dt_path)
        except Exception:
            # 尝试直接按路径解析
            target_dt = dtm.getDataType(path)
    elif name:
        # 按名称搜索（可能找到多个，取第一个）
        for dt in dtm.getAllDataTypes():
            if dt.getName() == name:
                target_dt = dt
                break
    else:
        return _make_error("Must provide 'name' or 'path'")

    if target_dt is None:
        return _make_error(f"Data type not found: {path or name}")

    old_name = target_dt.getName()
    old_path = target_dt.getPathName()

    tx_id = prog.startTransaction("Rename DataType")
    try:
        # DataType.setName() 不需要 SourceType 参数
        target_dt.setName(new_name)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename datatype: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "old_path": old_path,
        "new_path": target_dt.getPathName(),
        "type": "datatype"
    })


# ============================================================
# 命名空间/类重命名
# ============================================================

@route("/api/rename/namespace")
def rename_namespace(state, name="", new_name=""):
    """
    重命名命名空间或类。

    路由: GET /api/rename/namespace?name=Class1&new_name=MyClass
          GET /api/rename/namespace?name=std::vector&new_name=my_vector

    参数:
        name: 命名空间/类名称，支持路径如 std::MyClass (必填)
        new_name: 新名称 (必填)
    """
    if not name:
        return _make_error("name is required")
    if not new_name:
        return _make_error("new_name is required")

    prog, err = _get_program(state)
    if err:
        return err

    st = prog.getSymbolTable()
    global_ns = prog.getGlobalNamespace()

    # 解析命名空间路径
    path_parts = name.split("::")
    target_name = path_parts[-1]
    parent_ns = global_ns

    if len(path_parts) > 1:
        for part in path_parts[:-1]:
            found_ns = st.getNamespace(part, parent_ns)
            if found_ns is None:
                return _make_error(f"Namespace path not found: {name}")
            parent_ns = found_ns

    # 查找目标命名空间/类的符号
    target_sym = None
    for sym in st.getSymbols(target_name, parent_ns):
        sym_type = sym.getSymbolType()
        if sym_type == SymbolType.NAMESPACE or sym_type == SymbolType.CLASS:
            target_sym = sym
            break

    if target_sym is None:
        # 尝试直接获取命名空间对象
        ns_obj = st.getNamespace(target_name, parent_ns)
        if ns_obj:
            # 找到命名空间，但需要找到对应的符号来重命名
            for sym in st.getAllSymbols(True):
                if sym.getName() == target_name:
                    sym_type = sym.getSymbolType()
                    if sym_type == SymbolType.NAMESPACE or sym_type == SymbolType.CLASS:
                        sym_parent = sym.getParentNamespace()
                        if sym_parent and sym_parent.equals(parent_ns):
                            target_sym = sym
                            break

    if target_sym is None:
        return _make_error(f"Namespace or class not found: {name}")

    old_name = target_sym.getName()
    sym_type_str = str(target_sym.getSymbolType())

    tx_id = prog.startTransaction("Rename Namespace")
    try:
        target_sym.setName(new_name, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        if "Circular" in error_msg:
            return _make_error(f"Circular dependency detected: {new_name}")
        return _make_error(f"Failed to rename namespace: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "full_path": name,
        "symbol_type": sym_type_str,
        "type": "namespace"
    })


# ============================================================
# 反编译器级别变量重命名（推荐）
# ============================================================

def _decompile_function(prog, func, timeout=30):
    """
    反编译函数并返回 HighFunction。

    Returns:
        (high_func, error) 二元组
    """
    decomp = DecompInterface()
    decomp.openProgram(prog)

    try:
        monitor = ConsoleTaskMonitor()
        results = decomp.decompileFunction(func, int(timeout), monitor)

        if not results.decompileCompleted():
            error_msg = results.getErrorMessage()
            return None, _make_error(f"Decompilation failed: {error_msg}")

        high_func = results.getHighFunction()
        if high_func is None:
            return None, _make_error("Decompilation returned no HighFunction")

        return high_func, None
    finally:
        decomp.dispose()


@route("/api/rename/decompiler/variable")
def rename_decompiler_variable(state, function="", function_address="", var_name="", new_name="", timeout=30):
    """
    重命名反编译器中的局部变量（推荐方式）。

    与 /api/rename/variable 不同，此 API 直接操作反编译器识别的高级变量，
    修改后在反编译视图中立即可见。

    路由: GET /api/rename/decompiler/variable?function=main&var_name=local_8&new_name=counter
          GET /api/rename/decompiler/variable?function_address=0x401000&var_name=uVar1&new_name=result

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        var_name: 当前变量名（反编译视图中显示的名称）(必填)
        new_name: 新变量名 (必填)
        timeout: 反编译超时秒数 (默认 30)
    """
    if not var_name:
        return _make_error("var_name is required")
    if not new_name:
        return _make_error("new_name is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    # 反编译函数以获取 HighFunction
    high_func, err = _decompile_function(prog, func, timeout)
    if err:
        return err

    # 从 LocalSymbolMap 查找变量
    lsm = high_func.getLocalSymbolMap()
    target_sym = None

    for sym in lsm.getSymbols():
        if sym.getName() == var_name:
            target_sym = sym
            break

    if target_sym is None:
        # 列出可用变量帮助调试
        available = [s.getName() for s in lsm.getSymbols()]
        return _make_error(f"Variable not found in decompiler: {var_name}. Available: {available[:20]}")

    old_name = target_sym.getName()
    high_var = target_sym.getHighVariable()

    # 使用 HighFunctionDBUtil 更新数据库
    tx_id = prog.startTransaction("Rename Decompiler Variable")
    try:
        # updateDBVariable(HighSymbol, String name, DataType dataType, SourceType source)
        HighFunctionDBUtil.updateDBVariable(
            target_sym,
            new_name,
            None,  # 保持原数据类型
            SourceType.USER_DEFINED
        )
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename variable: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "function": func.getName(),
        "function_address": str(func.getEntryPoint()),
        "has_high_variable": high_var is not None,
        "type": "decompiler_variable"
    })


@route("/api/rename/decompiler/parameter")
def rename_decompiler_parameter(state, function="", function_address="", param="", new_name="", timeout=30):
    """
    重命名反编译器中的函数参数（推荐方式）。

    路由: GET /api/rename/decompiler/parameter?function=main&param=0&new_name=argc
          GET /api/rename/decompiler/parameter?function=main&param=param_1&new_name=argv

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        param: 参数索引(0,1,2...)或当前参数名 (必填)
        new_name: 新参数名 (必填)
        timeout: 反编译超时秒数 (默认 30)
    """
    if not param and param != 0:
        return _make_error("param is required (index or name)")
    if not new_name:
        return _make_error("new_name is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    # 反编译函数以获取 HighFunction
    high_func, err = _decompile_function(prog, func, timeout)
    if err:
        return err

    # 查找参数
    lsm = high_func.getLocalSymbolMap()
    target_sym = None
    param_index = None

    # 尝试作为索引解析
    try:
        param_index = int(param)
        # 按索引查找参数符号
        count = 0
        for sym in lsm.getSymbols():
            if sym.isParameter():
                if count == param_index:
                    target_sym = sym
                    break
                count += 1
    except (ValueError, TypeError):
        # 作为名称查找
        for sym in lsm.getSymbols():
            if sym.isParameter() and sym.getName() == str(param):
                target_sym = sym
                break

    if target_sym is None:
        # 列出可用参数帮助调试
        available = [s.getName() for s in lsm.getSymbols() if s.isParameter()]
        return _make_error(f"Parameter not found: {param}. Available: {available}")

    old_name = target_sym.getName()

    # 使用 HighFunctionDBUtil 更新数据库
    tx_id = prog.startTransaction("Rename Decompiler Parameter")
    try:
        HighFunctionDBUtil.updateDBVariable(
            target_sym,
            new_name,
            None,  # 保持原数据类型
            SourceType.USER_DEFINED
        )
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "Invalid" in error_msg:
            return _make_error(f"Invalid name: {new_name}")
        return _make_error(f"Failed to rename parameter: {error_msg}")

    return _make_success({
        "old_name": old_name,
        "new_name": new_name,
        "function": func.getName(),
        "function_address": str(func.getEntryPoint()),
        "type": "decompiler_parameter"
    })


# ============================================================
# 变量拆分（Split out as new variable）
# ============================================================

def _find_varnode_at_address(high_func, var_name, use_address, prog):
    """
    在指定地址查找变量的 Varnode。

    Args:
        high_func: HighFunction 对象
        var_name: 变量名
        use_address: 使用点地址
        prog: Program 对象

    Returns:
        (varnode, high_symbol, error) 三元组
    """
    lsm = high_func.getLocalSymbolMap()
    target_sym = None

    # 找到目标符号
    for sym in lsm.getSymbols():
        if sym.getName() == var_name:
            target_sym = sym
            break

    if target_sym is None:
        available = [s.getName() for s in lsm.getSymbols()]
        return None, None, _make_error(f"Variable not found: {var_name}. Available: {available[:20]}")

    high_var = target_sym.getHighVariable()
    if high_var is None:
        return None, None, _make_error(f"Variable {var_name} has no HighVariable (may be a constant reference)")

    # 解析目标地址
    addr, err = _parse_address(prog, use_address)
    if err:
        return None, None, err

    # 在 HighVariable 的所有 Varnode 实例中查找匹配地址的
    target_vn = None
    all_instances = []

    for vn in high_var.getInstances():
        pcode_op = vn.getDef()
        vn_addr = None

        if pcode_op is not None:
            vn_addr = pcode_op.getSeqnum().getTarget()
        else:
            # 尝试从 descendant 获取地址
            desc_iter = vn.getDescendants()
            if desc_iter.hasNext():
                desc_op = desc_iter.next()
                vn_addr = desc_op.getSeqnum().getTarget()

        if vn_addr is not None:
            all_instances.append(str(vn_addr))
            if vn_addr.equals(addr):
                target_vn = vn
                break

    if target_vn is None:
        return None, None, _make_error(
            f"No varnode found at address {use_address} for variable {var_name}. "
            f"Available addresses: {all_instances[:10]}"
        )

    return target_vn, target_sym, None


@route("/api/rename/decompiler/split")
def split_variable(state, function="", function_address="", var_name="", use_address="", new_name="", timeout=30):
    """
    拆分变量（Split out as new variable）。

    将变量在特定使用点拆分为独立的新变量。适用于编译器复用同一寄存器/栈位置
    存储不同逻辑含义的变量的情况（如循环变量被后续代码复用）。

    路由: GET /api/rename/decompiler/split?function=main&var_name=uVar1&use_address=0x401050&new_name=result

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        var_name: 要拆分的变量名 (必填)
        use_address: 变量使用点的地址，指定从哪个位置拆分 (必填)
        new_name: 拆分后新变量的名称 (必填)
        timeout: 反编译超时秒数 (默认 30)

    注意:
        - 只支持寄存器变量，栈变量暂不支持（Ghidra 限制）
        - use_address 应该是变量被定义或使用的指令地址
    """
    if not var_name:
        return _make_error("var_name is required")
    if not use_address:
        return _make_error("use_address is required (address where variable is used)")
    if not new_name:
        return _make_error("new_name is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    # 反编译函数
    high_func, err = _decompile_function(prog, func, timeout)
    if err:
        return err

    # 查找目标 Varnode
    target_vn, target_sym, err = _find_varnode_at_address(high_func, var_name, use_address, prog)
    if err:
        return err

    old_name = target_sym.getName()
    high_var = target_vn.getHigh()

    # 检查是否可以拆分（需要多个 merge group）
    instances = list(high_var.getInstances())
    if len(instances) <= 1:
        return _make_error(
            f"Variable {var_name} has only one instance, cannot split. "
            "Split is used when a variable has multiple disjoint uses."
        )

    tx_id = prog.startTransaction("Split Variable")
    try:
        # 拆分变量
        new_high_var = high_func.splitOutMergeGroup(high_var, target_vn)

        if new_high_var is None:
            prog.endTransaction(tx_id, False)
            return _make_error("splitOutMergeGroup returned None - variable may not be splittable")

        new_sym = new_high_var.getSymbol()
        if new_sym is None:
            prog.endTransaction(tx_id, False)
            return _make_error("Split succeeded but new variable has no symbol")

        # 重命名新变量
        HighFunctionDBUtil.updateDBVariable(
            new_sym,
            new_name,
            None,  # 保持原数据类型
            SourceType.USER_DEFINED
        )

        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        if "Duplicate" in error_msg or "already exists" in error_msg.lower():
            return _make_error(f"Name already exists: {new_name}")
        if "PcodeException" in error_msg or "split" in error_msg.lower():
            return _make_error(f"Cannot split variable (may be a stack variable or single-use): {error_msg}")
        return _make_error(f"Failed to split variable: {error_msg}")

    return _make_success({
        "original_name": old_name,
        "new_name": new_name,
        "use_address": use_address,
        "function": func.getName(),
        "function_address": str(func.getEntryPoint()),
        "instances_before_split": len(instances),
        "type": "split_variable"
    })


@route("/api/rename/decompiler/variable/instances")
def list_variable_instances(state, function="", function_address="", var_name="", timeout=30):
    """
    列出变量的所有使用点（用于确定拆分位置）。

    路由: GET /api/rename/decompiler/variable/instances?function=main&var_name=uVar1

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        var_name: 变量名 (必填)
        timeout: 反编译超时秒数 (默认 30)
    """
    if not var_name:
        return _make_error("var_name is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    high_func, err = _decompile_function(prog, func, timeout)
    if err:
        return err

    lsm = high_func.getLocalSymbolMap()
    target_sym = None

    for sym in lsm.getSymbols():
        if sym.getName() == var_name:
            target_sym = sym
            break

    if target_sym is None:
        available = [s.getName() for s in lsm.getSymbols()]
        return _make_error(f"Variable not found: {var_name}. Available: {available[:20]}")

    high_var = target_sym.getHighVariable()
    if high_var is None:
        return _make_error(f"Variable {var_name} has no HighVariable")

    instances = []
    for vn in high_var.getInstances():
        instance_info = {
            "storage": str(vn.getAddress()),
            "size": vn.getSize(),
        }

        # 获取定义点
        pcode_op = vn.getDef()
        if pcode_op is not None:
            instance_info["def_address"] = str(pcode_op.getSeqnum().getTarget())
            instance_info["def_opcode"] = str(pcode_op.getMnemonic())

        # 获取使用点
        uses = []
        for desc_op in vn.getDescendants():
            uses.append({
                "address": str(desc_op.getSeqnum().getTarget()),
                "opcode": str(desc_op.getMnemonic())
            })
        if uses:
            instance_info["uses"] = uses

        instances.append(instance_info)

    return _make_success({
        "variable": var_name,
        "function": func.getName(),
        "instance_count": len(instances),
        "can_split": len(instances) > 1,
        "instances": instances
    })
