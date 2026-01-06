"""
Symbol Tree API - 提供符号树查看功能

- 命名空间：列表、详情、树形结构
- 类：列表、成员查看
- 函数：列表（含命名空间）、内部符号
- 标签和全局变量
- 导入/导出符号
"""

from api import route


# ============================================================
# 辅助函数
# ============================================================

def _make_success(data):
    """构造成功响应"""
    return {"success": True, "data": data}


def _make_error(message):
    """构造错误响应"""
    return {"success": False, "error": message}


def _get_program(state):
    """从 state 获取当前程序"""
    prog = state.getCurrentProgram()
    if prog is None:
        return None, _make_error("No program loaded")
    return prog, None


def _parse_address(prog, addr_str):
    """解析地址字符串为 Address 对象"""
    try:
        addr_factory = prog.getAddressFactory()
        return addr_factory.getAddress(addr_str), None
    except Exception as e:
        return None, _make_error(f"Invalid address: {addr_str} - {str(e)}")


def _get_namespace_path(namespace):
    """获取命名空间的完整路径"""
    if namespace is None:
        return ""
    path_parts = []
    current = namespace
    while current is not None:
        name = current.getName()
        if name == "Global":
            break
        path_parts.insert(0, name)
        current = current.getParentNamespace()
    return "::".join(path_parts) if path_parts else "Global"


def _symbol_type_str(sym):
    """获取符号类型字符串"""
    return str(sym.getSymbolType())


# ============================================================
# 命名空间相关 API
# ============================================================

@route("/api/symbol_tree/namespaces")
def list_namespaces(state, limit=100):
    """
    列出顶级命名空间。

    路由: GET /api/symbol_tree/namespaces?limit=100

    Args:
        state: Ghidra GhidraState 对象
        limit: 最大返回数量

    Returns:
        dict: 顶级命名空间列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        st = prog.getSymbolTable()
        global_ns = prog.getGlobalNamespace()
        namespaces = []

        # 遍历所有符号，找出顶级命名空间
        seen = set()
        for sym in st.getAllSymbols(True):
            if len(namespaces) >= limit:
                break

            parent_ns = sym.getParentNamespace()
            if parent_ns is None:
                continue

            # 只收集 parent 为 Global 的命名空间
            if parent_ns.equals(global_ns):
                # 检查符号本身是否是命名空间/类
                sym_type = _symbol_type_str(sym)
                if sym_type in ("Namespace", "Class"):
                    name = sym.getName()
                    if name not in seen and name != "Global":
                        seen.add(name)
                        # 获取该命名空间下的符号数量
                        ns_obj = st.getNamespace(name, global_ns)
                        symbol_count = 0
                        if ns_obj:
                            for _ in st.getSymbols(ns_obj):
                                symbol_count += 1
                        namespaces.append({
                            "name": name,
                            "type": sym_type,
                            "symbol_count": symbol_count,
                        })

        # 也直接遍历命名空间
        for ns in st.getChildren(global_ns):
            if len(namespaces) >= limit:
                break
            name = ns.getName()
            if name not in seen and name != "Global":
                seen.add(name)
                symbol_count = 0
                for _ in st.getSymbols(ns):
                    symbol_count += 1
                ns_type = "Namespace"
                # 检查是否是类
                ns_sym = st.getNamespaceSymbol(ns)
                if ns_sym:
                    ns_type = _symbol_type_str(ns_sym)
                namespaces.append({
                    "name": name,
                    "type": ns_type,
                    "symbol_count": symbol_count,
                })

        return _make_success({
            "namespaces": namespaces,
            "count": len(namespaces),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_namespaces failed: {str(e)}")


@route("/api/symbol_tree/namespace")
def get_namespace(state, name="", limit=100):
    """
    获取指定命名空间的直接子项。

    路由: GET /api/symbol_tree/namespace?name=xxx&limit=100

    Args:
        state: Ghidra GhidraState 对象
        name: 命名空间名称（支持路径如 "std::vector"）
        limit: 最大返回数量

    Returns:
        dict: 命名空间内的符号和子命名空间
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not name:
        return _make_error("Namespace name is required")

    try:
        st = prog.getSymbolTable()
        global_ns = prog.getGlobalNamespace()

        # 解析命名空间路径
        path_parts = name.split("::")
        current_ns = global_ns

        for part in path_parts:
            found_ns = st.getNamespace(part, current_ns)
            if found_ns is None:
                return _make_error(f"Namespace not found: {name}")
            current_ns = found_ns

        # 收集子项
        symbols = []
        child_namespaces = []

        # 获取子命名空间
        for child_ns in st.getChildren(current_ns):
            child_name = child_ns.getName()
            symbol_count = 0
            for _ in st.getSymbols(child_ns):
                symbol_count += 1
            ns_type = "Namespace"
            ns_sym = st.getNamespaceSymbol(child_ns)
            if ns_sym:
                ns_type = _symbol_type_str(ns_sym)
            child_namespaces.append({
                "name": child_name,
                "type": ns_type,
                "symbol_count": symbol_count,
            })

        # 获取该命名空间下的符号
        for sym in st.getSymbols(current_ns):
            if len(symbols) >= limit:
                break
            sym_type = _symbol_type_str(sym)
            # 跳过命名空间和类符号（已在 child_namespaces 中）
            if sym_type in ("Namespace", "Class"):
                continue
            symbols.append({
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "type": sym_type,
                "is_primary": sym.isPrimary(),
                "is_external": sym.isExternal(),
            })

        return _make_success({
            "namespace": name,
            "path": _get_namespace_path(current_ns),
            "child_namespaces": child_namespaces,
            "symbols": symbols,
            "namespace_count": len(child_namespaces),
            "symbol_count": len(symbols),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"get_namespace failed: {str(e)}")


@route("/api/symbol_tree/namespace/tree")
def get_namespace_tree(state, name="", depth=3, limit=500):
    """
    获取命名空间的树形结构（递归）。

    路由: GET /api/symbol_tree/namespace/tree?name=xxx&depth=3&limit=500

    Args:
        state: Ghidra GhidraState 对象
        name: 命名空间名称，空字符串表示全局命名空间
        depth: 递归深度（默认3层）
        limit: 总节点数限制

    Returns:
        dict: 树形结构
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        st = prog.getSymbolTable()
        global_ns = prog.getGlobalNamespace()

        # 解析起始命名空间
        if name:
            path_parts = name.split("::")
            current_ns = global_ns
            for part in path_parts:
                found_ns = st.getNamespace(part, current_ns)
                if found_ns is None:
                    return _make_error(f"Namespace not found: {name}")
                current_ns = found_ns
            root_ns = current_ns
            root_name = name
        else:
            root_ns = global_ns
            root_name = "Global"

        # 计数器用于限制总节点数
        node_count = [0]

        def build_tree(ns, current_depth):
            """递归构建树"""
            if current_depth <= 0 or node_count[0] >= limit:
                return None

            children = []

            # 添加子命名空间
            for child_ns in st.getChildren(ns):
                if node_count[0] >= limit:
                    break
                node_count[0] += 1

                child_name = child_ns.getName()
                ns_type = "Namespace"
                ns_sym = st.getNamespaceSymbol(child_ns)
                if ns_sym:
                    ns_type = _symbol_type_str(ns_sym)

                child_node = {
                    "name": child_name,
                    "type": ns_type,
                }

                # 递归构建子树
                subtree = build_tree(child_ns, current_depth - 1)
                if subtree:
                    child_node["children"] = subtree
                else:
                    # 统计子项数量
                    symbol_count = 0
                    for _ in st.getSymbols(child_ns):
                        symbol_count += 1
                    child_node["symbol_count"] = symbol_count

                children.append(child_node)

            # 添加符号（仅在最后一层或空间允许时）
            if current_depth == 1 or len(children) == 0:
                for sym in st.getSymbols(ns):
                    if node_count[0] >= limit:
                        break
                    sym_type = _symbol_type_str(sym)
                    if sym_type in ("Namespace", "Class"):
                        continue
                    node_count[0] += 1
                    addr = sym.getAddress()
                    children.append({
                        "name": sym.getName(),
                        "type": sym_type,
                        "address": str(addr) if addr else None,
                    })

            return children if children else None

        tree_children = build_tree(root_ns, depth)

        result = {
            "name": root_name,
            "type": "Namespace",
        }
        if tree_children:
            result["children"] = tree_children

        return _make_success({
            "tree": result,
            "node_count": node_count[0],
            "depth": depth,
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"get_namespace_tree failed: {str(e)}")


# ============================================================
# 类相关 API
# ============================================================

@route("/api/symbol_tree/classes")
def list_classes(state, q="", limit=100):
    """
    列出所有类。

    路由: GET /api/symbol_tree/classes?q=xxx&limit=100

    Args:
        state: Ghidra GhidraState 对象
        q: 搜索关键词（可选）
        limit: 最大返回数量

    Returns:
        dict: 类列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        from ghidra.program.model.symbol import SymbolType

        st = prog.getSymbolTable()
        classes = []
        search_pattern = q.lower() if q else None

        for sym in st.getAllSymbols(True):
            if len(classes) >= limit:
                break

            if sym.getSymbolType() != SymbolType.CLASS:
                continue

            name = sym.getName()
            if search_pattern and search_pattern not in name.lower():
                continue

            parent_ns = sym.getParentNamespace()
            namespace = _get_namespace_path(parent_ns) if parent_ns else "Global"

            # 获取类命名空间下的成员数量
            class_ns = st.getNamespace(name, parent_ns)
            member_count = 0
            if class_ns:
                for _ in st.getSymbols(class_ns):
                    member_count += 1

            classes.append({
                "name": name,
                "address": str(sym.getAddress()),
                "namespace": namespace,
                "full_path": f"{namespace}::{name}" if namespace != "Global" else name,
                "member_count": member_count,
            })

        return _make_success({
            "query": q,
            "classes": classes,
            "count": len(classes),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_classes failed: {str(e)}")


@route("/api/symbol_tree/class")
def get_class(state, name=""):
    """
    获取类的成员（字段、方法）。

    路由: GET /api/symbol_tree/class?name=xxx

    Args:
        state: Ghidra GhidraState 对象
        name: 类名（支持完整路径如 "ns::ClassName"）

    Returns:
        dict: 类成员信息
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not name:
        return _make_error("Class name is required")

    try:
        from ghidra.program.model.symbol import SymbolType

        st = prog.getSymbolTable()
        global_ns = prog.getGlobalNamespace()

        # 解析类路径
        path_parts = name.split("::")
        class_name = path_parts[-1]
        parent_ns = global_ns

        if len(path_parts) > 1:
            for part in path_parts[:-1]:
                found_ns = st.getNamespace(part, parent_ns)
                if found_ns is None:
                    return _make_error(f"Namespace not found in path: {name}")
                parent_ns = found_ns

        # 查找类符号
        class_sym = None
        for sym in st.getSymbols(class_name, parent_ns):
            if sym.getSymbolType() == SymbolType.CLASS:
                class_sym = sym
                break

        if class_sym is None:
            return _make_error(f"Class not found: {name}")

        # 获取类命名空间
        class_ns = st.getNamespace(class_name, parent_ns)

        methods = []
        fields = []

        if class_ns:
            for sym in st.getSymbols(class_ns):
                sym_type = _symbol_type_str(sym)
                sym_info = {
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                    "type": sym_type,
                }

                if sym_type == "Function":
                    # 获取函数签名
                    fm = prog.getFunctionManager()
                    func = fm.getFunctionAt(sym.getAddress())
                    if func:
                        sym_info["signature"] = str(func.getSignature())
                        sym_info["is_thunk"] = func.isThunk()
                    methods.append(sym_info)
                else:
                    fields.append(sym_info)

        return _make_success({
            "class_name": class_name,
            "full_path": name,
            "address": str(class_sym.getAddress()),
            "methods": methods,
            "fields": fields,
            "method_count": len(methods),
            "field_count": len(fields),
        })

    except Exception as e:
        return _make_error(f"get_class failed: {str(e)}")


# ============================================================
# 函数符号相关 API
# ============================================================

@route("/api/symbol_tree/functions")
def list_functions(state, q="", namespace="", limit=100):
    """
    列出函数（带命名空间信息）。

    路由: GET /api/symbol_tree/functions?q=xxx&namespace=xxx&limit=100

    Args:
        state: Ghidra GhidraState 对象
        q: 搜索关键词（可选）
        namespace: 命名空间过滤（可选）
        limit: 最大返回数量

    Returns:
        dict: 函数列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        fm = prog.getFunctionManager()
        functions = []
        search_pattern = q.lower() if q else None
        ns_filter = namespace.lower() if namespace else None

        for func in fm.getFunctions(True):
            if len(functions) >= limit:
                break

            name = func.getName()

            # 名称过滤
            if search_pattern and search_pattern not in name.lower():
                continue

            # 命名空间过滤
            parent_ns = func.getParentNamespace()
            ns_path = _get_namespace_path(parent_ns)

            if ns_filter and ns_filter not in ns_path.lower():
                continue

            entry = func.getEntryPoint()
            body = func.getBody()

            functions.append({
                "name": name,
                "address": str(entry),
                "namespace": ns_path,
                "full_name": f"{ns_path}::{name}" if ns_path != "Global" else name,
                "signature": str(func.getSignature()),
                "size": body.getNumAddresses() if body else 0,
                "is_thunk": func.isThunk(),
                "is_external": func.isExternal(),
                "calling_convention": func.getCallingConventionName(),
            })

        return _make_success({
            "query": q,
            "namespace_filter": namespace,
            "functions": functions,
            "count": len(functions),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_functions failed: {str(e)}")


@route("/api/symbol_tree/function")
def get_function_symbols(state, name="", address=""):
    """
    获取函数内部符号（参数、局部变量、标签）。

    路由: GET /api/symbol_tree/function?name=xxx
          GET /api/symbol_tree/function?address=0x401000

    Args:
        state: Ghidra GhidraState 对象
        name: 函数名（与 address 二选一）
        address: 函数地址（与 name 二选一）

    Returns:
        dict: 函数内部符号信息
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not name and not address:
        return _make_error("Either 'name' or 'address' is required")

    try:
        fm = prog.getFunctionManager()
        func = None

        # 按地址查找
        if address:
            addr, err = _parse_address(prog, address)
            if err:
                return err
            func = fm.getFunctionAt(addr)
            if func is None:
                func = fm.getFunctionContaining(addr)
        # 按名称查找
        elif name:
            for f in fm.getFunctions(True):
                if f.getName() == name:
                    func = f
                    break

        if func is None:
            return _make_error(f"Function not found: {name or address}")

        # 获取参数
        parameters = []
        for param in func.getParameters():
            parameters.append({
                "name": param.getName(),
                "type": str(param.getDataType()),
                "ordinal": param.getOrdinal(),
                "storage": str(param.getVariableStorage()),
                "size": param.getLength(),
            })

        # 获取局部变量
        local_variables = []
        for var in func.getLocalVariables():
            storage = var.getVariableStorage()
            var_info = {
                "name": var.getName(),
                "type": str(var.getDataType()),
                "size": var.getLength(),
                "storage": str(storage),
            }
            # 尝试获取栈偏移
            if storage.isStackStorage():
                var_info["stack_offset"] = storage.getStackOffset()
            local_variables.append(var_info)

        # 获取函数范围内的标签
        labels = []
        st = prog.getSymbolTable()
        body = func.getBody()
        if body:
            for sym in st.getSymbols(body, True):
                sym_type = _symbol_type_str(sym)
                if sym_type == "Label":
                    labels.append({
                        "name": sym.getName(),
                        "address": str(sym.getAddress()),
                    })

        return _make_success({
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "namespace": _get_namespace_path(func.getParentNamespace()),
            "signature": str(func.getSignature()),
            "parameters": parameters,
            "local_variables": local_variables,
            "labels": labels,
            "parameter_count": len(parameters),
            "local_variable_count": len(local_variables),
            "label_count": len(labels),
        })

    except Exception as e:
        return _make_error(f"get_function_symbols failed: {str(e)}")


# ============================================================
# 标签和全局变量 API
# ============================================================

@route("/api/symbol_tree/labels")
def list_labels(state, q="", limit=100):
    """
    列出标签。

    路由: GET /api/symbol_tree/labels?q=xxx&limit=100

    Args:
        state: Ghidra GhidraState 对象
        q: 搜索关键词（可选）
        limit: 最大返回数量

    Returns:
        dict: 标签列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        from ghidra.program.model.symbol import SymbolType

        st = prog.getSymbolTable()
        fm = prog.getFunctionManager()
        labels = []
        search_pattern = q.lower() if q else None

        for sym in st.getAllSymbols(True):
            if len(labels) >= limit:
                break

            if sym.getSymbolType() != SymbolType.LABEL:
                continue

            name = sym.getName()
            if search_pattern and search_pattern not in name.lower():
                continue

            addr = sym.getAddress()

            # 获取所属函数
            func = fm.getFunctionContaining(addr)
            func_name = func.getName() if func else None

            labels.append({
                "name": name,
                "address": str(addr),
                "function": func_name,
                "is_primary": sym.isPrimary(),
                "source": str(sym.getSource()),
            })

        return _make_success({
            "query": q,
            "labels": labels,
            "count": len(labels),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_labels failed: {str(e)}")


@route("/api/symbol_tree/globals")
def list_globals(state, q="", limit=100):
    """
    列出全局变量。

    路由: GET /api/symbol_tree/globals?q=xxx&limit=100

    Args:
        state: Ghidra GhidraState 对象
        q: 搜索关键词（可选）
        limit: 最大返回数量

    Returns:
        dict: 全局变量列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        from ghidra.program.model.symbol import SymbolType

        st = prog.getSymbolTable()
        listing = prog.getListing()
        globals_list = []
        search_pattern = q.lower() if q else None

        for sym in st.getAllSymbols(True):
            if len(globals_list) >= limit:
                break

            # 检查是否是全局变量（GLOBAL_VAR 或在数据区的非函数符号）
            sym_type = sym.getSymbolType()
            if sym_type == SymbolType.GLOBAL_VAR or sym_type == SymbolType.GLOBAL:
                name = sym.getName()
                if search_pattern and search_pattern not in name.lower():
                    continue

                addr = sym.getAddress()

                # 尝试获取数据类型
                data = listing.getDataAt(addr)
                data_type = str(data.getDataType()) if data else None
                data_value = None
                if data:
                    try:
                        val = data.getValue()
                        if val is not None:
                            data_value = str(val)[:100]  # 截断长值
                    except:
                        pass

                globals_list.append({
                    "name": name,
                    "address": str(addr),
                    "data_type": data_type,
                    "value": data_value,
                    "namespace": _get_namespace_path(sym.getParentNamespace()),
                    "is_primary": sym.isPrimary(),
                    "source": str(sym.getSource()),
                })

        return _make_success({
            "query": q,
            "globals": globals_list,
            "count": len(globals_list),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_globals failed: {str(e)}")


# ============================================================
# 导入/导出 API
# ============================================================

@route("/api/symbol_tree/imports")
def list_imports(state, library="", limit=100):
    """
    列出导入的外部符号。

    路由: GET /api/symbol_tree/imports?library=xxx&limit=100

    Args:
        state: Ghidra GhidraState 对象
        library: 库名过滤（可选，如 "kernel32.dll"）
        limit: 最大返回数量

    Returns:
        dict: 导入符号列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        st = prog.getSymbolTable()
        fm = prog.getFunctionManager()
        imports = []
        lib_filter = library.lower() if library else None

        # 获取外部符号
        for sym in st.getExternalSymbols():
            if len(imports) >= limit:
                break

            # 获取外部位置信息
            ext_loc = sym.getExternalLocation() if hasattr(sym, 'getExternalLocation') else None

            lib_name = None
            if ext_loc:
                lib_name = ext_loc.getLibraryName()
            else:
                # 尝试从父命名空间获取库名
                parent = sym.getParentNamespace()
                if parent:
                    lib_name = parent.getName()

            # 库名过滤
            if lib_filter and lib_name:
                if lib_filter not in lib_name.lower():
                    continue

            name = sym.getName()
            addr = sym.getAddress()

            # 检查是否是函数
            is_function = False
            func = fm.getFunctionAt(addr) if addr else None
            if func:
                is_function = True

            imports.append({
                "name": name,
                "address": str(addr) if addr else None,
                "library": lib_name,
                "is_function": is_function,
                "symbol_type": _symbol_type_str(sym),
            })

        return _make_success({
            "library_filter": library,
            "imports": imports,
            "count": len(imports),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_imports failed: {str(e)}")


@route("/api/symbol_tree/exports")
def list_exports(state, limit=100):
    """
    列出导出的符号。

    路由: GET /api/symbol_tree/exports?limit=100

    Args:
        state: Ghidra GhidraState 对象
        limit: 最大返回数量

    Returns:
        dict: 导出符号列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        st = prog.getSymbolTable()
        fm = prog.getFunctionManager()
        exports = []

        # 方法1：通过入口点获取导出
        for addr in st.getExternalEntryPointIterator():
            if len(exports) >= limit:
                break

            # 获取该地址的符号
            syms = st.getSymbols(addr)
            for sym in syms:
                if sym.isExternalEntryPoint():
                    is_function = False
                    signature = None
                    func = fm.getFunctionAt(addr)
                    if func:
                        is_function = True
                        signature = str(func.getSignature())

                    exports.append({
                        "name": sym.getName(),
                        "address": str(addr),
                        "is_function": is_function,
                        "signature": signature,
                        "symbol_type": _symbol_type_str(sym),
                        "namespace": _get_namespace_path(sym.getParentNamespace()),
                    })
                    break  # 每个地址只取一个符号

        return _make_success({
            "exports": exports,
            "count": len(exports),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"list_exports failed: {str(e)}")
