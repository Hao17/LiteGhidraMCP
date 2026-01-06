"""
V1 List API - Unified Symbol Listing for AI/MCP Tools

State Passing Pattern - 面向 AI 的统一符号列表接口，支持多种过滤条件。

=== 设计目标 ===
- 提供类似 ls 的符号浏览功能，一个工具完成所有列表需求
- 支持地址范围过滤，便于分析特定区域
- 聚合结果，分类整理便于 AI 理解

=== 使用方式 ===
    import api_v1.list as v1_list
    result = v1_list.list_symbols(state, q="init*", types="functions", limit=50)

路由: GET /api/v1/list?q=<query>&types=<types>&start=<addr>&end=<addr>&limit=<limit>
"""

import fnmatch
from api import route
from api.datatype import _get_all_dtms


# ============================================================
# Compact Mode Schema
# ============================================================

COMPACT_SCHEMA = {
    "functions": ["name", "address", "size", "signature"],
    "classes": ["name", "address", "full_path"],
    "namespaces": ["name", "symbol_count"],
    "labels": ["name", "address", "function"],
    "globals": ["name", "address", "data_type"],
    "imports": ["name", "address", "library"],
    "exports": ["name", "address", "is_function", "signature"],
    "datatypes": ["name", "path", "archive", "size", "kind"],
}


def _to_compact(results):
    """Convert dict results to compact array format"""
    compact = {}
    for type_name, items in results.items():
        schema = COMPACT_SCHEMA.get(type_name, [])
        compact[type_name] = [
            [item.get(field) for field in schema]
            for item in items
        ]
    return compact


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
# Address Range Helpers
# ============================================================

def _parse_address_range(prog, start, end):
    """
    Parse address range parameters.

    Args:
        prog: Ghidra program
        start: Start address string (e.g., "0x401000")
        end: End address string (e.g., "0x402000")

    Returns:
        (start_addr, end_addr, error)
    """
    addr_factory = prog.getAddressFactory()
    start_addr = None
    end_addr = None

    if start:
        try:
            start_str = start if start.lower().startswith("0x") else "0x" + start
            start_addr = addr_factory.getAddress(start_str)
            if start_addr is None:
                return None, None, _err(f"Invalid start address: {start}")
        except Exception as e:
            return None, None, _err(f"Invalid start address: {start} - {str(e)}")

    if end:
        try:
            end_str = end if end.lower().startswith("0x") else "0x" + end
            end_addr = addr_factory.getAddress(end_str)
            if end_addr is None:
                return None, None, _err(f"Invalid end address: {end}")
        except Exception as e:
            return None, None, _err(f"Invalid end address: {end} - {str(e)}")

    return start_addr, end_addr, None


def _in_address_range(addr, start_addr, end_addr):
    """Check if address is within range [start, end]"""
    if addr is None:
        return False
    if start_addr and addr.compareTo(start_addr) < 0:
        return False
    if end_addr and addr.compareTo(end_addr) > 0:
        return False
    return True


# ============================================================
# Name Filter Helper
# ============================================================

def _matches_name_filter(name, query):
    """
    Check if name matches query pattern.

    Supports:
    - Substring match (default)
    - Wildcard patterns (* and ?)
    """
    if not query:
        return True

    q = query.lower()
    name_lower = name.lower()

    # Wildcard pattern
    if '*' in q or '?' in q:
        return fnmatch.fnmatch(name_lower, q)

    # Substring match
    return q in name_lower


def _get_namespace_path(namespace):
    """Get full namespace path string"""
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


# ============================================================
# Listing Handlers
# ============================================================

def _list_functions(prog, q, start_addr, end_addr, limit):
    """List functions with optional filters"""
    fm = prog.getFunctionManager()
    results = []

    for func in fm.getFunctions(True):
        if len(results) >= limit:
            break

        name = func.getName()
        if not _matches_name_filter(name, q):
            continue

        entry = func.getEntryPoint()
        if not _in_address_range(entry, start_addr, end_addr):
            continue

        body = func.getBody()
        results.append({
            "name": name,
            "address": "0x" + str(entry),
            "size": body.getNumAddresses() if body else 0,
            "signature": str(func.getSignature()),
            "is_external": func.isExternal(),
            "is_thunk": func.isThunk(),
        })

    return results


def _list_classes(prog, q, start_addr, end_addr, limit):
    """List classes with optional filters"""
    from ghidra.program.model.symbol import SymbolType

    st = prog.getSymbolTable()
    results = []

    for sym in st.getAllSymbols(True):
        if len(results) >= limit:
            break

        if sym.getSymbolType() != SymbolType.CLASS:
            continue

        name = sym.getName()
        if not _matches_name_filter(name, q):
            continue

        addr = sym.getAddress()
        if not _in_address_range(addr, start_addr, end_addr):
            continue

        parent_ns = sym.getParentNamespace()
        ns_path = _get_namespace_path(parent_ns)

        results.append({
            "name": name,
            "address": "0x" + str(addr),
            "namespace": ns_path,
            "full_path": f"{ns_path}::{name}" if ns_path != "Global" else name,
        })

    return results


def _list_namespaces(prog, q, limit):
    """List top-level namespaces (no address range filtering)"""
    st = prog.getSymbolTable()
    global_ns = prog.getGlobalNamespace()
    results = []
    seen = set()

    # Iterate all symbols to find top-level namespaces
    for sym in st.getAllSymbols(True):
        if len(results) >= limit:
            break

        parent_ns = sym.getParentNamespace()
        if parent_ns is None:
            continue

        # Only consider direct children of Global namespace
        grandparent = parent_ns.getParentNamespace()
        if grandparent is None or grandparent.getName() != "Global":
            if parent_ns.getName() != "Global":
                continue

        if parent_ns.getName() == "Global":
            continue

        name = parent_ns.getName()
        if name in seen:
            continue

        if not _matches_name_filter(name, q):
            continue

        seen.add(name)

        # Count symbols in namespace
        symbol_count = 0
        try:
            for _ in st.getSymbols(parent_ns):
                symbol_count += 1
                if symbol_count > 1000:  # Cap counting for performance
                    break
        except:
            pass

        results.append({
            "name": name,
            "symbol_count": symbol_count if symbol_count <= 1000 else "1000+",
        })

    return results


def _list_labels(prog, q, start_addr, end_addr, limit):
    """List labels with optional filters"""
    from ghidra.program.model.symbol import SymbolType

    st = prog.getSymbolTable()
    fm = prog.getFunctionManager()
    results = []

    for sym in st.getAllSymbols(True):
        if len(results) >= limit:
            break

        if sym.getSymbolType() != SymbolType.LABEL:
            continue

        name = sym.getName()
        if not _matches_name_filter(name, q):
            continue

        addr = sym.getAddress()
        if not _in_address_range(addr, start_addr, end_addr):
            continue

        func = fm.getFunctionContaining(addr)

        results.append({
            "name": name,
            "address": "0x" + str(addr),
            "function": func.getName() if func else None,
        })

    return results


def _list_globals(prog, q, start_addr, end_addr, limit):
    """List global variables with optional filters"""
    from ghidra.program.model.symbol import SymbolType

    st = prog.getSymbolTable()
    listing = prog.getListing()
    results = []

    for sym in st.getAllSymbols(True):
        if len(results) >= limit:
            break

        sym_type = sym.getSymbolType()
        # Check for GLOBAL_VAR or GLOBAL
        sym_type_str = str(sym_type)
        if "GLOBAL" not in sym_type_str:
            continue

        name = sym.getName()
        if not _matches_name_filter(name, q):
            continue

        addr = sym.getAddress()
        if not _in_address_range(addr, start_addr, end_addr):
            continue

        data = listing.getDataAt(addr)
        data_type = str(data.getDataType()) if data else None

        results.append({
            "name": name,
            "address": "0x" + str(addr),
            "data_type": data_type,
        })

    return results


def _list_imports(prog, q, library, limit):
    """List imported symbols (no address range, uses library filter)"""
    st = prog.getSymbolTable()
    results = []
    lib_filter = library.lower() if library else None

    for sym in st.getExternalSymbols():
        if len(results) >= limit:
            break

        name = sym.getName()
        if not _matches_name_filter(name, q):
            continue

        # Get library name from parent namespace
        lib_name = None
        parent = sym.getParentNamespace()
        if parent:
            lib_name = parent.getName()

        if lib_filter and lib_name:
            if lib_filter not in lib_name.lower():
                continue

        addr = sym.getAddress()
        results.append({
            "name": name,
            "address": "0x" + str(addr) if addr else None,
            "library": lib_name,
        })

    return results


def _list_exports(prog, q, limit):
    """List exported symbols (no address range)"""
    st = prog.getSymbolTable()
    fm = prog.getFunctionManager()
    results = []
    seen_addrs = set()

    for addr in st.getExternalEntryPointIterator():
        if len(results) >= limit:
            break

        addr_str = str(addr)
        if addr_str in seen_addrs:
            continue

        for sym in st.getSymbols(addr):
            if not sym.isExternalEntryPoint():
                continue

            name = sym.getName()
            if not _matches_name_filter(name, q):
                continue

            seen_addrs.add(addr_str)
            func = fm.getFunctionAt(addr)

            results.append({
                "name": name,
                "address": "0x" + addr_str,
                "is_function": func is not None,
                "signature": str(func.getSignature()) if func else None,
            })
            break  # One symbol per address

    return results


def _list_datatypes(state, q, archive, show_builtin, limit):
    """
    List datatypes with archive as root path.

    Args:
        state: Ghidra state (需要完整 state 以访问多个 DTM)
        q: Name filter (支持通配符 * ?)
        archive: Archive filter (空=所有可见库, 具体名称=指定库)
        show_builtin: 是否显示 BuiltInTypes (默认 False)
        limit: Max results

    Returns:
        list of datatype dicts
    """
    # 获取 DTM 列表
    dtms = _get_all_dtms(state)

    # 根据 show_builtin 过滤
    if not show_builtin:
        dtms = [(name, dtm) for name, dtm in dtms if name != "BuiltInTypes"]

    # 如果指定了 archive，仅查询该库
    if archive:
        dtms = [(name, dtm) for name, dtm in dtms if name == archive]
    else:
        # 调整遍历顺序：程序 DTM → 小型归档 → 大型标准库
        # 识别程序 DTM（is_modifiable=True）和标准库（名称包含 clib/lib 且类型数很多）
        prog = state.getCurrentProgram()
        prog_name = prog.getName() if prog else ""

        def sort_key(item):
            name, dtm = item
            # 程序本身优先 (0)
            if name == prog_name:
                return (0, 0)
            # 判断是否为大型标准库 (名称包含 clib/lib 且类型数 > 1000)
            is_large_lib = False
            try:
                type_count = sum(1 for _ in dtm.getAllDataTypes())
                name_lower = name.lower()
                if type_count > 1000 and ('clib' in name_lower or 'lib' in name_lower or 'generic' in name_lower):
                    is_large_lib = True
            except:
                pass
            # 大型标准库最后 (2)，其他用户归档中间 (1)
            if is_large_lib:
                return (2, name)
            return (1, name)

        dtms = sorted(dtms, key=sort_key)

    results = []
    for arch_name, dtm in dtms:
        if len(results) >= limit:
            break

        for dt in dtm.getAllDataTypes():
            if len(results) >= limit:
                break

            name = dt.getName()
            if not _matches_name_filter(name, q):
                continue

            results.append({
                "name": name,
                "path": dt.getPathName(),
                "archive": arch_name,
                "size": dt.getLength(),
                "kind": dt.__class__.__name__.replace("DataType", ""),
            })

    return results


# ============================================================
# Handler Dispatcher
# ============================================================

LIST_HANDLERS = {
    "functions": _list_functions,
    "classes": _list_classes,
    "namespaces": _list_namespaces,
    "labels": _list_labels,
    "globals": _list_globals,
    "imports": _list_imports,
    "exports": _list_exports,
    # Note: datatypes 使用特殊调用路径，不在此注册
}

ALL_TYPES = list(LIST_HANDLERS.keys()) + ["datatypes"]


# ============================================================
# Main List Function
# ============================================================

@route("/api/v1/list")
def list_symbols(state, q="", types="auto", start="", end="", library="", archive="", show_builtin="", limit=100, verbose=""):
    """
    Unified symbol listing API.

    Args:
        state: Ghidra GhidraState object
        q: Name filter (substring match, supports wildcards * ?)
        types: Symbol types to list:
               - "auto": Default to functions only
               - "all": List all symbol types
               - Comma-separated: "functions,classes,labels,datatypes"
        start: Start address for range filter (e.g., "0x401000")
        end: End address for range filter
        library: Library filter for imports (e.g., "kernel32")
        archive: Archive filter for datatypes (e.g., "init3.o")
        show_builtin: Show BuiltInTypes in datatypes ("true"/"1" to enable)
        limit: Max results per type (default 100)
        verbose: Output format:
               - "" (default): Compact array format with _schema
               - "true"/"1": Verbose dict format with all fields

    Returns:
        dict: Aggregated listing results

    Example:
        GET /api/v1/list                              # List all functions (compact)
        GET /api/v1/list?verbose=true                 # List functions (verbose)
        GET /api/v1/list?types=all&limit=50           # List all symbol types
        GET /api/v1/list?q=init*&types=functions      # List functions matching "init*"
        GET /api/v1/list?start=0x401000&end=0x402000  # List functions in address range
        GET /api/v1/list?types=imports&library=kernel32  # List kernel32 imports
        GET /api/v1/list?types=datatypes              # List datatypes (exclude BuiltInTypes)
        GET /api/v1/list?types=datatypes&show_builtin=true  # List all datatypes
        GET /api/v1/list?types=datatypes&archive=init3.o    # List datatypes from specific archive

    路由: GET /api/v1/list?q=<query>&types=<types>&start=<addr>&end=<addr>&limit=<limit>&verbose=<bool>
    """
    prog, err = _get_prog(state)
    if err:
        return err

    # Ensure parameters are strings
    q = str(q) if q else ""
    types = str(types) if types else "auto"
    start = str(start) if start else ""
    end = str(end) if end else ""
    library = str(library) if library else ""
    archive = str(archive) if archive else ""

    # Parse boolean parameters
    is_show_builtin = str(show_builtin).lower() in ("true", "1", "yes")

    # Parse limit
    try:
        limit = int(limit)
    except (ValueError, TypeError):
        limit = 100

    # Parse address range
    start_addr, end_addr, range_err = _parse_address_range(prog, start, end)
    if range_err:
        return range_err

    # Determine types to list
    if types == "auto":
        list_types = ["functions"]  # Default to functions
    elif types == "all":
        list_types = ALL_TYPES
    else:
        list_types = [t.strip() for t in types.split(",")]
        invalid = [t for t in list_types if t not in ALL_TYPES]
        if invalid:
            return _err(f"Invalid types: {invalid}. Valid: {ALL_TYPES}")

    # Execute listings
    results = {}
    errors = []

    for list_type in list_types:
        # datatypes uses special handler (needs state, not prog)
        if list_type == "datatypes":
            try:
                results[list_type] = _list_datatypes(state, q, archive, is_show_builtin, limit)
            except Exception as e:
                errors.append(f"datatypes: {str(e)}")
                results[list_type] = []
            continue

        handler = LIST_HANDLERS.get(list_type)
        if not handler:
            continue

        try:
            # Handlers have different signatures based on type
            if list_type == "namespaces":
                # Namespaces don't support address range
                results[list_type] = handler(prog, q, limit)
            elif list_type == "imports":
                # Imports use library filter instead of address range
                results[list_type] = handler(prog, q, library, limit)
            elif list_type == "exports":
                # Exports don't support address range
                results[list_type] = handler(prog, q, limit)
            else:
                # Standard handlers with address range support
                results[list_type] = handler(prog, q, start_addr, end_addr, limit)
        except Exception as e:
            errors.append(f"{list_type}: {str(e)}")
            results[list_type] = []

    # Build summary
    summary = {t: len(results.get(t, [])) for t in list_types}
    summary["total"] = sum(v for k, v in summary.items() if k != "total")

    # Parse verbose parameter
    is_verbose = str(verbose).lower() in ("true", "1", "yes")

    # Build response
    if is_verbose:
        # Verbose mode: full dict format
        response = {"summary": summary, "results": results}
    else:
        # Compact mode (default): array format with schema
        response = {
            "summary": summary,
            "results": _to_compact(results),
            "_schema": {t: COMPACT_SCHEMA[t] for t in list_types if t in COMPACT_SCHEMA},
        }

    # Only include errors if present
    if errors:
        response["errors"] = errors

    return _ok(response)
