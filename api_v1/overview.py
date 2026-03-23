"""
V1 Overview API - Comprehensive Binary Overview for AI/MCP Tools

State Passing Pattern - 一次调用返回二进制全景，消除初始阶段的多次往返。

=== 设计目标 ===
- 替代 basic_info，作为 AI 分析二进制的第一个调用
- 返回元数据、内存布局、统计、关键函数、导入导出、字符串等全景信息
- 灵感来自 ida-pro-mcp 的 survey_binary

路由: GET /api/v1/overview?verbose=false&top_funcs=20&top_strings=30
"""

import sys
from api import route

# ============================================================
# Java Class Imports (cached for hot reload)
# ============================================================

_CACHE_KEY_ST = '_ghidra_api_v1_overview_SymbolType'
if _CACHE_KEY_ST not in sys.modules:
    from ghidra.program.model.symbol import SymbolType as _ST
    sys.modules[_CACHE_KEY_ST] = _ST
SymbolType = sys.modules[_CACHE_KEY_ST]


# ============================================================
# Compact Mode Schema
# ============================================================

COMPACT_SCHEMA = {
    "segments": ["name", "start", "end", "size", "perms"],
    "entry_points": ["address", "name"],
    "top_functions": ["name", "address", "size", "xref_count"],
    "imports_by_library": ["library", "count", "top_symbols"],
    "exports": ["name", "address", "is_function"],
    "notable_strings": ["address", "value", "length"],
}


# ============================================================
# Response Helpers
# ============================================================

def _ok(data):
    return {"success": True, "data": data}


def _err(message):
    return {"success": False, "error": message}


# ============================================================
# Collectors
# ============================================================

def _collect_metadata(prog):
    """Collect program metadata."""
    language = prog.getLanguage()
    lang_desc = language.getLanguageDescription() if language else None
    compiler_spec = prog.getCompilerSpec()
    image_base = prog.getImageBase()

    return {
        "name": prog.getName(),
        "format": prog.getExecutableFormat() if hasattr(prog, 'getExecutableFormat') else None,
        "processor": str(language.getProcessor()) if language else None,
        "bits": lang_desc.getSize() if lang_desc else None,
        "endian": "big" if language and language.isBigEndian() else "little",
        "compiler": str(compiler_spec.getCompilerSpecID()) if compiler_spec else None,
        "image_base": "0x" + str(image_base) if image_base else None,
    }


def _collect_segments(prog):
    """Collect memory segments."""
    memory = prog.getMemory()
    if not memory:
        return []

    segments = []
    for block in memory.getBlocks():
        perms = ""
        if block.isRead():
            perms += "r"
        if block.isWrite():
            perms += "w"
        if block.isExecute():
            perms += "x"

        segments.append([
            block.getName(),
            "0x" + str(block.getStart()),
            "0x" + str(block.getEnd()),
            block.getSize(),
            perms,
        ])

    return segments


def _collect_statistics(prog):
    """Collect counts of functions, symbols, imports, exports, strings, classes."""
    fm = prog.getFunctionManager()
    st = prog.getSymbolTable()

    func_count = fm.getFunctionCount()
    symbol_count = st.getNumSymbols()

    # Count imports
    import_count = 0
    for _ in st.getExternalSymbols():
        import_count += 1

    # Count exports
    export_count = 0
    for _ in st.getExternalEntryPointIterator():
        export_count += 1

    # Count strings (cap at 50000 for performance)
    string_count = 0
    listing = prog.getListing()
    for data in listing.getDefinedData(True):
        if string_count >= 50000:
            break
        if data.hasStringValue():
            string_count += 1

    # Count classes
    class_count = 0
    for sym in st.getAllSymbols(True):
        if sym.getSymbolType() == SymbolType.CLASS:
            class_count += 1

    return {
        "functions": func_count,
        "symbols": symbol_count,
        "imports": import_count,
        "exports": export_count,
        "strings": string_count,
        "classes": class_count,
    }


def _collect_entry_points(prog, limit=10):
    """Collect entry points."""
    st = prog.getSymbolTable()
    fm = prog.getFunctionManager()
    entries = []

    for addr in st.getExternalEntryPointIterator():
        if len(entries) >= limit:
            break
        name = None
        for sym in st.getSymbols(addr):
            name = sym.getName()
            break
        if name is None:
            func = fm.getFunctionAt(addr)
            name = func.getName() if func else None
        entries.append(["0x" + str(addr), name])

    return entries


def _collect_top_functions(prog, limit=20):
    """
    Collect top functions by importance.

    Scoring: xref_count + (50 if user-named).
    Scans up to 5000 non-external non-thunk functions.
    Counts up to 200 inbound xrefs per function.
    """
    fm = prog.getFunctionManager()
    ref_mgr = prog.getReferenceManager()

    scored = []
    scan_count = 0

    for func in fm.getFunctions(True):
        if scan_count >= 5000:
            break
        if func.isExternal() or func.isThunk():
            continue
        scan_count += 1

        entry = func.getEntryPoint()
        name = func.getName()

        # Count inbound xrefs (cap 200)
        xref_count = 0
        for _ in ref_mgr.getReferencesTo(entry):
            xref_count += 1
            if xref_count >= 200:
                break

        # Bonus for user-named functions
        is_auto = name.startswith("FUN_") or name.startswith("thunk_")
        score = xref_count + (50 if not is_auto else 0)

        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        scored.append((score, name, entry, size, xref_count))

    # Sort descending by score
    scored.sort(key=lambda x: -x[0])

    return [
        [name, "0x" + str(entry), size, xref_count]
        for score, name, entry, size, xref_count in scored[:limit]
    ]


def _collect_imports_by_library(prog):
    """Collect imports grouped by library, showing top 5 symbols per lib."""
    st = prog.getSymbolTable()
    libs = {}  # lib_name -> list of symbol names

    for sym in st.getExternalSymbols():
        parent = sym.getParentNamespace()
        lib_name = parent.getName() if parent else "<unknown>"
        if lib_name not in libs:
            libs[lib_name] = []
        libs[lib_name].append(sym.getName())

    # Sort by count descending
    result = []
    for lib_name in sorted(libs.keys(), key=lambda k: -len(libs[k])):
        symbols = libs[lib_name]
        result.append([lib_name, len(symbols), symbols[:5]])

    return result


def _collect_exports(prog, limit=30):
    """Collect exported symbols."""
    st = prog.getSymbolTable()
    fm = prog.getFunctionManager()
    exports = []
    seen = set()

    for addr in st.getExternalEntryPointIterator():
        if len(exports) >= limit:
            break
        addr_str = str(addr)
        if addr_str in seen:
            continue
        seen.add(addr_str)

        name = None
        for sym in st.getSymbols(addr):
            if sym.isExternalEntryPoint():
                name = sym.getName()
                break

        func = fm.getFunctionAt(addr)
        exports.append([name or addr_str, "0x" + addr_str, func is not None])

    return exports


def _score_string(s):
    """Score a string by information value."""
    score = len(s)

    # Human-readable message
    if ' ' in s:
        score += 20
    # URL/path markers
    if any(marker in s.lower() for marker in ['http', '://', '.dll', '.so', '.exe', '.sys']):
        score += 30
    if '/' in s and len(s) > 10:
        score += 15
    # Format string
    if '%' in s:
        score += 15
    # Error/warning messages
    if any(kw in s.lower() for kw in ['error', 'fail', 'warn', 'invalid', 'denied', 'password', 'key', 'token', 'secret', 'flag']):
        score += 25

    return score


def _collect_notable_strings(prog, limit=30):
    """
    Collect notable strings scored by information value.

    Scans up to 10000 defined data items. Filters strings with length >= 6.
    Truncates display to 120 chars.
    """
    listing = prog.getListing()
    candidates = []
    scan_count = 0

    for data in listing.getDefinedData(True):
        if scan_count >= 10000:
            break
        if not data.hasStringValue():
            continue
        scan_count += 1

        value = data.getValue()
        if value is None:
            continue
        s = str(value)
        if len(s) < 6:
            continue

        score = _score_string(s)
        display = s[:120] + "..." if len(s) > 120 else s
        candidates.append((score, data.getAddress(), display, len(s)))

    # Sort by score descending
    candidates.sort(key=lambda x: -x[0])

    return [
        ["0x" + str(addr), display, length]
        for score, addr, display, length in candidates[:limit]
    ]


# ============================================================
# Main Overview Function
# ============================================================

@route("/api/v1/overview")
def overview(state, top_funcs=20, top_strings=30, verbose=""):
    """
    Comprehensive binary overview - recommended first call for analysis.

    Returns program metadata, memory layout, statistics, top functions,
    imports by library, exports, entry points, and notable strings.

    Args:
        state: Ghidra GhidraState object
        top_funcs: Number of top functions to include (default: 20)
        top_strings: Number of notable strings to include (default: 30)
        verbose: "true" for full dict format, default compact arrays

    路由: GET /api/v1/overview?top_funcs=20&top_strings=30&verbose=false
    """
    prog = state.getCurrentProgram()
    if prog is None:
        return _err("No program loaded")

    try:
        top_funcs = int(top_funcs)
    except (ValueError, TypeError):
        top_funcs = 20
    try:
        top_strings = int(top_strings)
    except (ValueError, TypeError):
        top_strings = 30

    is_verbose = str(verbose).lower() in ("true", "1", "yes")

    data = {
        "metadata": _collect_metadata(prog),
        "segments": _collect_segments(prog),
        "statistics": _collect_statistics(prog),
        "entry_points": _collect_entry_points(prog),
        "top_functions": _collect_top_functions(prog, top_funcs),
        "imports_by_library": _collect_imports_by_library(prog),
        "exports": _collect_exports(prog),
        "notable_strings": _collect_notable_strings(prog, top_strings),
    }

    if not is_verbose:
        data["_schema"] = COMPACT_SCHEMA

    return _ok(data)
