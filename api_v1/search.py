"""
V1 Search API - Unified Search for AI/MCP Tools

State Passing Pattern - 面向 AI 的统一搜索接口，支持智能类型推断。

=== 设计目标 ===
- 一个工具解决所有搜索需求，减少 AI 调用多个工具带来的可靠性下降
- 智能推断搜索类型，AI 无需关心底层搜索细节
- 聚合结果，分类整理便于 AI 理解

=== 使用方式 ===
    import api_v1.search as v1_search
    result = v1_search.search(state, query, types="auto", limit=20)

路由: GET /api/v1/search?q=<query>&types=<types>&limit=<limit>
"""

import re
from api import route


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
# Type Inference
# ============================================================

def _infer_search_types(query):
    """
    Infer search types based on query characteristics.

    Rules:
    - 0x... or pure hex (8+ chars): xrefs (cross references)
    - Contains * or ?: symbols, datatypes (wildcard search)
    - Short lowercase word: functions, symbols
    - Contains space or special chars: strings, comments
    - Default: functions, symbols, strings
    """
    q = query.strip()

    # Address pattern: 0x... or pure hex (8+ chars)
    if q.lower().startswith("0x") or (len(q) >= 8 and re.match(r'^[0-9a-fA-F]+$', q)):
        return ["xrefs"]

    # Wildcard pattern: contains * or ?
    if '*' in q or '?' in q:
        return ["symbols", "datatypes"]

    # Byte pattern: hex with spaces or ?? wildcards (e.g., "48 8b ?? 90")
    if re.match(r'^[0-9a-fA-F\s\?\.]+$', q) and (' ' in q or '??' in q):
        return ["bytes"]

    # Instruction pattern: common mnemonics
    mnemonics = ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'mov', 'push', 'pop', 'ret', 'lea', 'xor', 'cmp', 'test']
    q_lower = q.lower()
    if q_lower in mnemonics or any(q_lower.startswith(m + ' ') for m in mnemonics):
        return ["instructions"]

    # String/comment pattern: contains space or special chars
    if ' ' in q or any(c in q for c in ['"', "'", ':', '/', '\\', '.', '-']):
        return ["strings", "comments"]

    # Default: search functions, symbols, strings
    return ["functions", "symbols", "strings"]


# ============================================================
# Individual Search Functions
# ============================================================

def _search_functions(prog, query, limit):
    """Search function names"""
    matches = []
    pattern = query.lower()
    fm = prog.getFunctionManager()

    for func in fm.getFunctions(True):
        if len(matches) >= limit:
            break
        name = func.getName()
        if pattern in name.lower():
            entry = func.getEntryPoint()
            body = func.getBody()
            matches.append({
                "name": name,
                "address": str(entry),
                "size": body.getNumAddresses() if body else 0,
                "signature": str(func.getSignature()),
                "is_external": func.isExternal(),
            })

    return matches


def _search_symbols(prog, query, limit):
    """Search symbols (excluding functions)"""
    matches = []
    st = prog.getSymbolTable()

    # Use wildcard iterator if query contains * or ?
    if '*' in query or '?' in query:
        symbol_iter = st.getSymbolIterator(query, False)
        use_pattern = False
    else:
        symbol_iter = st.getAllSymbols(True)
        use_pattern = True
        pattern = query.lower()

    for sym in symbol_iter:
        if len(matches) >= limit:
            break

        sym_type = str(sym.getSymbolType())
        if sym_type == "Function":
            continue

        name = sym.getName()
        if use_pattern and pattern not in name.lower():
            continue

        matches.append({
            "name": name,
            "address": str(sym.getAddress()),
            "type": sym_type,
            "namespace": str(sym.getParentNamespace().getName()) if sym.getParentNamespace() else None,
        })

    return matches


def _search_strings(prog, query, limit):
    """Search defined strings"""
    matches = []
    pattern = query.lower()
    listing = prog.getListing()

    for data in listing.getDefinedData(True):
        if len(matches) >= limit:
            break
        if not data.hasStringValue():
            continue
        value = data.getValue()
        if value is None:
            continue

        str_value = str(value)
        if pattern not in str_value.lower():
            continue

        # Truncate long strings
        display = str_value[:200] + "..." if len(str_value) > 200 else str_value
        matches.append({
            "address": str(data.getAddress()),
            "value": display,
            "length": len(str_value),
        })

    return matches


def _search_comments(prog, query, limit):
    """Search all comment types"""
    from ghidra.program.model.listing import CodeUnit

    comment_types = {
        "EOL": CodeUnit.EOL_COMMENT,
        "PRE": CodeUnit.PRE_COMMENT,
        "POST": CodeUnit.POST_COMMENT,
        "PLATE": CodeUnit.PLATE_COMMENT,
        "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
    }

    matches = []
    pattern = query.lower()
    listing = prog.getListing()

    for cu in listing.getCodeUnits(True):
        if len(matches) >= limit:
            break

        for type_name, type_code in comment_types.items():
            if len(matches) >= limit:
                break
            comment = cu.getComment(type_code)
            if comment and pattern in comment.lower():
                matches.append({
                    "address": str(cu.getAddress()),
                    "type": type_name,
                    "comment": comment[:300] if len(comment) > 300 else comment,
                })

    return matches


def _search_instructions(prog, query, limit):
    """Search assembly instruction text"""
    matches = []
    pattern = query.lower()
    listing = prog.getListing()

    for instr in listing.getInstructions(True):
        if len(matches) >= limit:
            break

        instr_str = str(instr).lower()
        if pattern in instr_str:
            matches.append({
                "address": str(instr.getAddress()),
                "mnemonic": instr.getMnemonicString(),
                "instruction": str(instr),
            })

    return matches


def _search_xrefs(prog, query, limit):
    """Search cross references to/from an address"""
    # Parse address
    addr_str = query.strip()
    if not addr_str.lower().startswith("0x"):
        addr_str = "0x" + addr_str

    try:
        addr_factory = prog.getAddressFactory()
        addr = addr_factory.getAddress(addr_str)
    except:
        return []

    if addr is None:
        return []

    matches = []
    ref_mgr = prog.getReferenceManager()
    listing = prog.getListing()

    # Search references TO this address
    for ref in ref_mgr.getReferencesTo(addr):
        if len(matches) >= limit:
            break
        from_addr = ref.getFromAddress()

        context = None
        func = listing.getFunctionContaining(from_addr)
        if func:
            context = func.getName()

        instr = listing.getInstructionAt(from_addr)

        matches.append({
            "direction": "to",
            "from": str(from_addr),
            "to": str(ref.getToAddress()),
            "ref_type": str(ref.getReferenceType()),
            "context": context,
            "instruction": str(instr) if instr else None,
        })

    return matches


def _search_datatypes(prog, query, limit):
    """Search data types"""
    import fnmatch

    matches = []
    dtm = prog.getDataTypeManager()
    use_wildcard = '*' in query or '?' in query

    for dt in dtm.getAllDataTypes():
        if len(matches) >= limit:
            break

        name = dt.getName()
        if use_wildcard:
            if not fnmatch.fnmatch(name.lower(), query.lower()):
                continue
        else:
            if query.lower() not in name.lower():
                continue

        matches.append({
            "name": name,
            "path": str(dt.getPathName()),
            "category": str(dt.getCategoryPath()),
            "size": dt.getLength(),
        })

    return matches


def _search_bytes(prog, query, limit):
    """Search byte patterns with wildcards"""
    # Normalize pattern
    normalized = query.replace(" ", "").replace("??", "..").replace("?", ".")

    if not re.match(r'^[0-9a-fA-F.]+$', normalized):
        return []
    if len(normalized) % 2 != 0:
        return []

    byte_len = len(normalized) // 2
    search_bytes = []
    search_mask = []

    for i in range(byte_len):
        high = normalized[i * 2]
        low = normalized[i * 2 + 1]

        if high == '.' and low == '.':
            search_bytes.append(0)
            search_mask.append(0x00)
        elif high == '.':
            search_bytes.append(int(low, 16))
            search_mask.append(0x0F)
        elif low == '.':
            search_bytes.append(int(high, 16) << 4)
            search_mask.append(0xF0)
        else:
            search_bytes.append(int(high + low, 16))
            search_mask.append(0xFF)

    matches = []
    memory = prog.getMemory()

    for block in memory.getBlocks():
        if len(matches) >= limit:
            break
        if not block.isInitialized():
            continue

        start = block.getStart()
        end = block.getEnd()
        addr = start

        while addr is not None and addr.compareTo(end) <= 0 and len(matches) < limit:
            if addr.add(byte_len - 1).compareTo(end) > 0:
                break

            match_found = True
            try:
                for i in range(byte_len):
                    b = memory.getByte(addr.add(i)) & 0xFF
                    if (b & search_mask[i]) != (search_bytes[i] & search_mask[i]):
                        match_found = False
                        break
            except:
                match_found = False

            if match_found:
                actual_bytes = []
                try:
                    for i in range(byte_len):
                        b = memory.getByte(addr.add(i))
                        actual_bytes.append(format(b & 0xFF, '02x'))
                except:
                    actual_bytes = ["??"] * byte_len

                matches.append({
                    "address": str(addr),
                    "bytes": " ".join(actual_bytes),
                })
                addr = addr.add(1)
            else:
                addr = addr.add(1)

    return matches


# ============================================================
# Search Dispatcher
# ============================================================

SEARCH_HANDLERS = {
    "functions": _search_functions,
    "symbols": _search_symbols,
    "strings": _search_strings,
    "comments": _search_comments,
    "instructions": _search_instructions,
    "xrefs": _search_xrefs,
    "datatypes": _search_datatypes,
    "bytes": _search_bytes,
}

ALL_TYPES = list(SEARCH_HANDLERS.keys())


# ============================================================
# Main Search Function
# ============================================================

@route("/api/v1/search")
def search(state, q="", types="auto", limit=20):
    """
    Unified search with smart type inference.

    Args:
        state: Ghidra GhidraState object
        q: Search query string
        types: Search types (comma-separated or special values)
               - "auto": Smart inference based on query
               - "all": Search all types
               - Specific types: "functions,symbols,strings"
        limit: Max results per type (default 20)

    Returns:
        dict: Aggregated search results
    """
    prog, err = _get_prog(state)
    if err:
        return err

    if not q or not q.strip():
        return _err("Query is required")

    query = q.strip()

    # Determine search types
    if types == "auto":
        search_types = _infer_search_types(query)
    elif types == "all":
        search_types = ALL_TYPES
    else:
        search_types = [t.strip() for t in types.split(",")]
        # Validate types
        invalid = [t for t in search_types if t not in SEARCH_HANDLERS]
        if invalid:
            return _err(f"Invalid types: {invalid}. Valid: {ALL_TYPES}")

    # Execute searches
    results = {}
    errors = []

    for search_type in search_types:
        handler = SEARCH_HANDLERS.get(search_type)
        if not handler:
            continue

        try:
            results[search_type] = handler(prog, query, limit)
        except Exception as e:
            errors.append(f"{search_type}: {str(e)}")
            results[search_type] = []

    # Build summary
    summary = {t: len(results.get(t, [])) for t in search_types}
    summary["total"] = sum(summary.values())

    return _ok({
        "query": query,
        "types_searched": search_types,
        "results": results,
        "summary": summary,
        "errors": errors if errors else None,
    })
