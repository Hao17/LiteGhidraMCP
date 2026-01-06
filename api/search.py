"""
搜索 API - State 传递模式 (Search API - State Passing Pattern)

提供各类搜索功能，包括：
- 语义搜索：函数、符号、注释
- 数据搜索：字符串、标量
- 模式搜索：字节模式、指令
- 引用搜索：交叉引用
- 类型搜索：数据类型

=== 使用方式 ===
    import api.search as search_api
    result = search_api.search_functions(state, "main")
"""


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


# ============================================================
# 语义搜索
# ============================================================

def search_functions(state, query, limit=100):
    """
    搜索函数名称。

    Args:
        state: Ghidra GhidraState 对象
        query: 搜索关键词（大小写不敏感）
        limit: 最大返回数量

    Returns:
        dict: 匹配的函数列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        search_pattern = query.lower()
        matches = []

        fm = prog.getFunctionManager()
        for func in fm.getFunctions(True):
            if len(matches) >= limit:
                break
            name = func.getName()
            if search_pattern in name.lower():
                entry = func.getEntryPoint()
                body = func.getBody()
                matches.append({
                    "name": name,
                    "address": str(entry),
                    "size": body.getNumAddresses() if body else 0,
                    "signature": str(func.getSignature()),
                    "is_thunk": func.isThunk(),
                    "is_external": func.isExternal(),
                    "calling_convention": func.getCallingConventionName(),
                })

        return _make_success({
            "query": query,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_functions failed: {str(e)}")


def search_symbols(state, query, sym_type=None, limit=100):
    """
    搜索符号（标签、变量等）。

    Args:
        state: Ghidra GhidraState 对象
        query: 搜索关键词（支持通配符 * 和 ?）
        sym_type: 符号类型过滤 (Label, Function, Parameter, LocalVar, GlobalVar, Class, Namespace, ExternalLib, 等)
        limit: 最大返回数量

    Returns:
        dict: 匹配的符号列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        matches = []
        st = prog.getSymbolTable()

        # 使用通配符迭代器（如果查询包含 * 或 ?）
        if '*' in query or '?' in query:
            symbol_iter = st.getSymbolIterator(query, False)  # caseSensitive=False
        else:
            # 普通模糊匹配
            search_pattern = query.lower()
            symbol_iter = st.getAllSymbols(True)

        use_pattern_match = '*' not in query and '?' not in query

        for sym in symbol_iter:
            if len(matches) >= limit:
                break

            sym_type_str = str(sym.getSymbolType())

            # 类型过滤
            if sym_type and sym_type.lower() != sym_type_str.lower():
                continue

            name = sym.getName()

            # 模糊匹配（非通配符模式）
            if use_pattern_match and search_pattern not in name.lower():
                continue

            matches.append({
                "name": name,
                "address": str(sym.getAddress()),
                "symbol_type": sym_type_str,
                "is_primary": sym.isPrimary(),
                "is_external": sym.isExternal(),
                "namespace": str(sym.getParentNamespace().getName()) if sym.getParentNamespace() else None,
                "source": str(sym.getSource()),
            })

        return _make_success({
            "query": query,
            "type_filter": sym_type,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_symbols failed: {str(e)}")


def search_comments(state, query, comment_type=None, limit=100):
    """
    搜索注释（EOL, Pre, Post, Plate, Repeatable）。

    Args:
        state: Ghidra GhidraState 对象
        query: 搜索关键词
        comment_type: 注释类型过滤 (EOL, PRE, POST, PLATE, REPEATABLE) 或 None 搜索全部
        limit: 最大返回数量

    Returns:
        dict: 匹配的注释列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        from ghidra.program.model.listing import CodeUnit

        # 注释类型映射
        comment_types = {
            "EOL": CodeUnit.EOL_COMMENT,
            "PRE": CodeUnit.PRE_COMMENT,
            "POST": CodeUnit.POST_COMMENT,
            "PLATE": CodeUnit.PLATE_COMMENT,
            "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
        }

        # 确定要搜索的注释类型
        if comment_type:
            upper_type = comment_type.upper()
            if upper_type not in comment_types:
                return _make_error(f"Invalid comment_type: {comment_type}. Valid: {list(comment_types.keys())}")
            types_to_search = {upper_type: comment_types[upper_type]}
        else:
            types_to_search = comment_types

        search_pattern = query.lower()
        matches = []
        listing = prog.getListing()

        # 遍历所有代码单元
        for cu in listing.getCodeUnits(True):
            if len(matches) >= limit:
                break

            for type_name, type_code in types_to_search.items():
                if len(matches) >= limit:
                    break

                comment = cu.getComment(type_code)
                if comment and search_pattern in comment.lower():
                    matches.append({
                        "address": str(cu.getAddress()),
                        "comment_type": type_name,
                        "comment": comment[:500] if len(comment) > 500 else comment,
                        "mnemonic": str(cu.getMnemonicString()) if hasattr(cu, 'getMnemonicString') else None,
                    })

        return _make_success({
            "query": query,
            "type_filter": comment_type,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_comments failed: {str(e)}")


# ============================================================
# 数据搜索
# ============================================================

def search_strings(state, query, encoding=None, limit=100):
    """
    搜索已定义的字符串数据。

    Args:
        state: Ghidra GhidraState 对象
        query: 搜索关键词
        encoding: 编码过滤 (ASCII, UTF-8, UTF-16, unicode, 等) 或 None 搜索全部
        limit: 最大返回数量

    Returns:
        dict: 匹配的字符串列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        search_pattern = query.lower()
        matches = []

        listing = prog.getListing()
        data_iterator = listing.getDefinedData(True)

        for data in data_iterator:
            if len(matches) >= limit:
                break

            if not data.hasStringValue():
                continue

            value = data.getValue()
            if value is None:
                continue

            str_value = str(value)
            if search_pattern not in str_value.lower():
                continue

            # 获取数据类型名称（用于编码判断）
            data_type = data.getDataType()
            type_name = data_type.getName() if data_type else "Unknown"

            # 编码过滤
            if encoding:
                enc_lower = encoding.lower()
                type_lower = type_name.lower()
                # 简单匹配：检查类型名是否包含编码关键字
                if enc_lower not in type_lower and not (
                    enc_lower == "ascii" and "string" in type_lower and "unicode" not in type_lower
                ):
                    continue

            # 截断过长字符串
            display_value = str_value[:500] + "..." if len(str_value) > 500 else str_value

            matches.append({
                "address": str(data.getAddress()),
                "value": display_value,
                "length": len(str_value),
                "data_type": type_name,
            })

        return _make_success({
            "query": query,
            "encoding_filter": encoding,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_strings failed: {str(e)}")


def search_scalars(state, value, size=None, limit=100):
    """
    搜索标量/立即数。

    Args:
        state: Ghidra GhidraState 对象
        value: 要搜索的数值（支持十进制或十六进制字符串如 "0x1234"）
        size: 数值大小过滤 (1, 2, 4, 8 字节) 或 None 搜索全部
        limit: 最大返回数量

    Returns:
        dict: 匹配的标量位置列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    try:
        # 解析数值
        if isinstance(value, str):
            if value.lower().startswith("0x"):
                search_value = int(value, 16)
            else:
                search_value = int(value)
        else:
            search_value = int(value)
    except ValueError:
        return _make_error(f"Invalid value: {value}")

    try:
        matches = []
        listing = prog.getListing()

        # 遍历所有指令，检查操作数中的标量
        for instr in listing.getInstructions(True):
            if len(matches) >= limit:
                break

            found_in_instr = False
            num_operands = instr.getNumOperands()

            for i in range(num_operands):
                if found_in_instr:
                    break

                # 使用 getScalar(operandIndex) 获取特定操作数的标量
                scalar = instr.getScalar(i)
                if scalar is None:
                    continue

                scalar_value = scalar.getValue()
                scalar_size = scalar.bitLength() // 8

                # 数值匹配
                if scalar_value != search_value:
                    continue

                # 大小过滤
                if size and scalar_size != size:
                    continue

                matches.append({
                    "address": str(instr.getAddress()),
                    "value": scalar_value,
                    "hex_value": hex(scalar_value) if scalar_value >= 0 else hex(scalar_value & 0xFFFFFFFFFFFFFFFF),
                    "size": scalar_size,
                    "instruction": str(instr),
                    "operand_index": i,
                })
                found_in_instr = True  # 每条指令只记录一次

        return _make_success({
            "search_value": search_value,
            "hex_search": hex(search_value) if search_value >= 0 else hex(search_value & 0xFFFFFFFFFFFFFFFF),
            "size_filter": size,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_scalars failed: {str(e)}")


# ============================================================
# 模式搜索
# ============================================================

def search_bytes(state, pattern, limit=100, align=1):
    """
    搜索字节模式（支持通配符）。

    Args:
        state: Ghidra GhidraState 对象
        pattern: 十六进制字节模式，如 "48 8b ?? 90" 或 "488b..90"
                 ?? 或 .. 表示通配符
        limit: 最大返回数量
        align: 对齐要求 (1=任意, 2=双字节对齐, 4=四字节对齐)

    Returns:
        dict: 匹配的地址列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not pattern:
        return _make_error("Pattern is required")

    try:
        import re

        # 标准化模式字符串：移除空格，统一通配符格式
        normalized = pattern.replace(" ", "").replace("??", "..").replace("?", ".")

        # 验证模式格式
        if not re.match(r'^[0-9a-fA-F.]+$', normalized):
            return _make_error(f"Invalid pattern format: {pattern}. Use hex digits and ?? or .. for wildcards")

        if len(normalized) % 2 != 0:
            return _make_error(f"Pattern must have even number of characters: {normalized}")

        # 将模式转换为字节数组和掩码
        byte_len = len(normalized) // 2
        search_bytes = []
        search_mask = []

        for i in range(byte_len):
            high = normalized[i * 2]
            low = normalized[i * 2 + 1]

            if high == '.' and low == '.':
                # 完全通配符
                search_bytes.append(0)
                search_mask.append(0x00)
            elif high == '.':
                # 高位通配符
                search_bytes.append(int(low, 16))
                search_mask.append(0x0F)
            elif low == '.':
                # 低位通配符
                search_bytes.append(int(high, 16) << 4)
                search_mask.append(0xF0)
            else:
                # 精确匹配
                search_bytes.append(int(high + low, 16))
                search_mask.append(0xFF)

        matches = []
        memory = prog.getMemory()

        # 遍历所有内存块搜索
        for block in memory.getBlocks():
            if len(matches) >= limit:
                break

            # 跳过非初始化的块
            if not block.isInitialized():
                continue

            start = block.getStart()
            end = block.getEnd()

            # 从块起始位置开始搜索
            addr = start
            while addr is not None and addr.compareTo(end) <= 0 and len(matches) < limit:
                # 检查对齐
                addr_offset = addr.getOffset()
                if align > 1 and (addr_offset % align) != 0:
                    addr = addr.add(1)
                    continue

                # 检查是否有足够的字节可读
                if addr.add(byte_len - 1).compareTo(end) > 0:
                    break

                # 尝试匹配
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
                    # 读取实际字节
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

                    # 移动到下一个可能的位置
                    addr = addr.add(max(1, align))
                else:
                    addr = addr.add(1)

        return _make_success({
            "pattern": pattern,
            "normalized_pattern": normalized,
            "alignment": align,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_bytes failed: {str(e)}")


def search_instructions(state, query, limit=100):
    """
    搜索汇编指令文本。

    Args:
        state: Ghidra GhidraState 对象
        query: 指令搜索关键词（如 "call", "mov eax", "jmp"）
        limit: 最大返回数量

    Returns:
        dict: 匹配的指令列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        search_pattern = query.lower()
        matches = []
        listing = prog.getListing()

        for instr in listing.getInstructions(True):
            if len(matches) >= limit:
                break

            # 获取完整指令字符串
            instr_str = str(instr).lower()

            if search_pattern in instr_str:
                # 获取指令字节
                instr_bytes = []
                try:
                    length = instr.getLength()
                    addr = instr.getAddress()
                    memory = prog.getMemory()
                    for i in range(length):
                        b = memory.getByte(addr.add(i))
                        instr_bytes.append(format(b & 0xFF, '02x'))
                except:
                    instr_bytes = []

                matches.append({
                    "address": str(instr.getAddress()),
                    "mnemonic": instr.getMnemonicString(),
                    "instruction": str(instr),
                    "bytes": " ".join(instr_bytes),
                    "length": instr.getLength(),
                })

        return _make_success({
            "query": query,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_instructions failed: {str(e)}")


# ============================================================
# 引用搜索
# ============================================================

def search_xrefs_to(state, address):
    """
    搜索所有引用到指定地址的交叉引用。

    Args:
        state: Ghidra GhidraState 对象
        address: 目标地址（字符串格式，如 "0x401000"）

    Returns:
        dict: 引用列表（谁引用了这个地址）
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not address:
        return _make_error("Address is required")

    addr, err = _parse_address(prog, address)
    if err:
        return err

    try:
        matches = []
        ref_mgr = prog.getReferenceManager()
        listing = prog.getListing()

        refs = ref_mgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()

            # 获取来源位置的上下文
            context = None
            func = listing.getFunctionContaining(from_addr)
            if func:
                context = f"in {func.getName()}"

            instr = listing.getInstructionAt(from_addr)
            instr_str = str(instr) if instr else None

            matches.append({
                "from_address": str(from_addr),
                "to_address": str(ref.getToAddress()),
                "ref_type": str(ref.getReferenceType()),
                "is_call": ref.getReferenceType().isCall(),
                "is_jump": ref.getReferenceType().isJump(),
                "is_data": ref.getReferenceType().isData(),
                "operand_index": ref.getOperandIndex(),
                "instruction": instr_str,
                "context": context,
            })

        return _make_success({
            "target_address": address,
            "references": matches,
            "count": len(matches),
        })

    except Exception as e:
        return _make_error(f"search_xrefs_to failed: {str(e)}")


def search_xrefs_from(state, address):
    """
    搜索从指定地址发出的所有引用。

    Args:
        state: Ghidra GhidraState 对象
        address: 源地址（字符串格式，如 "0x401000"）

    Returns:
        dict: 引用列表（这个地址引用了谁）
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not address:
        return _make_error("Address is required")

    addr, err = _parse_address(prog, address)
    if err:
        return err

    try:
        matches = []
        ref_mgr = prog.getReferenceManager()
        listing = prog.getListing()

        refs = ref_mgr.getReferencesFrom(addr)
        for ref in refs:
            to_addr = ref.getToAddress()

            # 获取目标位置的上下文
            context = None
            func = listing.getFunctionAt(to_addr)
            if func:
                context = f"function {func.getName()}"
            else:
                # 检查是否是数据
                data = listing.getDataAt(to_addr)
                if data and data.hasStringValue():
                    value = str(data.getValue())
                    context = f"string: {value[:50]}..." if len(value) > 50 else f"string: {value}"

            matches.append({
                "from_address": str(ref.getFromAddress()),
                "to_address": str(to_addr),
                "ref_type": str(ref.getReferenceType()),
                "is_call": ref.getReferenceType().isCall(),
                "is_jump": ref.getReferenceType().isJump(),
                "is_data": ref.getReferenceType().isData(),
                "operand_index": ref.getOperandIndex(),
                "context": context,
            })

        return _make_success({
            "source_address": address,
            "references": matches,
            "count": len(matches),
        })

    except Exception as e:
        return _make_error(f"search_xrefs_from failed: {str(e)}")


# ============================================================
# 类型搜索
# ============================================================

def search_data_types(state, query, limit=100):
    """
    搜索数据类型。

    Args:
        state: Ghidra GhidraState 对象
        query: 搜索关键词（支持通配符 * 和 ?）
        limit: 最大返回数量

    Returns:
        dict: 匹配的数据类型列表
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        import fnmatch

        matches = []
        dtm = prog.getDataTypeManager()

        # 判断是否使用通配符模式
        use_wildcard = '*' in query or '?' in query

        if use_wildcard:
            # 使用 fnmatch 进行通配符匹配
            for dt in dtm.getAllDataTypes():
                if len(matches) >= limit:
                    break
                # fnmatch 支持 * 和 ? 通配符
                if fnmatch.fnmatch(dt.getName().lower(), query.lower()):
                    matches.append({
                        "name": dt.getName(),
                        "path": str(dt.getPathName()),
                        "category": str(dt.getCategoryPath()),
                        "length": dt.getLength(),
                        "description": dt.getDescription() or "",
                        "display_name": dt.getDisplayName(),
                    })
        else:
            # 模糊搜索（包含匹配）
            search_pattern = query.lower()
            for dt in dtm.getAllDataTypes():
                if len(matches) >= limit:
                    break
                if search_pattern in dt.getName().lower():
                    matches.append({
                        "name": dt.getName(),
                        "path": str(dt.getPathName()),
                        "category": str(dt.getCategoryPath()),
                        "length": dt.getLength(),
                        "description": dt.getDescription() or "",
                        "display_name": dt.getDisplayName(),
                    })

        return _make_success({
            "query": query,
            "matches": matches,
            "count": len(matches),
            "limit": limit
        })

    except Exception as e:
        return _make_error(f"search_data_types failed: {str(e)}")


# ============================================================
# 聚合搜索
# ============================================================

def search_all(state, query, limit=50):
    """
    聚合搜索 - 同时搜索函数、符号、字符串。

    Args:
        state: Ghidra GhidraState 对象
        query: 搜索关键词
        limit: 每种类型的最大返回数量

    Returns:
        dict: 聚合搜索结果
    """
    prog, err = _get_program(state)
    if err:
        return err

    if not query:
        return _make_error("Query is required")

    try:
        results = {
            "functions": [],
            "symbols": [],
            "strings": []
        }

        # 搜索函数
        func_result = search_functions(state, query, limit)
        if func_result.get("success"):
            results["functions"] = func_result["data"]["matches"]

        # 搜索符号（排除函数）
        sym_result = search_symbols(state, query, None, limit)
        if sym_result.get("success"):
            # 过滤掉函数类型的符号
            results["symbols"] = [
                s for s in sym_result["data"]["matches"]
                if s["symbol_type"] != "Function"
            ][:limit]

        # 搜索字符串
        str_result = search_strings(state, query, None, limit)
        if str_result.get("success"):
            results["strings"] = str_result["data"]["matches"]

        # 生成摘要
        total = len(results["functions"]) + len(results["symbols"]) + len(results["strings"])

        return _make_success({
            "query": query,
            "results": results,
            "summary": {
                "total": total,
                "functions": len(results["functions"]),
                "symbols": len(results["symbols"]),
                "strings": len(results["strings"])
            }
        })

    except Exception as e:
        return _make_error(f"search_all failed: {str(e)}")
