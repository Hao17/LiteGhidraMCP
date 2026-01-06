"""
基础信息 API - 获取当前程序的基础信息

路由: GET /api/basic_info
"""

from api import route


@route("/api/basic_info")
def basic_info(state):
    """
    获取当前程序的基础信息。

    Args:
        state: Ghidra 的 GhidraState 对象

    Returns:
        包含程序基础信息的字典
    """
    result = {
        "success": False,
        "program": None,
        "errors": []
    }

    try:
        prog = state.getCurrentProgram()
        if prog is None:
            result["errors"].append("No program loaded")
            return result

        result["success"] = True

        # 基本信息
        result["program"] = {
            "name": prog.getName(),
            "executable_path": prog.getExecutablePath() if hasattr(prog, 'getExecutablePath') else None,
            "executable_format": prog.getExecutableFormat() if hasattr(prog, 'getExecutableFormat') else None,
        }

        # 当前地址
        current_addr = state.getCurrentAddress()
        if current_addr:
            result["program"]["current_address"] = str(current_addr)

        # 当前选择
        current_selection = state.getCurrentSelection()
        if current_selection and not current_selection.isEmpty():
            result["program"]["has_selection"] = True
            result["program"]["selection_range_count"] = current_selection.getNumAddressRanges()
        else:
            result["program"]["has_selection"] = False

        # 域文件信息
        domain_file = prog.getDomainFile()
        if domain_file:
            result["program"]["domain_file"] = {
                "name": domain_file.getName(),
                "path": str(domain_file.getPathname()) if hasattr(domain_file, 'getPathname') else None,
            }

        # 语言和编译器信息
        language = prog.getLanguage()
        if language:
            result["program"]["language"] = {
                "id": str(language.getLanguageID()),
                "processor": str(language.getProcessor()),
                "endian": "big" if language.isBigEndian() else "little",
                "size": language.getLanguageDescription().getSize() if language.getLanguageDescription() else None,
            }

        compiler_spec = prog.getCompilerSpec()
        if compiler_spec:
            result["program"]["compiler"] = {
                "id": str(compiler_spec.getCompilerSpecID()),
            }

        # 内存信息
        memory = prog.getMemory()
        if memory:
            blocks = []
            for block in memory.getBlocks():
                blocks.append({
                    "name": block.getName(),
                    "start": str(block.getStart()),
                    "end": str(block.getEnd()),
                    "size": block.getSize(),
                    "permissions": {
                        "read": block.isRead(),
                        "write": block.isWrite(),
                        "execute": block.isExecute(),
                    }
                })
            result["program"]["memory"] = {
                "total_size": memory.getSize(),
                "block_count": len(blocks),
                "blocks": blocks
            }

        # 地址信息
        image_base = prog.getImageBase()
        result["program"]["address_info"] = {
            "image_base": str(image_base) if image_base else None,
        }

        # 符号表统计
        symbol_table = prog.getSymbolTable()
        if symbol_table:
            result["program"]["symbols"] = {
                "total_count": symbol_table.getNumSymbols(),
            }

        # 函数统计
        function_manager = prog.getFunctionManager()
        if function_manager:
            result["program"]["functions"] = {
                "total_count": function_manager.getFunctionCount(),
            }
            # 入口点
            entry_points = []
            for entry in prog.getSymbolTable().getExternalEntryPointIterator():
                entry_points.append(str(entry))
            if entry_points:
                result["program"]["entry_points"] = entry_points[:10]

    except Exception as e:
        result["success"] = False
        result["errors"].append(f"Exception: {str(e)}")

    return result
