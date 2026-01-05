"""
基础信息 API (Basic Info API)

提供当前加载程序的基础信息，包括：
- 程序名称、路径
- 架构、语言信息
- 内存布局概要
- 入口点信息

路由: GET /api/basic_info

参数约定:
- args[0]: 结果输出文件路径
- args[1:]: 暂无额外参数
"""

import json
import os


def get_result_output_path():
    """从脚本参数中获取结果输出文件路径"""
    try:
        args = getScriptArgs()
        if args is not None and len(args) > 0:
            return args[0]
    except NameError:
        pass
    except Exception:
        pass
    return None


def write_result(result, filepath):
    """将结果写入指定文件"""
    try:
        dir_path = os.path.dirname(filepath)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return True
    except Exception as e:
        return f"Failed to write result: {str(e)}"


def get_basic_info():
    """
    获取当前程序的基础信息。

    Returns:
        包含程序基础信息的字典
    """
    result = {
        "success": False,
        "program": None,
        "errors": []
    }

    try:
        prog = currentProgram()
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
                "endian": str(language.isBigEndian() and "big" or "little"),
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

        # 入口点信息
        addr_factory = prog.getAddressFactory()
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
            # 获取入口点函数
            entry_points = []
            for entry in prog.getSymbolTable().getExternalEntryPointIterator():
                entry_points.append(str(entry))
            if entry_points:
                result["program"]["entry_points"] = entry_points[:10]  # 限制数量

    except Exception as e:
        result["success"] = False
        result["errors"].append(f"Exception: {str(e)}")

    return result


# ============================================================
# 脚本入口点
# ============================================================

if __name__ == "__main__":
    # 获取基础信息
    info_result = get_basic_info()

    # 获取结果输出路径
    output_path = get_result_output_path()

    if output_path:
        write_status = write_result(info_result, output_path)
        if write_status is True:
            print(f"[basic_info] Result written to: {output_path}")
        else:
            print(f"[basic_info] Failed to write result: {write_status}")
            print(json.dumps(info_result, indent=2))
    else:
        print("[basic_info] No output path provided, printing to console:")
        print(json.dumps(info_result, indent=2))
