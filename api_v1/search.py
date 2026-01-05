"""
api_v1/search.py - 聚合搜索API（自包含）

面向AI的统一搜索接口，同时搜索函数、符号、字符串。
这个脚本完全自包含，不依赖其他模块。

参数约定:
- args[0]: 结果输出文件路径
- args[1]: 命令 (all/functions/strings)
- args[2]: 搜索关键词
- args[3]: (可选) limit
"""

import json


# ============================================================
# 公共工具函数
# ============================================================

def get_args():
    """获取脚本参数"""
    try:
        args = getScriptArgs()
        return list(args) if args else []
    except NameError:
        return []


def get_output_path():
    """获取结果输出文件路径 (args[0])"""
    args = get_args()
    return args[0] if args else None


def get_command():
    """获取命令 (args[1])"""
    args = get_args()
    return args[1] if len(args) > 1 else "all"


def get_query():
    """获取搜索关键词 (args[2])"""
    args = get_args()
    return args[2] if len(args) > 2 else ""


def get_limit():
    """获取结果数量限制 (args[3])"""
    args = get_args()
    if len(args) > 3:
        try:
            return int(args[3])
        except ValueError:
            pass
    return 50


def write_result(result):
    """将结果写入输出文件"""
    output_path = get_output_path()
    if not output_path:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return False

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[search] Failed to write result: {e}")
        return False


def make_success(data):
    """构造成功响应"""
    return {"success": True, "data": data}


def make_error(message):
    """构造错误响应"""
    return {"success": False, "error": message}


# ============================================================
# 搜索功能实现
# ============================================================

def search_all(query, limit=50):
    """
    统一搜索 - 同时搜索函数、符号、字符串。

    Args:
        query: 搜索关键词
        limit: 每种类型的最大返回数量

    Returns:
        dict: 聚合搜索结果
    """
    try:
        prog = currentProgram()
        if not prog:
            return make_error("No program loaded")

        if not query:
            return make_error("Query is required")

        search_pattern = query.lower()
        results = {
            "functions": [],
            "symbols": [],
            "strings": []
        }

        # 搜索函数
        fm = prog.getFunctionManager()
        for func in fm.getFunctions(True):
            if len(results["functions"]) >= limit:
                break
            name = func.getName()
            if search_pattern in name.lower():
                results["functions"].append({
                    "name": name,
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses() if func.getBody() else 0
                })

        # 搜索符号（排除函数符号避免重复）
        st = prog.getSymbolTable()
        for sym in st.getAllSymbols(True):
            if len(results["symbols"]) >= limit:
                break
            sym_type = str(sym.getSymbolType())
            if sym_type == "Function":
                continue
            name = sym.getName()
            if search_pattern in name.lower():
                results["symbols"].append({
                    "name": name,
                    "address": str(sym.getAddress()),
                    "symbol_type": sym_type
                })

        # 搜索字符串
        data_iterator = prog.getListing().getDefinedData(True)
        for data in data_iterator:
            if len(results["strings"]) >= limit:
                break
            if not data.hasStringValue():
                continue
            value = data.getValue()
            if value is None:
                continue
            str_value = str(value)
            if search_pattern in str_value.lower():
                # 截断过长的字符串
                display_value = str_value[:200] + "..." if len(str_value) > 200 else str_value
                results["strings"].append({
                    "address": str(data.getAddress()),
                    "value": display_value,
                    "length": len(str_value)
                })

        # 生成摘要
        total = len(results["functions"]) + len(results["symbols"]) + len(results["strings"])

        return make_success({
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
        return make_error(str(e))


def search_functions(query, limit=100):
    """
    仅搜索函数。

    Args:
        query: 搜索关键词
        limit: 最大返回数量

    Returns:
        dict: 函数搜索结果
    """
    try:
        prog = currentProgram()
        if not prog:
            return make_error("No program loaded")

        if not query:
            return make_error("Query is required")

        search_pattern = query.lower()
        matches = []

        fm = prog.getFunctionManager()
        for func in fm.getFunctions(True):
            if len(matches) >= limit:
                break
            name = func.getName()
            if search_pattern in name.lower():
                matches.append({
                    "name": name,
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses() if func.getBody() else 0,
                    "signature": str(func.getSignature())
                })

        return make_success({
            "query": query,
            "matches": matches,
            "count": len(matches)
        })

    except Exception as e:
        return make_error(str(e))


def search_strings(query, limit=100):
    """
    仅搜索字符串。

    Args:
        query: 搜索关键词
        limit: 最大返回数量

    Returns:
        dict: 字符串搜索结果
    """
    try:
        prog = currentProgram()
        if not prog:
            return make_error("No program loaded")

        if not query:
            return make_error("Query is required")

        search_pattern = query.lower()
        matches = []

        data_iterator = prog.getListing().getDefinedData(True)
        for data in data_iterator:
            if len(matches) >= limit:
                break
            if not data.hasStringValue():
                continue
            value = data.getValue()
            if value is None:
                continue
            str_value = str(value)
            if search_pattern in str_value.lower():
                matches.append({
                    "address": str(data.getAddress()),
                    "value": str_value,
                    "length": len(str_value)
                })

        return make_success({
            "query": query,
            "matches": matches,
            "count": len(matches)
        })

    except Exception as e:
        return make_error(str(e))


# ============================================================
# 脚本入口
# ============================================================

if __name__ == "__main__":
    command = get_command()
    query = get_query()
    limit = get_limit()

    if command == "all":
        result = search_all(query, limit)
    elif command == "functions":
        result = search_functions(query, limit)
    elif command == "strings":
        result = search_strings(query, limit)
    else:
        result = make_error(f"Unknown command: {command}. Use: all, functions, strings")

    write_result(result)
