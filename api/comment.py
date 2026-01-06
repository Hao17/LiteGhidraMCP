# api/comment.py
"""Comment API - 设置/删除注释"""

from api import route
from ghidra.program.model.listing import CodeUnit

COMMENT_TYPES = {
    "EOL": CodeUnit.EOL_COMMENT,
    "PRE": CodeUnit.PRE_COMMENT,
    "POST": CodeUnit.POST_COMMENT,
    "PLATE": CodeUnit.PLATE_COMMENT,
    "REPEATABLE": CodeUnit.REPEATABLE_COMMENT
}


def _get_program(state):
    """获取当前程序"""
    prog = state.getCurrentProgram()
    if not prog:
        return None, {"success": False, "error": "No program loaded"}
    return prog, None


def _parse_address(prog, addr_str):
    """解析地址字符串"""
    try:
        addr = prog.getAddressFactory().getAddress(addr_str)
        if addr is None:
            return None, {"success": False, "error": f"Invalid address: {addr_str}"}
        return addr, None
    except Exception as e:
        return None, {"success": False, "error": f"Address parse error: {str(e)}"}


def _resolve_address(state, address="", name=""):
    """根据 address 或 name 解析目标地址"""
    prog, err = _get_program(state)
    if err:
        return None, None, err

    if address:
        addr, err = _parse_address(prog, address)
        if err:
            return None, None, err
        return prog, addr, None

    if name:
        fm = prog.getFunctionManager()
        for func in fm.getFunctions(True):
            if func.getName() == name:
                return prog, func.getEntryPoint(), None
        return None, None, {"success": False, "error": f"Function not found: {name}"}

    return None, None, {"success": False, "error": "Must provide 'address' or 'name'"}


@route("/api/comment/set")
def set_comment(state, address="", name="", type="EOL", text=""):
    """
    设置注释。

    路由: GET /api/comment/set?address=0x401000&type=EOL&text=注释内容
          GET /api/comment/set?name=main&type=PLATE&text=函数说明

    参数:
        address: 目标地址 (与 name 二选一)
        name: 函数名，设置函数入口点的注释 (与 address 二选一)
        type: 注释类型，默认 EOL。可选: EOL/PRE/POST/PLATE/REPEATABLE
        text: 注释内容，空字符串表示删除
    """
    # 1. 验证 type
    type_upper = type.upper()
    if type_upper not in COMMENT_TYPES:
        valid_types = "/".join(COMMENT_TYPES.keys())
        return {"success": False, "error": f"Invalid type: {type}. Valid: {valid_types}"}
    comment_type = COMMENT_TYPES[type_upper]

    # 2. 解析地址
    prog, addr, err = _resolve_address(state, address, name)
    if err:
        return err

    # 3. 获取 CodeUnit
    listing = prog.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    if not code_unit:
        return {"success": False, "error": f"No code unit at address: {addr}"}

    # 4. 在事务中设置 comment
    comment_text = text if text else None  # 空字符串转 None 表示删除
    tx_id = prog.startTransaction("Set Comment")
    try:
        code_unit.setComment(comment_type, comment_text)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return {"success": False, "error": f"Failed to set comment: {str(e)}"}

    # 5. 返回结果
    return {
        "success": True,
        "address": str(addr),
        "type": type_upper,
        "text": text,
        "action": "deleted" if not text else "set"
    }
