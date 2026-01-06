"""
服务器状态 API - 用于验证热重载

模块加载时记录时间戳，通过对比时间戳可验证热重载是否生效。

路由: GET /api/status
"""

import time

from api import route

# 模块加载时间戳（每次 reload 会更新）
_MODULE_LOAD_TIME = time.time()
_MODULE_LOAD_TIME_STR = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(_MODULE_LOAD_TIME))


@route("/api/status")
def status(state):
    """
    获取服务器和模块状态信息。

    Args:
        state: Ghidra 的 GhidraState 对象

    Returns:
        包含状态信息的字典
    """
    current_time = time.time()

    result = {
        "success": True,
        "server": {
            "current_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_time)),
            "current_timestamp": current_time,
        },
        "module": {
            "name": "api.status",
            "load_time": _MODULE_LOAD_TIME_STR,
            "load_timestamp": _MODULE_LOAD_TIME,
            "uptime_seconds": round(current_time - _MODULE_LOAD_TIME, 2),
        },
        "state": {
            "has_program": False,
            "program_name": None,
        }
    }

    # 检查 Ghidra 状态
    try:
        if state:
            prog = state.getCurrentProgram()
            if prog:
                result["state"]["has_program"] = True
                result["state"]["program_name"] = prog.getName()
    except Exception as e:
        result["state"]["error"] = str(e)

    return result
