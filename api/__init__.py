# api/ - API 模块目录
#
# 使用 @route 装饰器自动注册 API 路由。
# 新增 API 只需创建文件并使用装饰器，然后调用 /_reload 热重载即可生效。
#
# 示例:
#   from api import route
#
#   @route("/api/my_api")
#   def my_function(state, param1="", param2=None):
#       return {"success": True, "data": ...}

# 路由注册表
_routes = {}


def route(path, methods=None):
    """
    路由装饰器 - 自动注册 API 路由

    Args:
        path: 路由路径，如 "/api/basic_info"
        methods: 允许的 HTTP 方法列表，默认 ["GET"]

    示例:
        @route("/api/my_api")
        def my_function(state, param1="", limit=100):
            return {"success": True, ...}

        # 请求: GET /api/my_api?param1=value&limit=50
        # 自动调用: my_function(state, param1="value", limit=50)
    """
    if methods is None:
        methods = ["GET"]

    def decorator(func):
        _routes[path] = {
            "handler": func,
            "methods": methods,
            "module": func.__module__,
            "name": func.__name__,
        }
        return func

    return decorator


def get_routes():
    """获取所有已注册的路由"""
    return _routes


def clear_routes():
    """清空路由注册表（热重载前调用）"""
    _routes.clear()


def get_route_list():
    """获取路由列表（用于调试/状态展示）"""
    return [
        {"path": path, "module": info["module"], "handler": info["name"]}
        for path, info in sorted(_routes.items())
    ]
