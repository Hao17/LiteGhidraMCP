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


def dispatch_route(path, state, params=None):
    """
    分发路由请求到对应的处理函数

    Args:
        path: 请求路径
        state: Ghidra state 对象
        params: 查询参数字典（可选，默认为空字典）

    Returns:
        处理函数的返回结果，通常是字典
    """
    if path not in _routes:
        return None

    if params is None:
        params = {}

    route_info = _routes[path]
    handler = route_info["handler"]

    # 根据 handler 签名的默认值类型，自动转换 URL 参数类型
    # URL 参数总是 string，但 handler 可能期望 int 等类型
    if params:
        import inspect
        try:
            sig = inspect.signature(handler)
            for key, value in params.items():
                if key in sig.parameters and isinstance(value, str):
                    default = sig.parameters[key].default
                    if isinstance(default, int):
                        try:
                            params[key] = int(value)
                        except (ValueError, TypeError):
                            pass  # 保留原始字符串，让 handler 自行处理
                    elif isinstance(default, float):
                        try:
                            params[key] = float(value)
                        except (ValueError, TypeError):
                            pass
        except (ValueError, TypeError):
            pass  # inspect 失败时不影响正常调用

    # 调用处理函数，传递 state 和参数
    return handler(state, **params)
