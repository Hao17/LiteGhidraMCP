# api_v1/ - 聚合API版本1
#
# 面向AI的高级接口，使用 @route 装饰器自动注册路由。
# 本包所有路由使用 /api/v1/* 前缀。

from api import route

__all__ = ["route"]
