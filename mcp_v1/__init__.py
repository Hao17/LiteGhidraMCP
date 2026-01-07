"""
MCP V1 Module - Model Context Protocol Support for Ghidra Bridge

This module provides MCP (Model Context Protocol) server support,
wrapping the api_v1 interfaces as MCP tools for AI integration.

Usage:
    from mcp_v1.server import set_ghidra_state, start_mcp_sse_server

    set_ghidra_state(cached_state)
    start_mcp_sse_server(host="127.0.0.1", port=8804)
"""

__version__ = "0.1.0"
