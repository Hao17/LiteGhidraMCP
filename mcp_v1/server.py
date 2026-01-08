"""
MCP SSE Server - Model Context Protocol Support for Ghidra Bridge

This module provides MCP server implementation using FastMCP with SSE transport.
It wraps api_v1 interfaces as MCP tools for AI integration.

Usage:
    from mcp_v1.server import set_ghidra_state, start_mcp_sse_server

    set_ghidra_state(cached_state)
    actual_port = start_mcp_sse_server(host="127.0.0.1", port=8804)
"""

import json
import socket
import threading
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ============================================================
# FastMCP Instance (created lazily with correct settings)
# ============================================================

mcp: Optional[FastMCP] = None


def _create_mcp_instance(host: str = "127.0.0.1", port: int = 8804) -> FastMCP:
    """Create FastMCP instance with specified host and port."""
    global mcp
    mcp = FastMCP(name="Ghidra-MCP-Bridge", host=host, port=port)
    _register_mcp_tools()
    return mcp

# ============================================================
# Ghidra State Reference
# ============================================================

_ghidra_state = None


def set_ghidra_state(state):
    """
    Set the Ghidra state object for tool access.

    This should be called before starting the MCP server,
    typically from ghidra_mcp_server.py after caching state.

    Args:
        state: Ghidra GhidraState object
    """
    global _ghidra_state
    _ghidra_state = state


def get_ghidra_state():
    """Get the cached Ghidra state object."""
    return _ghidra_state


# ============================================================
# MCP Tools (registered via _register_mcp_tools)
# ============================================================

def ghidra_search(
    query: str,
    types: str = "auto",
    limit: int = 20,
    verbose: bool = False
) -> dict:
    """
    Search the loaded binary for functions, symbols, strings, etc.

    This is a unified search tool that supports multiple search types
    with smart type inference based on query pattern.

    Args:
        query: Search query string. Examples:
            - "main" - search for function/symbol named main
            - "0x401000" - search for cross-references to address
            - "*init*" - wildcard search for symbols/datatypes
            - "48 8b ??" - byte pattern search
            - "call" - instruction mnemonic search
        types: Search types to use:
            - "auto" (default): Smart inference based on query
            - "all": Search all types
            - Comma-separated list: "functions,symbols,strings,comments,instructions,xrefs,datatypes,bytes"
        limit: Maximum results per type (default: 20)
        verbose: If True, return full dict format; if False, return compact arrays

    Returns:
        dict with search results grouped by type, including:
            - summary: count per type
            - results: matched items per type
            - _schema: field names for compact mode
    """
    if _ghidra_state is None:
        return {"success": False, "error": "Ghidra state not available"}

    from api_v1 import search as v1_search
    return v1_search.search(
        _ghidra_state,
        q=query,
        types=types,
        limit=limit,
        verbose="true" if verbose else ""
    )


def ghidra_view(
    query: str,
    view_type: str = "both",
    timeout: int = 30,
    limit: int = 500,
    verbose: bool = False
) -> dict:
    """
    View decompiled code and/or disassembly for functions.

    This tool provides function analysis results including C pseudo-code
    from the decompiler and assembly instructions.

    Args:
        query: Function identifier(s). Can be:
            - Function name: "main", "FUN_00401000"
            - Address: "0x401000"
            - Multiple comma-separated: "main,init,0x401000"
        view_type: What to return:
            - "both" (default): Decompiled code AND disassembly
            - "decompile": Only C pseudo-code
            - "disassemble": Only assembly instructions
        timeout: Decompilation timeout in seconds (default: 30)
        limit: Maximum instructions for disassembly (default: 500)
        verbose: If True, return full dict format; if False, return compact format

    Returns:
        dict with function analysis results including:
            - functions: list of analyzed functions
            - For each function: info (name, address, signature, size),
              decompiled code lines, assembly instructions
    """
    if _ghidra_state is None:
        return {"success": False, "error": "Ghidra state not available"}

    from api_v1 import view as v1_view
    return v1_view.view(
        _ghidra_state,
        q=query,
        type=view_type,
        timeout=timeout,
        limit=limit,
        verbose="true" if verbose else ""
    )


def ghidra_list(
    query: str = "",
    types: str = "auto",
    start: str = "",
    end: str = "",
    library: str = "",
    archive: str = "",
    show_builtin: bool = False,
    limit: int = 100,
    verbose: bool = False
) -> dict:
    """
    List symbols in the binary (like ls command).

    This tool provides a unified way to browse and filter symbols
    in the loaded binary.

    Args:
        query: Name filter pattern. Supports:
            - Substring match: "init" matches "initialize", "init_data"
            - Wildcards: "get*" matches "getData", "getSize"
        types: Symbol types to list:
            - "auto" (default): List functions only
            - "all": List all symbol types
            - Comma-separated: "functions,classes,namespaces,labels,globals,imports,exports,datatypes"
        start: Start address for range filter (e.g., "0x401000")
        end: End address for range filter (e.g., "0x402000")
        library: Filter imports by library name (e.g., "kernel32")
        archive: Filter datatypes by archive name (e.g., "init3.o")
        show_builtin: Include BuiltInTypes in datatype results (default: False)
        limit: Maximum results per type (default: 100)
        verbose: If True, return full dict format; if False, return compact arrays

    Returns:
        dict with listing results including:
            - summary: count per type
            - results: items per type with relevant fields
    """
    if _ghidra_state is None:
        return {"success": False, "error": "Ghidra state not available"}

    from api_v1 import list as v1_list
    return v1_list.list_symbols(
        _ghidra_state,
        q=query,
        types=types,
        start=start,
        end=end,
        library=library,
        archive=archive,
        show_builtin="true" if show_builtin else "",
        limit=limit,
        verbose="true" if verbose else ""
    )


def ghidra_edit(
    action: str,
    name: str = "",
    address: str = "",
    new_name: str = "",
    function: str = "",
    function_address: str = "",
    var_name: str = "",
    param: str = "",
    type: str = "",
    text: str = "",
    use_address: str = "",
    path: str = "",
    category: str = "/",
    fields: str = "",
    members: str = "",
    params: str = "",
    return_type: str = "",
    base_type: str = "",
    struct: str = "",
    enum: str = "",
    field: str = "",
    at: int = -1,
    new_type: str = "",
    new_comment: str = "",
    value: int = 0,
    source: str = "",
    dest_category: str = "",
    code: str = "",
    packing: int = 0,
    size: int = 4,
    calling_convention: str = "",
    verbose: bool = False
) -> dict:
    """
    Edit the binary (rename, set types, add comments, create structures, etc.).

    This is a unified editing tool supporting all modification operations.

    Args:
        action: The operation to perform. Available actions:

            **Rename operations:**
            - "rename.function": Rename a function
              Params: (name or address) + new_name
            - "rename.variable": Rename local variable (Listing level)
              Params: (function or function_address) + var_name + new_name
            - "rename.parameter": Rename function parameter (Listing level)
              Params: (function or function_address) + param (index or name) + new_name
            - "rename.global": Rename global variable
              Params: (name or address) + new_name
            - "rename.label": Rename a label
              Params: address + new_name
            - "rename.datatype": Rename a datatype
              Params: (name or path) + new_name
            - "rename.namespace": Rename namespace/class
              Params: name + new_name
            - "rename.decompiler.variable": Rename variable in decompiler view (recommended)
              Params: (function or function_address) + var_name + new_name
            - "rename.decompiler.parameter": Rename parameter in decompiler view
              Params: (function or function_address) + param + new_name
            - "rename.decompiler.split": Split variable at specific use point
              Params: (function or function_address) + var_name + use_address + new_name

            **DataType set operations:**
            - "datatype.set.return": Set function return type
              Params: function + type
            - "datatype.set.parameter": Set function parameter type
              Params: function + param + type
            - "datatype.set.decompiler.variable": Set decompiler variable type
              Params: function + var_name + type
            - "datatype.set.decompiler.parameter": Set decompiler parameter type
              Params: function + param + type
            - "datatype.set.global": Set global variable type
              Params: address + type
            - "datatype.set.field": Set struct field type
              Params: struct + field + type

            **DataType create operations:**
            - "datatype.create.struct": Create a structure
              Params: name + fields (JSON array) + category (optional) + packing (optional)
              fields format: [{"name": "x", "type": "int", "comment": "..."}]
            - "datatype.create.enum": Create an enumeration
              Params: name + members (JSON object or array) + category (optional) + size (optional)
              members format: {"OK": 0, "ERROR": 1} or [{"name": "OK", "value": 0}]
            - "datatype.create.typedef": Create a typedef
              Params: name + base_type + category (optional)
            - "datatype.create.union": Create a union
              Params: name + members (JSON array) + category (optional)
            - "datatype.create.funcdef": Create a function definition (function pointer type)
              Params: name + return_type + params (JSON array) + calling_convention (optional)

            **DataType manage operations:**
            - "datatype.struct.field.add": Add field to struct
              Params: struct + type + name + at (index, -1 for end)
            - "datatype.struct.field.delete": Delete field from struct
              Params: struct + field (index or name)
            - "datatype.struct.field.modify": Modify struct field
              Params: struct + field + new_name/new_type/new_comment
            - "datatype.enum.member.add": Add enum member
              Params: enum + name + value
            - "datatype.enum.member.delete": Delete enum member
              Params: enum + name
            - "datatype.delete": Delete a datatype
              Params: name or path
            - "datatype.parse.c": Parse C code to create types
              Params: code + category (optional)

            **Comment operations:**
            - "comment.set": Set or delete a comment
              Params: (address or name) + type (EOL/PRE/POST/PLATE/REPEATABLE) + text

        verbose: If True, include input parameters in response

    Returns:
        dict with operation result including success status and any errors

    Examples:
        ghidra_edit(action="rename.function", name="FUN_00401000", new_name="main")
        ghidra_edit(action="datatype.set.return", function="main", type="int")
        ghidra_edit(action="rename.decompiler.variable", function="main", var_name="local_8", new_name="counter")
        ghidra_edit(action="comment.set", address="0x401000", type="EOL", text="Entry point")
        ghidra_edit(action="datatype.create.struct", name="Point", fields='[{"name":"x","type":"int"},{"name":"y","type":"int"}]')
    """
    if _ghidra_state is None:
        return {"success": False, "error": "Ghidra state not available"}

    from api_v1 import edit as v1_edit

    # Build request body
    body = {"action": action}

    # Add non-empty parameters
    param_map = {
        "name": name,
        "address": address,
        "new_name": new_name,
        "function": function,
        "function_address": function_address,
        "var_name": var_name,
        "param": param,
        "type": type,
        "text": text,
        "use_address": use_address,
        "path": path,
        "category": category if category != "/" else "",
        "struct": struct,
        "enum": enum,
        "field": field,
        "new_type": new_type,
        "new_comment": new_comment,
        "source": source,
        "dest_category": dest_category,
        "code": code,
        "base_type": base_type,
        "return_type": return_type,
        "calling_convention": calling_convention,
    }

    for key, val in param_map.items():
        if val:
            body[key] = val

    # Handle special parameters
    if at != -1:
        body["at"] = at
    if value != 0:
        body["value"] = value
    if packing != 0:
        body["packing"] = packing
    if size != 4:
        body["size"] = size
    if category and category != "/":
        body["category"] = category

    # Handle JSON string parameters
    if fields:
        try:
            body["fields"] = json.loads(fields) if isinstance(fields, str) else fields
        except json.JSONDecodeError:
            body["fields"] = fields
    if members:
        try:
            body["members"] = json.loads(members) if isinstance(members, str) else members
        except json.JSONDecodeError:
            body["members"] = members
    if params:
        try:
            body["params"] = json.loads(params) if isinstance(params, str) else params
        except json.JSONDecodeError:
            body["params"] = params

    if verbose:
        body["verbose"] = True

    return v1_edit.edit(_ghidra_state, body)


def ghidra_basic_info() -> dict:
    """
    Get basic information about the loaded program.

    Returns program metadata including name, architecture, compiler,
    memory layout, and analysis statistics.

    Returns:
        dict with program information including:
            - name: Program name
            - path: File path
            - language: Processor architecture
            - compiler: Compiler specification
            - address_size: Address size in bits
            - image_base: Base address
            - memory_blocks: List of memory regions
            - function_count: Number of functions
            - symbol_count: Number of symbols
    """
    if _ghidra_state is None:
        return {"success": False, "error": "Ghidra state not available"}

    from api import basic_info
    return basic_info.basic_info(_ghidra_state)


def _register_mcp_tools():
    """Register all MCP tools on the global mcp instance."""
    if mcp is None:
        raise RuntimeError("MCP instance not created yet")

    mcp.tool()(ghidra_search)
    mcp.tool()(ghidra_view)
    mcp.tool()(ghidra_list)
    mcp.tool()(ghidra_edit)
    mcp.tool()(ghidra_basic_info)


# ============================================================
# MCP Server Management
# ============================================================

_mcp_thread: Optional[threading.Thread] = None
_mcp_actual_port: Optional[int] = None


def _is_port_available(host: str, port: int) -> bool:
    """Check if a port is available for binding."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def _find_available_port(host: str, start_port: int, max_attempts: int = 100) -> int:
    """Find an available port starting from start_port."""
    for offset in range(max_attempts):
        port = start_port + offset
        if _is_port_available(host, port):
            return port
    raise RuntimeError(f"No available port found after {max_attempts} attempts starting from {start_port}")


def start_mcp_sse_server(host: str = "127.0.0.1", port: int = 8804) -> Optional[int]:
    """
    Start the MCP SSE server in a daemon thread.

    Args:
        host: Hostname to bind to (default: "127.0.0.1")
        port: Port number (default: 8804)

    Returns:
        int: Actual port number if successful, None if failed
    """
    global _mcp_thread, _mcp_actual_port, mcp

    # Find an available port (similar to HTTP server logic)
    try:
        actual_port = _find_available_port(host, port)
    except RuntimeError as e:
        print(f"[Ghidra-MCP-Bridge] MCP server error: {e}")
        return None


    # Create FastMCP instance with correct settings
    mcp = _create_mcp_instance(host=host, port=actual_port)

    def run_server():
        try:
            import asyncio
            import uvicorn

            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Get the SSE Starlette app from FastMCP
            starlette_app = mcp.sse_app()

            # Use log_config=None to avoid Ghidrathon stream access issues
            config = uvicorn.Config(
                starlette_app,
                host=host,
                port=actual_port,
                log_config=None,  # Critical: disable logging config for Ghidrathon
                log_level="warning",
            )
            server = uvicorn.Server(config)
            loop.run_until_complete(server.serve())
        except BaseException:
            pass  # TODO: Thread logs need file output (Ghidrathon threads can't access console)

    _mcp_thread = threading.Thread(
        target=run_server,
        daemon=True,
        name="MCPServer"
    )
    _mcp_thread.start()
    _mcp_actual_port = actual_port
    return actual_port


def get_mcp_thread() -> Optional[threading.Thread]:
    """Get the MCP server thread."""
    return _mcp_thread


def get_mcp_port() -> Optional[int]:
    """Get the actual MCP server port."""
    return _mcp_actual_port
