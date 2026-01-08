#!/usr/bin/env python3
"""
MCP SSE Proxy Server - Independent process that proxies MCP requests to Ghidra HTTP API.

This script runs as a standalone process (outside Ghidra) and provides MCP SSE transport.
All Ghidra operations are proxied through the HTTP API, avoiding Ghidrathon thread issues.

Architecture:
    Claude Desktop <--SSE--> mcp_sse_proxy.py <--HTTP--> Ghidra Bridge (HTTP Server)

Usage:
    python mcp_sse_proxy.py [--host HOST] [--port PORT] [--ghidra-port GHIDRA_PORT]

    --host: SSE server bind address (default: 127.0.0.1)
    --port: SSE server port (default: 8804)
    --ghidra-port: Ghidra HTTP API port (default: 8803)

Claude Desktop Configuration:
    {
        "mcpServers": {
            "ghidra": {
                "url": "http://127.0.0.1:8804/sse"
            }
        }
    }

Requirements:
    pip install mcp uvicorn httpx
"""

import argparse
import json
import sys
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from mcp.server.fastmcp import FastMCP

# ============================================================
# Configuration
# ============================================================

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8804
DEFAULT_GHIDRA_PORT = 8803

_ghidra_host = DEFAULT_HOST
_ghidra_port = DEFAULT_GHIDRA_PORT


def _ghidra_url(path: str) -> str:
    """Build Ghidra HTTP API URL."""
    return f"http://{_ghidra_host}:{_ghidra_port}{path}"


def _http_get(path: str, timeout: float = 30.0) -> dict:
    """Make HTTP GET request to Ghidra API."""
    try:
        url = _ghidra_url(path)
        with urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        return {"success": False, "error": f"Connection failed: {e}"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON response: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _http_post(path: str, body: dict, timeout: float = 30.0) -> dict:
    """Make HTTP POST request to Ghidra API."""
    try:
        url = _ghidra_url(path)
        data = json.dumps(body).encode("utf-8")
        req = Request(url, data=data, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        return {"success": False, "error": f"Connection failed: {e}"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON response: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _check_ghidra_connection() -> bool:
    """Check if Ghidra HTTP API is accessible."""
    result = _http_get("/api/basic_info", timeout=2.0)
    return result.get("success", False)


# ============================================================
# MCP Server Setup
# ============================================================

mcp = FastMCP(name="Ghidra-MCP-Bridge")


@mcp.tool()
def ghidra_search(
    query: str,
    types: str = "auto",
    limit: int = 20,
    verbose: bool = False
) -> dict:
    """
    Search the loaded binary for functions, symbols, strings, etc.

    This is a unified search tool that supports multiple search types
    with intelligent type inference based on the query pattern.

    Args:
        query: Search query (supports wildcards * and ?)
               - Function/symbol names: "main", "*init*", "str*"
               - Addresses: "0x401000" (searches xrefs)
               - Hex bytes: "48 8b ??" (byte pattern search)
        types: Search types, comma-separated or special values:
               - "auto": Smart detection based on query (default)
               - "all": Search all types
               - Specific: "functions", "symbols", "strings", "xrefs",
                          "bytes", "instructions", "comments", "datatypes"
        limit: Maximum results per type (default: 20)
        verbose: If True, return full dict format; if False, compact arrays

    Returns:
        dict with:
            - success: bool
            - data.query: the search query
            - data.types_searched: list of types that were searched
            - data.summary: count per type
            - data.results: matched items per type
            - data._schema: field names for compact mode
    """
    params = f"q={query}&types={types}&limit={limit}"
    if verbose:
        params += "&verbose=true"
    return _http_get(f"/api/v1/search?{params}")


@mcp.tool()
def ghidra_view(
    query: str,
    view_type: str = "both",
    timeout: int = 30,
    limit: int = 500,
    verbose: bool = False
) -> dict:
    """
    View decompiled code and/or disassembly for functions.

    Supports batch queries for multiple functions at once.

    Args:
        query: Function identifier(s), comma-separated for batch:
               - By name: "main", "init"
               - By address: "0x401000"
               - Batch: "main,init,0x401000"
        view_type: What to return:
               - "both": Decompiled C code + assembly (default)
               - "decompile": Only decompiled C code
               - "disassemble": Only assembly instructions
        timeout: Decompilation timeout in seconds (default: 30)
        limit: Max assembly instructions per function (default: 500)
        verbose: If True, return full dict format; if False, compact

    Returns:
        dict with:
            - success: bool
            - data.functions: list of function results
            - For each function: info (name, address, signature, size),
              decompiled code lines, assembly instructions
    """
    params = f"q={query}&type={view_type}&timeout={timeout}&limit={limit}"
    if verbose:
        params += "&verbose=true"
    return _http_get(f"/api/v1/view?{params}")


@mcp.tool()
def ghidra_list(
    query: str = "",
    types: str = "auto",
    start: str = "",
    end: str = "",
    namespace: str = "",
    library: str = "",
    limit: int = 100,
    verbose: bool = False
) -> dict:
    """
    List symbols in the binary (like 'ls' for the symbol tree).

    Provides a browsable view of functions, classes, imports, exports, etc.

    Args:
        query: Optional name filter (supports wildcards * and ?)
               Examples: "init*", "*handler*", "FUN_*"
        types: What to list, comma-separated or special values:
               - "auto": functions (default)
               - "all": all symbol types
               - Specific: "functions", "classes", "namespaces", "labels",
                          "globals", "imports", "exports", "datatypes"
        start: Start address for range filter (e.g., "0x401000")
        end: End address for range filter (e.g., "0x402000")
        namespace: Filter by namespace (e.g., "std", "MyClass")
        library: Filter imports by library name (e.g., "kernel32", "libc")
        limit: Maximum results per type (default: 100)
        verbose: If True, return full dict format; if False, compact

    Returns:
        dict with:
            - success: bool
            - data.query: filter query if provided
            - data.types_listed: list of types that were listed
            - data.summary: count per type
            - data.results: items per type with relevant fields
    """
    params = f"limit={limit}"
    if query:
        params += f"&q={query}"
    if types != "auto":
        params += f"&types={types}"
    if start:
        params += f"&start={start}"
    if end:
        params += f"&end={end}"
    if namespace:
        params += f"&namespace={namespace}"
    if library:
        params += f"&library={library}"
    if verbose:
        params += "&verbose=true"
    return _http_get(f"/api/v1/list?{params}")


@mcp.tool()
def ghidra_edit(
    action: str,
    # Common parameters
    name: str = "",
    address: str = "",
    new_name: str = "",
    function: str = "",
    function_address: str = "",
    # Type-related parameters
    type: str = "",
    var_name: str = "",
    param: str = "",
    # Comment parameters
    text: str = "",
    # DataType creation parameters
    fields: str = "",
    members: str = "",
    base_type: str = "",
    return_type: str = "",
    params_json: str = "",
    category: str = "/",
    # Other parameters
    use_address: str = "",
    timeout: int = 30,
    verbose: bool = False
) -> dict:
    """
    Edit symbols, types, and comments in the binary.

    This unified edit tool supports renaming, type changes, and comments.
    All changes are persisted to the Ghidra project.

    Args:
        action: The edit action to perform. Available actions:
            Rename actions:
            - "rename.function": Rename a function
            - "rename.variable": Rename a local variable (Listing level)
            - "rename.parameter": Rename a function parameter (Listing level)
            - "rename.global": Rename a global variable
            - "rename.label": Rename a label
            - "rename.datatype": Rename a data type
            - "rename.namespace": Rename a namespace/class
            - "rename.decompiler.variable": Rename variable in decompiler view (recommended)
            - "rename.decompiler.parameter": Rename parameter in decompiler view
            - "rename.decompiler.split": Split a variable at specific use point

            DataType set actions:
            - "datatype.set.return": Set function return type
            - "datatype.set.parameter": Set function parameter type
            - "datatype.set.decompiler.variable": Set variable type in decompiler
            - "datatype.set.decompiler.parameter": Set parameter type in decompiler
            - "datatype.set.global": Set global variable type
            - "datatype.set.field": Set struct field type

            DataType create actions:
            - "datatype.create.struct": Create a new struct
            - "datatype.create.enum": Create a new enum
            - "datatype.create.typedef": Create a typedef alias
            - "datatype.create.union": Create a union type
            - "datatype.create.funcdef": Create a function pointer type

            DataType management:
            - "datatype.struct.field.add": Add field to struct
            - "datatype.struct.field.delete": Delete field from struct
            - "datatype.struct.field.modify": Modify struct field
            - "datatype.enum.member.add": Add enum member
            - "datatype.enum.member.delete": Delete enum member
            - "datatype.delete": Delete a data type
            - "datatype.parse.c": Parse C code to create types

            Comment actions:
            - "comment.set": Set or delete a comment

        name: Symbol/type name (for rename, datatype operations)
        address: Address in hex (e.g., "0x401000")
        new_name: New name for rename operations
        function: Function name for variable/parameter operations
        function_address: Function address (alternative to function name)
        type: Type string (e.g., "int", "char *", "MyStruct *")
        var_name: Variable name for variable operations
        param: Parameter index (0-based) or name
        text: Comment text (empty string to delete)
        fields: JSON array for struct fields: [{"name": "x", "type": "int"}]
        members: JSON for enum members: {"OK": 0, "ERROR": 1}
        base_type: Base type for typedef
        return_type: Return type for function definitions
        params_json: JSON array of parameters for function definitions
        category: Category path for new types (default: "/")
        use_address: Address for split variable operation
        timeout: Timeout for decompiler operations (default: 30)
        verbose: If True, return detailed input/output info

    Returns:
        dict with:
            - success: bool
            - For single action: action result
            - For batch: results array with individual outcomes

    Examples:
        ghidra_edit(action="rename.function", name="FUN_00401000", new_name="main")
        ghidra_edit(action="datatype.set.return", function="main", type="int")
        ghidra_edit(action="rename.decompiler.variable", function="main", var_name="local_8", new_name="counter")
        ghidra_edit(action="comment.set", address="0x401000", type="EOL", text="Entry point")
        ghidra_edit(action="datatype.create.struct", name="Point", fields='[{"name":"x","type":"int"},{"name":"y","type":"int"}]')
    """
    body = {"action": action}

    # Add non-empty parameters
    if name:
        body["name"] = name
    if address:
        body["address"] = address
    if new_name:
        body["new_name"] = new_name
    if function:
        body["function"] = function
    if function_address:
        body["function_address"] = function_address
    if type:
        body["type"] = type
    if var_name:
        body["var_name"] = var_name
    if param:
        body["param"] = param
    if text:
        body["text"] = text
    if fields:
        body["fields"] = fields
    if members:
        body["members"] = members
    if base_type:
        body["base_type"] = base_type
    if return_type:
        body["return_type"] = return_type
    if params_json:
        body["params"] = params_json
    if category != "/":
        body["category"] = category
    if use_address:
        body["use_address"] = use_address
    if timeout != 30:
        body["timeout"] = timeout
    if verbose:
        body["verbose"] = True

    return _http_post("/api/v1/edit", body)


@mcp.tool()
def ghidra_basic_info() -> dict:
    """
    Get basic information about the currently loaded program.

    Returns program name, architecture, language, entry points,
    memory layout, and analysis statistics.

    Returns:
        dict with:
            - success: bool
            - name: Program name
            - path: File path
            - language: Architecture info (processor, size, endian)
            - compiler: Compiler specification
            - entry_points: List of entry point addresses
            - memory: Memory block summary
            - function_count: Number of functions
            - symbol_count: Number of symbols
    """
    return _http_get("/api/basic_info")


# ============================================================
# Main Entry Point
# ============================================================

def main():
    global _ghidra_host, _ghidra_port

    parser = argparse.ArgumentParser(
        description="MCP SSE Proxy for Ghidra Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This proxy runs as an independent process and forwards MCP requests
to the Ghidra HTTP API, avoiding Ghidrathon thread limitations.

Examples:
    python mcp_sse_proxy.py                          # Default ports
    python mcp_sse_proxy.py --port 8810              # Custom SSE port
    python mcp_sse_proxy.py --ghidra-port 8805       # Custom Ghidra port
"""
    )
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"SSE server bind address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"SSE server port (default: {DEFAULT_PORT})")
    parser.add_argument("--ghidra-host", default=DEFAULT_HOST,
                        help=f"Ghidra HTTP API host (default: {DEFAULT_HOST})")
    parser.add_argument("--ghidra-port", type=int, default=DEFAULT_GHIDRA_PORT,
                        help=f"Ghidra HTTP API port (default: {DEFAULT_GHIDRA_PORT})")
    args = parser.parse_args()

    _ghidra_host = args.ghidra_host
    _ghidra_port = args.ghidra_port

    # Check Ghidra connection with retries
    print(f"Connecting to Ghidra at http://{_ghidra_host}:{_ghidra_port}...", end="", flush=True)
    max_retries = 10
    for attempt in range(max_retries):
        if _check_ghidra_connection():
            print(" OK")
            break
        print(".", end="", flush=True)
        import time
        time.sleep(0.5)
    else:
        print(" FAILED")
        print(f"Error: Cannot connect to Ghidra HTTP API after {max_retries} attempts")
        print(f"Make sure Ghidra Bridge is running on port {_ghidra_port}")
        sys.exit(1)
    print(f"Starting MCP SSE server on http://{args.host}:{args.port}/sse")
    print(f"Press Ctrl+C to stop")

    # Update FastMCP settings
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    # Run the SSE server
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
