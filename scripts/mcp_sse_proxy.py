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


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
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


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
def ghidra_view(
    query: str = "",
    view_type: str = "both",
    timeout: int = 30,
    limit: int = 500,
    verbose: bool = False
) -> dict:
    """
    View decompiled code, disassembly, raw memory, or export data types as C header.

    Supports batch queries for multiple functions at once.

    Args:
        query: Function identifier(s), comma-separated for batch:
               - By name: "main", "init"
               - By address: "0x401000"
               - Batch: "main,init,0x401000"
               - For type=header: category path filter (default "/" for all)
               - For type=memory: start address (e.g., "0x611")
        view_type: What to return:
               - "both": Decompiled C code + assembly (default)
               - "decompile": Only decompiled C code
               - "disassemble": Only assembly instructions
               - "header": Export data types as C header format
               - "memory": Read raw bytes from address (query=address, limit=byte count)
        timeout: Decompilation timeout in seconds (default: 30)
        limit: Max assembly instructions per function (default: 500);
               for memory: number of bytes to read
        verbose: If True, return full dict format; if False, compact

    Returns:
        dict with:
            - success: bool
            - For functions: data.functions list with info, decompiled code, assembly
            - For header: data.header with C header content
    """
    params = f"q={query}&type={view_type}&timeout={timeout}&limit={limit}"
    if verbose:
        params += "&verbose=true"
    return _http_get(f"/api/v1/view?{params}")


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
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


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False})
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
    # Function signature parameter
    signature: str = "",
    # Comment parameters
    text: str = "",
    # C code for datatype.parse.c
    code: str = "",
    # Split variable parameter
    use_address: str = "",
    # Other parameters
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
            - "rename.function_signature": Modify function name, return type, calling convention,
              and parameters via C signature string (RECOMMENDED for function modifications)
            - "rename.variable": Rename a local variable (Listing level)
            - "rename.global": Rename a global variable
            - "rename.label": Rename a label
            - "rename.datatype": Rename a data type
            - "rename.namespace": Rename a namespace/class
            - "rename.decompiler.variable": Rename variable in decompiler view (recommended)
            - "rename.decompiler.split": Split a variable at specific use point

            DataType actions:
            - "datatype.parse.c": Parse C code to create types (struct/enum/typedef/union/funcdef)
            - "datatype.set.decompiler.variable": Set variable type in decompiler
            - "datatype.set.global": Set global variable type
            - "datatype.set.field": Set struct field type

            Comment actions:
            - "comment.set": Set or delete a comment

        name: Symbol/type name (for rename, datatype operations)
        address: Address in hex (e.g., "0x401000")
        new_name: New name for rename operations
        function: Function name for variable operations
        function_address: Function address (alternative to function name)
        type: Type string (e.g., "int", "char *", "MyStruct *")
        var_name: Variable name for variable operations
        signature: C function signature for rename.function_signature
                   (e.g., "int main(int argc, char **argv)")
                   Supports calling conventions: __stdcall, __cdecl, __fastcall, etc.
        text: Comment text (empty string to delete)
        code: C code for datatype.parse.c action
        use_address: Address for split variable operation
        timeout: Timeout for decompiler operations (default: 30)
        verbose: If True, return detailed input/output info

    Returns:
        dict with:
            - success: bool
            - For single action: action result
            - For batch: results array with individual outcomes

    Examples:
        ghidra_edit(action="rename.function_signature", function="FUN_00401000", signature="int main(int argc, char **argv)")
        ghidra_edit(action="rename.decompiler.variable", function="main", var_name="local_8", new_name="counter")
        ghidra_edit(action="comment.set", address="0x401000", type="EOL", text="Entry point")
        ghidra_edit(action="datatype.parse.c", code="typedef struct { int x; int y; } Point;")
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
    if signature:
        body["signature"] = signature
    if text:
        body["text"] = text
    if code:
        body["code"] = code
    if use_address:
        body["use_address"] = use_address
    if timeout != 30:
        body["timeout"] = timeout
    if verbose:
        body["verbose"] = True

    return _http_post("/api/v1/edit", body)


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
def ghidra_overview(
    verbose: bool = False,
    top_funcs: int = 20,
    top_strings: int = 30
) -> dict:
    """
    Get a comprehensive overview of the currently loaded binary.

    Recommended first call when starting analysis. Returns program metadata,
    memory layout, statistics, top functions by importance, imports grouped
    by library, exports, notable strings, and entry points — all in one call.

    Args:
        verbose: If True, return full dict format; if False, compact arrays
        top_funcs: Number of top functions to include (default: 20)
        top_strings: Number of notable strings to include (default: 30)

    Returns:
        dict with:
            - success: bool
            - data.metadata: name, format, processor, bits, endian, compiler, image_base
            - data.segments: memory segments [name, start, end, size, perms]
            - data.statistics: counts of functions, symbols, imports, exports, strings, classes
            - data.entry_points: [address, name] pairs
            - data.top_functions: [name, address, size, xref_count] sorted by importance
            - data.imports_by_library: [library, count, top_symbols] grouped by library
            - data.exports: [name, address, is_function]
            - data.notable_strings: [address, value, length] scored by information value
    """
    params = f"top_funcs={top_funcs}&top_strings={top_strings}"
    if verbose:
        params += "&verbose=true"
    return _http_get(f"/api/v1/overview?{params}")


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True})
def ghidra_exec(
    code: str,
    language: str = "python",
    readonly: bool = True,
    noanalysis: bool = True,
    timeout: int = 120,
) -> dict:
    """Execute a script in Ghidra with full API access.

    Supports Python and Java scripts. In GUI mode, runs via runScript()
    in the current session. In headless mode, launches a separate Ghidra
    process for isolated execution.

    Python scripts have access to all Ghidra Flat API functions:
        currentProgram(), toAddr(), getFunctionAt(), getReferencesTo(),
        monitor(), getBytes(), and all Java class imports.
        Set `result` variable to return structured data.
        Use print() for text output (captured in 'stdout').

    Java scripts: provide the run() method body. Has access to all
        GhidraScript methods. Use println() for output.

    Args:
        code: Script source code to execute.
              Python: arbitrary code with Flat API access.
              Java: body of the run() method (extends GhidraScript).
        language: "python" (default) or "java"
        readonly: If True (default), program is opened read-only (headless mode).
                  Prevents accidental modifications. Set False to allow writes.
        noanalysis: If True (default), skip auto-analysis for faster execution.
        timeout: Max execution time in seconds (default: 120)

    Returns:
        result: Value of 'result' variable (Python) or null
        stdout: Captured print/println output
        success: Whether execution succeeded
        error/traceback: Error details on failure
        mode: "gui" or "headless"

    Examples:
        # Count functions
        code: "result = currentProgram().getFunctionManager().getFunctionCount()"

        # List function names
        code: "fm = currentProgram().getFunctionManager()\\nfor f in fm.getFunctions(True):\\n    print(f.getName())"

        # Batch rename with write access
        code: "...", readonly: false
    """
    body = {
        "code": code,
        "language": language,
        "readonly": readonly,
        "noanalysis": noanalysis,
        "timeout": timeout,
    }
    return _http_post("/api/v1/exec", body, timeout=float(timeout) + 10)


# ============================================================
# Conditional Tools (registered at startup based on capabilities)
# ============================================================

def _check_version_support() -> bool:
    """Check if Ghidra server supports version control."""
    result = _http_get("/api/version/log", timeout=2.0)
    return result.get("success", False)


def _register_version_tool():
    """Conditionally register ghidra_version tool if server supports it."""
    if not _check_version_support():
        return False

    @mcp.tool()
    def ghidra_version(
        action: str,
        comment: str = "",
        version: int = 0,
        diff: int = 0,
        limit: int = 50,
    ) -> dict:
        """
        Version control operations (commit, log, rollback, revert).

        Only available when the program is in a shared Ghidra Server project.
        Provides git-like version management for collaborative reverse engineering.

        Args:
            action: Operation to perform:
                - "log": Show version history (optionally with diff)
                - "commit": Save and checkin changes to server
                - "rollback": Discard uncommitted local changes, revert to last commit
                - "revert": Permanently delete versions after N, go back to version N (DESTRUCTIVE)
            comment: Commit message (for "commit" action)
            version: Target version number (for "revert" action, required)
            diff: Compare with version N (for "log" action, 0=no diff)
            limit: Max log entries or diff items (default: 50)

        Returns:
            dict with:
                - success: bool
                - For log: versions list, current_version, is_checked_out
                - For log+diff: additional diff.changes list
                - For commit: action, comment, version
                  - error_code "merge_required": server has newer version, rollback and re-apply needed
                  - error_code "checkout_conflict": another user holds exclusive checkout
                - For rollback: action, program name
                - For revert: target_version, deleted_versions list
        """
        from urllib.parse import quote
        if action == "log":
            params = f"limit={limit}"
            if diff > 0:
                params += f"&diff={diff}"
            return _http_get(f"/api/version/log?{params}")
        elif action == "commit":
            return _http_get(f"/api/version/commit?comment={quote(comment)}")
        elif action == "rollback":
            return _http_get("/api/version/rollback")
        elif action == "revert":
            return _http_get(f"/api/version/revert?version={version}")
        else:
            return {"success": False, "error": f"Unknown action: {action}. Use: log, commit, rollback, revert"}

    return True


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
    # Register conditional tools
    if _register_version_tool():
        print("  Version control: enabled (ghidra_version tool registered)")
    else:
        print("  Version control: not available (non-server mode)")

    print(f"Starting MCP SSE server on http://{args.host}:{args.port}/sse")
    print(f"Press Ctrl+C to stop")

    # Update FastMCP settings
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    # Run the SSE server
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
