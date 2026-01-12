#!/usr/bin/env python3
"""
MCP stdio server for Claude Desktop debugging.

This is a standalone process that proxies MCP tool calls to Ghidra HTTP API.

Usage:
    python mcp_stdio.py [--host HOST] [--port PORT]

Claude Desktop config:
    {
      "mcpServers": {
        "ghidra": {
          "command": "python",
          "args": ["/path/to/mcp_stdio.py", "--port", "8803"]
        }
      }
    }
"""

import argparse
import json
import urllib.request
import urllib.error
from mcp.server.fastmcp import FastMCP

# Default Ghidra Bridge connection
GHIDRA_HOST = "127.0.0.1"
GHIDRA_PORT = 8803

mcp = FastMCP(name="Ghidra-MCP-Bridge")


def _call_api(path: str, method: str = "GET", body: dict = None) -> dict:
    """Call Ghidra HTTP API."""
    url = f"http://{GHIDRA_HOST}:{GHIDRA_PORT}{path}"
    try:
        if method == "POST" and body:
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
        else:
            req = urllib.request.Request(url)

        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        return {"success": False, "error": f"Connection failed: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def ghidra_search(
    query: str,
    types: str = "auto",
    limit: int = 20,
    verbose: bool = False
) -> dict:
    """
    Search the loaded binary for functions, symbols, strings, etc.

    Args:
        query: Search query (e.g., "main", "0x401000", "*init*", "48 8b ??")
        types: "auto", "all", or comma-separated list
        limit: Maximum results per type
        verbose: Return full dict format if True
    """
    params = f"q={urllib.parse.quote(query)}&types={types}&limit={limit}"
    if verbose:
        params += "&verbose=true"
    return _call_api(f"/api/v1/search?{params}")


@mcp.tool()
def ghidra_view(
    query: str = "",
    view_type: str = "both",
    timeout: int = 30,
    limit: int = 500,
    verbose: bool = False
) -> dict:
    """
    View decompiled code, disassembly, or export data types as C header.

    Args:
        query: Function name or address (e.g., "main", "0x401000")
               For type=header: category path filter (default "/" for all)
        view_type: "both", "decompile", "disassemble", or "header"
        timeout: Decompilation timeout in seconds
        limit: Maximum instructions for disassembly
        verbose: Return full dict format if True
    """
    params = f"q={urllib.parse.quote(query)}&type={view_type}&timeout={timeout}&limit={limit}"
    if verbose:
        params += "&verbose=true"
    return _call_api(f"/api/v1/view?{params}")


@mcp.tool()
def ghidra_list(
    query: str = "",
    types: str = "auto",
    start: str = "",
    end: str = "",
    library: str = "",
    limit: int = 100,
    verbose: bool = False
) -> dict:
    """
    List symbols in the binary (like ls command).

    Args:
        query: Name filter pattern (supports wildcards)
        types: "auto", "all", or comma-separated (functions,classes,imports,exports,etc.)
        start: Start address for range filter
        end: End address for range filter
        library: Filter imports by library name
        limit: Maximum results per type
        verbose: Return full dict format if True
    """
    params = f"types={types}&limit={limit}"
    if query:
        params += f"&q={urllib.parse.quote(query)}"
    if start:
        params += f"&start={start}"
    if end:
        params += f"&end={end}"
    if library:
        params += f"&library={urllib.parse.quote(library)}"
    if verbose:
        params += "&verbose=true"
    return _call_api(f"/api/v1/list?{params}")


@mcp.tool()
def ghidra_edit(
    action: str,
    name: str = "",
    address: str = "",
    new_name: str = "",
    function: str = "",
    function_address: str = "",
    var_name: str = "",
    type: str = "",
    signature: str = "",
    text: str = "",
    code: str = "",
    use_address: str = "",
    timeout: int = 30,
    verbose: bool = False
) -> dict:
    """
    Edit the binary (rename, set types, add comments).

    Args:
        action: Operation to perform. Available actions:
            Rename:
            - "rename.function_signature": Modify function via C signature (RECOMMENDED)
            - "rename.variable", "rename.global", "rename.label"
            - "rename.datatype", "rename.namespace"
            - "rename.decompiler.variable", "rename.decompiler.split"
            DataType:
            - "datatype.parse.c": Create types from C code
            - "datatype.set.decompiler.variable", "datatype.set.global", "datatype.set.field"
            Comment:
            - "comment.set"
        name: Symbol name (for rename operations)
        address: Address (hex string like "0x401000")
        new_name: New name for rename operations
        function: Function name for variable operations
        function_address: Function address (alternative to function name)
        var_name: Variable name
        type: Data type string
        signature: C function signature for rename.function_signature
                   (e.g., "int main(int argc, char **argv)")
        text: Comment text
        code: C code for datatype.parse.c
        use_address: Address for split variable operation
        timeout: Timeout for decompiler operations
        verbose: Include input params in response
    """
    body = {"action": action}
    if name: body["name"] = name
    if address: body["address"] = address
    if new_name: body["new_name"] = new_name
    if function: body["function"] = function
    if function_address: body["function_address"] = function_address
    if var_name: body["var_name"] = var_name
    if type: body["type"] = type
    if signature: body["signature"] = signature
    if text: body["text"] = text
    if code: body["code"] = code
    if use_address: body["use_address"] = use_address
    if timeout != 30: body["timeout"] = timeout
    if verbose: body["verbose"] = True

    return _call_api("/api/v1/edit", method="POST", body=body)


@mcp.tool()
def ghidra_basic_info() -> dict:
    """Get basic information about the loaded program."""
    return _call_api("/api/basic_info")


if __name__ == "__main__":
    import urllib.parse

    parser = argparse.ArgumentParser(description="MCP stdio server for Ghidra")
    parser.add_argument("--host", default="127.0.0.1", help="Ghidra Bridge host")
    parser.add_argument("--port", type=int, default=8803, help="Ghidra Bridge port")
    args = parser.parse_args()

    GHIDRA_HOST = args.host
    GHIDRA_PORT = args.port

    mcp.run(transport="stdio")
