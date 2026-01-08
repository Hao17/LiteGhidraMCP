#!/usr/bin/env python3
"""
MCP and HTTP API test script for Ghidra Bridge.

Tests MCP SSE server connection and/or HTTP API endpoints.

Usage:
    python test_mcp.py [--host HOST] [--port PORT] [--http-port HTTP_PORT] [--mode MODE]

Modes:
    both  - Test both MCP SSE and HTTP API (default)
    mcp   - Test only MCP SSE
    http  - Test only HTTP API

Requirements:
    pip install mcp httpx

Known Issues (2026-01-08):
    - MCP SSE: Connection and initialization succeed, but list_tools times out.
      Possible causes:
      1. uvicorn SSE responses may be buffered in daemon thread
      2. FastMCP SSE implementation may not be compatible with Ghidrathon thread environment
      3. asyncio event loop limitations in sub-threads

      The MCP server runs in a daemon thread (mcp_v1/server.py:525-530),
      and tool responses may not be properly sent back through SSE stream.

      Workaround: Use stdio mode (mcp_stdio.py) which proxies through HTTP API.
"""

import argparse
import asyncio
import json
import os
import socket
import sys
import urllib.request
import urllib.error


def disable_proxy_for_localhost():
    """Clear proxy env vars for localhost connections."""
    proxy_vars = [
        'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
        'http_proxy', 'https_proxy', 'all_proxy',
        'SOCKS_PROXY', 'socks_proxy'
    ]
    for var in proxy_vars:
        if var in os.environ:
            del os.environ[var]
    os.environ['NO_PROXY'] = '127.0.0.1,localhost,::1'
    os.environ['no_proxy'] = '127.0.0.1,localhost,::1'


def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Quick check if port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def test_http_api(host: str, port: int) -> bool:
    """Test HTTP API endpoints."""
    print(f"\n{'=' * 50}")
    print("HTTP API Test")
    print(f"{'=' * 50}")

    base_url = f"http://{host}:{port}"

    if not check_port_open(host, port):
        print(f"Error: No server on {host}:{port}")
        return False

    print(f"Server: {base_url}")

    # Test basic_info
    print("\n[1] Testing /api/basic_info...")
    try:
        with urllib.request.urlopen(f"{base_url}/api/basic_info", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success"):
                print(f"    Program: {data.get('name', 'N/A')}")
                print(f"    Language: {data.get('language', 'N/A')}")
                print(f"    Functions: {data.get('function_count', 'N/A')}")
            else:
                print(f"    Error: {data.get('error')}")
                return False
    except Exception as e:
        print(f"    Failed: {e}")
        return False

    # Test v1/list
    print("\n[2] Testing /api/v1/list...")
    try:
        with urllib.request.urlopen(f"{base_url}/api/v1/list?limit=5", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success"):
                summary = data.get("summary", {})
                print(f"    Found: {summary}")
            else:
                print(f"    Error: {data.get('error')}")
    except Exception as e:
        print(f"    Failed: {e}")

    # Test v1/search
    print("\n[3] Testing /api/v1/search?q=main...")
    try:
        with urllib.request.urlopen(f"{base_url}/api/v1/search?q=main&limit=3", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success"):
                summary = data.get("summary", {})
                print(f"    Results: {summary}")
            else:
                print(f"    Error: {data.get('error')}")
    except Exception as e:
        print(f"    Failed: {e}")

    print(f"\n{'=' * 50}")
    print("HTTP API: OK")
    print(f"{'=' * 50}")
    return True


async def test_mcp_sse(host: str, port: int) -> bool:
    """Test MCP SSE server connection."""
    print(f"\n{'=' * 50}")
    print("MCP SSE Test")
    print(f"{'=' * 50}")

    if host in ('127.0.0.1', 'localhost', '::1'):
        disable_proxy_for_localhost()

    from mcp import ClientSession
    from mcp.client.sse import sse_client

    sse_url = f"http://{host}:{port}/sse"

    if not check_port_open(host, port):
        print(f"Error: No server on {host}:{port}")
        return False

    print(f"SSE URL: {sse_url}")
    print("Connecting...")

    try:
        async with sse_client(sse_url, timeout=10.0, sse_read_timeout=30.0) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("Connected!")

                # List tools with timeout
                print("\nListing tools...")
                try:
                    tools_result = await asyncio.wait_for(
                        session.list_tools(),
                        timeout=15.0
                    )
                    tools = tools_result.tools

                    print(f"\nAvailable tools ({len(tools)}):")
                    for tool in tools:
                        print(f"  - {tool.name}")

                    # Test a tool
                    if any(t.name == "ghidra_basic_info" for t in tools):
                        print("\nCalling ghidra_basic_info...")
                        result = await asyncio.wait_for(
                            session.call_tool("ghidra_basic_info", {}),
                            timeout=15.0
                        )
                        if result.content:
                            for item in result.content:
                                if hasattr(item, 'text'):
                                    data = json.loads(item.text)
                                    if data.get("success"):
                                        print(f"  Program: {data.get('name')}")
                                        print(f"  Functions: {data.get('function_count')}")

                except asyncio.TimeoutError:
                    print("  Timeout waiting for response")
                    print("  (Server may not be sending keep-alive events)")
                    return False

                print(f"\n{'=' * 50}")
                print("MCP SSE: OK")
                print(f"{'=' * 50}")
                return True

    except ExceptionGroup as eg:
        print(f"\nConnection errors:")
        for exc in eg.exceptions:
            exc_name = type(exc).__name__
            if "Timeout" in exc_name:
                print(f"  - Read timeout (server may lack keep-alive)")
            else:
                print(f"  - {exc_name}: {exc}")
        return False
    except Exception as e:
        print(f"\nError: {type(e).__name__}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test Ghidra MCP Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python test_mcp.py                           # Test both (SSE:8804, HTTP:8803)
    python test_mcp.py --port 8869               # Custom SSE port
    python test_mcp.py --mode http               # HTTP only
    python test_mcp.py --mode mcp --port 8869    # MCP only
"""
    )
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=8804, help="MCP SSE port (default: 8804)")
    parser.add_argument("--http-port", type=int, default=8803, help="HTTP API port (default: 8803)")
    parser.add_argument("--mode", choices=["both", "mcp", "http"], default="both",
                        help="Test mode: both, mcp, or http (default: both)")
    args = parser.parse_args()

    if args.host in ('127.0.0.1', 'localhost', '::1'):
        disable_proxy_for_localhost()

    print("Ghidra MCP Bridge Test")
    print("=" * 50)

    results = {}

    if args.mode in ("both", "http"):
        results["http"] = test_http_api(args.host, args.http_port)

    if args.mode in ("both", "mcp"):
        results["mcp"] = asyncio.run(test_mcp_sse(args.host, args.port))

    # Summary
    print(f"\n{'=' * 50}")
    print("Summary")
    print(f"{'=' * 50}")
    for name, ok in results.items():
        status = "PASS" if ok else "FAIL"
        print(f"  {name.upper()}: {status}")

    success = all(results.values())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
