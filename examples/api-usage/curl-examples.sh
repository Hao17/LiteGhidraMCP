#!/bin/bash
# Ghidra MCP Bridge - API Usage Examples
# This script demonstrates common API calls using curl

# Configuration
API_BASE="${GHIDRA_MCP_API:-http://localhost:8803}"

echo "========================================="
echo "Ghidra MCP Bridge - API Examples"
echo "API Base: $API_BASE"
echo "========================================="
echo

# Color output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

run_example() {
    echo -e "${BLUE}==> $1${NC}"
    echo -e "${GREEN}$ $2${NC}"
    eval $2
    echo
}

# -------------------- Basic Info --------------------
run_example "Get server status" \
    "curl -s '$API_BASE/api/status' | jq ."

run_example "Get program basic info" \
    "curl -s '$API_BASE/api/basic_info' | jq ."

# -------------------- Search API --------------------
echo "========== Search API =========="
echo

run_example "Search functions by name" \
    "curl -s '$API_BASE/api/search/functions?q=main&limit=10' | jq ."

run_example "Search symbols with wildcard" \
    "curl -s '$API_BASE/api/search/symbols?q=*printf*' | jq ."

run_example "Search strings" \
    "curl -s '$API_BASE/api/search/strings?q=error&limit=20' | jq ."

run_example "Search bytes pattern" \
    "curl -s '$API_BASE/api/search/bytes?pattern=48%208b%20??%2090&limit=20' | jq ."

run_example "Search instructions" \
    "curl -s '$API_BASE/api/search/instructions?q=call&limit=20' | jq ."

run_example "Search cross-references to address" \
    "curl -s '$API_BASE/api/search/xrefs/to?address=0x401000' | jq ."

# -------------------- View API --------------------
echo "========== View API =========="
echo

run_example "Decompile function by name" \
    "curl -s '$API_BASE/api/view/decompile?name=main' | jq ."

run_example "Decompile function by address" \
    "curl -s '$API_BASE/api/view/decompile?address=0x401000' | jq ."

run_example "Disassemble function" \
    "curl -s '$API_BASE/api/view/disassemble?name=main&limit=50' | jq ."

# -------------------- V1 API (Aggregated) --------------------
echo "========== V1 Aggregated API =========="
echo

run_example "V1 Search (auto type detection)" \
    "curl -s '$API_BASE/api/v1/search?q=main&limit=20' | jq ."

run_example "V1 View (batch queries)" \
    "curl -s '$API_BASE/api/v1/view?q=main,init&type=both' | jq ."

run_example "V1 List (symbol browsing)" \
    "curl -s '$API_BASE/api/v1/list?types=functions&limit=20' | jq ."

run_example "V1 Export data types as C header" \
    "curl -s '$API_BASE/api/v1/view?type=header' | jq -r '.data.header_code'"

# -------------------- Symbol Tree API --------------------
echo "========== Symbol Tree API =========="
echo

run_example "List namespaces" \
    "curl -s '$API_BASE/api/symbol_tree/namespaces' | jq ."

run_example "List functions" \
    "curl -s '$API_BASE/api/symbol_tree/functions?limit=20' | jq ."

run_example "Get function details" \
    "curl -s '$API_BASE/api/symbol_tree/function?name=main' | jq ."

run_example "List imports" \
    "curl -s '$API_BASE/api/symbol_tree/imports?library=kernel32' | jq ."

# -------------------- Edit API (POST) --------------------
echo "========== V1 Edit API (POST) =========="
echo

run_example "Rename function" \
    "curl -s -X POST '$API_BASE/api/v1/edit' \\
        -H 'Content-Type: application/json' \\
        -d '{\"action\": \"rename.function\", \"name\": \"FUN_00401000\", \"new_name\": \"main\"}' | jq ."

run_example "Set function return type" \
    "curl -s -X POST '$API_BASE/api/v1/edit' \\
        -H 'Content-Type: application/json' \\
        -d '{\"action\": \"datatype.set.return\", \"function\": \"main\", \"type\": \"int\"}' | jq ."

run_example "Set comment" \
    "curl -s -X POST '$API_BASE/api/v1/edit' \\
        -H 'Content-Type: application/json' \\
        -d '{\"action\": \"comment.set\", \"name\": \"main\", \"type\": \"PLATE\", \"text\": \"Main entry point\"}' | jq ."

run_example "Parse C code to create data type" \
    "curl -s -X POST '$API_BASE/api/v1/edit' \\
        -H 'Content-Type: application/json' \\
        -d '{\"action\": \"datatype.parse.c\", \"code\": \"typedef struct { int x; int y; } Point;\"}' | jq ."

run_example "Batch edit operations" \
    "curl -s -X POST '$API_BASE/api/v1/edit' \\
        -H 'Content-Type: application/json' \\
        -d '{\"actions\": [{\"action\": \"rename.function\", \"name\": \"FUN_00401000\", \"new_name\": \"main\"}, {\"action\": \"datatype.set.return\", \"function\": \"main\", \"type\": \"int\"}, {\"action\": \"comment.set\", \"name\": \"main\", \"type\": \"PLATE\", \"text\": \"Main entry\"}]}' | jq ."

# -------------------- Hot Reload --------------------
echo "========== Management API =========="
echo

run_example "Hot reload API modules" \
    "curl -s '$API_BASE/_reload' | jq ."

echo "========================================="
echo "All examples completed!"
echo "========================================="
