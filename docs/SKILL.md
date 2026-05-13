# Ghidra MCP Bridge — Usage Skill

This document teaches AI assistants how to effectively use the Ghidra MCP tools for binary analysis. Install it as context for your AI client.

---

## Analysis Workflow

### Step 1: Overview First

Always start with `ghidra_overview` to understand the binary before diving in.

```
ghidra_overview()
```

This returns: metadata (format, arch, bits), memory segments, function/string/import counts, top functions by xref importance, imports grouped by library, exports, and notable strings. Use this to form your analysis plan.

### Step 2: Search for Targets

Use `ghidra_search` with smart type inference — the `types="auto"` default detects what you're looking for:

```
ghidra_search(query="main")              # Finds functions/symbols named "main"
ghidra_search(query="0x401000")          # Finds xrefs to/from this address
ghidra_search(query="48 8b ?? 90")       # Byte pattern search (wildcards: ??)
ghidra_search(query="password")          # Finds in functions + symbols + strings
ghidra_search(query="*init*")            # Wildcard search across types
ghidra_search(query="AES", types="strings")  # Force specific type
```

### Step 3: Read Code

Use `ghidra_view` to decompile/disassemble. Batch multiple functions in one call:

```
ghidra_view(query="main")                         # Decompile + disassemble
ghidra_view(query="main,init,0x401000")           # Batch: 3 functions at once
ghidra_view(query="main", view_type="decompile")  # Decompile only (faster)
ghidra_view(query="0x611", view_type="memory", limit=256)  # Raw bytes
ghidra_view(view_type="header")                   # Export all types as C header
```

### Step 4: Browse Symbols

Use `ghidra_list` to explore the symbol tree — like `ls` for binaries:

```
ghidra_list()                                  # List all functions (default)
ghidra_list(types="imports", library="libc")   # libc imports only
ghidra_list(types="classes")                   # List all classes
ghidra_list(query="*handler*")                 # Wildcard filter
ghidra_list(start="0x401000", end="0x402000")  # Functions in address range
ghidra_list(types="all")                       # Everything: functions, classes, imports, exports...
```

### Step 5: Annotate

Use `ghidra_edit` for renaming, typing, and commenting. Prefer function signature for comprehensive changes:

```
# Rename via full C signature (name + return type + params in one shot)
ghidra_edit(action="rename.function_signature",
            function="FUN_00401000",
            signature="int main(int argc, char **argv)")

# Rename decompiler variable (what you see in decompiled code)
ghidra_edit(action="rename.decompiler.variable",
            function="main", var_name="local_8", new_name="counter")

# Set variable type
ghidra_edit(action="datatype.set.decompiler.variable",
            function="main", var_name="counter", type="uint32_t")

# Add comment
ghidra_edit(action="comment.set",
            address="0x401000", type="PLATE", text="Program entry point")

# Create struct from C code
ghidra_edit(action="datatype.parse.c",
            code="typedef struct { int x; int y; } Point;")
```

### Step 6: Custom Scripts (Advanced)

Use `ghidra_exec` for anything the built-in tools don't cover:

```
# Count functions
ghidra_exec(code="result = currentProgram().getFunctionManager().getFunctionCount()")

# Write operations need readonly=False
ghidra_exec(code="...", readonly=False)
```

---

## Tips & Patterns

### Efficient Batch Operations

- **Batch view**: comma-separate queries — `ghidra_view(query="funcA,funcB,funcC")` is 1 call instead of 3
- **Batch edit**: use multiple `ghidra_edit` calls for different actions (rename, type, comment) on the same function

### Naming Conventions for `ghidra_edit`

| Action | Required params | Notes |
|--------|----------------|-------|
| `rename.function_signature` | `function` + `signature` | Best for functions — sets name, return type, params at once |
| `rename.decompiler.variable` | `function` + `var_name` + `new_name` | Use this, NOT `rename.variable` |
| `datatype.set.decompiler.variable` | `function` + `var_name` + `type` | Use this, NOT `datatype.set.variable` |
| `datatype.parse.c` | `code` | Supports struct/enum/typedef/union |
| `comment.set` | `address` + `type` + `text` | Types: EOL, PRE, POST, PLATE, REPEATABLE |

### Decompiler-level vs Listing-level

Always prefer `decompiler.*` actions over plain `rename.variable` / `rename.parameter`. The decompiler may merge multiple low-level variables into one logical variable — listing-level renames can silently fail.

### Search Strategy

1. Know the name? → `ghidra_search(query="exact_name")`
2. Know a pattern? → `ghidra_search(query="*pattern*")`
3. Know an address? → `ghidra_search(query="0xADDR")` for xrefs
4. Looking for strings? → `ghidra_search(query="keyword", types="strings")`
5. Looking for byte patterns? → `ghidra_search(query="48 89 5c ?? 08")`

### Common Analysis Patterns

**Top-down**: `overview` → pick interesting functions from `top_functions` → `view` each → follow xrefs with `search`

**String-based**: `overview` → scan `notable_strings` → `search` xrefs to interesting strings → `view` referencing functions

**Import-driven**: `list(types="imports")` → identify crypto/network/file APIs → `search` xrefs to them → `view` callers

**Address range**: `list(start="0x401000", end="0x402000")` → enumerate functions in a code section → `view` each

### Version Control (Server Mode Only)

```
ghidra_version(action="log")            # View history
ghidra_version(action="log", diff=3)    # Diff against version 3
ghidra_version(action="rollback")       # Undo last change
ghidra_version(action="revert", version=5)  # Go back to version 5 (destructive!)
```

Write operations auto-commit — no manual commit needed.

---

## Service Discovery

Before analysis, discover running clients and their binaries:

```bash
gmcp status --json
```

Returns:
```json
{
  "server": {"running": true, "port": 13100},
  "clients": [
    {
      "id": 1, "http_port": 8803, "sse_port": 8804,
      "mcp_url": "http://127.0.0.1:8804/sse",
      "program": "my_binary", "processor": "AARCH64", "functions": 1234
    }
  ]
}
```

Use this to identify which MCP endpoint connects to which binary.

---

## gmcp CLI Quick Reference

```bash
# Setup
pip install -e .            # Install CLI
gmcp info                   # Show config
gmcp build                  # Build Docker image
gmcp status                 # Show running clients & binaries
gmcp status --json          # Machine-readable status

# Server + Client (one command)
gmcp up -r myrepo -b mybinary
gmcp down

# Server lifecycle
gmcp server up / down / restart / logs
gmcp server users / repos
gmcp server add-user alice
gmcp server clean --yes

# Client lifecycle (N=1-9, auto port: 880N3/880N4)
gmcp client start 1 -r myrepo -b mybinary
gmcp client start 2 -r myrepo -b other_binary
gmcp client stop 1
gmcp client logs 1

# Development
gmcp dev up                 # Hot-reload mode
gmcp dev reload             # Reload API modules
gmcp dev test               # Test endpoints
gmcp dev health             # Container health
gmcp dev shell              # Enter container

# Troubleshooting
gmcp troubleshoot check
gmcp troubleshoot fix

# Install skill + MCP for AI clients
gmcp install claude-code    # CLAUDE.md + MCP connection
gmcp install codex          # AGENTS.md
gmcp install cursor         # .cursor/rules/ghidra-mcp.md
gmcp install copilot        # .github/copilot-instructions.md
gmcp install claude-desktop # Claude Desktop config.json
gmcp install coco           # Coco MCP config
```
