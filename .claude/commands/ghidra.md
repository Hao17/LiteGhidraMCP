# Ghidra MCP Binary Analysis

Analyze a binary loaded in Ghidra via MCP tools. Follows a systematic top-down workflow.

## Arguments
- `$ARGUMENTS` — Optional: function name, address, or analysis focus (e.g., "crypto functions", "main")

## Prerequisites

Before analysis, verify MCP is connected. Call `ghidra_overview()`:

- Returns metadata + a non-trivial function count → connected, continue to the workflow below.
- Tool missing or errors out → run `/ghidra-setup` to bring up a client.

**Multi-binary case.** If you need a binary that's not the one currently loaded, start a separate client (`gmcp client start 2 ...`) and call its tools via the `ghidra-2_*` prefix — see `/ghidra-setup` for the port/name table. Don't switch programs inside an existing client; runtime switching is disabled by design.

## Workflow

### Step 1: Overview

Start with `ghidra_overview` to understand the binary:

```
ghidra_overview()
```

Returns: metadata (format, arch, bits), memory segments, statistics, top functions by xref importance, imports by library, exports, notable strings. Use this to form an analysis plan.

### Step 2: Search for Targets

Use `ghidra_search` with smart type inference (`types="auto"` is default):

```
ghidra_search(query="main")              # Functions/symbols named "main"
ghidra_search(query="0x401000")          # Xrefs to/from this address
ghidra_search(query="48 8b ?? 90")       # Byte pattern (wildcards: ??)
ghidra_search(query="password")          # Functions + symbols + strings
ghidra_search(query="*init*")            # Wildcard search
ghidra_search(query="AES", types="strings")  # Force specific type
```

**Search strategy:**
1. Know the name? → `query="exact_name"`
2. Know a pattern? → `query="*pattern*"`
3. Know an address? → `query="0xADDR"` for xrefs
4. Looking for strings? → `types="strings"`
5. Byte patterns? → `query="48 89 5c ?? 08"`

### Step 3: Read Code

Use `ghidra_view` to decompile/disassemble. Batch multiple in one call:

```
ghidra_view(query="main")                         # Decompile + disassemble
ghidra_view(query="main,init,0x401000")           # Batch: 3 functions at once
ghidra_view(query="main", view_type="decompile")  # Decompile only (faster)
ghidra_view(query="0x611", view_type="memory", limit=256)  # Raw bytes
ghidra_view(view_type="header")                   # Export all types as C header
```

### Step 4: Browse Symbols

Use `ghidra_list` — like `ls` for binaries:

```
ghidra_list()                                  # All functions (default)
ghidra_list(types="imports", library="libc")   # libc imports only
ghidra_list(types="classes")                   # All classes
ghidra_list(query="*handler*")                 # Wildcard filter
ghidra_list(start="0x401000", end="0x402000")  # Functions in address range
ghidra_list(types="all")                       # Everything
```

### Step 5: Annotate

Use `ghidra_edit` for renaming, typing, and commenting. See `/ghidra-annotate` for full reference.

Quick examples:
```
ghidra_edit(action="rename.function_signature", function="FUN_00401000", signature="int main(int argc, char **argv)")
ghidra_edit(action="rename.decompiler.variable", function="main", var_name="local_8", new_name="counter")
ghidra_edit(action="comment.set", address="0x401000", type="PLATE", text="Program entry point")
```

## Analysis Patterns

**Top-down**: overview → pick interesting functions from `top_functions` → view each → follow xrefs with search

**String-based**: overview → scan `notable_strings` → search xrefs to interesting strings → view referencing functions

**Import-driven**: `list(types="imports")` → identify crypto/network/file APIs → search xrefs → view callers

**Address range**: `list(start="0x401000", end="0x402000")` → enumerate functions in a section → view each
