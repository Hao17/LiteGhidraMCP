# Ghidra MCP Binary Analysis

Analyze a binary loaded in Ghidra via MCP tools. Follows a systematic top-down workflow.

## Arguments
- `$ARGUMENTS` — Optional: function name, address, or analysis focus (e.g., "crypto functions", "main")

## Mental Model — `gmcp` vs MCP tools (READ THIS FIRST)

There are **two completely separate layers** here, and confusing them is the #1 source of wasted turns:

| Layer | What it is | How you call it | What it can do |
|---|---|---|---|
| **`gmcp` CLI** | A shell command (`pip install -e .` from the Bridge repo). Manages Docker containers. | Via the **Bash tool** (`gmcp server up`, `gmcp client start ...`) | Start/stop the Ghidra Server, spawn client containers, import binaries, configure MCP endpoints. |
| **MCP tools** (`ghidra_*`) | The MCP protocol tools your AI client is already connected to. | Direct tool calls (`ghidra_overview`, `ghidra_search`, ...) | **Only** analyze the one binary already loaded in the client this MCP connection points at. |

### What each layer CANNOT do

- **MCP tools cannot start, stop, switch, or import binaries.** There is no `ghidra_start_server`, no `ghidra_load_binary`, no "open this other .so" command. Don't go looking — runtime program switching is intentionally disabled. Each MCP connection is bound to **exactly one** binary for its entire lifetime.
- **`gmcp` cannot decompile or read program data.** It's pure container/lifecycle management. To inspect bytes or functions you must go through MCP tools.

### Anti-patterns to avoid

- ❌ "I'm already connected to `ghidra_*`, let me ask it to load `other.so`." → **Wrong.** Drop to Bash and run `gmcp client start 2 -r <repo> -b other -f ./other.so`, then connect a *second* MCP (`ghidra-2_*`).
- ❌ "Let me call `ghidra_overview` to see if the server is up before starting it." → **Wrong direction.** Use `gmcp status` via Bash; MCP tools only exist *after* a client is running and registered.
- ❌ Calling MCP tools to "restart" or "reload" Ghidra. → **Use Bash:** `gmcp client stop N` / `gmcp client start N ...`. The only MCP-side reload is `_reload` for hot-reloading API code, not for changing binaries.
- ❌ Treating multiple connected MCPs (`ghidra_*`, `ghidra-2_*`, `ghidra-3_*`) as one. Each prefix is a **separate binary in a separate container**. Always pick the right prefix for the binary you want.

### When to drop to Bash (use `gmcp`) vs stay in MCP

- Need to **analyze the currently-connected binary** → MCP tools.
- Need a **different binary** / **second binary in parallel** / **fresh container** → Bash + `gmcp client start N ...`, then `/ghidra-setup` step 5 to wire up the new MCP.
- Need to know **what's running** / **what's loaded where** → Bash: `gmcp status` (returns a JSON map of client N → binary).
- Container looks unhealthy / port not responding → Bash: `gmcp client logs N`, `gmcp troubleshoot check`.

## Prerequisites

Before analysis, verify MCP is connected. Call `ghidra_overview()`:

- Returns metadata + a non-trivial function count → connected, continue to the workflow below.
- Tool missing or errors out → **do not retry MCP tools.** Run `/ghidra-setup` (which uses `gmcp` via Bash) to bring up a client.

**Multi-binary case.** If the binary you need is not the one this MCP connection points at:

1. Don't ask the existing `ghidra_*` tools to "switch" — they can't.
2. In a Bash shell: `gmcp client start 2 -r <repo> -b <other_binary> -f <path/to/other.so>` (pick the next free N, see `gmcp status`).
3. Wire up the new client's MCP: `gmcp install mcp claude-code --client 2` (this writes a *new* MCP server registration named `ghidra-2`).
4. Restart the AI client / reload MCPs so `ghidra-2_*` tools appear.
5. Now use `ghidra-2_overview`, `ghidra-2_search`, etc. for that binary. The original `ghidra_*` still points at the original binary — both stay live in parallel.

Port/name table is in `/ghidra-setup`. Client N → MCP name `ghidra-N` (Client 1 = bare `ghidra`), SSE port `8804 + (N-1)*10`.

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
