# Ghidra MCP Annotation

Annotate a binary in Ghidra — rename functions/variables, set types, add comments, create structs.

## Arguments
- `$ARGUMENTS` — Optional: function name or address to focus annotation on

## Action Reference

All annotation uses `ghidra_edit`. Key actions:

| Action | Required params | Notes |
|--------|----------------|-------|
| `rename.function_signature` | `function` + `signature` | Best for functions — sets name, return type, params at once |
| `rename.decompiler.variable` | `function` + `var_name` + `new_name` | Always use this, NOT `rename.variable` |
| `datatype.set.decompiler.variable` | `function` + `var_name` + `type` | Always use this, NOT `datatype.set.variable` |
| `datatype.set.decompiler.parameter` | `function` + `param` + `type` | Param by index or name |
| `datatype.parse.c` | `code` | Create struct/enum/typedef/union from C code |
| `comment.set` | `address` + `type` + `text` | Types: EOL, PRE, POST, PLATE, REPEATABLE |

### Why decompiler-level?

Always prefer `decompiler.*` actions over plain `rename.variable` / `rename.parameter`. The decompiler may merge multiple low-level variables into one logical variable — listing-level renames can silently fail.

## Workflow

### Step 1: View the function

```
ghidra_view(query="$ARGUMENTS", view_type="decompile")
```

### Step 2: Rename function via signature

Set name, return type, calling convention, and parameters in one shot:

```
ghidra_edit(action="rename.function_signature",
            function="FUN_00401000",
            signature="int main(int argc, char **argv)")
```

Supports calling conventions: `__stdcall`, `__cdecl`, `__fastcall`, `__thiscall`, `__vectorcall`

### Step 3: Rename variables

```
ghidra_edit(action="rename.decompiler.variable",
            function="main", var_name="local_8", new_name="counter")
```

### Step 4: Set variable types

```
ghidra_edit(action="datatype.set.decompiler.variable",
            function="main", var_name="counter", type="uint32_t")
```

### Step 5: Create custom types

```
ghidra_edit(action="datatype.parse.c",
            code="typedef struct { int x; int y; } Point;")
```

### Step 6: Add comments

```
ghidra_edit(action="comment.set",
            address="0x401000", type="PLATE", text="Program entry point")
```

### Step 7: Verify

```
ghidra_view(query="$ARGUMENTS", view_type="decompile")
```

## Version Control (Server Mode)

Write operations auto-commit. Manual controls:

```
ghidra_version(action="log")                       # View history
ghidra_version(action="log", diff=3)               # Diff against version 3
ghidra_version(action="rollback")                   # Undo last change
ghidra_version(action="revert", version=5)          # Go back to version 5 (destructive!)
```
