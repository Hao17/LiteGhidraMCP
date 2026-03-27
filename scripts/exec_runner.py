"""
Ghidra Script Execution Runner.

Runs user-provided Python code inside Ghidra with full Flat API access.
Used by both GUI mode (via runScript) and Headless mode (via analyzeHeadless -postScript).

Protocol:
    args[0] = result JSON output path
    args[1] = user code file path

The user code is exec()'d in this script's globals(), so all Ghidra Flat API
functions (currentProgram, toAddr, getFunctionAt, etc.) are available.

If the user code sets a `result` variable, it will be serialized into the output.
Print output is captured in `stdout`.
"""

import io
import json
import sys
import traceback


def _serialize(obj, depth=0):
    """Recursively convert Python/Java objects to JSON-safe types."""
    if depth > 10:
        return str(obj)

    if obj is None:
        return None
    if isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (list, tuple)):
        return [_serialize(item, depth + 1) for item in obj]
    if isinstance(obj, dict):
        return {str(k): _serialize(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, set):
        return [_serialize(item, depth + 1) for item in obj]

    # Java objects - try common patterns
    try:
        # Java toString()
        s = str(obj)
        # If it's a meaningful string, use it
        if s and not s.startswith("<") and "object at 0x" not in s:
            return s
    except Exception:
        pass

    # Java collections
    try:
        # Try to iterate (Java List, Set, etc.)
        items = []
        for item in obj:
            items.append(_serialize(item, depth + 1))
            if len(items) > 1000:
                items.append("...(truncated)")
                break
        return items
    except (TypeError, StopIteration):
        pass

    # Java Map
    try:
        entry_set = obj.entrySet()
        result = {}
        for entry in entry_set:
            result[str(entry.getKey())] = _serialize(entry.getValue(), depth + 1)
        return result
    except (AttributeError, TypeError):
        pass

    return str(obj)


# ============================================================
# Main execution
# ============================================================

args = getScriptArgs()
result_path = args[0]
code_path = args[1]

with open(code_path, 'r', encoding='utf-8') as f:
    user_code = f.read()

# Capture stdout
_buf = io.StringIO()
_old_stdout = sys.stdout

try:
    sys.stdout = _buf
    exec(user_code, globals())
    sys.stdout = _old_stdout

    output = {
        "success": True,
        "stdout": _buf.getvalue(),
    }

    # Serialize the 'result' variable if user set it
    if 'result' in dir() or 'result' in globals():
        try:
            output["result"] = _serialize(globals().get('result'))
        except Exception as e:
            output["result"] = str(globals().get('result'))
            output["result_serialization_warning"] = str(e)

except Exception:
    sys.stdout = _old_stdout
    output = {
        "success": False,
        "error": str(sys.exc_info()[1]),
        "traceback": traceback.format_exc(),
        "stdout": _buf.getvalue(),
    }

with open(result_path, 'w', encoding='utf-8') as f:
    json.dump(output, f, ensure_ascii=False)
