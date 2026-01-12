"""
V1 Edit API - Unified Edit for AI/MCP Tools

State Passing Pattern - AI-oriented unified editing interface supporting batch operations.

=== Design Goals ===
- One tool for all editing needs (rename, datatype, comment)
- Support batch operations for efficient bulk modifications
- Error collection without failing entire batch
- POST-only endpoint with JSON body

=== Usage ===
    import api_v1.edit as v1_edit

    # Single action
    result = v1_edit.edit(state, body={"action": "rename.function", "name": "FUN_00401000", "new_name": "main"})

    # Batch mode
    result = v1_edit.edit(state, body={"actions": [
        {"action": "rename.function", "name": "FUN_00401000", "new_name": "main"},
        {"action": "datatype.set.return", "function": "main", "type": "int"}
    ]})

Route: POST /api/v1/edit
"""

from api import rename as rename_api
from api import datatype as datatype_api
from api import comment as comment_api


# ============================================================
# Response Helpers
# ============================================================

def _ok(data):
    """Construct success response"""
    return {"success": True, "data": data}


def _err(message):
    """Construct error response"""
    return {"success": False, "error": message}


# ============================================================
# Handler Mapping
# ============================================================

ACTION_HANDLERS = {
    # ==================== Rename Actions ====================
    "rename.function": rename_api.rename_function,
    "rename.variable": rename_api.rename_variable,
    "rename.parameter": rename_api.rename_parameter,
    "rename.global": rename_api.rename_global,
    "rename.label": rename_api.rename_label,
    "rename.datatype": rename_api.rename_datatype,
    "rename.namespace": rename_api.rename_namespace,
    "rename.decompiler.variable": rename_api.rename_decompiler_variable,
    "rename.decompiler.parameter": rename_api.rename_decompiler_parameter,
    "rename.decompiler.split": rename_api.split_variable,

    # ==================== DataType Set Actions ====================
    "datatype.set.return": datatype_api.set_return_type,
    "datatype.set.parameter": datatype_api.set_parameter_type,
    "datatype.set.decompiler.variable": datatype_api.set_decompiler_variable_type,
    "datatype.set.decompiler.parameter": datatype_api.set_decompiler_parameter_type,
    "datatype.set.global": datatype_api.set_global_type,
    "datatype.set.field": datatype_api.set_struct_field_type,

    # ==================== DataType Parse (C code) ====================
    "datatype.parse.c": datatype_api.parse_c_code,

    # ==================== Comment Actions ====================
    "comment.set": comment_api.set_comment,
}

ALL_ACTIONS = list(ACTION_HANDLERS.keys())


# ============================================================
# Handler Execution
# ============================================================

import json as _json

# Parameters that need JSON string conversion (underlying APIs expect strings)
_JSON_STRING_PARAMS = {"fields", "members", "params"}


def _call_handler(state, action, params):
    """
    Call an action handler and normalize the response.

    Args:
        state: Ghidra state object
        action: Action name (e.g., "rename.function")
        params: Dict of parameters for the action

    Returns:
        dict: Normalized result with "success" and action-specific fields
    """
    handler = ACTION_HANDLERS.get(action)
    if handler is None:
        return {"success": False, "error": f"Unknown action: {action}"}

    try:
        # Convert list/dict params to JSON strings (underlying APIs expect strings)
        converted_params = {}
        for k, v in params.items():
            if k in _JSON_STRING_PARAMS and isinstance(v, (list, dict)):
                converted_params[k] = _json.dumps(v)
            else:
                converted_params[k] = v

        # Call the underlying API function
        result = handler(state, **converted_params)

        # Normalize response - add action field
        if result.get("success"):
            normalized = {"success": True, "action": action}
            # Copy all fields except "success"
            for k, v in result.items():
                if k != "success":
                    normalized[k] = v
            return normalized
        else:
            return {
                "success": False,
                "action": action,
                "error": result.get("error", "Unknown error")
            }
    except Exception as e:
        return {
            "success": False,
            "action": action,
            "error": str(e)
        }


def _handle_single(state, body, verbose=False):
    """
    Handle single action request.

    Args:
        state: Ghidra state object
        body: Request body dict with "action" and params
        verbose: If True, include input params in response

    Returns:
        dict: Action result
    """
    action = body.get("action")
    if not action:
        return _err("Missing 'action' field")

    if action not in ACTION_HANDLERS:
        return _err(f"Unknown action: {action}. Available actions: {ALL_ACTIONS}")

    # Extract params (everything except "action")
    params = {k: v for k, v in body.items() if k != "action"}

    result = _call_handler(state, action, params)

    if verbose and result.get("success"):
        result["input"] = params

    if result.get("success"):
        return _ok(result)
    else:
        return result


def _handle_batch(state, actions, verbose=False):
    """
    Handle batch action request.

    Args:
        state: Ghidra state object
        actions: List of action dicts, each with "action" and params
        verbose: If True, include input params in response

    Returns:
        dict: Batch result with summary, results, and errors
    """
    if not isinstance(actions, list):
        return _err("'actions' must be an array")

    if len(actions) == 0:
        return _err("'actions' array is empty")

    results = []
    errors = []
    succeeded = 0
    failed = 0

    for i, action_def in enumerate(actions):
        if not isinstance(action_def, dict):
            error_entry = {
                "index": i,
                "error": "Action must be an object"
            }
            errors.append(error_entry)
            results.append({"success": False, "error": "Action must be an object"})
            failed += 1
            continue

        action = action_def.get("action")
        if not action:
            error_entry = {
                "index": i,
                "error": "Missing 'action' field"
            }
            errors.append(error_entry)
            results.append({"success": False, "error": "Missing 'action' field"})
            failed += 1
            continue

        if action not in ACTION_HANDLERS:
            error_entry = {
                "index": i,
                "action": action,
                "error": f"Unknown action: {action}"
            }
            errors.append(error_entry)
            results.append({"success": False, "action": action, "error": f"Unknown action: {action}"})
            failed += 1
            continue

        # Extract params (everything except "action")
        params = {k: v for k, v in action_def.items() if k != "action"}

        result = _call_handler(state, action, params)

        if result.get("success"):
            succeeded += 1
            if verbose:
                result["index"] = i
                result["input"] = params
            results.append(result)
        else:
            failed += 1
            error_entry = {
                "index": i,
                "action": action,
                "error": result.get("error", "Unknown error")
            }
            if verbose:
                error_entry["input"] = params
            errors.append(error_entry)
            results.append(result)

    response = {
        "summary": {
            "total": len(actions),
            "succeeded": succeeded,
            "failed": failed
        },
        "results": results
    }

    if errors:
        response["errors"] = errors

    return _ok(response)


# ============================================================
# Main Entry Point (called from server's do_POST)
# ============================================================

def edit(state, body):
    """
    Unified edit API for rename, datatype, and comment operations.

    This function is called directly from the server's do_POST handler,
    not via the @route decorator (since it's POST-only).

    Args:
        state: Ghidra GhidraState object
        body: JSON request body (dict)
            - Single action: {"action": "...", ...params}
            - Batch: {"actions": [...]}
            - Optional: "verbose": true for detailed output

    Returns:
        dict: Edit results

    Examples:
        # Single action
        POST /api/v1/edit
        {"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}

        # Batch
        POST /api/v1/edit
        {"actions": [
            {"action": "rename.function", "name": "FUN_00401000", "new_name": "main"},
            {"action": "datatype.set.return", "function": "main", "type": "int"}
        ]}
    """
    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    # Check for verbose flag
    verbose = body.get("verbose", False)
    if isinstance(verbose, str):
        verbose = verbose.lower() in ("true", "1", "yes")

    # Batch mode: "actions" array
    if "actions" in body:
        return _handle_batch(state, body["actions"], verbose)

    # Single mode: "action" field
    if "action" in body:
        return _handle_single(state, body, verbose)

    # No action specified - return help
    return _ok({
        "message": "V1 Edit API - POST JSON body with 'action' or 'actions'",
        "available_actions": ALL_ACTIONS,
        "examples": {
            "single": {
                "action": "rename.function",
                "name": "FUN_00401000",
                "new_name": "main"
            },
            "batch": {
                "actions": [
                    {"action": "rename.function", "name": "FUN_00401000", "new_name": "main"},
                    {"action": "datatype.set.return", "function": "main", "type": "int"}
                ]
            }
        }
    })
