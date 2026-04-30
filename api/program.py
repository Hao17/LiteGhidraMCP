# api/program.py - Program inventory/import API (runtime switching is deprecated)

from api import route


@route("/api/program/list")
def list_programs(state):
    """List all programs in the current project/repository."""
    from docker_only_ghidra_mcp_server import _list_programs
    programs = _list_programs()
    return {"success": True, "programs": programs, "total": len(programs)}


@route("/api/program/open")
def open_program(state, name=""):
    """Deprecated. Program selection must be fixed at startup."""
    return {
        "success": False,
        "error": (
            "Runtime program switching is deprecated and disabled. "
            "Start the bridge with PROGRAM_NAME (or Docker BINARY) set to "
            "the target program name/path."
        ),
    }


@route("/api/program/import", writes=True)
def import_program(state, path="", name="", analyze="true"):
    """
    Import a binary file into the current project/repository.

    Route: GET /api/program/import?path=/path/to/binary&name=my_binary&analyze=true
    """
    if not path:
        return {"success": False, "error": "Missing 'path' parameter"}

    from docker_only_ghidra_mcp_server import _import_program
    try:
        do_analyze = str(analyze).lower() in ("true", "1", "yes")
        result = _import_program(path, name=name, analyze=do_analyze)
        return {"success": True, **result}
    except Exception as e:
        return {"success": False, "error": str(e)}
