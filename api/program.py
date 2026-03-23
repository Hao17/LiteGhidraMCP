# api/program.py - Program management API (list/switch/import programs)

from api import route


@route("/api/program/list")
def list_programs(state):
    """List all programs in the current project/repository."""
    from ghidra_mcp_server_pyghidra import _list_programs
    programs = _list_programs()
    return {"success": True, "programs": programs, "total": len(programs)}


@route("/api/program/open")
def open_program(state, name=""):
    """Switch the active program by name."""
    if not name:
        return {"success": False, "error": "Missing 'name' parameter"}
    from ghidra_mcp_server_pyghidra import _switch_program
    try:
        prog = _switch_program(name)
        return {
            "success": True,
            "program": {
                "name": prog.getName(),
                "arch": str(prog.getLanguage().getProcessor()),
                "bits": prog.getLanguage().getDefaultSpace().getSize() * 8,
                "functions": prog.getFunctionManager().getFunctionCount()
            }
        }
    except (FileNotFoundError, RuntimeError) as e:
        return {"success": False, "error": str(e)}


@route("/api/program/import")
def import_program(state, path="", name="", analyze="true"):
    """
    Import a binary file into the current project/repository.

    Route: GET /api/program/import?path=/path/to/binary&name=my_binary&analyze=true
    """
    if not path:
        return {"success": False, "error": "Missing 'path' parameter"}

    from ghidra_mcp_server_pyghidra import _import_program
    try:
        do_analyze = str(analyze).lower() in ("true", "1", "yes")
        result = _import_program(path, name=name, analyze=do_analyze)
        return {"success": True, **result}
    except Exception as e:
        return {"success": False, "error": str(e)}
