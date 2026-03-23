# api/program.py - Program management API (list/switch programs)

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
