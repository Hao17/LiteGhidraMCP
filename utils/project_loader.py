"""
Project Loader Utility - Handles Ghidra project loading in different modes.

Supports:
- Local filesystem projects (volume mounts)
- Ghidra Server projects (network connections)
- Single project mode
"""

import os
from typing import Optional, Tuple, Dict

def get_project_config() -> Dict[str, any]:
    """
    Parse environment variables for project configuration.

    Returns:
        dict: Project configuration with keys:
            - mode: 'local' or 'server'
            - path: Project directory path (local mode)
            - name: Project name
            - server_host, server_port, server_user, server_repo (server mode)
            - auto_analyze: Whether to auto-analyze on load
    """
    return {
        "mode": os.getenv("PROJECT_MODE", "local"),
        "path": os.getenv("PROJECT_PATH", "/ghidra-projects"),
        "name": os.getenv("PROJECT_NAME", "default"),
        "server_host": os.getenv("GHIDRA_SERVER_HOST", ""),
        "server_port": int(os.getenv("GHIDRA_SERVER_PORT", "13100")),
        "server_user": os.getenv("GHIDRA_SERVER_USER", ""),
        "server_repo": os.getenv("GHIDRA_SERVER_REPO", "/"),
        "auto_analyze": os.getenv("AUTO_ANALYZE", "false").lower() == "true"
    }

def validate_local_project(project_path: str, project_name: str) -> Tuple[bool, str]:
    """
    Validate local project directory and files.

    Returns:
        (success: bool, message: str)
    """
    # Check if project directory exists
    if not os.path.isdir(project_path):
        return False, f"Project directory does not exist: {project_path}"

    # Check for .gpr project configuration file
    gpr_file = os.path.join(project_path, f"{project_name}.gpr")
    if not os.path.isfile(gpr_file):
        return False, f"Project file not found: {gpr_file}"

    # Check for .rep project repository directory
    rep_dir = os.path.join(project_path, f"{project_name}.rep")
    if not os.path.isdir(rep_dir):
        return False, f"Project repository directory not found: {rep_dir}"

    return True, f"Local project validated: {project_path}/{project_name}"

def load_project(state):
    """
    Load Ghidra project based on environment configuration.

    This function is called by ghidra_mcp_server.py during startup
    to ensure the correct project is loaded in headless mode.

    Args:
        state: Ghidra GhidraState object

    Returns:
        dict: {"success": bool, "message": str, "config": dict}
    """
    config = get_project_config()

    if config["mode"] == "local":
        # Local filesystem mode
        success, message = validate_local_project(config["path"], config["name"])
        if not success:
            return {"success": False, "message": message, "config": config}

        # analyzeHeadless already loaded the project, just validate
        current_program = state.getCurrentProgram()
        if current_program is None:
            return {
                "success": False,
                "message": "No program loaded in Ghidra state",
                "config": config
            }

        return {
            "success": True,
            "message": f"Local project loaded: {config['name']}",
            "config": config,
            "program_name": current_program.getName()
        }

    elif config["mode"] == "server":
        # Ghidra Server mode
        # analyzeHeadless -connect parameter already handled connection, just validate
        current_program = state.getCurrentProgram()
        if current_program is None:
            return {
                "success": False,
                "message": "Failed to connect to Ghidra Server or load project",
                "config": config
            }

        return {
            "success": True,
            "message": f"Server project loaded: {config['server_host']}:{config['server_port']}/{config['name']}",
            "config": config,
            "program_name": current_program.getName()
        }

    else:
        return {
            "success": False,
            "message": f"Invalid PROJECT_MODE: {config['mode']} (must be 'local' or 'server')",
            "config": config
        }
