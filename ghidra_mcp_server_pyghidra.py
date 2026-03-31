"""
PyGhidra-based MCP Bridge for AI Repository Integration.

This script uses PyGhidra (Ghidra 12.0+) to provide an external AI agent
with programmatic access to Ghidra's analysis capabilities. It exposes a lightweight
HTTP JSON API that allows AI systems to query decompilation data, perform reverse
engineering tasks, and execute scripted operations within Ghidra.

Key differences from Ghidrathon version:
- Uses PyGhidra instead of Ghidrathon (official support)
- Starts JVM from Python (not vice versa)
- No dependency on analyzeHeadless -postScript
- Better support for multi-threading

Entry point: main()
"""

import importlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.request import urlopen
from urllib.parse import urlparse, parse_qs

# Add /app to sys.path for module imports
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Import PyGhidra before any Ghidra imports
import pyghidra

from utils.logging_config import get_log_file_path, log_debug, log_info

HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8803"))
MCP_PORT = int(os.environ.get("GHIDRA_MCP_SSE_PORT", "8804"))

_server_instance: Optional["ThreadingHTTPServer"] = None
_server_thread: Optional[threading.Thread] = None

# Cache Ghidra context (PyGhidra style)
_ghidra_project = None
_current_program = None
_mock_state = None

# Server mode shared project state
_server_handle = None     # Reserved for shared-project server integrations
_project = None           # Underlying Project object (server mode shared project)
_program_lock = threading.Lock()


class MockGhidraState:
    """
    Mock GhidraState object for API compatibility.

    In PyGhidra mode, we don't have the same state object as Ghidrathon,
    so we create a lightweight mock that provides the same interface.
    """
    def __init__(self, project, program):
        self._project = project
        self._program = program

    def getCurrentProgram(self):
        """Get current program (compatible with Ghidrathon API)."""
        return self._program

    def getProject(self):
        """Get Ghidra project (shared project in server mode, GhidraProject in local mode)."""
        return _project or self._project

    def getCurrentAddress(self):
        """Get current address (returns None in headless mode)."""
        return None

    def getCurrentSelection(self):
        """Get current selection (returns None in headless mode)."""
        return None

    def getCurrentHighlight(self):
        """Get current highlight (returns None in headless mode)."""
        return None

    def getTool(self):
        """Get current tool (returns None in headless mode)."""
        return None


def _import_program(path, name="", analyze=True):
    """Import a binary file into the current project/repository.

    Returns dict with program info on success.
    """
    global _current_program

    proj = _project
    if proj is None and _ghidra_project:
        proj = _ghidra_project._project

    if proj is None:
        raise RuntimeError("No project loaded")

    from java.io import File as JavaFile
    from ghidra.app.util.importer import AutoImporter, MessageLog
    from ghidra.util.task import TaskMonitor

    binary_file = JavaFile(path)
    if not binary_file.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Determine program name
    prog_name = name if name else binary_file.getName()

    # Check if program already exists
    root = proj.getProjectData().getRootFolder()
    if root.getFile(prog_name) is not None:
        raise RuntimeError(f"Program '{prog_name}' already exists in project")

    # Import using AutoImporter (returns LoadResults in Ghidra 12.0+)
    msg = MessageLog()
    load_results = AutoImporter.importByUsingBestGuess(
        binary_file, proj, "/", proj, msg, TaskMonitor.DUMMY
    )

    if load_results is None:
        raise RuntimeError(f"Import failed: {msg}")

    # Extract the primary loaded domain object (Program) from LoadResults
    program = None
    try:
        # LoadResults is iterable, each item is a Loaded<DomainObject>
        for loaded in load_results:
            dom_obj = loaded.getDomainObject()
            program = dom_obj
            break  # Take the first (primary) result
    except Exception:
        # Fallback: LoadResults might have getPrimaryDomainObject
        try:
            program = load_results.getPrimaryDomainObject()
        except Exception:
            pass

    if program is None:
        raise RuntimeError(f"Import returned no program. Log: {msg}")

    original_name = program.getName()

    # Run auto-analysis if requested
    if analyze:
        try:
            from ghidra.app.util.importer import AutoAnalysisManager
            mgr = AutoAnalysisManager.getAnalysisManager(program)
            txid = program.startTransaction("Auto-analysis")
            try:
                mgr.initializeOptions()
                mgr.reAnalyzeAll(None)
                mgr.startAnalysis(TaskMonitor.DUMMY)
            finally:
                program.endTransaction(txid, True)
        except Exception:
            pass  # Analysis is best-effort

    # CRITICAL: Call load_results.save() to create DomainFile in project folder
    # program.save() only saves internal state; load_results.save() creates the file
    load_results.save(TaskMonitor.DUMMY)

    # Release after save (DomainFile persists in project)
    load_results.release(proj)

    # Rename domain file if custom name specified (after save + release)
    if name and original_name != name:
        df = root.getFile(original_name)
        if df is not None:
            try:
                df.setName(name)
            except Exception:
                prog_name = original_name  # Keep original name on rename failure

    # For shared projects (server mode), check in the file to the server
    versioned = False
    df = root.getFile(prog_name)
    if df is None:
        df = root.getFile(original_name)  # Try original name
    if df is not None and _project is not None:
        try:
            # Ensure repository connection is alive
            repo = proj.getProjectData().getRepository()
            if repo is not None:
                try:
                    repo.connect()
                except Exception:
                    pass  # May already be connected

            if not df.isVersioned():
                df.addToVersionControl("Imported via API", False, TaskMonitor.DUMMY)
                versioned = True
            else:
                versioned = True
        except Exception:
            pass  # Version control is best-effort

    result = {
        "name": prog_name,
        "message": f"Successfully imported '{prog_name}'",
        "versioned": versioned
    }
    return result


def _collect_all_files(folder):
    """Recursively collect all DomainFiles from a folder tree."""
    files = list(folder.getFiles())
    for sub in folder.getFolders():
        files.extend(_collect_all_files(sub))
    return files


def _find_domain_file(root_folder, target_name):
    """
    Find a DomainFile by name or path.
    Supports: "libmetasec_ml.so", "38.1.0/libmetasec_ml.so", "/38.1.0/libmetasec_ml.so"

    For Ghidra Server shared projects, DomainFolder.getFolder() navigates
    server subdirectories on demand (lazy loading).
    """
    # Try direct lookup in root first
    domain_file = root_folder.getFile(target_name)
    if domain_file is not None:
        return domain_file

    # Try as path: navigate folder hierarchy
    path = target_name.lstrip("/")
    if "/" in path:
        parts = path.rsplit("/", 1)
        folder = root_folder
        for part in parts[0].split("/"):
            if part:
                sub = folder.getFolder(part)
                if sub is None:
                    folder = None
                    break
                folder = sub
        if folder is not None:
            domain_file = folder.getFile(parts[1])
            if domain_file is not None:
                return domain_file

    # Fallback: recursive search by filename
    file_name = target_name.rsplit("/", 1)[-1] if "/" in target_name else target_name
    for f in _collect_all_files(root_folder):
        if f.getName() == file_name:
            return f

    return None


def _init_ghidra_project():
    """
    Initialize Ghidra using PyGhidra and load the project.

    This replaces the analyzeHeadless approach.
    """
    global _ghidra_project, _current_program, _mock_state, _server_handle, _project

    print("[PyGhidra-MCP-Bridge] Initializing PyGhidra...")

    # Start Ghidra (this initializes the JVM and Ghidra Application)
    pyghidra.start(verbose=True)
    print("[PyGhidra-MCP-Bridge] ✓ PyGhidra started successfully")

    # Import Ghidra APIs (must be after pyghidra.start())
    from ghidra.base.project import GhidraProject

    # Get project configuration from environment
    project_mode = os.environ.get("PROJECT_MODE", "local")
    project_path = os.environ.get("PROJECT_PATH", "/ghidra-projects")
    project_name = os.environ.get("PROJECT_NAME", "default")

    print(f"[PyGhidra-MCP-Bridge] Loading project: {project_name}")
    print(f"[PyGhidra-MCP-Bridge] Mode: {project_mode}")
    print(f"[PyGhidra-MCP-Bridge] Path: {project_path}")

    if project_mode == "local":
        # Open or create local project
        _ghidra_project = GhidraProject.openProject(
            project_path,
            project_name,
            restore=True  # Create if doesn't exist
        )
        print(f"[PyGhidra-MCP-Bridge] ✓ Project opened: {project_name}")

        # Open program selected at startup via PROGRAM_NAME (name or project path).
        root_folder = _ghidra_project.getProjectData().getRootFolder()
        program_files = list(root_folder.getFiles())
        all_files = _collect_all_files(root_folder)
        target_name = os.environ.get("PROGRAM_NAME", "")

        if target_name:
            domain_file = _find_domain_file(root_folder, target_name)
            if domain_file is None:
                names = [f.getPathname() for f in all_files]
                raise FileNotFoundError(f"Program '{target_name}' not found. Available: {names}")
            folder_path = domain_file.getPathname().rsplit("/", 1)[0] or "/"
            _current_program = _ghidra_project.openProgram(folder_path, domain_file.getName(), False)
            print(f"[PyGhidra-MCP-Bridge] ✓ Program loaded (PROGRAM_NAME): {domain_file.getPathname()}")
        elif program_files:
            # Open first program
            program_file = program_files[0]
            program_name = program_file.getName()
            _current_program = _ghidra_project.openProgram("/", program_name, False)
            print(f"[PyGhidra-MCP-Bridge] ✓ Program loaded: {program_name}")
        elif all_files:
            domain_file = all_files[0]
            folder_path = domain_file.getPathname().rsplit("/", 1)[0] or "/"
            _current_program = _ghidra_project.openProgram(folder_path, domain_file.getName(), False)
            print(f"[PyGhidra-MCP-Bridge] ✓ Program loaded: {domain_file.getPathname()}")
        else:
            print("[PyGhidra-MCP-Bridge] ⚠ No programs found in project")
            print("[PyGhidra-MCP-Bridge] ⚠ You can import binaries via API or manually")
            _current_program = None

    elif project_mode == "server":
        # Ghidra Server mode with SSH key authentication
        server_host = os.environ.get("GHIDRA_SERVER_HOST", "localhost")
        server_port = int(os.environ.get("GHIDRA_SERVER_PORT", "13100"))
        server_user = os.environ.get("GHIDRA_SERVER_USER", "")
        server_keystore = os.environ.get("GHIDRA_SERVER_KEYSTORE", "")  # Path to SSH private key

        print(f"[PyGhidra-MCP-Bridge] Connecting to Ghidra Server: {server_host}:{server_port}")
        print(f"[PyGhidra-MCP-Bridge] User: {server_user if server_user else '(anonymous)'}")
        print(f"[PyGhidra-MCP-Bridge] Authentication: {'SSH key (' + server_keystore + ')' if server_keystore else 'Anonymous'}")

        try:
            from ghidra.framework.client import ClientUtil, HeadlessClientAuthenticator
            from java.lang import System
            from javax.net.ssl import HttpsURLConnection, SSLContext
            from java.security import SecureRandom
            import jpype

            # Disable SSL hostname verification for Docker networking (host.docker.internal)
            # This is needed because the server's SSL certificate contains "localhost"
            # but Docker connects via "host.docker.internal"

            # Create a trust manager that accepts all certificates using JProxy
            @jpype.JImplements("javax.net.ssl.X509TrustManager")
            class AllTrustManager:
                @jpype.JOverride
                def checkClientTrusted(self, chain, authType):
                    pass
                @jpype.JOverride
                def checkServerTrusted(self, chain, authType):
                    pass
                @jpype.JOverride
                def getAcceptedIssuers(self):
                    return None

            # Create a hostname verifier that accepts all hostnames using JProxy
            @jpype.JImplements("javax.net.ssl.HostnameVerifier")
            class AllHostnameVerifier:
                @jpype.JOverride
                def verify(self, hostname, session):
                    return True

            # Install the permissive trust manager and hostname verifier
            sc = SSLContext.getInstance("TLS")
            trust_managers = jpype.JArray(jpype.JClass("javax.net.ssl.TrustManager"))([AllTrustManager()])
            sc.init(None, trust_managers, SecureRandom())

            # Set SSL factory for HTTPS URLs
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
            HttpsURLConnection.setDefaultHostnameVerifier(AllHostnameVerifier())

            # CRITICAL: Set default SSLContext globally for all SSL connections (including SSLSocket)
            # This is needed for Ghidra's ClientUtil.getRepositoryServer() which uses SSLSocket
            SSLContext.setDefault(sc)

            # Also disable endpoint identification for SSL sockets
            from javax.net.ssl import SSLParameters
            System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3")
            System.setProperty("https.protocols", "TLSv1.2,TLSv1.3")

            print(f"[PyGhidra-MCP-Bridge] ✓ SSL hostname verification disabled globally for Docker compatibility")

            # Install headless authenticator with SSH key authentication
            # IMPORTANT: No password prompts - only SSH key authentication
            if server_user and server_keystore:
                # SSH key authentication mode
                print(f"[PyGhidra-MCP-Bridge] Installing headless authenticator with SSH key")
                print(f"[PyGhidra-MCP-Bridge] Keystore: {server_keystore}")

                # Verify keystore file exists
                if not os.path.exists(server_keystore):
                    raise FileNotFoundError(f"SSH keystore not found: {server_keystore}")

                # Install authenticator with keystore, NO password prompts
                HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
                    server_user,
                    server_keystore,
                    False  # CRITICAL: Never prompt for password
                )
                print(f"[PyGhidra-MCP-Bridge] ✓ SSH key authenticator installed")

            elif server_user and not server_keystore:
                # User specified but no keystore - this is an error
                raise ValueError(
                    "GHIDRA_SERVER_USER specified but GHIDRA_SERVER_KEYSTORE not set. "
                    "SSH key authentication required. Password authentication has been removed."
                )
            else:
                # Anonymous access mode
                print(f"[PyGhidra-MCP-Bridge] Installing headless authenticator for anonymous access")
                HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
                    None, None, False  # No password prompt for anonymous mode
                )

            # Connect to Ghidra Server (already authenticated via HeadlessClientAuthenticator)
            server_handle = ClientUtil.getRepositoryServer(server_host, server_port, True)

            # Check connection status
            if not server_handle.isConnected():
                raise Exception(f"Failed to establish server connection - isConnected() returned False")

            print(f"[PyGhidra-MCP-Bridge] ✓ Connected to server")
            print(f"[PyGhidra-MCP-Bridge] Server user: {server_handle.getUser()}")

            # List available repositories
            repos = server_handle.getRepositoryNames()
            print(f"[PyGhidra-MCP-Bridge] Available repositories: {list(repos) if repos else '(none)'}")

            # Determine repository name
            repo_name = os.environ.get("GHIDRA_SERVER_REPO", "")
            if not repo_name and repos and len(repos) > 0:
                repo_name = repos[0]
                print(f"[PyGhidra-MCP-Bridge] Using first repository: {repo_name}")

            if not repo_name:
                repo_name = "/mcp-projects"

            # Create repository if it doesn't exist
            # Strip leading '/' for API calls (Ghidra uses bare names internally)
            repo_bare = repo_name.lstrip("/")
            repo_list = list(repos) if repos else []
            if repo_bare not in repo_list:
                print(f"[PyGhidra-MCP-Bridge] Repository '{repo_bare}' not found in user's list, creating...")
                try:
                    server_handle.createRepository(repo_bare)
                    print(f"[PyGhidra-MCP-Bridge] ✓ Created repository: {repo_bare}")
                except Exception as e:
                    if "DuplicateFile" in str(type(e).__name__) or "already exists" in str(e):
                        print(f"[PyGhidra-MCP-Bridge] Repository '{repo_bare}' exists but not in user's list, waiting for ACL sync...")
                        # Repo exists but user doesn't have access yet — wait for server ACL sync
                        for _retry in range(6):
                            time.sleep(5)
                            repos = server_handle.getRepositoryNames()
                            if repo_bare in list(repos or []):
                                print(f"[PyGhidra-MCP-Bridge] ✓ Repository '{repo_bare}' now accessible")
                                break
                        else:
                            raise RuntimeError(f"Repository '{repo_bare}' exists but not accessible after 30s. Check server ACL.")
                    else:
                        raise

            # Create shared project connected to server repository
            _server_handle = server_handle

            local_project_dir = "/ghidra-projects"
            local_project_name = f"checkout-{repo_bare}"
            os.makedirs(local_project_dir, exist_ok=True)

            print(f"[PyGhidra-MCP-Bridge] Opening shared project for repository '{repo_bare}'...")

            from ghidra.pyghidra import PyGhidraProjectManager
            from ghidra.framework.model import ProjectLocator
            import shutil

            locator = ProjectLocator(local_project_dir, local_project_name)
            repo_adapter = server_handle.getRepository(repo_bare)
            if repo_adapter is None:
                raise RuntimeError(f"Failed to get repository adapter for '{repo_bare}'")

            pm = PyGhidraProjectManager()

            # Clean stale local checkout to ensure fresh connection
            local_gpr = os.path.join(local_project_dir, f"{local_project_name}.gpr")
            local_rep = os.path.join(local_project_dir, f"{local_project_name}.rep")
            if os.path.exists(local_gpr):
                os.remove(local_gpr)
            if os.path.exists(local_rep):
                shutil.rmtree(local_rep, ignore_errors=True)

            _project = pm.createProject(locator, repo_adapter, False)
            print(f"[PyGhidra-MCP-Bridge] ✓ Created shared project")

            # List programs in server repository
            root_folder = _project.getProjectData().getRootFolder()
            program_files = list(root_folder.getFiles())
            all_files = _collect_all_files(root_folder)
            if all_files:
                names = []
                for f in all_files:
                    path = f.getPathname()  # e.g. "/38.1.0/libsscronet_live.so"
                    names.append(path.lstrip("/"))
                print(f"[PyGhidra-MCP-Bridge] Programs in repo ({len(names)}): {names}")
            else:
                print(f"[PyGhidra-MCP-Bridge] Programs in repo: (empty)")

            # Auto-import binary if IMPORT_BINARY_NAME is set
            import_name = os.environ.get("IMPORT_BINARY_NAME", "")
            if import_name:
                import_path = f"/import/{import_name}"
                if os.path.exists(import_path):
                    existing = root_folder.getFile(import_name)
                    if existing is None:
                        print(f"[PyGhidra-MCP-Bridge] Importing binary: {import_name}")
                        _import_program(import_path, name=import_name, analyze=True)
                        print(f"[PyGhidra-MCP-Bridge] ✓ Binary imported: {import_name}")
                        # Refresh file list after import
                        program_files = list(root_folder.getFiles())
                        all_files = _collect_all_files(root_folder)
                    else:
                        print(f"[PyGhidra-MCP-Bridge] Binary already exists: {import_name}")
                else:
                    print(f"[PyGhidra-MCP-Bridge] ⚠ Import file not found: {import_path}")

            # Open program: prefer PROGRAM_NAME env var, fallback to first available
            # Supports paths like "38.1.0/libmetasec_ml.so" or just "libmetasec_ml.so"
            target_name = os.environ.get("PROGRAM_NAME", "")
            if target_name:
                domain_file = _find_domain_file(root_folder, target_name)
                if domain_file is None:
                    # DomainFolder can't see server subdirectories after createProject.
                    # Close project, reopen via GhidraProject which can openProgram by path.
                    # Build list of paths to try: explicit path first, then scan subfolders
                    paths_to_try = ["/" + target_name.lstrip("/")]

                    # If target has no path separator, scan subfolders by filename
                    if "/" not in target_name:
                        # Use all_files from earlier listing to find matching filenames
                        for f in all_files:
                            if f.getName() == target_name:
                                resolved = f.getPathname()  # e.g. "/38.1.0/libsscronet_live.so"
                                if resolved not in paths_to_try:
                                    paths_to_try.append(resolved)
                                    print(f"[PyGhidra-MCP-Bridge] Found '{target_name}' at: {resolved}")

                    for try_path in paths_to_try:
                        try:
                            if _project is not None:
                                _project.close()
                                _project = None
                            _ghidra_project = GhidraProject.openProject(
                                local_project_dir, local_project_name
                            )
                            folder_path = try_path.rsplit("/", 1)[0] or "/"
                            prog_name = try_path.rsplit("/", 1)[1]
                            _current_program = _ghidra_project.openProgram(folder_path, prog_name, False)
                            _project = _ghidra_project.getProject()
                            if _current_program is not None:
                                print(f"[PyGhidra-MCP-Bridge] ✓ Program loaded via path: {_current_program.getName()}")
                                domain_file = True  # skip normal DomainFile open
                                break
                        except Exception as e:
                            print(f"[PyGhidra-MCP-Bridge] openProgram('{try_path}') error: {type(e).__name__}: {e}")

                if domain_file is None:
                    available = [f.getPathname() for f in all_files] if all_files else []
                    raise FileNotFoundError(
                        f"Program '{target_name}' not found. Available: {available}"
                    )
            elif program_files:
                domain_file = program_files[0]
            elif all_files:
                domain_file = all_files[0]
            else:
                domain_file = None

            if domain_file is True:
                pass  # Already loaded via GhidraProject.openProgram above
            elif domain_file:
                from ghidra.util.task import TaskMonitor
                _current_program = domain_file.getDomainObject(_project, False, False, TaskMonitor.DUMMY)
                print(f"[PyGhidra-MCP-Bridge] ✓ Program loaded: {domain_file.getName()}")
            else:
                print(f"[PyGhidra-MCP-Bridge] ⚠ No programs in repository")
                _current_program = None

        except Exception as e:
            print(f"[PyGhidra-MCP-Bridge] ✗ Failed to connect to server: {e}")
            import traceback
            traceback.print_exc()
            raise

    else:
        raise ValueError(f"Invalid PROJECT_MODE: {project_mode} (must be 'local' or 'server')")

    # Create mock state object for API compatibility
    _mock_state = MockGhidraState(_ghidra_project, _current_program)

    return _mock_state


def _list_programs():
    """List all programs in the current project/repository."""
    proj_data = None
    if _project is not None:
        proj_data = _project.getProjectData()
    elif _ghidra_project is not None:
        proj_data = _ghidra_project.getProjectData()
    if proj_data is None:
        return []

    root = proj_data.getRootFolder()
    results = []
    for f in _collect_all_files(root):
        info = {"name": f.getName(), "path": f.getPathname()}
        if _current_program:
            info["active"] = (f.getName() == _current_program.getName())
        else:
            info["active"] = False
        results.append(info)
    return results


def _switch_program(name):
    """Deprecated. Program selection must be fixed at startup."""
    raise RuntimeError(
        "Runtime program switching is deprecated and disabled. "
        "Start a dedicated bridge/client with PROGRAM_NAME or BINARY set "
        "to the target program name/path."
    )


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
    try:
        s = str(obj)
        if s and not s.startswith("<") and "object at 0x" not in s:
            return s
    except Exception:
        pass
    try:
        items = []
        for item in obj:
            items.append(_serialize(item, depth + 1))
            if len(items) > 1000:
                items.append("...(truncated)")
                break
        return items
    except (TypeError, StopIteration):
        pass
    try:
        result = {}
        for entry in obj.entrySet():
            result[str(entry.getKey())] = _serialize(entry.getValue(), depth + 1)
        return result
    except (AttributeError, TypeError):
        pass
    return str(obj)


def _exec_python_inprocess(code):
    """Execute Python code in-process with access to currentProgram via globals."""
    import io
    import traceback

    # Build globals with Flat API-like functions
    exec_globals = {
        "__builtins__": __builtins__,
        "currentProgram": lambda: _current_program,
        "currentAddress": lambda: None,
        "currentSelection": lambda: None,
        "currentHighlight": lambda: None,
    }

    # Make Java imports available
    try:
        import ghidra
        exec_globals["ghidra"] = ghidra
    except ImportError:
        pass

    _buf = io.StringIO()
    _old_stdout = sys.stdout
    start_time = time.time()

    try:
        sys.stdout = _buf
        exec(code, exec_globals)
        sys.stdout = _old_stdout

        output = {
            "success": True,
            "stdout": _buf.getvalue(),
            "execution_time_ms": int((time.time() - start_time) * 1000),
        }

        if "result" in exec_globals:
            try:
                output["result"] = _serialize(exec_globals["result"])
            except Exception as e:
                output["result"] = str(exec_globals["result"])
                output["result_serialization_warning"] = str(e)

    except Exception:
        sys.stdout = _old_stdout
        output = {
            "success": False,
            "error": str(sys.exc_info()[1]),
            "traceback": traceback.format_exc(),
            "stdout": _buf.getvalue(),
            "execution_time_ms": int((time.time() - start_time) * 1000),
        }

    return output


def _exec_java_headless(code, readonly=True, noanalysis=True, timeout=120):
    """Execute Java code via analyzeHeadless subprocess.

    Supports two forms:
    - Full class: code contains 'extends GhidraScript' -> run as-is
    - Snippet: code is the run() method body -> wrap in template
    """
    import re
    import tempfile as _tempfile

    ts = int(time.time() * 1000)
    result_path = os.path.join(_tempfile.gettempdir(), f"ghidra_exec_result_{ts}.json")
    cleanup_files = [result_path]
    is_full_class = "extends GhidraScript" in code

    if is_full_class:
        # Extract class name from source
        match = re.search(r'public\s+class\s+(\w+)', code)
        if not match:
            return {"success": False, "error": "Could not find 'public class <Name>' in Java code"}
        class_name = match.group(1)
        code_content = code
    else:
        class_name = f"GhidraExec_{ts}"
        code_content = _build_java_script(class_name, code)

    script_file = os.path.join(_tempfile.gettempdir(), f"{class_name}.java")
    with open(script_file, 'w', encoding='utf-8') as f:
        f.write(code_content)
    cleanup_files.append(script_file)

    try:
        # For full scripts, result_path is passed as args[0] but script may not use it
        # For template-wrapped snippets, the template writes result JSON
        cmd = _build_headless_cmd(
            script_name=f"{class_name}.java",
            script_path=_tempfile.gettempdir(),
            result_path=result_path,
            extra_args=[],
            readonly=readonly,
            noanalysis=noanalysis,
        )

        start_time = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        execution_time_ms = int((time.time() - start_time) * 1000)

        # Try to read structured result (template-wrapped scripts write this)
        if os.path.exists(result_path):
            with open(result_path, 'r', encoding='utf-8') as f:
                result = json.load(f)
        else:
            # Full scripts: success based on return code, stdout from subprocess
            result = {
                "success": proc.returncode == 0,
                "stdout": "",
            }
            if proc.returncode != 0:
                result["error"] = "Script execution failed (non-zero exit code)"

        # Extract println output from analyzeHeadless stdout
        # Script println() lines appear as: "INFO  ClassName.java> message (GhidraScript)"
        if proc.stdout:
            lines = proc.stdout.split("\n")
            script_output = []
            for line in lines:
                stripped = line.strip()
                if "(GhidraScript)" not in stripped:
                    continue
                # Remove "INFO  " prefix and " (GhidraScript)" suffix
                parts = stripped.split(None, 1)
                if len(parts) < 2:
                    continue
                msg = parts[1]
                paren_idx = msg.rfind("(GhidraScript)")
                if paren_idx > 0:
                    msg = msg[:paren_idx].rstrip()
                # Remove "ClassName.java> " prefix from println output
                gt_idx = msg.find("> ")
                if gt_idx > 0 and msg[:gt_idx].endswith(".java"):
                    msg = msg[gt_idx + 2:]
                script_output.append(msg)

            if script_output and not result.get("stdout"):
                result["stdout"] = "\n".join(script_output)

            result["subprocess_stdout"] = proc.stdout[-4000:]

        if proc.stderr:
            result["subprocess_stderr"] = proc.stderr[-2000:]

        result["returncode"] = proc.returncode
        result["execution_time_ms"] = execution_time_ms
        return result

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Timeout after {timeout}s",
        }
    except FileNotFoundError as e:
        return {
            "success": False,
            "error": f"analyzeHeadless not found: {e}",
        }
    finally:
        for fp in cleanup_files:
            try:
                os.remove(fp)
            except OSError:
                pass


def _build_java_script(class_name, user_code):
    """Build a Java Ghidra script from template by replacing placeholders."""
    template_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "scripts", "exec_runner_template.java"
    )
    with open(template_path, 'r', encoding='utf-8') as f:
        template = f.read()
    return template.replace("{CLASS_NAME}", class_name).replace("{USER_CODE}", user_code)


def _build_headless_cmd(script_name, script_path, result_path, extra_args=None,
                        readonly=True, noanalysis=True):
    """Build analyzeHeadless command line from environment configuration."""
    import tempfile as _tempfile

    ghidra_home = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
    analyze = os.path.join(ghidra_home, "support", "analyzeHeadless")

    project_mode = os.environ.get("PROJECT_MODE", "local")
    project_path = os.environ.get("PROJECT_PATH", "/ghidra-projects")
    project_name = os.environ.get("PROJECT_NAME", "default")

    # Determine current program name
    prog_name = ""
    if _current_program:
        prog_name = _current_program.getName()

    if project_mode == "server":
        server_host = os.environ.get("GHIDRA_SERVER_HOST", "localhost")
        server_port = os.environ.get("GHIDRA_SERVER_PORT", "13100")
        server_user = os.environ.get("GHIDRA_SERVER_USER", "")
        server_keystore = os.environ.get("GHIDRA_SERVER_KEYSTORE", "")
        repo_name = os.environ.get("GHIDRA_SERVER_REPO", "").lstrip("/")

        cmd = [
            analyze,
            f"ghidra://{server_host}:{server_port}/{repo_name}/",
        ]
        if server_user:
            cmd.extend(["-connect", server_user])
        if server_keystore:
            cmd.extend(["-keystore", server_keystore])
        if prog_name:
            cmd.extend(["-process", prog_name])
    else:
        cmd = [analyze, project_path, project_name]
        if prog_name:
            cmd.extend(["-process", prog_name])

    if readonly:
        cmd.append("-readOnly")
    if noanalysis:
        cmd.append("-noanalysis")

    # Script arguments: result_path first, then extras
    script_args = [result_path] + (extra_args or [])
    cmd.extend(["-postScript", script_name] + script_args)
    cmd.extend(["-scriptPath", script_path])

    return cmd


def _discover_and_load_api_modules():
    """
    自动发现并加载 api/ 和 api_v*/ 目录下所有模块。
    模块使用 @route 装饰器自动注册路由。
    """
    # Ensure script directory is in sys.path (PyGhidra may reset it)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # 先 reload api 包本身，确保使用最新版本
    import api
    importlib.reload(api)
    from api import clear_routes, get_route_list

    # 清空现有路由
    clear_routes()

    reloaded = []
    errors = []

    # 收集所有 API 目录: api/ + api_v*/
    api_dirs = []

    # 主目录 api/
    main_api_dir = os.path.join(script_dir, "api")
    if os.path.isdir(main_api_dir):
        api_dirs.append(("api", main_api_dir))

    # 版本化目录 api_v1/, api_v2/, ...
    for entry in sorted(os.listdir(script_dir)):
        if entry.startswith("api_v") and os.path.isdir(os.path.join(script_dir, entry)):
            api_dirs.append((entry, os.path.join(script_dir, entry)))

    # 加载每个目录下的模块
    for package_name, api_dir in api_dirs:
        for filename in sorted(os.listdir(api_dir)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue

            module_name = f"{package_name}.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                importlib.reload(module)
                reloaded.append(module_name)
            except Exception as e:
                errors.append(f"{module_name}: {e}")

    return {
        "success": len(errors) == 0,
        "reloaded": reloaded,
        "routes": get_route_list(),
        "errors": errors if errors else None
    }


def _cache_ghidra_context():
    """Initialize PyGhidra and load API modules."""
    global _mock_state

    # Initialize PyGhidra and load project
    _mock_state = _init_ghidra_project()

    # Load API modules
    result = _discover_and_load_api_modules()
    if not result.get("success"):
        print(f"[PyGhidra-MCP-Bridge] Warning: Failed to load some API modules: {result.get('errors')}")

    return result.get("routes", [])


class GhidraRequestHandler(BaseHTTPRequestHandler):
    server_version = "PyGhidraMCP/1.0"

    def _send_json(self, payload: Dict[str, Any], status: int = 200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length) if length else b""
        try:
            return json.loads(data.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def log_message(self, format: str, *args: Any) -> None:
        # Log HTTP requests to file
        try:
            log_debug("HTTP %s", format % args)
        except Exception:
            pass

    def do_GET(self):
        """Handle GET requests."""
        from api import dispatch_route

        # Special system routes
        if self.path == "/_reload":
            result = _discover_and_load_api_modules()
            self._send_json(result)
            return

        if self.path == "/_shutdown":
            self._send_json({"success": True, "message": "Shutdown requested"})
            # Shutdown in background thread
            def shutdown():
                time.sleep(0.5)
                if _server_instance:
                    _server_instance.shutdown()
            threading.Thread(target=shutdown, daemon=True).start()
            return

        # Dispatch to API routes
        try:
            # Parse URL to separate path and query string
            parsed = urlparse(self.path)
            path = parsed.path
            query_params = parse_qs(parsed.query)
            # Convert query params to single values (instead of lists)
            params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

            # Pass mock state to route handlers
            result = dispatch_route(path, _mock_state, params)
            if result is not None:
                self._send_json(result)
            else:
                self._send_json({"error": f"Unknown route: {path}"}, 404)
        except Exception as exc:
            log_debug(f"Error handling GET {self.path}: {exc}")
            self._send_json({"error": str(exc)}, 500)

    def do_POST(self):
        """Handle POST requests."""
        from api import dispatch_route

        try:
            path = self.path.split("?")[0]

            # ============================================================
            # V1 Edit API (POST-only) - wrapped with checkout/commit
            # ============================================================
            if path == "/api/v1/edit":
                try:
                    body = self._read_json()
                except ValueError as e:
                    return self._send_json(
                        {"success": False, "error": str(e)}, 400
                    )
                from api.checkout import ensure_checkout, auto_commit
                ok, err = ensure_checkout(_mock_state)
                if not ok:
                    return self._send_json(err)
                from api_v1 import edit as v1_edit
                result = v1_edit.edit(_mock_state, body)
                if isinstance(result, dict) and result.get("success", False):
                    commit_info = auto_commit(_mock_state)
                    if commit_info is not None:
                        result["_commit"] = commit_info
                return self._send_json(result)

            # ============================================================
            # V1 Exec API (POST-only) - Script execution
            # ============================================================
            if path == "/api/v1/exec":
                try:
                    body = self._read_json()
                except ValueError as e:
                    return self._send_json(
                        {"success": False, "error": str(e)}, 400
                    )

                code = body.get("code", "")
                language = body.get("language", "python")
                readonly = body.get("readonly", True)

                if not code.strip():
                    return self._send_json({"success": False, "error": "Missing 'code'"})

                # Checkout/commit wrapper for non-readonly exec
                if not readonly:
                    from api.checkout import ensure_checkout, auto_commit
                    ok, err = ensure_checkout(_mock_state)
                    if not ok:
                        return self._send_json(err)

                if language == "java":
                    noanalysis = body.get("noanalysis", True)
                    timeout = body.get("timeout", 120)
                    result = _exec_java_headless(
                        code, readonly=readonly, noanalysis=noanalysis, timeout=timeout
                    )
                else:
                    result = _exec_python_inprocess(code)

                result["mode"] = "headless"

                if not readonly and isinstance(result, dict) and result.get("success", False):
                    from api.checkout import auto_commit
                    commit_info = auto_commit(_mock_state)
                    if commit_info is not None:
                        result["_commit"] = commit_info

                return self._send_json(result)

            # Read JSON body
            body = self._read_json()

            # Dispatch to API routes (pass body as query params)
            result = dispatch_route(path, _mock_state, body)
            if result is not None:
                self._send_json(result)
            else:
                self._send_json({"error": f"Unknown route: {path}"}, 404)
        except Exception as exc:
            log_debug(f"Error handling POST {self.path}: {exc}")
            self._send_json({"error": str(exc)}, 500)


def start_server(host: str = HOST, port: int = PORT):
    """Start the HTTP API server."""
    global _server_instance, _server_thread

    # Try to find available port
    for attempt in range(10):
        try:
            server = ThreadingHTTPServer((host, port), GhidraRequestHandler)
            _server_instance = server

            # Start server in daemon thread
            def run():
                server.serve_forever()

            _server_thread = threading.Thread(target=run, daemon=True)
            _server_thread.start()

            return server, port
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"[PyGhidra-MCP-Bridge] Port {port} in use, trying {port + 1}...")
                port += 1
            else:
                raise

    raise RuntimeError(f"Could not find available port after 10 attempts")


def _start_mcp_server(host: str, port: int, http_port: int):
    """Start MCP SSE Proxy as subprocess."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mcp_script = os.path.join(script_dir, "scripts", "mcp_sse_proxy.py")

    if not os.path.exists(mcp_script):
        print(f"[PyGhidra-MCP-Bridge] Warning: MCP SSE script not found: {mcp_script}")
        return None

    # Start MCP server as subprocess
    for attempt in range(10):
        try:
            cmd = [
                sys.executable,
                mcp_script,
                "--host", host,
                "--port", str(port),
                "--ghidra-port", str(http_port)
            ]

            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )

            # Wait a bit to ensure it started
            time.sleep(1)
            return port
        except Exception as e:
            if attempt < 9:
                port += 1
            else:
                print(f"[PyGhidra-MCP-Bridge] Warning: Failed to start MCP server: {e}")
                return None

    return None


def _print_startup_banner(host: str, port: int, mcp_port: Optional[int], routes: list):
    """Print startup information."""
    print("\n")
    print("=" * 60)
    print("  Ghidra MCP Bridge - PyGhidra Edition")
    print("=" * 60)

    # Server URLs
    http_url = f"http://{host}:{port}"
    print(f"HTTP API:   {http_url}")
    if mcp_port:
        mcp_url = f"http://{host}:{mcp_port}/sse"
        print(f"MCP SSE:    {mcp_url}")
        mcp_config = json.dumps({"type": "sse", "url": mcp_url})
        print(f"MCP Config: {mcp_config}")

    # Log file
    print(f"Log file:   {get_log_file_path()}")

    # Program info
    if _current_program:
        name = _current_program.getName()
        lang = _current_program.getLanguage()
        arch = lang.getProcessor().toString()
        bits = lang.getDefaultSpace().getSize() * 8
        func_count = _current_program.getFunctionManager().getFunctionCount()
        print(f"Program:    {name} ({arch}/{bits}-bit, {func_count} functions)")
    else:
        print(f"Program:    (No program loaded)")

    # API routes
    print(f"API Routes: {len(routes)} endpoints loaded")

    print("=" * 60)
    print(f"Try: {http_url}/api/basic_info")
    print("=" * 60)
    print("\n")


def main():
    """Main entry point for PyGhidra mode."""
    try:
        # Initialize Ghidra and load API modules
        print("[PyGhidra-MCP-Bridge] Starting...")
        routes = _cache_ghidra_context()

        # Start HTTP API server
        srv, actual_port = start_server(host=HOST, port=PORT)

        # Start MCP SSE Proxy
        actual_mcp_port = _start_mcp_server(host=HOST, port=MCP_PORT, http_port=actual_port)

        # Print startup banner
        _print_startup_banner(HOST, actual_port, actual_mcp_port, routes)

        # Keep main thread alive
        print("[PyGhidra-MCP-Bridge] Server running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[PyGhidra-MCP-Bridge] Shutting down...")
            if _server_instance:
                _server_instance.shutdown()

        return srv
    except Exception as exc:
        print(f"[PyGhidra-MCP-Bridge] Failed to start server: {exc}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    # Ensure this module is accessible by name (not just as __main__)
    # so that API modules importing "ghidra_mcp_server_pyghidra" see the same globals.
    sys.modules["ghidra_mcp_server_pyghidra"] = sys.modules[__name__]
    main()
