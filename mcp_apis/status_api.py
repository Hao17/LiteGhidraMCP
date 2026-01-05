from typing import Dict, Any

from .common import get_current_address, get_program


def handle_status() -> Dict[str, Any]:
    prog = get_program()
    current_addr = get_current_address()
    return {
        "status": "ok",
        "program": prog.getName(),
        "currentAddress": str(current_addr) if current_addr else None,
    }
