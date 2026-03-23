"""
Memory API - Read raw bytes from program memory.

State Passing Pattern - read bytes at arbitrary addresses for constant tables,
S-Box, key schedules, etc.

Routes:
    GET /api/memory/read?address=0x611&length=256&format=hex
"""

from api import route
import struct
import base64

MAX_LENGTH = 16384  # 16KB


def _format_values(raw, fmt):
    """Format raw byte list according to the requested format."""
    if fmt == "hex":
        return ' '.join('%02x' % b for b in raw)
    elif fmt == "base64":
        return base64.b64encode(bytes(raw)).decode('ascii')
    elif fmt == "ascii":
        return ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
    elif fmt.startswith("u"):
        size_map = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}
        base = fmt.replace("le", "").replace("be", "")
        elem_size = size_map.get(base)
        if elem_size is None:
            # fallback to hex
            return ' '.join('%02x' % b for b in raw)
        is_big = fmt.endswith("be")
        # truncate to aligned length
        usable = (len(raw) // elem_size) * elem_size
        result = []
        fmt_char = {1: 'B', 2: ('>H' if is_big else '<H'),
                    4: ('>I' if is_big else '<I'),
                    8: ('>Q' if is_big else '<Q')}
        for i in range(0, usable, elem_size):
            chunk = bytes(raw[i:i + elem_size])
            if elem_size == 1:
                result.append(chunk[0])
            else:
                result.append(struct.unpack(fmt_char[elem_size], chunk)[0])
        return result
    else:
        # fallback to hex
        return ' '.join('%02x' % b for b in raw)


@route("/api/memory/read")
def read_memory(state, address="", length=256, format="hex"):
    """
    Read raw bytes from program memory.

    Args:
        state: Ghidra state object
        address: Start address (e.g., "0x611")
        length: Number of bytes to read (max 16384)
        format: Output format - hex/base64/ascii/u8/u16le/u16be/u32le/u32be/u64le/u64be

    Route: GET /api/memory/read?address=<addr>&length=256&format=hex
    """
    prog = state.getCurrentProgram()
    if prog is None:
        return {"success": False, "error": "No program loaded"}

    addr_str = str(address).strip()
    if not addr_str:
        return {"success": False, "error": "Parameter 'address' is required"}

    # Parse address
    if not addr_str.lower().startswith("0x"):
        addr_str = "0x" + addr_str
    try:
        addr = prog.getAddressFactory().getAddress(addr_str)
    except Exception:
        addr = None
    if addr is None:
        return {"success": False, "error": "Invalid address: %s" % address}

    # Clamp length
    length = min(int(length), MAX_LENGTH)
    if length <= 0:
        return {"success": False, "error": "Length must be positive"}

    # Validate format
    fmt = str(format).lower()
    valid_formats = ("hex", "base64", "ascii",
                     "u8", "u16le", "u16be", "u32le", "u32be", "u64le", "u64be")
    if fmt not in valid_formats:
        return {"success": False,
                "error": "Invalid format: %s. Valid: %s" % (format, ", ".join(valid_formats))}

    # Read bytes
    mem = prog.getMemory()
    raw = []
    for i in range(length):
        try:
            b = mem.getByte(addr.add(i)) & 0xFF
            raw.append(b)
        except Exception:
            break  # hit unreadable address, truncate

    if not raw:
        return {"success": False, "error": "Cannot read memory at %s" % addr_str}

    # Memory block name
    block = mem.getBlock(addr)
    block_name = block.getName() if block else None

    # Format output
    values = _format_values(raw, fmt)

    data = {
        "address": "0x" + str(addr),
        "length": len(raw),
        "block": block_name,
        "format": fmt,
        "values": values,
    }

    # Attach ascii preview for non-ascii formats
    if fmt != "ascii":
        data["ascii_preview"] = ''.join(
            chr(b) if 32 <= b < 127 else '.' for b in raw[:64]
        )

    return {"success": True, "data": data}
