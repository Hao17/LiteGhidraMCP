# Ghidra MCP Bridge

English | [简体中文](README_ZH.md)

> **Version**: this branch targets Ghidra 12.0+ (PyGhidra). Ghidra 11.x users → [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) branch or the [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag.

A PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+, exposing Ghidra's reverse engineering capabilities to AI agents.

### Highlights

- **7 MCP tools** — single entry, pattern-dispatched to 50+ APIs. No tool sprawl.
- **Version control + AI/human collaboration** — multiple AI agents and humans work on the same binary via Ghidra Server, with full version history.
- **Multi-binary cross-analysis** — spin up multiple clients against different binaries in one project. Ideal for VMP unpacking, DLL-EXE interaction tracing, and multi-module firmware.
- **AI-friendly** — install the skill and let Claude Code / Codex start the server, import binaries, configure MCP, and begin analysis.

---

## Quick Start

### Let AI do it ⭐

```bash
git clone https://github.com/Hao17/LiteGhidraMCP.git && cd LiteGhidraMCP
pip install -e .
gmcp install -d . skill claude-code   # or: codex / cursor / copilot
```

Then tell your AI: *"Help me analyze ~/Downloads/firmware.bin"* — the skill teaches it the rest.

### Docker (recommended)

```bash
pip install -e .                                # installs the `gmcp` CLI
gmcp server up                                  # first run prompts admin registration
gmcp server repo create test                    # admin-owned: clients can't create repos
gmcp client start 1 --repo test --binary-file ~/firmware.bin
gmcp install mcp claude-code                    # or: claude-desktop / coco
```

HTTP API on `:8803`, MCP SSE on `:8804/sse`. Multi-client port math: client N → `8800+(N-1)*10+3` (HTTP) / `+4` (SSE).

> **Apple Silicon / ARM hosts**: the official Ghidra distribution has no `linux_arm_64` decompiler binary; the compose files default to `linux/amd64` to avoid `Could not find decompiler executable`.

For multi-client setup, GUI connection, the local-project mode, and user/ACL management → **[docker/QUICKSTART.md](docker/QUICKSTART.md)**.

### GUI mode (no Docker)

Run the script directly inside Ghidra:

1. Launch with PyGhidra: `<ghidra_install>/support/pyghidraRun`
2. Install Bridge deps **into the PyGhidra venv** (not system Python):
   ```bash
   ~/Library/ghidra/ghidra_<VERSION>_PUBLIC/venv/bin/python3 -m pip install -r requirements.txt
   ```
3. In Ghidra → Script Manager → add this repo to script directories → run `ghidra_mcp_server.py`

If you see `MCP proxy failed to start` + `ModuleNotFoundError: No module named 'mcp'`, step 2 hit the wrong Python.

---

## MCP Tools

| Tool | Description |
|------|-------------|
| **ghidra_overview** | Binary survey — metadata, memory layout, key functions, imports/exports, strings |
| **ghidra_search** | Search functions, symbols, strings, cross-references, bytes, instructions |
| **ghidra_view** | Decompilation / disassembly / memory viewing |
| **ghidra_list** | Symbol list browsing (functions, classes, imports, exports, ...) |
| **ghidra_edit** | Rename, set datatypes, add comments (batch supported) |
| **ghidra_exec** | Execute custom Python/Java scripts with full Ghidra API access |
| **ghidra_version** | Version log / rollback / revert (Server mode only) |

For the underlying HTTP API (50+ routes), see **[CLAUDE.md](CLAUDE.md)**.

---

## Documentation

- **[docker/QUICKSTART.md](docker/QUICKSTART.md)** — Docker deployment, multi-client, user/ACL management, troubleshooting
- **[skills/SKILL.md](skills/SKILL.md)** — the workflow doc that `gmcp install skill` writes into your project
- **[CLAUDE.md](CLAUDE.md)** — full API reference, architecture, hot reload, contributing
