---
Source agent: Scanner Engine Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, backend/apps/scanning/engine/, 01-research/tool-availability-matrix/
Status: draft
---

# External Tool Integration Review

- **Base Implementation**: All external tools inherit from `ExternalTool` in `backend/apps/scanning/engine/tools/base.py`.
- **Execution Mechanism**: Tools are executed using either `_exec()` (which utilizes `subprocess.run()`) or `_exec_async()` (which utilizes `asyncio.create_subprocess_exec()`). Both methods strictly pass arguments as arrays/lists (bypassing `shell=True`), which mitigates direct shell injection.
- **Output Management**: Output size is aggressively capped at 5MB (`_MAX_OUTPUT_BYTES`) to prevent memory exhaustion from verbose tools.
- **Availability Constraints**: The `is_available()` check queries the system `PATH` via `shutil.which()`. Tools explicitly identified in the tool availability matrix (e.g., Nuclei, Nmap, Subfinder) must be present in the deployment environment (e.g., Docker container or Nixpacks).
