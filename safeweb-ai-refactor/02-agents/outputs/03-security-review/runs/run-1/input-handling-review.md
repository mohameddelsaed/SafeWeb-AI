---
Source agent: Security Review Agent
Run date: 2026-06-23
Inputs used: src/services/api.ts, backend/config/settings/base.py, backend/apps/accounts/models.py, backend/apps/scanning/views.py, backend/apps/scanning/engine/tools/base.py
Status: draft
---

# Input Handling Review

- **Ingestion**: User inputs (targets, domains, auth configs) are validated via Django REST Framework serializers (e.g., `ScanCreateSerializer`).
- **Execution Risks**: External tools are invoked using `subprocess.run(args, ...)` or `asyncio.create_subprocess_exec` in `backend/apps/scanning/engine/tools/base.py`. Because the arguments are passed as lists rather than raw shell strings (and `shell=True` is omitted), classic shell injection is mitigated.
- **Argument Injection Risks**: Since user-provided targets are appended to command-line arrays, there remains a potential risk of argument injection (e.g., `--flag payload`) if tool wrappers do not strictly sanitize the shape of the target string.
