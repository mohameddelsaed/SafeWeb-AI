---
Source agent: Security Review Agent
Run date: 2026-06-23
Inputs used: src/services/api.ts, backend/config/settings/base.py, backend/apps/accounts/models.py, backend/apps/scanning/views.py
Status: draft
---

# Tenant Isolation Review

- **Architecture**: Shared Database, Shared Schema.
- **Enforcement**: Isolation is enforced purely at the application layer via ORM query filtering. 
- **Evidence**: `backend/apps/scanning/views.py` consistently uses `.filter(user=request.user)` or `.get(id=id, user=request.user)` to restrict access to Scans and Vulnerabilities.
- **Database Level**: No Row-Level Security (RLS) policies are configured in the Django models or settings. Reliance is entirely on view-level query constraints.
