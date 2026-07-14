---
Source agent: Database Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, backend/apps/*/models.py, 01-research/deployment-research/multi-tenancy-patterns.md
Status: draft
---

# ORM Optimization Review

- **`select_related` Usage**: Identified in `backend/apps/chatbot/actions.py` to eagerly fetch the parent `Scan` while querying a `Vulnerability`, and in `admin_panel/views.py` to fetch `User` metadata along with `Scan` list queries.
- **`prefetch_related` Usage**: Explicitly used in `backend/apps/scanning/views.py` (`ScanDetailView`) to efficiently fetch all associated vulnerabilities without triggering an N+1 query pattern. It is also used in the `learn` app for many-to-many relationships (categories and tags).
- **Multi-Tenancy Performance**: Tenant isolation relies on filtering via `user=request.user`. While functionally secure, scaling will eventually require composite indexes (e.g., on `user_id` and `created_at`) to maintain read performance for large multi-tenant datasets.
