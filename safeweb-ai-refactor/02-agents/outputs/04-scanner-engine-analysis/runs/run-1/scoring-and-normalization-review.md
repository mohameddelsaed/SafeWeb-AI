---
Source agent: Scanner Engine Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, backend/apps/scanning/engine/, 01-research/tool-availability-matrix/
Status: draft
---

# Scoring and Normalization Review

- **Intermediate Representation**: External wrappers and native testers yield data via the `ToolResult` dataclass or generic dicts.
- **Normalization Pipeline**: The `ScanOrchestrator` consumes these results. Phase 5 iterates through tool findings and calls `_create_vuln(vuln_data)`.
- **Deduplication**: Findings are deduplicated based on an MD5 signature computed from the vulnerability `name` and the `affected_url`. This prevents repeated findings if multiple tools flag the same issue on the same endpoint.
- **Database Insertion**: The normalized dict is purged of internal state keys (keys prefixed with `_`) and mapped directly into the `Vulnerability` Django ORM model (`Vulnerability.objects.create()`).
