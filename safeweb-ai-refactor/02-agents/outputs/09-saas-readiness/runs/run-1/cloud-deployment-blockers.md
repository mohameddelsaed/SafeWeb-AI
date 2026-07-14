---
Source agent: SaaS Readiness Agent
Run date: 2026-06-23
Status: draft
---

# Cloud Deployment Blockers

1. **Subprocess Resource Exhaustion (BE-003)**: Spawning numerous heavy CLI tools (`nuclei`) per scan could exhaust system resources (CPU/RAM/File Descriptors) when dozens of scans run concurrently in a multi-tenant cloud environment. This blocks safe concurrent scaling.
2. **In-Memory Fallback Threading (BE-002)**: Spawning background threads directly in the web server process when Celery is unreachable risks RAM exhaustion and API worker crashes under heavy multi-tenant load.
3. **Missing API Versioning (BE-001)**: The lack of a formal API versioning strategy blocks seamless feature rollouts to multi-tenant customers, risking widespread disruption.
