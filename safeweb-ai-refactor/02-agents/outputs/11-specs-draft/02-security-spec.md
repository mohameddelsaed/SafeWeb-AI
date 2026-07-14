---
Spec ID: 02-security-spec
Version: 1.0
Status: draft
Source agent: Spec Generation Agent
Run date: 2026-06-23
Supersedes: none
---

## 1. Purpose & Scope
Governs the internal security posture of SafeWeb AI itself (auth, secrets, isolation). It does NOT govern the security scanning engine's detection rules (see 03-scanner-engine-spec).

## 2. Findings Addressed
| Finding ID | Source Agent | How This Spec Resolves It |
|---|---|---|
| BE-003 | Backend Agent | Mandates strict resource limits on spawned processes to prevent host starvation. |

## 3. Requirements
### 3.1 Functional Requirements
- REQ-SEC-001: JWT tokens must be used for API authentication with strict expiration.
- REQ-SEC-002: AI API keys (e.g., OpenRouter) must be encrypted at rest in the database.

### 3.2 Non-Functional Requirements
- REQ-SEC-NFR-001: All spawned subprocesses (e.g., nuclei) must execute with strict timeouts and bounded memory limits (cgroups/ulimit) to mitigate BE-003.

## 4. Out of Scope
- Specific detection rules for the scanner engine.

## 5. Dependencies
- Depends on: 01-architecture-spec
- Depended on by: 07-multi-tenancy-spec

## 6. Open Questions / Decisions Needed
- None

## 7. Acceptance Criteria
No plaintext API keys in DB; subprocesses cleanly timeout without hanging the host.

## 8. Change Log
| Version | Date | What changed | Why |
|---|---|---|---|
| 1.0 | 2026-06-23 | Initial draft | Agent 11 execution |
