---
Spec ID: 10-deployment-spec
Version: 1.0
Status: approved
Source agent: Spec Generation Agent
Run date: 2026-06-23
Supersedes: none
---

## 1. Purpose & Scope
Governs cloud provider provisioning, containerization, and CI/CD pipelines.

## 2. Findings Addressed
| Finding ID | Source Agent | How This Spec Resolves It |
|---|---|---|
| BE-003 | Backend Agent | Enforces container memory limits (cgroups) for the worker environment running external tools. |

## 3. Requirements
### 3.1 Functional Requirements
- REQ-DEP-001: The system shall be deployed to AWS (EC2/ECS) using Docker containers.
- REQ-DEP-002: CI/CD must be handled by GitHub Actions.

### 3.2 Non-Functional Requirements
- REQ-DEP-NFR-001: The deployment architecture must keep costs within typical student project free-tier constraints where possible.

## 4. Out of Scope
- Application code logic.

## 5. Dependencies
- Depends on: 01-architecture-spec
- Depended on by: 11-monitoring-spec

## 6. Open Questions / Decisions Needed
- None

## 7. Acceptance Criteria
Infrastructure can be provisioned entirely via IaC scripts without manual UI clicks.

## 8. Change Log
| Version | Date | What changed | Why |
|---|---|---|---|
| 1.0 | 2026-06-23 | Initial draft | Agent 11 execution |
