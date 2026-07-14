# SafeWeb AI Autonomous Pentesting Constitution
**Version**: 2.0.0  
**Status**: ENFORCED  

This document defines the non-negotiable architectural principles and safety invariants governing the SafeWeb AI autonomous multi-agent pentesting platform. All future code modifications, subagents, and deployment pipelines must strictly adhere to these articles.

## Article I: Non-Negotiable Safety & Scope Governance
1. **Mandatory Scope Allowlist Gate**: No Tier-2 (execution-capable) agent shall execute any tool call or network transmission until the target URL, hostname, and IP address have been deterministically validated against an explicit, user-authorized scope allowlist. Out-of-scope redirection requests must trigger an immediate flow termination (`aborted_scope_violation`).
2. **Default Non-Destructive Intensity**: All scan workflows default to `intensity=safe`. State-mutating payloads (e.g., `DELETE`/`UPDATE` SQL injection, account deletion CSRF, destructive fuzzing) are strictly forbidden unless the engagement playbook explicitly passes an opt-in `intensity=destructive` flag signed by an authorized organization admin.
3. **Hardware Kill-Switch**: The control plane must expose an emergency kill-switch endpoint capable of immediately revoking Celery task tokens and killing all associated ephemeral Docker sandbox containers within 500 milliseconds.

## Article II: Ephemeral & Isolated Execution Boundaries
1. **Zero Control-Plane Tool Execution**: No offensive CLI binary (`nmap`, `nuclei`, `sqlmap`, `ffuf`), exploit script, or untrusted payload shall ever execute directly on the Django API server or Celery orchestrator host.
2. **Single-Use Container Sandboxes**: Every pentest scan engagement must execute inside an ephemeral, network-isolated Docker sandbox (`safeweb-agent-sandbox`). The container must be destroyed immediately upon scan completion or failure. Never reuse a sandbox across separate engagements.

## Article III: The Verification Oracle Invariant
1. **Zero Auto-Trust of Scanners**: Output from automated vulnerability scanners (`nuclei`, `nikto`, `wpscan`) or raw LLM exploit drafts shall never be directly reported as confirmed vulnerabilities. All discovery hits enter the system with `verification_status = 'candidate'`.
2. **3/3 Deterministic Re-Proof Gate**: A candidate finding must be independently re-verified by the `PoC Validator Agent` running inside a clean, unauthenticated sandbox shell. The exploit must successfully trigger the exact vulnerability indicator exactly **3 out of 3 consecutive times**.
3. **Mandatory Proof Capsule**: Only findings possessing a compiled `proof_capsule` (containing exact HTTP request/response buffers, reproduction steps, and CVSS v3.1 vectors) shall be promoted to `verified` status and passed to reporting.

## Article IV: Universal Infrastructure Parity
1. **Strict PostgreSQL Mandate**: SQLite is permanently forbidden across all environments (local development, CI/CD testing, staging, and production). Every instance must connect to PostgreSQL 15+ with the `pgvector` extension enabled.
2. **Universal MCP Tool Layer**: All external tool wrappers must implement the Model Context Protocol (MCP) JSON-RPC schema. Models must interact with tools via structured typed schemas, never via raw shell string concatenations.
3. **Cloud-Agnostic Containerization**: The architecture must maintain 100% parity across local `docker-compose.yml` and production container deployments, ensuring zero vendor lock-in between AWS, Azure, and Railway/Vercel.
