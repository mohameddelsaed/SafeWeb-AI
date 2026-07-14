# SafeWeb AI — Codebase Audit Report (Phase 1)

This audit evaluates the current state of the `safeweb-ai` repository against the strict specifications provided in the Master Build Prompt (Features 01-13).

## 3.1 What Exists and Works
- **F01 Authentication & Identity:** Custom `User` model with email/password registration, JWT sessions, basic OAuth routes, and 2FA functionality exist in `backend/apps/accounts/models.py`.
- **F04 Scan Engine:** A sophisticated, modular scanner orchestration system exists in `backend/apps/scanning/engine/`. It correctly manages recon, crawling, external tools with fallback support (`engine/tools/base.py`), and streams progress via SSE.
- **F05 Vulnerability Detection:** Broad test coverage (`xss_tester.py`, logic testing, WAF bypassers) mapped to canonical OWASP categories exists and is well-tested.
- **F07 AI-Powered Explanation:** `LLMReasoningEngine` exists to triage findings using standard system prompts.
- **F08 Reporting Engine:** PDF, CSV, JSON, and SARIF exports are implemented in `backend/apps/scanning/engine/report_generator.py`.
- **F09 Dashboard:** The React frontend contains a solid `Dashboard.tsx` displaying Security Posture metrics, vulnerability severities, and scan trends.

## 3.2 What Exists But Is Wrong
- 🔴 **CRITICAL — F02 Multi-Tenant Org System:** Users are tied to a single `Tenant` via a simple ForeignKey (`tenant = models.ForeignKey(...)` in `accounts/models.py`), which violates the spec: "Users can belong to multiple organizations and switch between them." Role is also stored on the user rather than the membership junction.
- 🟠 **HIGH — F04 Scan Engine:** The scan models use simple string `target` inputs, bypassing proper Target health validation. It also lacks a "Custom" mode for selecting specific vulnerability categories, and rate limiting inputs.
- 🟠 **HIGH — F06 AI Provider Gateway:** The `LLMProvider` abstraction exists, but it lacks per-user/org configuration overrides (no database schema for it) and lacks cost/token tracking.
- 🟡 **MEDIUM — F11 SaaS Infrastructure:** Subscription plans (`free`, `pro`, `enterprise`) are tied to the `User` model rather than the `Tenant` (Org) model.

## 3.3 What Is Entirely Missing
- 🔴 **CRITICAL — F03 Target Management:** There is no discrete `Target` model. Consequently, DNS validation, target consent flows ("You confirm you are authorized..."), and reusable target scoping features do not exist.
- 🟠 **HIGH — F08 Reporting Engine:** Features for sharing reports via public or password-protected links are missing.
- 🟠 **HIGH — F11 SaaS Infrastructure:** The frontend onboarding wizard (Name Org -> Add Target -> Run Scan) and automated monthly usage metering logic are missing.
- 🟡 **MEDIUM — F12 Deployment & Infrastructure:** The root `docker-compose.yml` to spin up the entire multi-container stack (web, worker, redis, db) is missing.

## 3.4 Architectural Problems
- **Identity vs. Org Separation:** The system currently treats users as siloed entities under a single tenant. B2B SaaS demands a many-to-many relationship (`Organization` <-> `OrganizationMembership` <-> `User`), so users can switch organizations seamlessly.
- **Target Traceability:** Scans executing directly against arbitrary URL strings prevents the platform from tracking longitudinal risk scoring and history for specific web properties.
- **Missing Distributed Tracing:** Logging lacks a `request_id` correlation token across the API, Worker, and DB layers, violating F13 observability specs.

## 3.5 Technical Debt Inventory
- **Configuration Duplication:** The presence of both `celery_app.py` and `config/celery_app.py` creates developer confusion.
- **Scattered AI Tooling:** While `LLMProvider` is centralized, AI triggers are tightly coupled inside `ScanOrchestrator` rather than leveraging a decoupled AI event pipeline.
- **Missing Integration Tests for Org Isolation:** While `TenantManager` implicitly filters data, we lack automated database-layer integration tests guaranteeing Org A cannot access Org B's records via bypassing the manager.

---

## 4. Agentic Upgrade QA Reconciliation & Sign-off (Phase G)

As of the **Agentic Upgrade QA Pass**, all previously identified architectural issues and feature gaps regarding the AI Agent layer have been thoroughly verified with real execution testing:
- **Phase C (Orchestration & Verification Engine):** Verified via `test_agent_integration_qa.py` and `test_phase_f_adversarial_qa.py`. The 4-wave parallel scan execution (`wave_0a`–`wave_0d`), memory retrieval, and secondary independent verification engine (`VerificationEngine.verify_all()`) function reliably under async/celery task execution without blocking the event loop.
- **Phase D (Browser MCP & Scope Enforcement):** Verified strict scope enforcement (`ENFORCE_QA_SCOPE=true`) using wildcard matching and domain filtering, plus browser session handoff persistence.
- **Phase E (PostgreSQL + pgvector Infrastructure):** Confirmed complete removal of SQLite references. Verified that all migrations cleanly apply to PostgreSQL (`safeweb-db` running `pgvector/pgvector:pg15`) and that 1536-dimension vector embeddings (`ExploitMemory`) execute similarity searches using `L2Distance`.
- **Phase F (Adversarial & End-to-End Resilience):** Verified real scan creation against target instances (DVWA), hard out-of-scope rejection, false-positive suppression, prompt injection filtering, stuck-loop ceiling intervention, and JS intelligence secret scanning (`test_phase_f_adversarial_qa.py`).
- **Regression (G1):** Confirmed all 208 backend regression tests and test suites pass cleanly on the upgraded database and execution engine.
