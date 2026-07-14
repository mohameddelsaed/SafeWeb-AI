# Phase 0 & Phase 1: Component Inventory, Reality Check, and Classification Decisions

## Phase 0 Component Inventory & Reality Check

### 1. Backend Applications (`backend/apps/`)
- **`accounts`**: Manages User identity, RBAC, Organizations (`Organization`, `OrganizationMembership`), authentication (JWT via `djangorestframework-simplejwt`), 2FA (TOTP), and subscriptions (`Plan`). **Confidence: HIGH (95%)**.
- **`scanning`**: Core domain app. Models `Target`, `Scan`, `Vulnerability`, and `ScanReport`. Handles scan job dispatching to Celery, SSE streaming endpoints, scan configuration, and PDF/CSV export views. **Confidence: HIGH (90%)**.
- **`chatbot`**: OpenRouter LLM wrapper (`engine.py`) with conversational memory (last 10 messages) and 7 local keyword/function-calling actions (`actions.py`). **Confidence: MEDIUM (75%)**. Currently a chatbot acting on user prompts, not an autonomous agent orchestrator.
- **`ml`**: Models `MLModel` and `MLPrediction` to track metadata for trained models. **Confidence: MEDIUM (65%)**. Schema exists, but needs upgrade to host vector storage.
- **`learn`**, **`admin_panel`**, **`core`**: Educational academy, SaaS administration panel, and shared utilities/tracing middlewares. **Confidence: HIGH (90-95%)**.

### 2. Scanning Engine Modules (`backend/apps/scanning/engine/`)
- **`orchestrator.py`**: Coordinates the hardcoded 7-phase sequential scan pipeline. **Confidence: HIGH (85%) as deterministic scanner**, but brittle as an agentic system.
- **`tools/base.py` & `registry.py`**: Central catalog wrapping ~61 CLI security tools (`nmap`, `nuclei`, `sqlmap`, `ffuf`, etc.). **Confidence: HIGH (90%)**. Excellent foundation, needs MCP schema upgrade.
- **`recon/` (48 files)**: Async reconnaissance modules executed across 4 waves. **Confidence: HIGH (90%)**.
- **`testers/` (89 files)**: Vulnerability detection scripts mapped to OWASP/WSTG categories. **Confidence: HIGH (85%)**.
- **`crawler.py`**: BFS web crawler discovering links, forms, inputs, and API endpoints. **Confidence: HIGH (85%)**.
- **`payloads/`**: Curated wordlists, SecLists subsets, and WAF bypass payload dictionaries. **Confidence: HIGH (95%)**.
- **`ai/`, `learning/`, `chaining/`, `ml/evidence_verifier.py`**: Early attempts at intelligent synthesis. **Confidence: MEDIUM (70%)**.

### 3. Frontend Route & Page Structure (`src/`)
React 18 + Vite + TypeScript application with 30 public/user pages and 7 admin pages. **Confidence: HIGH (95%)**. Verified by Playwright E2E suites.

### 4. Deployment Reality Check
- Azure App Service, Static Web Apps, Blob Storage, Key Vault, ACI Tool Sidecar: **NOT IN CODEBASE (10% reality)**. Documented architectural aspiration only; active configs are Railway and Vercel.
- PostgreSQL Flexible Server & Redis: **PARTIALLY PREPARED (85% code readiness)**. Currently falls back to SQLite in local dev.

---

## Phase 1 Classification Decisions

- **`accounts`**: KEEP AS-IS. Multi-tenant boundary for scope authorization.
- **`scanning`**: UPGRADE IN PLACE. Add LangGraph state fields to `Scan` and verification status / proof capsule fields to `Vulnerability`.
- **`chatbot`**: REPLACE. Replace with LangGraph agent loop and MCP tool invocation.
- **`ml`**: UPGRADE IN PLACE. Enable `pgvector` for long-term exploit memory vector embeddings.
- **`learn`**, **`admin_panel`**, **`core`**: KEEP AS-IS. Decoupled from offensive engine.
- **`orchestrator.py`**: REPLACE. Replace with LangGraph cyclic graph orchestrator node.
- **`tools/base.py` & `registry.py`**: UPGRADE IN PLACE. Wrap wrappers in MCP JSON-RPC parameter and output schemas.
- **`recon/` (48 files)**: UPGRADE IN PLACE. Modularize into `recon_mcp_server` invoked by Tier-1 Recon Agent.
- **`testers/` (89 files)**: UPGRADE IN PLACE. Re-classify from auto-trusted exploits to candidate generators for Tier-1 Vuln Scanner.
- **`crawler.py`**: REPLACE. Upgrade to interactive Playwright multi-tab Browser MCP Server.
- **`payloads/`**: KEEP AS-IS. Essential wordlists and fuzzing dictionaries.
- **`ai/`, `learning/`, `chaining/`**: REPLACE. Replace with Exploit Chainer Agent and Hierarchical Memory System.
- **`ml/evidence_verifier.py` & False Positive Ensemble**: UPGRADE IN PLACE. Hardened into the Section 10 PoC Validator Agent (3/3 deterministic re-proof loop).
- **Frontend UI (`src/`)**: UPGRADE IN PLACE. Add Scope Consent Modal and Live Agent Activity SSE Feed.
- **`docker-compose.yml` & Database**: UPGRADE IN PLACE. Purge SQLite, enforce PostgreSQL + `pgvector`, add containerized `agent_sandbox` and `frontend`.
