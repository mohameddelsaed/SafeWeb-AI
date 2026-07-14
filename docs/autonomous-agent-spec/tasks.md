# Master Implementation Checklist & Verification Plan

## Phase 1: Database & Infrastructure Enforcements
- [x] **Task 1.1**: Purge SQLite dependencies and enforce PostgreSQL connection validation.
  - *Files*: `backend/config/settings/base.py`, `backend/config/settings/development.py`, `.env.example`.
  - *Test*: Run `pytest backend/tests/test_tenant_isolation.py`. Confirm startup fails if `DATABASE_URL` points to sqlite or is unset.
- [x] **Task 1.2**: Add `pgvector` Django extension and apply model schema diffs for `Scan`, `Vulnerability`, and `ExploitMemory`.
  - *Files*: `backend/apps/scanning/models.py`, `backend/apps/ml/models.py`, new migration file `backend/apps/scanning/migrations/0005_agentic_fields.py`.
  - *Test*: Run `python backend/manage.py makemigrations && python backend/manage.py migrate`. Verify table structures in Postgres CLI.
- [x] **Task 1.3**: Update Docker Compose topology with 6 parity services including `agent_sandbox`.
  - *Files*: `docker-compose.yml`, `backend/Dockerfile.sandbox`.
  - *Test*: Run `docker-compose up --build -d`. Execute `docker ps` to verify all 6 containers report `healthy`.

## Phase 2: Sandbox SSH Layer & MCP Tool Wrappers
- [x] **Task 2.1**: Build `AsyncSSHSandboxProvider` connecting Celery worker to `agent_sandbox`.
  - *Files*: `backend/apps/scanning/engine/sandbox/provider.py`.
  - *Test*: Unit test executing `whoami` inside sandbox via SSH provider from Django test runner.
- [x] **Task 2.2**: Upgrade `tools/base.py` to expose MCP JSON-RPC formatting and integrate memory/timeout ceilings.
  - *Files*: `backend/apps/scanning/engine/tools/base.py`, `backend/apps/scanning/engine/tools/mcp_server.py`.
  - *Test*: Run `pytest backend/apps/scanning/test_engine_mocks.py`. Verify tool output returns valid JSON-RPC schema.
- [x] **Task 2.3**: Wrap top-priority offensive tools (`subfinder`, `httpx`, `nuclei`, `sqlmap`, `ffuf`) into MCP registry.
  - *Files*: `backend/apps/scanning/engine/tools/registry.py`, `backend/apps/scanning/engine/tools/wrappers/*.py`.
  - *Test*: Execute wrapper unit tests verifying safe flag injections (`--batch --safe-req`).

## Phase 3: LangGraph Engine & Specialist Nodes
- [x] **Task 3.1**: Install `langgraph` / `langchain-core` and implement `LangGraphOrchestrator` Celery task loop.
  - *Files*: `backend/requirements.txt`, `backend/apps/scanning/engine/langgraph_engine.py`, `backend/apps/scanning/views.py`.
  - *Test*: Dispatch mock scan task via Celery; inspect Celery logs to verify StateGraph transitions from `scope_gate` to `orchestrator`.
- [x] **Task 3.2**: Implement Tier-1 Recon and Vuln Scanner specialist nodes with auto-summarization.
  - *Files*: `backend/apps/scanning/engine/nodes/recon_node.py`, `backend/apps/scanning/engine/nodes/vuln_node.py`.
  - *Test*: Mock tool output and confirm nodes append summarized findings into `StateGraph.discovered_endpoints`.
- [x] **Task 3.3**: Implement Tier-2 Web/API Exploit Agent node and load Markdown Skill files.
  - *Files*: `backend/apps/scanning/engine/nodes/exploit_node.py`, `backend/apps/scanning/engine/knowledge/skills/*.md`.
  - *Test*: Feed mock endpoint into node; verify prompt injection loads correct skill markdown based on task tags.

## Phase 4: Verification Oracle & Headless Browser MCP
- [x] **Task 4.1**: Build `PoC Validator Agent` node implementing the 3/3 deterministic re-proof loop.
  - *Files*: `backend/apps/scanning/engine/nodes/validator_node.py`, `backend/apps/scanning/engine/verification.py`.
  - *Test*: Pass mock candidate finding; verify node executes 3 isolated replay checks before writing `proof_capsule` to DB.
- [x] **Task 4.2**: Transform `crawler.py` into interactive `browser_mcp_server` using Playwright multi-tab contexts.
  - *Files*: `backend/apps/scanning/engine/headless/browser_mcp.py`.
  - *Test*: E2E test launching browser server, navigating to local test page, filling login form, and extracting session cookie.

## Phase 5: UI Observability & Declarative Playbooks
- [x] **Task 5.1**: Build YAML declarative playbook parser and create standard engagement profiles.
  - *Files*: `backend/apps/scanning/engine/playbooks/parser.py`, `backend/apps/scanning/engine/playbooks/configs/*.yaml`.
  - *Test*: Parse `web-app-quick.yaml` and verify LangGraph engine configures matching phase timeouts and tool allowlists.
- [x] **Task 5.2**: Update frontend React UI to display Scope Consent Modal and Live Agent Graph Feed via SSE.
  - *Files*: `src/pages/ScanWebsite.tsx`, `src/pages/ScanResults.tsx`, `src/components/scanning/AgentActivityGraph.tsx`.
  - *Test*: Run Playwright frontend E2E suite (`npx playwright test`). Verify consent modal blocks scan initiation until allowlist checkbox is selected.

## Phase 6: Multi-Provider AI Gateway Expansion (10 Providers)
- [x] **Task 6.1**: Expand `AIConfiguration.provider` choices and update `LLMProvider` routing engine to natively support 10 AI providers with automatic fallback and OpenAI-compatible routing.
  - *Files*: `backend/apps/accounts/models.py`, `backend/apps/scanning/engine/ai/provider.py`, `backend/tests/test_multi_provider_routing.py`.
  - *Test*: Execute `python -m pytest tests/test_multi_provider_routing.py` and verify all 10 provider routing URLs, authorization headers, and default models pass cleanly.
