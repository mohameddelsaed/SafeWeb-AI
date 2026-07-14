# SafeWeb AI — Implementation Plan (Phase 2)

Based on the Phase 1 Codebase Audit, here is the concrete, sequenced implementation plan to build out Features 01-13.

## Phase A: Database & Security Foundations
Resolving the critical architectural gaps before building upstream features.

### F02: Multi-Tenant Org System
- **Files to touch:**
  - `backend/apps/accounts/models.py`
  - `backend/apps/accounts/serializers.py`
  - `backend/apps/accounts/views.py`
  - `backend/apps/accounts/middleware.py`
- **Changes:**
  - Rename `Tenant` to `Organization` and add `plan_tier`, `usage_counters`, `owner` fields.
  - Create `OrganizationMembership` (Many-to-Many model between `User` and `Organization`) with a `role` field (owner, admin, member).
  - Update `TenantMiddleware` to extract `X-Organization-ID` from headers to set the active organization for `TenantManager`.
  - Remove the legacy `tenant` ForeignKey and `plan` fields from the `User` model.
- **Testing Strategy:** DB constraints testing; unit test `TenantManager` isolation under `OrganizationMembership` context.

### F03: Target Management
- **Files to touch:**
  - `backend/apps/scanning/models.py`
  - `backend/apps/scanning/views.py`
  - `backend/apps/scanning/serializers.py`
  - `src/pages/Targets.tsx` (NEW)
- **Changes:**
  - Add `Target` model: `id`, `organization` (FK), `domain`, `display_name`, `tags`, `is_dns_verified`, `consent_timestamp`, `consent_user_id`, `created_at`, `current_score`.
  - Update `Scan` model to have `target_entity = models.ForeignKey(Target)`.
  - Implement DNS verification action (checking for a custom TXT record) on the Target viewset.
  - Build `Targets.tsx` in React for Target CRUD and verification status.
- **Testing Strategy:** Integration test ensuring scans cannot start without a valid, consented `Target`.

---

## Phase B: Core Logic & AI Scaling
Upgrading the scan engine and AI capabilities.

### F04: Scan Engine Customization
- **Files to touch:**
  - `backend/apps/scanning/models.py`
  - `backend/apps/scanning/engine/orchestrator.py`
- **Changes:**
  - Add `custom` depth choice to `Scan.SCAN_DEPTHS`.
  - Add `selected_categories` (JSONField) to `Scan` to store specific vulnerability types to test.
  - Update `ScanOrchestrator` to selectively instantiate only the Testers matching the `selected_categories` when in `custom` mode.
- **Testing Strategy:** Mock Tester registry and assert that omitted categories are skipped during scan dispatch.

### F06: AI Provider Gateway Settings
- **Files to touch:**
  - `backend/apps/accounts/models.py`
  - `backend/apps/scanning/engine/ai/provider.py`
- **Changes:**
  - Create `AIConfiguration` model (FK to `Organization`) to store `provider_name`, `model_name`, `encrypted_api_key`, and `token_usage`.
  - Update `LLMProvider` to query the current organization's `AIConfiguration`. Fall back to global platform settings if not provided.
- **Testing Strategy:** Unit test `LLMProvider` initialization with mocked database context.

### F07: AI-Powered Vulnerability Explanation
- **Files to touch:**
  - `backend/apps/scanning/models.py`
  - `backend/apps/scanning/engine/ai/reasoning.py`
- **Changes:**
  - Add `ai_explanation` and `ai_remediation` text fields to the `Vulnerability` model.
  - Implement a post-scan async task in `reasoning.py` that batches critical/high findings to the LLM to populate these non-expert-friendly fields.
- **Testing Strategy:** Mock OpenRouter responses and verify the generated explanations are correctly saved to the vulnerability objects.

---

## Phase C: UI & Infrastructure Polish
Finalizing the SaaS experience, deployment, and observability.

### F08: Report Sharing
- **Files to touch:**
  - `backend/apps/scanning/models.py`
  - `backend/apps/scanning/views.py`
- **Changes:**
  - Add `SharedReport` model: `scan` (FK), `access_token` (UUID), `password_hash`, `expires_at`.
  - Add `PublicReportView` to serve read-only scan summaries and PDFs, protected by password/token validation.
- **Testing Strategy:** Integration tests validating unauthenticated denial and token-based access.

### F11: SaaS Infrastructure (Onboarding)
- **Files to touch:**
  - `src/pages/Onboarding.tsx` (NEW)
  - `src/App.tsx`
- **Changes:**
  - Build a guided `Onboarding` wizard (Step 1: Create Organization, Step 2: Add Target, Step 3: Run Scan).
  - Add global React router guard: if a user logs in and has no Targets, force redirect to `/onboarding`.
- **Testing Strategy:** Frontend routing state tests.

### F12 & F13: Deployment & Observability
- **Files to touch:**
  - `docker-compose.yml` (NEW)
  - `backend/apps/core/middleware.py` (NEW)
  - `backend/config/settings/base.py`
- **Changes:**
  - Create `docker-compose.yml` defining `web`, `celery_worker`, `redis`, and `db` (Postgres/SQLite).
  - Create `RequestIDMiddleware` to attach `X-Request-ID` to threading context and standard Django logging outputs.
- **Testing Strategy:** Local docker deployment verification; log parsing validation.
