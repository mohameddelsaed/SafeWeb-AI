# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 5: Spec Kit Framework

**Status:** Phase 5 of 10
**Populates:** `03-specs/_spec-template.md` and defines validation rules for everything `03-specs/` will eventually contain.
**Used by:** Spec Generation Agent (11) when writing, QC review gate (Deliverable 9) when validating, Implementation Planning Agent (12) when reading.

---

## 0. Why a Shared Skeleton Matters

Every spec must look structurally identical — same header, same section order — even though their content differs completely. This is what lets the QC gate run *automated-style* consistency checks (does every spec have a "Findings Addressed" section? does every requirement have an ID?) instead of relying on a human to manually re-read all twelve for compliance. It's also what lets the Implementation Planning Agent cite spec sections predictably (`07-multi-tenancy-spec.md §3.2`) without re-learning each spec's layout.

---

## 1. The Shared Spec Template (`03-specs/_spec-template.md`)

Every spec in `03-specs/` is a copy of this skeleton with its sections filled in:

```markdown
---
Spec ID: <e.g. 07-multi-tenancy-spec>
Version: 1.0
Status: draft | in-review | approved
Source agent: Spec Generation Agent
Run date: <date>
Supersedes: <previous version, if a revision — otherwise "none">
---

## 1. Purpose & Scope
What this spec governs, in 2-4 sentences. One sentence stating explicitly what
it does NOT govern (cross-reference the spec that does).

## 2. Findings Addressed
Table: Finding ID | Source Agent | How This Spec Resolves It
Every in-domain finding from Agents 1-9 must appear here. A finding that exists
in this domain but isn't listed is treated as a defect in the spec.

## 3. Requirements
### 3.1 Functional Requirements
Numbered, testable statements (REQ-<SPEC-PREFIX>-001, 002, ...). Each one
should be falsifiable — a reviewer must be able to look at an implementation
and say yes/no it satisfies REQ-XXX-001, not "sort of."

### 3.2 Non-Functional Requirements
Performance, security, scalability, reliability constraints relevant to this
spec's domain. Same numbering convention.

## 4. Out of Scope
Explicit list of things someone might expect to find here but won't, with a
pointer to which spec actually covers it.

## 5. Dependencies
- Depends on: <other specs this one assumes are already decided>
- Depended on by: <other specs that assume this one's decisions>

## 6. Open Questions / Decisions Needed
Anything genuinely unresolved at spec-generation time. Each gets an owner
(human or "next agent run") and blocks Status: approved until resolved.

## 7. Acceptance Criteria
The concrete bar implementation must clear for this spec to be considered
satisfied. This is what Implementation Planning Agent's tasks ultimately get
checked against.

## 8. Change Log
Version | Date | What changed | Why
```

---

## 2. Per-Spec Definitions

Format per spec: **Required Sections beyond the shared skeleton**, **Required Level of Detail**, **Validation Criteria**, **Review Criteria**.

---

### 00-product-spec.md
- **Required sections:** Target user persona (the non-security-specialist), Core user journeys (signup → first scan → reading a report → acting on it), MVP feature inventory vs. explicitly deferred features, Success metrics
- **Level of detail:** User-journey level — readable by a non-technical stakeholder (a professor evaluating the project, a future non-technical co-founder). No implementation detail belongs here.
- **Validation criteria:** Every other spec's requirements must trace back to something implied here; flag any downstream spec introducing a capability with no product justification (scope creep risk, especially important given this is a bounded graduation project, not an unlimited-runway startup).
- **Review criteria:** Does the persona and journey actually match "non-specialist user trying to secure their own web app" rather than drifting toward an expert-pentester tool; is the MVP feature set realistically buildable by the team and timeline.

---

### 01-architecture-spec.md
- **Required sections:** Target component diagram (described in text/structured form, not just prose), Service boundaries & single-responsibility statement per service, Data flow for the two core operations (triggering a scan, generating a report), Technology stack decisions with rationale (citing `decisions.md`), Multi-tenancy integration summary (full detail deferred to Multi-Tenancy Spec — this section just shows how the architecture accommodates it)
- **Level of detail:** Component-level — every component named in `repo-map.md` gets an explicit disposition (kept as-is, merged into X, replaced by Y, removed entirely).
- **Validation criteria:** Every `ARCH-NNN` finding is either resolved by a stated architectural decision or explicitly deferred with reasoning; no component from `repo-map.md` is left without a disposition.
- **Review criteria:** Internal consistency against Database, API, and Deployment specs — e.g., service boundaries here must match the API endpoint grouping in the API Spec.

---

### 02-security-spec.md
- **Required sections:** Threat model specific to this product (a scanner storing other people's scan results, target URLs, and AI provider API keys is itself a high-value target), Authentication & session design, Secrets management design (especially user-supplied AI provider keys), Tenant isolation enforcement mechanism (cross-references Multi-Tenancy Spec for the data layer, owns the application-layer enforcement here), Input validation policy for user-submitted scan targets, Audit logging requirements (cross-references Monitoring Spec)
- **Level of detail:** Concrete enough that a reviewer can check "does the implementation actually do this" — no requirement may simply say "use best practices" or "follow OWASP guidelines" without specifying which control, applied where.
- **Validation criteria:** Every `SEC-NNN` finding is resolved with a specific control; nothing is marked addressed without an actual requirement backing it.
- **Review criteria:** A security-literate reviewer (this maps well to a course/thesis advisor review) can trace each control back to the threat it mitigates.

---

### 03-scanner-engine-spec.md
- **Required sections:** Tool inventory & runtime detection logic, Fallback parity requirements (per tool: required minimum equivalence level — full/partial/documented-gap — between primary and fallback path), Finding normalization schema (single internal format regardless of source), False-positive mitigation strategy, Degraded-mode user disclosure requirement (when a scan ran with reduced tool coverage, the user must be told, not just the system)
- **Level of detail:** Per-tool granularity — every tool from `tool-fallback-gap-report.md` gets its own requirement entry, not a generic blanket statement.
- **Validation criteria:** Every `SCAN-NNN` finding addressed; specifically, every instance of silent degradation found in the analysis phase has a corresponding REQ forcing explicit user disclosure.
- **Review criteria:** Would a non-specialist user, reading the resulting disclosure, actually understand their scan was less thorough than usual? If not, the requirement isn't specific enough.

---

### 04-ai-pipeline-spec.md
- **Required sections:** Provider abstraction interface contract (request/response shape, streaming, error semantics — this is the contract every feature codes against), Supported providers (OpenRouter as default free-tier, paid providers as pluggable adapters, Ollama as local fallback), Per-user/tenant provider configuration model, Prompt management strategy (versioned, centralized — no prompts embedded directly in feature code), Cost & rate-limit handling per provider, Fallback trigger behavior (when does the system fall back to Ollama, and how is that communicated to the user)
- **Level of detail:** Interface-contract level for the abstraction layer; specific enough about OpenRouter/Ollama that an implementer doesn't need to re-research the provider research docs.
- **Validation criteria:** Every `AI-NNN` provider-coupling finding has a corresponding requirement forcing it through the abstraction layer; the interface contract is concrete enough to be testable.
- **Review criteria:** Could a new paid provider genuinely be added later by writing one adapter against this contract, with zero changes to feature code? If the spec doesn't make that true, it's not done.

---

### 05-reporting-engine-spec.md
- **Required sections:** Report data model, Explainability requirements (mapping raw findings to non-jargon explanation + severity context + suggested next step), Export formats, Tenant-scoping of report storage and access, Template versioning
- **Level of detail:** Concrete enough to define what fields a report template needs (not full visual design — that's an implementation/design decision).
- **Validation criteria:** Every `FE-NNN` finding tagged as reporting-relevant is addressed.
- **Review criteria:** Would a non-specialist genuinely understand a sample report generated against this spec, without needing to look anything up?

---

### 06-saas-spec.md
- **Required sections:** Tenant lifecycle (signup, active use, plan/tier if any, offboarding/data deletion), Usage metering requirements (scans/month, AI calls/month, trackable per tenant even before billing exists), Plan/tier model (can be a single free tier at launch — must still be modeled so it's extensible), Realistic SaaS NFRs scoped to an early-stage/student-project context (don't spec five-nines uptime for a system with no paying customers yet)
- **Level of detail:** Business/product-process level, not implementation level.
- **Validation criteria:** Every item in `cloud-deployment-blockers.md` that's product/business-process in nature (not purely technical) is addressed or explicitly deferred with rationale logged to `decisions.md`.
- **Review criteria:** Is the scope honest about what's needed for a credible graduation-project SaaS demo versus what would only matter at real commercial scale? Over-speccing here wastes implementation time that should go toward the technical specs.

---

### 07-multi-tenancy-spec.md
- **Required sections:** Isolation pattern decision (shared-schema-with-tenant-id / schema-per-tenant / DB-per-tenant) with rationale referencing `decisions.md` and the Database Analysis Agent's recommendation, Tenant identification & propagation mechanism through the full request lifecycle, Data isolation enforcement layer (where exactly is tenant_id checked — middleware, ORM-level, both), Tenant-scoped resource limits (e.g., concurrent scan limits per tenant), Cross-tenant test requirements
- **Level of detail:** This is the single most load-bearing spec in the kit — every ambiguous table, every cross-tenant risk, every concurrency concern routes through here. Detail must be implementation-ready, not directional.
- **Validation criteria:** Zero tables remain classified AMBIGUOUS after this spec; every `DB-NNN`, tenant-relevant `ARCH-NNN`, and `SEC-NNN` finding is resolved here or explicitly delegated with a citation to where.
- **Review criteria:** Could a developer implement tenant isolation correctly from this spec alone, without needing to ask "but what happens when...")? Gaps here are the highest-risk gaps in the entire framework.

---

### 08-api-spec.md
- **Required sections:** API style & versioning policy, Endpoint inventory grouped by domain (auth, scans, reports, AI/chatbot, tenant management), Auth/tenant-scoping middleware contract (references Multi-Tenancy Spec for the underlying mechanism, owns how it's applied at the API layer), Standard error response format, Rate limiting policy
- **Level of detail:** Endpoint-level — every endpoint found in `integration-points.md` gets an entry showing its target-state shape (kept/changed/new/removed).
- **Validation criteria:** Every endpoint in `integration-points.md` accounted for; every `BE-NNN` concurrency/scaling finding has a corresponding API-layer requirement (queueing behavior, rate limits, etc.).
- **Review criteria:** Internal consistency with Architecture Spec's service boundaries and Multi-Tenancy Spec's enforcement mechanism.

---

### 09-database-spec.md
- **Required sections:** Target schema by domain, Migration strategy (how existing data, if any, moves to the new schema), Tenant column/constraint policy, Indexing strategy, Backup/retention policy
- **Level of detail:** Table/column-level — this spec should be detailed enough to write migrations directly from it.
- **Validation criteria:** Every table from `tenant-data-model-gap-report.md` is resolved with a concrete target-state definition; classification (tenant-scoped/global) is final, not still "ambiguous."
- **Review criteria:** Consistency with Multi-Tenancy Spec's isolation pattern decision — the schema must actually implement the pattern chosen there, not a different one.

---

### 10-deployment-spec.md
- **Required sections:** Cloud provider decision (AWS or Azure, with rationale logged to `decisions.md`), Containerization approach, Infrastructure-as-code tooling, CI/CD pipeline design, Environment strategy (dev/staging/prod, or a scoped-down version appropriate to project size), Secrets management in the deployment context, Rough cost estimate at expected demo/early-usage scale
- **Level of detail:** Concrete enough to actually provision infrastructure from — specific services, not "use a cloud database."
- **Validation criteria:** Every item in `cloud-deployment-blockers.md` that's infrastructure-related is addressed.
- **Review criteria:** Is the cost estimate realistic for a student project (free-tier/low-cost cloud options should be favored explicitly, given the same free-tier-first philosophy already applied to the AI provider choice)?

---

### 11-monitoring-spec.md
- **Required sections:** Logging strategy (must be tenant-tagged, per Multi-Tenancy Spec's audit requirements), Metrics & dashboards (scan throughput, AI call volume/cost, error rates), Alerting thresholds, Audit trail requirements (satisfies Security Spec's audit logging requirement), Lightweight incident-response notes appropriate to project scale
- **Level of detail:** Specific enough to configure actual logging/metrics tooling from — not a generic "we will monitor the system" statement.
- **Validation criteria:** Directly satisfies the audit logging requirement cited in Security Spec §3 (cross-spec dependency must be honored, not just mentioned).
- **Review criteria:** Proportionate to project scale — this should be lightweight and buildable, not an enterprise observability stack the team can't realistically operate.

---

## 3. Cross-Spec Consistency Rules (enforced at QC gate, previewed here)

These are spelled out now because the Spec Generation Agent needs to write with them in mind, not discover them only at review time:

1. **Multi-Tenancy Spec is upstream of Database, API, and Security specs.** If any of those three make a tenancy-related decision that Multi-Tenancy Spec doesn't already state, that's a contradiction — Multi-Tenancy Spec must be updated, not the downstream spec quietly diverging.
2. **Deployment Spec's cloud provider decision must match whatever's logged in `decisions.md`** — it doesn't get to re-decide AWS vs. Azure independently.
3. **AI Pipeline Spec's provider list must match `01-research/ai-provider-research/`** — no spec introduces a provider that wasn't actually researched.
4. **Product Spec is the root.** Any requirement in any other spec that can't be traced, even indirectly, to a product-spec user journey or success metric is a flag for the QC gate, not an automatic rejection — sometimes infrastructure requirements (e.g., specific indexing) won't trace cleanly, and that's fine — but it should be a deliberate, reviewed exception, not an oversight.

---

*Next: Deliverable 6 — Documentation Templates (the reusable templates referenced throughout this spec kit and the agent prompts: audit reports, architecture assessments, security reviews, refactoring plans, risk assessments, tech debt reports, scalability reviews, SaaS readiness reviews).*
