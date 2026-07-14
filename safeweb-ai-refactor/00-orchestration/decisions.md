# Decisions Log

## DEC-001: Deployment target is cloud (AWS or Azure), provider TBD
Date: 2026-06-23
Decided by: Omar
Rationale: explicit answer in project audit. Final AWS-vs-Azure choice deferred
to Deployment Spec (Step 12), informed by 01-research/deployment-research/.
Status: partially open — "cloud, not self-hosted" is final; specific provider is not.

## DEC-002: Multi-tenant architecture, from the foundation up
Date: 2026-06-23
Decided by: Omar
Rationale: explicit answer in project audit. Isolation pattern (shared-schema vs
schema-per-tenant vs DB-per-tenant) deferred to Multi-Tenancy Spec (Step 12),
informed by Database Analysis Agent (Step 7).
Status: "multi-tenant" is final; isolation pattern is not.

## DEC-003: External security tools are optional at runtime
Date: 2026-06-23
Decided by: Omar
Rationale: tools installed on the server when available, but the system must
remain correct via SafeWeb's own fallback scripts when absent. This is a hard
product requirement, not a nice-to-have — Scanner Engine Spec must not weaken
this to "best effort."
Status: final.

## DEC-004: AI provider strategy — free-tier-first, flexible, with local fallback
Date: 2026-06-23
Decided by: Omar
Rationale: OpenRouter (free tier) as default, with support for ChatGPT/Claude/
other paid providers as pluggable options, per-user-configurable choice, and
Ollama retained as a local fallback. This shapes AI Pipeline Spec directly.
Status: final on strategy; specific provider list may grow over time via the
plug-in pattern (AI Pipeline Spec FEAT-008).
