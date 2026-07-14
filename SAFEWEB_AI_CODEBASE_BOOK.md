# SafeWeb AI Codebase Book

## A Source-Grounded Technical Walkthrough of the Repository

Authoring basis: direct inspection of the current repository structure, major runtime files, representative scan-engine internals, deployment manifests, and app-level models, views, serializers, tasks, and frontend entrypoints.

Important framing:

- This manuscript is grounded in the checked-in code, not only in README claims.
- Where the repository narrative and the checked-in manifests diverge, the divergence is called out explicitly.
- The scanning engine is too large to explain line-by-line in every module, so repeated patterns are explained once and then mapped to the relevant directories and representative files.

---

## Table of Contents

1. [What SafeWeb AI Is](#1-what-safeweb-ai-is)
2. [How the Project Boots and Runs](#2-how-the-project-boots-and-runs)
3. [Backend Architecture: Django as the Control Plane](#3-backend-architecture-django-as-the-control-plane)
4. [Data Model and API Surface](#4-data-model-and-api-surface)
5. [The Scanning Engine: The Core of the Product](#5-the-scanning-engine-the-core-of-the-product)
6. [Frontend Architecture: React as the Operator Console](#6-frontend-architecture-react-as-the-operator-console)
7. [Runtime Data Flow: Auth, Scans, SSE, Chat, and Background Work](#7-runtime-data-flow-auth-scans-sse-chat-and-background-work)
8. [Security Decisions, Tradeoffs, and Codebase Risks](#8-security-decisions-tradeoffs-and-codebase-risks)
9. [Deployment, Tooling, and Operational Reality](#9-deployment-tooling-and-operational-reality)
10. [How to Extend the System Safely](#10-how-to-extend-the-system-safely)
11. [Glossary](#11-glossary)
12. [Appendix A: Backend File Map](#12-appendix-a-backend-file-map)
13. [Appendix B: Frontend File Map](#13-appendix-b-frontend-file-map)
14. [Appendix C: Major API Groups](#14-appendix-c-major-api-groups)
15. [Appendix D: Verified Mismatches and Gaps](#15-appendix-d-verified-mismatches-and-gaps)

---

## 1. What SafeWeb AI Is

SafeWeb AI is a full-stack web application security platform built around one central idea: a conventional SaaS application can act as a control plane for an unusually large vulnerability-scanning engine.

At a high level, the repository combines five systems inside one product:

1. A Django API server that owns users, scans, findings, chat sessions, exports, and admin workflows.
2. A React single-page application that acts as the operator dashboard for launching scans, reading results, and chatting with the assistant.
3. A scan orchestration layer that coordinates reconnaissance, crawling, vulnerability testing, verification, scoring, and reporting.
4. An external tool integration layer that wraps command-line security tools behind Python classes.
5. An AI layer that powers the chatbot and some scan reasoning paths.

That hybrid structure explains why the codebase feels like two repositories merged into one:

- Part of it looks like a normal web app.
- Part of it looks like a penetration-testing toolkit platform.

### 1.1 The Most Important Mental Model

The cleanest way to understand the repository is this:

- Django is the stateful brain.
- Celery and threads are the work dispatchers.
- The scan engine is the execution plant.
- React is the control surface.
- Redis is the queue and coordination layer.
- The database is the system memory.

### 1.2 A Diagram in Words

Imagine the system as three horizontal lanes.

Lane 1, the user lane:

- A user opens the React frontend.
- The frontend authenticates with JWTs.
- The user creates a scan, views progress, exports reports, or opens the chatbot.

Lane 2, the control plane:

- Django receives the request.
- Django writes or updates `Scan`, `Vulnerability`, `ChatSession`, and related rows.
- Django decides whether to run work immediately, in a background thread, or via Celery.

Lane 3, the execution lane:

- The scan engine resolves scope, crawls the target, invokes internal testers, optionally calls external binaries, verifies results, computes scores, and writes findings back.
- SSE and polling let the frontend observe those state changes live.

### 1.3 Repository Shape at a Glance

| Area | What It Contains | Why It Matters |
| --- | --- | --- |
| `backend/` | Django project, Celery entrypoints, apps, tests, scripts | Backend runtime and scan engine |
| `src/` | React app, routes, pages, services, contexts, components | Operator-facing UI |
| `scripts/` | PowerShell install and verification scripts for security tools | Local operator/tooling setup |
| `tools/` | Local tool cache/install target | External security binaries and supporting assets |
| Root config files | Vite, Tailwind, TypeScript, Nixpacks, Railway, Vercel | Build and deployment behavior |
| Documentation files | README, diagrams, presentation artifacts | Project narrative, some of it ahead of code reality |

### 1.4 Verified Code Reality vs Project Narrative

One of the most important facts about this repository is that there is some drift between the product story and the checked-in operational files.

| Topic | Narrative in project docs | Verified in current code/manifests | Practical conclusion |
| --- | --- | --- | --- |
| Cloud target | Azure App Service, Static Web Apps, PostgreSQL, Redis, Blob, Key Vault | `railway.toml`, `vercel.json`, `nixpacks.toml`, `backend/Procfile` are present and concrete | The current checked-in deployment path is more Railway/Vercel/Nixpacks-oriented than Azure-IaC-oriented |
| Infrastructure as code | Azure infrastructure is described extensively | No `infra/` directory was found in the inspected tree | Treat Azure infrastructure claims as roadmap or external setup, not current repo truth |
| Scan breadth | Very broad coverage is claimed | The engine tree is indeed very large, with many testers, wrappers, recon modules, OOB helpers, payload sets, and reporting utilities | The broad scanner claim is materially supported by the codebase |
| File and URL scanning | Mentioned in parts of the project story | Some file and URL scan paths are commented or described as deactivated | Website scanning is the live primary path |

That distinction matters because a good onboarding document should tell engineers what the code does now, not only what the project intends to become.

---

## 2. How the Project Boots and Runs

This chapter explains the startup chain, from repository root to running processes.

### 2.1 Root-Level Runtime Files

The root of the repository is not just scaffolding. It is where the frontend build, the deployment manifests, and some environment assumptions are encoded.

| File | Role | Key takeaway |
| --- | --- | --- |
| `package.json` | Frontend dependency and script manifest | `dev`, `build`, `lint`, `format`, and `preview` are frontend-centric |
| `vite.config.ts` | Vite dev/build behavior | Defines dev proxying and chunk splitting |
| `tailwind.config.js` | Tailwind theme | Encodes the project's cyber-styled visual identity |
| `postcss.config.js` | CSS post-processing | Tailwind + Autoprefixer pipeline |
| `tsconfig.json` and `tsconfig.node.json` | TypeScript compiler behavior | Strong typing and Vite toolchain support |
| `index.html` | Frontend HTML shell | Vite mounts the SPA here |
| `vercel.json` | Frontend deployment behavior | SPA rewrite to `index.html` and security/cache headers |
| `railway.toml` | Backend platform settings | Health check path and restart policy |
| `nixpacks.toml` | Backend build plan | Install Python deps, collect static files, migrate, create admin, start Gunicorn |
| `backend/Procfile` | Process declaration | Runs Gunicorn with `config.wsgi:application` |

### 2.2 Frontend Toolchain Boot

The frontend startup path is intentionally small.

1. `src/main.tsx` imports React, ReactDOM, `App`, and global CSS from `index.css`.
2. It renders `<App />` inside `React.StrictMode`.
3. `App.tsx` owns the real application architecture: route tree, lazy loading, guards, and the chatbot widget.

This is a good separation. `main.tsx` is just the mount point; `App.tsx` is the application shell.

### 2.3 Backend Toolchain Boot

The backend has four entrypoints that matter conceptually:

| File | Purpose | Important detail |
| --- | --- | --- |
| `backend/manage.py` | Django management CLI | Defaults to `config.settings.development` |
| `backend/config/wsgi.py` | WSGI app entrypoint | Also defaults to `config.settings.development` |
| `backend/config/asgi.py` | ASGI app entrypoint | Also defaults to `config.settings.development` |
| `backend/celery_app.py` | Celery bootstrap plus tool registration | Worker startup tries to register external tools |

That defaulting behavior is a notable implementation choice. It makes local development easy, but it also means production depends on environment variables overriding a development-first default. That is convenient, but fragile if deployment config is incomplete.

### 2.4 Settings Layering

The settings package is structured the way many production Django projects are structured:

- `config/settings/base.py` holds shared defaults.
- `config/settings/development.py` adjusts for local work.
- `config/settings/production.py` hardens the app for deployed use.

#### What `base.py` centralizes

The base settings file is one of the most important files in the repository. It defines:

- Installed Django apps and project apps.
- Middleware chain.
- Database configuration through `dj_database_url` with SQLite fallback.
- The custom user model.
- REST Framework behavior.
- SimpleJWT settings.
- CORS and CSRF behavior.
- Celery broker and result backend configuration.
- Scan-related tuning and AI-related environment variables.
- Logging behavior.

In architectural terms, `base.py` is the system contract. If an engineer wants to understand auth, storage, queueing, or middleware behavior, this file is the first stop.

#### What `development.py` changes

The development settings are designed for speed and convenience:

- `DEBUG` is enabled.
- Celery is effectively turned into synchronous local execution with eager mode.
- email uses a console backend.
- some throttling constraints are relaxed.

That means developers can test scan flows without standing up a full queueing topology.

#### What `production.py` changes

The production settings move in the normal direction:

- `DEBUG` is off.
- secure cookies and redirect/security settings are enabled.
- HSTS and related security headers are configured.
- a deployment-oriented host and origin setup is used.

One practical detail matters here: the production file reflects Railway-style assumptions more clearly than Azure App Service assumptions.

### 2.5 Celery Has Two Layers of Meaning

The repository contains both `backend/celery_app.py` and `backend/config/celery_app.py`.

That is not automatically wrong, but it creates a subtle cognitive burden.

- One layer is the Celery app configuration itself.
- Another layer adds worker-ready behavior that attempts tool registration.

For a new engineer, the important point is that SafeWeb AI does not treat Celery as just a generic task queue. It also treats worker boot as a system initialization phase for the scanning environment.

### 2.6 URL Routing Is a High-Level System Map

`backend/config/urls.py` mounts the major backend domains under predictable API prefixes.

This file makes the system legible immediately because it shows the real product boundaries:

- authentication and account management
- scanning and scan dashboards
- chatbot
- admin panel
- learning center

In mature Django codebases, top-level URL routing is often one of the fastest ways to understand product shape. That is true here.

---

## 3. Backend Architecture: Django as the Control Plane

SafeWeb AI uses Django in a way that is larger than standard CRUD but still fundamentally recognizable.

Django owns the authoritative state of the platform. The scan engine may do the hard work, but Django decides what exists, what is in progress, what belongs to whom, and what the UI is allowed to see.

### 3.1 The Six Main Apps

| App | Responsibility | Architectural role |
| --- | --- | --- |
| `accounts` | users, auth, sessions, API keys, contact, careers | identity and access boundary |
| `scanning` | scans, findings, exports, SSE, scheduling, webhooks | core product domain |
| `chatbot` | AI assistant sessions and messages | interactive support and action layer |
| `ml` | phishing and malware models | preserved ML subsystem |
| `admin_panel` | privileged dashboards and management APIs | internal operations plane |
| `learn` | educational article content | content subsystem |

### 3.2 `accounts`: Identity, Sessions, 2FA, and Public Intake

The `accounts` app is broader than its name suggests. It is both the identity system and the home for public submission forms.

#### Core models

`accounts/models.py` defines these important domain objects:

- `User`: UUID-based custom user, email login, role, subscription plan, 2FA fields, profile metadata.
- `APIKey`: programmatic access credentials tied to a user.
- `UserSession`: session tracking with IP/user-agent context.
- `ContactMessage`: inbound contact form data.
- `JobApplication`: public career/application intake.

The decision to use a custom user model is the correct one for a product like this. It avoids future pain when adding plan tiers, organization metadata, or security fields.

#### Serializer design

`accounts/serializers.py` encodes several important product rules:

- strong password validation
- login payload structure
- profile update shaping
- session serialization
- 2FA verification input handling

In Django REST Framework, serializers are where API input becomes platform policy. That is true here.

#### View design

`accounts/views.py` contains the operational auth surface:

- register
- login
- logout
- verify current user
- refresh token
- Google auth entrypoint
- forgot/reset/change password
- profile read/update
- API key list/create/delete
- recent session listing
- 2FA enable and verify
- contact submission
- job application submission

This file is long, but the length comes from responsibility breadth rather than deep algorithmic complexity.

#### The 2FA implementation

The 2FA flow is worth calling out because it is concrete and production-shaped:

1. The enable endpoint generates a TOTP secret.
2. It builds a provisioning URI.
3. It renders a QR code as a base64 PNG.
4. The verify endpoint validates the submitted code.
5. If valid, the user is marked as 2FA-enabled and backup codes are returned.

That is a real security feature, not a placeholder.

#### Why contact and careers live here

This is a product-structure compromise. Strict domain purists might split contact/careers into a separate public app. This repository keeps them in `accounts`, probably because they are inbound user-related records and simpler to manage that way.

### 3.3 `scanning`: The Product Core

The `scanning` app is the heart of the system. It is large because it combines:

- the persistent scan domain model
- the public scan API
- export logic
- findings management
- scope management
- webhooking
- scheduled scans
- multi-target scanning
- asset tracking
- live progress streaming
- task dispatch hooks
- the entire engine directory

Conceptually, it is both the product domain and the product execution layer.

This is the most important app in the backend and deserves its own full chapter, which comes next.

### 3.4 `chatbot`: An Assistant That Can Act

The chatbot app has a narrower but interesting architecture.

#### Data layer

- `ChatSession` stores a conversation container.
- `ChatMessage` stores messages, roles, feedback, and optional action metadata.

#### Engine layer

`chatbot/engine.py` contains three core ingredients:

- a large system prompt that teaches the model about the product and its allowed behavior
- a set of action tool definitions
- a local knowledge base fallback

That means the chatbot is not just an LLM wrapper. It is a constrained orchestration layer with product-specific memory and tools.

#### Action layer

`chatbot/actions.py` is where model intent becomes concrete platform behavior. The registered actions include:

- starting scans
- fetching recent scans
- checking scan status
- exporting scans
- reading subscription info
- reading vulnerability details
- emitting navigation directives

This action layer is the key safety boundary. It limits what the assistant can do to named, reviewable functions.

#### View layer

`chatbot/views.py` exposes:

- send message
- list sessions
- get session detail
- delete session
- send feedback on a message
- fetch suggestions
- fetch analytics

That is exactly the right split for an AI feature in a SaaS product: conversation storage, constrained actions, and feedback capture.

### 3.5 `ml`: Preserved Intelligence Modules

The `ml` app contains at least two substantial modules:

- phishing URL detection
- malware file detection

Both combine rule-based fallback logic with model-loading and prediction behavior. The important architectural fact is that this subsystem still exists even though some related product flows appear de-emphasized or deactivated in the current repository.

This tells you something about the project history: SafeWeb AI likely evolved from a broader security-analysis idea into a more focused web application scanning product, but it retained the ML experiments and infrastructure.

### 3.6 `admin_panel`: Internal Operations Surface

The admin app is a classic privileged operational plane.

It includes:

- admin dashboard metrics
- user management
- scan oversight and cancellation
- ML management actions
- settings management
- contact and application review

This is important because SafeWeb AI is not coded like a toy student project where all admin work happens in Django admin. It has a bespoke operational API layer.

### 3.7 `learn`: Lightweight but Purposeful

The `learn` app is intentionally simple:

- an `Article` model
- filtered article listing
- article detail retrieval by slug or id

This app rounds out the platform story. SafeWeb AI is not only a scanner; it is also trying to be a learning and guidance product.

---

## 4. Data Model and API Surface

If the previous chapter explained the system by app, this chapter explains it by data and workflow.

### 4.1 The Core Entity Relationship in Plain English

The central relational story of the system is:

- A `User` owns many `Scan` records.
- A `Scan` owns many `Vulnerability` records.
- A `Scan` may also own auth configs, reports, assets, webhook deliveries, and child scans.
- A `User` also owns API keys, sessions, scopes, scheduled scans, and webhooks.
- A `ChatSession` may belong to a user and optionally be associated with a scan.

That means SafeWeb AI is fundamentally scan-centric, not chatbot-centric and not content-centric.

### 4.2 `Scan` Is the Most Important Model

The `Scan` model in `scanning/models.py` acts like the backbone of the platform.

It stores or coordinates:

- target URL
- scan type
- depth
- scope mode
- status
- timing and progress metadata
- recon results
- tester results
- data-version style live-update support
- parent and child scan relationships
- completion and error fields

This is not a minimal table. It is a workflow ledger. It contains both business metadata and runtime telemetry.

That design choice makes the UI easier to build because most scan state can be read from one place. The tradeoff is that the model becomes broad and potentially heavy.

### 4.3 `Vulnerability` Is Both a Finding and a Report Unit

The `Vulnerability` model stores more than a simple severity label. It carries:

- name and category
- affected URL
- description, impact, and remediation text
- evidence
- CWE and CVSS metadata
- verification state
- false-positive score
- exploit-related metadata
- attack-chain fields

This is the right shape for a security product because findings have to serve three audiences at once:

- the scanner engine
- the frontend UI
- exported reports

### 4.4 Supporting Scan Models

The scan domain has several supporting models that tell you the product is intended to scale beyond single-click scans.

| Model | Why it exists |
| --- | --- |
| `AuthConfig` | authenticated scanning |
| `ScheduledScan` | recurring scan execution |
| `ScanReport` | persisted export artifacts |
| `Webhook` and `WebhookDelivery` | outbound event integration |
| `ScopeDefinition` | reusable scoping rules |
| `MultiTargetScan` | bulk scanning workflows |
| `DiscoveredAsset` | asset inventory / attack surface tracking |
| `NucleiTemplate` | template-driven external scanning support |

These are not decorative models. They represent product expansion paths already expressed in the schema.

### 4.5 The API Is Organized by User Intent

A good API is not only about REST style. It should map to user goals. The SafeWeb AI API mostly does.

#### Authentication and profile APIs

The auth layer includes registration, login, token refresh, current-user verification, password flows, API key management, session viewing, and 2FA.

This means the frontend does not need to infer identity state. It can always ask the backend for a canonical answer.

#### Scanning APIs

The scan layer includes endpoints for:

- starting scans
- resolving and confirming wide scopes
- reading scan details
- deleting and rescanning
- exporting
- listing findings
- comparison and dashboard metrics
- streaming progress via SSE
- template, scope, webhook, scheduled-scan, asset, auth-config, and multi-target management

That is a large API surface, but it follows the product shape closely.

#### Chatbot APIs

The chat layer exposes message send, session history, feedback, suggestions, and analytics.

#### Admin APIs

The admin layer exposes privileged operational control over users, scans, ML state, settings, contacts, and applications.

#### Learn APIs

The learn layer exposes public article listing and detail retrieval.

### 4.6 The Authentication Flow, Step by Step

Here is the actual platform auth loop in plain language.

1. The user registers or logs in through the frontend.
2. Django validates credentials and returns JWT tokens.
3. The frontend stores tokens client-side.
4. Subsequent Axios requests include the access token.
5. If the access token expires, the frontend interceptor queues failed requests, uses the refresh token, and replays pending requests.
6. The backend can also record session metadata and support API-key access patterns.
7. If 2FA is enabled, TOTP verification becomes part of the protected account flow.

This is a strong and pragmatic design for a single-page app.

### 4.7 The Scan Lifecycle at the Data Layer

The full scan lifecycle looks like this:

1. A `Scan` row is created in a pending state.
2. Optional scope resolution may expand the target set.
3. Background execution begins.
4. Progress, recon data, tester results, and findings are incrementally written back.
5. SSE and polling read those changes live.
6. Final score, reports, and completion metadata are written.
7. The frontend presents the finished or failed result.

The key architectural choice is that the database is the single source of truth for scan progress. The frontend is not listening to a private in-memory queue; it is listening to the persistent product state.

### 4.8 The Vulnerability Lifecycle

A finding does not appear out of nowhere. In this repository it usually goes through a pipeline like this:

1. A tester or tool identifies suspicious behavior.
2. It constructs a vulnerability payload using helper methods from the tester base.
3. The result is normalized into a database-backed `Vulnerability` object.
4. Verification and false-positive reduction stages may refine confidence.
5. The frontend renders it with severity, evidence, and remediation.
6. Export generators serialize it into JSON, CSV, PDF, HTML, or related reporting formats.

This explains why the finding schema is rich. The object has to survive several lives.

---

## 5. The Scanning Engine: The Core of the Product

This is the most important chapter because the scan engine is what makes SafeWeb AI more than a standard dashboard application.

The engine is large enough that the right way to explain it is as a layered system rather than as a list of hundreds of files.

### 5.1 The Engine Directory Is a Security Platform in Miniature

The `backend/apps/scanning/engine/` tree contains multiple families of modules:

- orchestrators
- crawlers
- recon modules
- analyzers
- testers
- payload collections
- OOB helpers
- external tool wrappers
- scoring and reporting helpers
- comparison and verification utilities
- scope resolution and multi-target support

The key insight is this: the repository does not implement scanning as one giant function. It implements scanning as a toolbox of narrow components coordinated by a central conductor.

### 5.2 `orchestrator.py` Is the Conductor

`orchestrator.py` is where the whole system comes together.

At a high level, it is responsible for:

- taking a scan identifier
- loading the scan record
- deciding how scope should be handled
- coordinating the asynchronous website scan path
- invoking verification and other later-stage processing
- updating persistent progress

This is the file where product workflow and engine workflow meet.

#### Why an orchestrator is the right pattern here

Security scanning has many independent activities:

- discover targets
- crawl pages
- inspect headers and cookies
- fuzz inputs
- confirm out-of-band callbacks
- correlate findings
- score the target
- render reports

Trying to do all of that inside a model method or a view function would collapse under its own complexity. The orchestrator gives the system a place to sequence heterogeneous work without polluting the web layer.

### 5.3 Scope Resolution Is a Real First-Class Concern

`engine/scope/scope_resolver.py` is an important design signal.

The repository explicitly distinguishes three scope modes:

- `single_domain`
- `wildcard`
- `wide_scope`

That means the scan engine is not built only for single-URL inspection. It is designed to grow into broader attack-surface workflows.

#### What the resolver actually does

The resolver normalizes input and then changes strategy based on scope type:

- `single_domain` returns the normalized target directly.
- `wildcard` uses certificate transparency discovery plus seed domains, then probes alive hosts.
- `wide_scope` uses organization-level OSINT methods such as reverse WHOIS, ASN enumeration, CT-org search, then probes live URLs.

This is a mature design choice because scope is one of the hardest product problems in security tooling. If scope is wrong, everything after it is wrong.

### 5.4 The Crawler Turns Targets into Attack Surface

`engine/crawler.py` defines the structures that the rest of the engine consumes.

Its page and form dataclasses are not cosmetic. They are the attack surface model.

The crawler's job is to produce things like:

- URLs to revisit
- query parameters to mutate
- forms to submit
- form inputs to fuzz
- evidence of dynamic or SPA behavior

This is crucial because testers do not want raw HTML; they want normalized attack vectors.

#### Why the crawler is architecturally central

In a web vulnerability scanner, crawling quality directly limits testing quality.

- If the crawler misses forms, auth and injection tests lose coverage.
- If it misses parameters, input-based testers underperform.
- If it misses SPA-rendered routes, modern app coverage becomes shallow.

That is why this repository invests in a richer crawler instead of treating crawling as a one-off helper.

### 5.5 `BaseTester` Defines the Contract for Vulnerability Modules

`engine/testers/base_tester.py` is one of the most important reuse points in the entire codebase.

It centralizes common tester behavior such as:

- HTTP request helpers
- standardized vulnerability object construction
- payload augmentation
- recon-aware behavior
- WAF-aware behavior
- victim session and browser-context support

This is the correct pattern for a large vulnerability suite. Without a shared base class, each tester would reinvent transport, evidence formatting, and vulnerability schema logic.

### 5.6 A Representative Tester: `xss_tester.py`

The XSS tester is a good example of how individual testers are structured.

It shows several important engine-wide patterns:

1. Payloads are chosen by scan depth.
2. Payloads can be augmented with SecLists-derived material.
3. WAF detection influences payload order and bias.
4. Different input surfaces are tested separately: URL params, form inputs, DOM cues, headers, and deep-only special cases.
5. Vulnerabilities are built through a normalized helper path, not hand-shaped inconsistently.

The XSS tester does not only look for a single reflected string. It branches into:

- reflected XSS
- form-based reflected XSS
- context-aware XSS
- stored XSS
- mutation XSS
- DOM clobbering checks
- header-based injection
- blind XSS concepts
- client-side template injection
- SVG-related injection paths

Even if some detections are heuristic rather than browser-verified, the design shows that the team thought in terms of vulnerability families, not only simplistic payload substitution.

### 5.7 Engine Pattern: Depth Controls Cost and Ambition

Several parts of the repository point to the same architectural idea: scan depth is a strategy control.

- shallow scans do less work
- medium scans add broader context-aware behavior
- deep scans unlock expensive or riskier paths such as stored tests, mutation tests, blind callback tests, and richer probing

This is a practical way to balance operator time, resource use, and coverage.

### 5.8 External Tools Are Wrapped, Not Hardcoded

The external tool layer is built around two files conceptually:

- `engine/tools/base.py`
- `engine/tools/registry.py`

#### What `ExternalTool` does

The base wrapper class defines a common interface for external binaries:

- availability checks via PATH lookup
- subprocess execution with timeout handling
- async execution support
- normalized parsing contract
- graceful degradation when binaries are absent

This matters because production deployments rarely have every offensive tool available. The code anticipates that reality.

#### What the registry does

The registry acts like a tool inventory service.

It lets the engine:

- register all wrappers
- ask which tools support which capabilities
- run health checks
- avoid scattering tool-discovery logic across the engine

That is a good application of the registry pattern. It keeps external tooling pluggable.

### 5.9 Why Graceful Degradation Matters Here

Many academic or prototype scanners assume the full toolchain exists. SafeWeb AI does not.

The code repeatedly assumes that:

- a binary may be missing
- a subprocess may time out
- a third-party tool may fail noisily

The scanner tries to continue instead of collapsing the entire scan.

This is one of the better engineering choices in the repository.

### 5.10 Reconnaissance Is Not a Single Phase, It Is a Data Feed

The engine tree contains many recon modules, and the scope resolver itself already performs discovery-style work.

The important architectural point is that recon in this codebase is not just a preamble. It is an intelligence layer that later stages consume.

For example:

- detected technologies influence testing choices
- discovered parameters widen input fuzzing
- WAF signals alter payload strategy
- asset/scope discoveries change which hosts are tested

This is why `BaseTester` accepts recon context. Recon is treated as input to exploitation strategy, not only as report decoration.

### 5.11 OOB Support Means the Engine Is Designed for Blind Bugs

`engine/oob/oob_manager.py` is a strong signal of scanner maturity.

The OOB layer exists to support vulnerabilities that do not prove themselves in-band, such as:

- blind SQL injection
- blind SSRF
- XXE with external entity callbacks
- command injection with DNS/HTTP egress
- server-side template injection with external effects

#### What the OOB manager does

- generates unique callback identifiers and URLs
- maps payloads to callback context
- polls for interactions
- correlates returned evidence to the original attempted attack
- translates confirmed callbacks into finding objects with vulnerability metadata

This is exactly what a serious scanner needs to move beyond reflected-response bugs.

### 5.12 Comparison and Trend Analysis Are First-Class Features

`engine/scan_comparison.py` shows that the product is not only about one-off scans. It also cares about change over time.

It computes:

- new findings
- fixed findings
- recurring findings
- severity changes
- regressions
- posture trend data

This is strategically important. Most organizations do not ask only, "What is broken?" They ask, "Is security getting better or worse over time?"

### 5.13 Scoring Encodes Product Judgment

`engine/scoring.py` handles two related jobs:

- converting technical attributes into CVSS-like reasoning
- collapsing vulnerability sets into an overall security score and category

This is not just arithmetic. It is product philosophy turned into code.

Any platform that emits a single score is making a judgment about how critical, high, medium, and low findings should combine. That judgment lives here.

### 5.14 Reporting Turns Raw Results into User-Facing Deliverables

`engine/report_generator.py` exists because a scanner is not finished when it detects something. It is finished when a human can consume the result.

The report generator supports multiple output modes, including PDF generation. It is responsible for translating scan state and vulnerability objects into documents that can be exported, shared, and archived.

That makes it the final presentation layer of the backend.

### 5.15 The Engine's Real Architectural Shape

If you reduce the engine to its actual moving parts, the structure looks like this:

1. Normalize target and scope.
2. Discover assets and pages.
3. Turn pages into fuzzable inputs.
4. Run analyzers and testers.
5. Run or consult external tools when available.
6. Confirm blind callbacks where necessary.
7. Normalize findings.
8. Verify, correlate, score, and compare.
9. Persist results and generate reports.

This is the core technical identity of SafeWeb AI.

### 5.16 Why the Engine Is Both Powerful and Hard to Maintain

The engine is the product's strength, but also its maintenance risk.

Reasons it is powerful:

- many vulnerability classes are represented
- internal and external testing strategies are combined
- OOB confirmation exists
- reporting and scoring are integrated
- scoping and comparison are productized

Reasons it is hard to maintain:

- many modules mean many implicit contracts
- the tester surface area is large
- tool wrappers depend on local environment realities
- views, tasks, models, and engine code are tightly coupled through the `Scan` lifecycle

A new engineer should expect that working safely in this engine requires discipline, not only Python knowledge.

---

## 6. Frontend Architecture: React as the Operator Console

The frontend is best understood as an operator dashboard rather than a marketing site, even though the repository also contains public informational pages.

### 6.1 `App.tsx` Is the Frontend Architecture Diagram

`src/App.tsx` tells you almost everything important about the UI structure.

It contains:

- route declarations
- page-level lazy loading
- protected-route logic
- admin-route logic
- error boundary wrapping
- suspense boundaries
- always-available chatbot widget mounting

This is a strong app-shell design. It keeps routing, protection, and resilience visible in one place.

### 6.2 Route Groups Reflect Product Groups

The route tree divides naturally into three classes:

- public pages: home, auth, legal, informational, learning
- authenticated product pages: dashboard, scan creation, scan results, history, profile, assets, scopes, scheduled scans, comparisons
- admin pages: dashboard and management consoles

This mirrors the backend app partitioning closely, which is good. Frontend and backend product mental models line up.

### 6.3 `AuthContext.tsx` Centralizes Identity State

The auth context performs several critical jobs:

- verifying the current user on startup
- exposing login and registration methods
- exposing logout behavior
- refreshing profile data
- surfacing authenticated state to the rest of the app

This means the application does not scatter auth logic across pages. That is the correct React architecture for this size of product.

### 6.4 `api.ts` Is the Browser-Side Integration Layer

`src/services/api.ts` is one of the most important frontend files.

It does much more than send HTTP requests.

It provides:

- a configured Axios client
- token attachment
- automatic refresh on 401
- queued retry behavior during refresh
- grouped API namespaces for each major backend domain

This file is what lets the rest of the frontend feel clean. Pages can call `scanAPI`, `chatAPI`, `userAPI`, or `adminAPI` rather than rebuild request logic repeatedly.

### 6.5 Why the Refresh Queue Matters

Many frontend apps implement token refresh badly. They allow multiple simultaneous refresh requests and create race conditions.

This repository instead queues failed requests while a refresh is in progress and then replays them.

That is exactly the right pattern for a multi-request SPA.

### 6.6 `ScanWebsite.tsx` Encodes Product Configuration Logic

The scan-creation page is not just a form. It is a UI expression of backend scan semantics.

It deals with:

- target input
- scan depth
- scope mode
- optional resolution/confirmation flow for broad scope
- payload shaping to match backend expectations

That means the page is a product policy adapter, not only a presentation component.

### 6.7 `ScanResults.tsx` Is the Most Important Product Page

The scan-results page is where most of the product's architectural complexity becomes visible to users.

It coordinates:

- initial scan loading
- polling and SSE live updates
- progress and timing visualization
- findings and summary tabs
- export actions
- rescan actions
- false-positive or finding refresh behavior

This page is effectively the frontend equivalent of the backend orchestrator: it is where many subsystems converge.

### 6.8 The Chatbot Widget Is Integrated, Not Bolted On

`src/components/layout/ChatbotWidget.tsx` is architecturally interesting because it is mounted globally rather than only on a chat page.

It handles:

- open/close widget behavior
- welcome prompts and suggestions
- session history
- markdown rendering
- action-aware responses
- feedback capture
- optional scan-aware context via route-derived scan IDs

That choice makes the assistant feel like a product capability rather than a separate feature silo.

### 6.9 Styling and Visual Language

The frontend styling stack consists primarily of:

- `index.css`
- Tailwind configuration
- component-level utility classes

The theme is cyber-security-oriented rather than neutral enterprise minimalism. That is visible in:

- dark-first presentation
- branded accent colors
- custom animations and more stylized design language

This matters more than it may seem. Visual identity is part of product positioning, especially for a security platform.

### 6.10 How to Read the Frontend Efficiently

For a new engineer, the fastest useful reading order is:

1. `src/main.tsx`
2. `src/App.tsx`
3. `src/contexts/AuthContext.tsx`
4. `src/services/api.ts`
5. `src/pages/ScanWebsite.tsx`
6. `src/pages/ScanResults.tsx`
7. `src/components/layout/ChatbotWidget.tsx`

After those files, the rest of the frontend becomes much easier to navigate because you already understand routing, identity, transport, the main workflow, and the assistant integration.

---

## 7. Runtime Data Flow: Auth, Scans, SSE, Chat, and Background Work

This chapter explains how the moving pieces interact while the system is alive.

### 7.1 Auth Flow End to End

The auth flow spans both backend and frontend cleanly.

#### Browser side

- the user submits credentials
- tokens are stored client-side
- the auth context requests verification to hydrate user state
- the Axios interceptor keeps access tokens fresh

#### Server side

- Django validates credentials
- JWT tokens are issued through the auth views
- session metadata can be recorded
- profile and security endpoints provide the current account state

#### Why this works well

The backend stays authoritative, but the frontend is resilient enough to survive token expiry without blowing up the user session immediately.

### 7.2 Scan Creation Flow

The scan creation flow is more sophisticated than a single POST.

1. The frontend gathers target, depth, and scope configuration.
2. For broad scope modes, it may ask the backend to resolve or confirm scope before final execution.
3. Django creates the scan record.
4. Django dispatches work either to Celery or to a fallback background thread, depending on environment/runtime mode.
5. The frontend redirects into a results-centric workflow.

This is a good example of backend and frontend aligning around domain semantics rather than generic forms.

### 7.3 Progress Updates: Database as the Hub

The platform's live-update design is centered on persistent scan state.

That means:

- the engine updates the `Scan` row and related findings as work proceeds
- the frontend can poll safely because state lives in the database
- SSE can stream progress events derived from the same persisted source of truth

This is a pragmatic design. If the connection drops, the UI can reconnect and recover from the database state.

### 7.4 Why Both SSE and Polling Exist

The scan-results page uses both real-time and fallback synchronization strategies.

That may seem redundant, but it is actually sensible.

- SSE provides low-latency push-style updates.
- Polling protects the UI if SSE is interrupted by proxy behavior, browser issues, or deployment quirks.

This dual-path approach is particularly useful in environments where long-lived streaming connections may be less reliable than normal HTTP requests.

### 7.5 Celery and Redis in Practice

The codebase treats Celery as the preferred async execution model, but not the only one.

#### In development

- eager task execution makes local setup simpler
- developers can work without a separately managed distributed queue

#### In fuller environments

- Redis acts as broker/result backend
- Celery workers handle scan execution and scheduled work
- worker startup also tries to prepare the tool registry

This flexibility is useful during development, but it also means there are multiple execution behaviors engineers need to understand.

### 7.6 The Chat Flow

The chatbot is another end-to-end loop.

1. The widget sends a user message.
2. The backend loads recent conversational context.
3. The chatbot engine prepares the system prompt and action context.
4. The model or fallback knowledge logic generates a response.
5. If an allowed action is needed, the action layer executes it.
6. The response and any action metadata are persisted.
7. The frontend renders the message, markdown, and optional feedback controls.

This is a good architecture for an AI feature because the dangerous step, doing something, is separated from the generative step, saying something.

### 7.7 Export Flow

When a user exports a scan:

1. the frontend triggers an export endpoint
2. Django gathers scan and vulnerability data
3. the reporting layer serializes the results into the requested format
4. the file or payload is returned or stored as a report artifact

This is straightforward, but important. In security products, reporting is not secondary; it is often the actual deliverable customers care about.

### 7.8 Scheduled and Multi-Target Execution

The presence of scheduled-scan and multi-target models plus task handlers shows a broader operating model:

- the system is intended to monitor over time, not only scan once
- the platform can expand from single-target UX to estate-level workflows

This is strategically significant because it pushes the product toward ongoing security operations rather than isolated testing.

---

## 8. Security Decisions, Tradeoffs, and Codebase Risks

A good codebase explanation should not only praise architecture. It should also explain where the system is strong, where it is compromised for pragmatism, and where future bugs are likely to concentrate.

### 8.1 Strong Decisions in This Repository

Several implementation choices are solid.

#### Custom user model from the start

This avoids painful migrations later and supports plans, roles, 2FA, and future organization features cleanly.

#### JWT plus refresh flow

This is a natural fit for a React SPA and is implemented with enough frontend rigor to avoid common refresh races.

#### 2FA support

The TOTP flow is concrete and useful.

#### Graceful degradation for tool wrappers

The scan engine expects imperfect environments and keeps working when some tools are missing.

#### SSE plus polling fallback

This improves resilience for long-running scan workflows.

#### Rich finding model

This supports both UI rendering and report generation without lossy transformations.

### 8.2 Practical Tradeoffs

Some choices are understandable, but have costs.

#### Development-default settings in multiple entrypoints

Pros:

- fast local setup

Cons:

- deployment can accidentally inherit unsafe defaults if environment selection is incomplete

#### Large view modules

`scanning/views.py` and `accounts/views.py` carry many concerns.

Pros:

- it is easy to find endpoints in one place

Cons:

- change risk is higher
- review burden is higher
- subtle cross-endpoint coupling becomes more likely

#### Rich `Scan` model

Pros:

- one authoritative state object for the frontend

Cons:

- model bloat
- heavier serialization
- more schema churn risk as features evolve

#### Hybrid execution model

Pros:

- local development remains easy

Cons:

- behavior differs between eager mode, thread fallback, and Celery-backed execution

### 8.3 Risks and Engineering Hotspots

These are the parts of the repository where careful engineers should expect complexity and regression risk.

#### The scan engine contract surface

There are many implicit contracts between:

- crawler output
- tester input expectations
- vulnerability building helpers
- scan model fields
- report generation

If one of those shapes changes casually, many downstream paths can break.

#### External tool environment drift

The more wrappers a project has, the more sensitive it becomes to:

- PATH configuration
- binary version differences
- platform-specific shell behavior
- timeouts and output parsing edge cases

#### Deployment drift between story and manifests

The repository currently tells more than one deployment story. That can mislead new maintainers and complicate incident response.

#### Preserved but de-emphasized subsystems

The ML modules and some scan types exist, but parts of the live product appear more web-scan-centered. That kind of partial deactivation can confuse future contributors unless it is documented clearly.

### 8.4 Security Features That Matter at the Product Level

From a product-security standpoint, the codebase includes meaningful defenses and controls:

- secure password rules
- JWT-based auth
- 2FA
- session visibility
- API keys
- deployment-time security headers in frontend hosting config
- production hardening in Django settings

This is not a naive security product that ignores its own security posture.

### 8.5 The Most Honest Summary of the Architecture

SafeWeb AI is technically ambitious and structurally serious, but it is also still carrying the marks of a fast-moving project:

- some parts are polished
- some parts are broad rather than deeply normalized
- some operational stories are ahead of the checked-in manifests

That combination is common in strong student-built or early-stage product codebases.

---

## 9. Deployment, Tooling, and Operational Reality

This chapter explains what the repository actually supports operationally.

### 9.1 Verified Deployment Files

The checked-in deployment files show a concrete runtime story.

#### `backend/Procfile`

Runs Gunicorn against `config.wsgi:application` with two workers and a 120-second timeout.

#### `railway.toml`

Defines:

- health check path `/api/health/`
- health check timeout
- restart policy

This is backend-platform-oriented and directly executable.

#### `nixpacks.toml`

Defines a Python-focused build plan that:

- installs backend requirements
- collects static assets
- runs migrations
- runs `create_admin.py`
- starts Gunicorn

This is the clearest checked-in description of how the backend is expected to boot in a managed environment.

#### `vercel.json`

Defines the frontend deployment shape:

- Vite framework build
- output directory `dist`
- SPA rewrite to `index.html`
- immutable caching for assets
- several security headers

### 9.2 The README's Azure Story vs Repository Reality

The README and project context describe a much broader Azure deployment narrative, including App Service, Static Web Apps, PostgreSQL, Redis, Blob Storage, Key Vault, Application Insights, and Bicep-defined infrastructure.

However, within the inspected repository tree:

- those Azure deployment manifests were not present
- no `infra/` directory was found
- the concrete checked-in deployment files point elsewhere

The most responsible interpretation is:

- Azure is a target architecture or external deployment plan
- Railway/Vercel/Nixpacks are the concrete checked-in operational path

Any future team should resolve that ambiguity explicitly.

### 9.3 Local Tooling Is a Major Part of the Product

SafeWeb AI is unusual in that a meaningful portion of its power depends on local or attached security tooling.

The `scripts/` directory includes PowerShell automation for:

- installing toolchains
- fixing missing tools
- checking core tools
- verifying all tools
- capturing screenshots and related artifacts

This is a major operational clue: the scanner is designed to work in environments where external offensive tooling may need to be provisioned into the project context.

### 9.4 `tools/` Is Not Just a Convenience Folder

The `tools/` directory is the local landing zone for supporting binaries and related assets.

In practical terms, it is part of the runtime perimeter of the product. If that directory is empty or inconsistent, external-wrapper coverage drops.

### 9.5 Expected Local Development Loop

Based on the repository structure, the normal development loop is roughly:

1. install frontend dependencies
2. install backend Python dependencies
3. configure environment variables
4. run Django locally
5. run Vite locally
6. optionally provision Redis/Celery and security tools depending on depth of testing

Because development settings use eager Celery execution, the system can still be exercised without full distributed infrastructure, which lowers onboarding friction.

### 9.6 Operational Consequence of External Tools

This platform is not operationally equivalent to a pure Django app.

It depends on:

- command-line tool availability
- network conditions
- browser automation support for richer crawling paths
- potentially different behavior across Windows and Linux environments

That is normal for a scanner, but it must be treated as part of the production and staging design, not as an afterthought.

---

## 10. How to Extend the System Safely

This chapter is for the next engineering team.

### 10.1 How to Add a New Tester

The repository already implies the correct extension pattern.

1. Add a new tester file under `backend/apps/scanning/engine/testers/`.
2. Inherit from `BaseTester`.
3. Reuse request helpers and vulnerability builders.
4. Make depth behavior explicit.
5. Register or invoke the tester through the engine's orchestration path.

The most important rule is consistency. Findings must be shaped in the same way as existing testers, or exports and UI rendering will degrade.

### 10.2 How to Add a New External Tool Wrapper

The wrapper system already gives a clear template.

1. Create a wrapper under `engine/tools/wrappers/`.
2. Inherit from `ExternalTool`.
3. Define `name`, `binary`, capabilities, timeout, `run`, and `parse_output`.
4. Let the registry discover or register it.
5. Ensure missing-binary behavior fails softly.

The key principle is that wrappers should never assume a perfect environment.

### 10.3 How to Add a New Recon Module

A recon module should follow the same discipline:

- produce structured output
- be callable by the orchestrator or related recon coordinator
- fail without crashing the full scan
- enrich downstream tester behavior when possible

The best recon modules are not noisy. They produce actionable intelligence that later phases can consume.

### 10.4 How to Add a New Backend Feature

The clean backend expansion path is:

1. model or schema change
2. serializer contract
3. view or viewset behavior
4. URL registration
5. frontend service method
6. frontend page/component usage

Skipping the serializer layer or overloading models with view-specific logic will make the code harder to maintain.

### 10.5 How to Add a New Frontend Page

The existing route structure suggests the correct sequence:

1. add the page under `src/pages/`
2. add a lazy import in `App.tsx`
3. attach it to the correct public, protected, or admin route group
4. use the service layer in `api.ts`
5. keep page-level data orchestration separate from low-level transport logic

### 10.6 Recommended Refactoring Priorities

If a new team were taking over this repository, the highest-value refactors would likely be:

1. split oversized view modules, especially in `scanning` and `accounts`
2. document or consolidate the dual Celery bootstrap pattern
3. align deployment documentation with checked-in manifests
4. formalize which scan types and ML paths are active vs legacy
5. add stronger test coverage around scan orchestration and findings normalization

### 10.7 The Best Way to Read Before You Change Anything

Before modifying the system, a new engineer should read in this order:

1. `backend/config/settings/base.py`
2. `backend/config/urls.py`
3. `backend/apps/scanning/models.py`
4. `backend/apps/scanning/views.py`
5. `backend/apps/scanning/tasks.py`
6. `backend/apps/scanning/engine/orchestrator.py`
7. `backend/apps/scanning/engine/testers/base_tester.py`
8. `src/App.tsx`
9. `src/contexts/AuthContext.tsx`
10. `src/services/api.ts`
11. `src/pages/ScanWebsite.tsx`
12. `src/pages/ScanResults.tsx`

If you understand those files, you understand the product.

---

## 11. Glossary

| Term | Meaning in this codebase |
| --- | --- |
| `Scan` | the primary unit of scanning work and progress tracking |
| `Vulnerability` | a normalized finding persisted for UI and reporting |
| scan depth | a strategy knob controlling cost and aggressiveness |
| scope type | how broadly the target should be expanded before testing |
| SSE | Server-Sent Events used for live scan progress updates |
| OOB | out-of-band confirmation for blind vulnerabilities |
| external tool wrapper | Python adapter around a security CLI binary |
| `BaseTester` | abstract superclass for vulnerability testing modules |
| `AuthConfig` | scan-time authentication configuration |
| `MultiTargetScan` | bulk scanning workflow object |
| `ScanReport` | export artifact or report record |
| `ChatSession` | persisted conversation container for the assistant |
| `UserSession` | tracked user login/session context |

---

## 12. Appendix A: Backend File Map

### Backend Entry and Config Files

| File | Why it matters |
| --- | --- |
| `backend/manage.py` | CLI entrypoint for Django |
| `backend/celery_app.py` | Celery bootstrap and tool registration |
| `backend/config/wsgi.py` | WSGI app entrypoint |
| `backend/config/asgi.py` | ASGI app entrypoint |
| `backend/config/urls.py` | top-level API routing |
| `backend/config/settings/base.py` | shared backend runtime contract |
| `backend/config/settings/development.py` | local-dev overrides |
| `backend/config/settings/production.py` | deployed-environment overrides |
| `backend/requirements.txt` | backend dependency manifest |
| `backend/Procfile` | Gunicorn process definition |

### `accounts` Files

| File | Responsibility |
| --- | --- |
| `backend/apps/accounts/models.py` | users, sessions, API keys, contact, careers |
| `backend/apps/accounts/serializers.py` | auth/profile validation and shaping |
| `backend/apps/accounts/views.py` | auth and account API endpoints |
| `backend/apps/accounts/urls.py` | auth route registration |
| `backend/apps/accounts/profile_urls.py` | profile, API keys, sessions, 2FA routes |
| `backend/apps/accounts/contact_urls.py` | contact submission route |
| `backend/apps/accounts/careers_urls.py` | job application route |

### `scanning` Files

| File | Responsibility |
| --- | --- |
| `backend/apps/scanning/models.py` | scan and findings domain model |
| `backend/apps/scanning/serializers.py` | scan API contracts |
| `backend/apps/scanning/views.py` | scan lifecycle API and operational endpoints |
| `backend/apps/scanning/tasks.py` | async and scheduled work |
| `backend/apps/scanning/urls.py` | core scan routes |
| `backend/apps/scanning/dashboard_urls.py` | dashboard metrics routes |
| `backend/apps/scanning/list_urls.py` | scan listing routes |

### Representative Engine Files

| File | Why it matters |
| --- | --- |
| `backend/apps/scanning/engine/orchestrator.py` | scan execution conductor |
| `backend/apps/scanning/engine/crawler.py` | page and form discovery |
| `backend/apps/scanning/engine/testers/base_tester.py` | tester contract and helpers |
| `backend/apps/scanning/engine/testers/xss_tester.py` | representative deep tester implementation |
| `backend/apps/scanning/engine/tools/base.py` | external binary wrapper contract |
| `backend/apps/scanning/engine/tools/registry.py` | tool registration and capability lookup |
| `backend/apps/scanning/engine/oob/oob_manager.py` | blind callback management |
| `backend/apps/scanning/engine/scope/scope_resolver.py` | scope expansion logic |
| `backend/apps/scanning/engine/scoring.py` | security score and severity logic |
| `backend/apps/scanning/engine/report_generator.py` | report serialization |
| `backend/apps/scanning/engine/scan_comparison.py` | scan diffing and posture trend |

### `chatbot`, `ml`, `admin_panel`, and `learn`

| File | Responsibility |
| --- | --- |
| `backend/apps/chatbot/models.py` | persisted chat state |
| `backend/apps/chatbot/engine.py` | LLM orchestration and knowledge fallback |
| `backend/apps/chatbot/actions.py` | allowed assistant actions |
| `backend/apps/chatbot/views.py` | chat endpoints |
| `backend/apps/chatbot/urls.py` | chat route registration |
| `backend/apps/ml/phishing_detector.py` | phishing model and heuristics |
| `backend/apps/ml/malware_detector.py` | malware model and heuristics |
| `backend/apps/admin_panel/models.py` | admin alerts/settings |
| `backend/apps/admin_panel/views.py` | privileged admin operations |
| `backend/apps/admin_panel/urls.py` | admin route registration |
| `backend/apps/learn/models.py` | learning content model |
| `backend/apps/learn/views.py` | article listing/detail |
| `backend/apps/learn/urls.py` | learning route registration |

---

## 13. Appendix B: Frontend File Map

| File | Responsibility |
| --- | --- |
| `src/main.tsx` | frontend mount point |
| `src/App.tsx` | route shell, lazy loading, guards, chatbot mount |
| `src/index.css` | global visual styling |
| `src/contexts/AuthContext.tsx` | auth state and identity actions |
| `src/services/api.ts` | Axios client, token refresh, API namespaces |
| `src/pages/ScanWebsite.tsx` | scan creation and scope UI |
| `src/pages/ScanResults.tsx` | live scan results and exports |
| `src/components/layout/ChatbotWidget.tsx` | globally available assistant UI |

There are many additional pages, components, hooks, and types under `src/`, but the files above form the fastest reliable path to understanding how the frontend actually behaves.

---

## 14. Appendix C: Major API Groups

### Auth and User

- register
- login
- logout
- verify current user
- refresh token
- Google auth entrypoint
- forgot/reset/change password
- profile read/update
- API key create/list/delete
- session list
- 2FA enable/verify

### Scanning

- create website scan
- resolve or confirm broad scope
- get scan detail
- delete scan
- rescan
- export scan
- list findings
- compare scans
- dashboard/history routes
- SSE stream
- auth-config, webhook, scope, template, scheduled-scan, multi-target, asset routes

### Chatbot

- send message
- list sessions
- get session detail
- delete session
- message feedback
- suggestions
- analytics

### Admin

- dashboard metrics
- user management
- scan oversight
- ML operations
- settings management
- contact review
- application review

### Learning

- article list
- article detail

---

## 15. Appendix D: Verified Mismatches and Gaps

This appendix is intentionally blunt because it is often the most useful part of onboarding documentation.

### 15.1 Azure Narrative vs Checked-In Files

The project narrative strongly describes Azure deployment, but the concrete deployment files in the repository point to Railway, Vercel, and Nixpacks behavior. If Azure is the real target, the repo should either include its infrastructure artifacts or the docs should clearly distinguish target architecture from present implementation.

### 15.2 Missing `infra/` Directory

The requested explanation expected `infra/`, but that directory was not present in the inspected workspace tree. Any explanation of infrastructure-as-code beyond that absence would be speculation.

### 15.3 Active vs Legacy Product Surface

The repository contains evidence of broader ambitions, including additional scan types and preserved ML modules, while the dominant live product path is website scanning. This should be documented explicitly for future maintainers.

### 15.4 Oversized Files

Some files, especially the larger view modules and engine coordinators, carry many responsibilities. They are understandable, but they are also likely future refactoring targets.

---

## Closing Perspective

SafeWeb AI is best understood as a security operations platform built on top of a conventional web stack. Django provides state, policy, and APIs. React provides the operator experience. The scanning engine provides the real product differentiation. Redis and Celery provide runtime elasticity when available. The assistant and ML modules provide augmentation layers around that core.

What makes the repository interesting is not only its size. It is the fact that it tries to connect product UX, security scanning methodology, external-tool interoperability, live progress streaming, and AI assistance into one coherent system.

That coherence is not perfect yet. There is deployment drift, some feature-history residue, and some large-module maintenance risk. But the architecture is real, the core workflows are concrete, and the repository contains enough structure that a disciplined new team could extend it successfully.

If you understand the scan model, the orchestrator, the tester base class, the API service layer, and the scan-results page, you understand the product.