```markdown
# SafeWeb AI
## AI-Powered Web Application Vulnerability Scanner & Penetration Testing Platform
### Technical System Documentation

---

# 1. Project Overview

**SafeWeb AI** is a professional-grade, full-stack cybersecurity web application built as a university graduation project. The platform delivers enterprise-level web application security assessments by combining:

1. **Automated Vulnerability Scanning** — 85+ vulnerability testers across OWASP Top 10 and beyond
2. **Intelligent Reconnaissance** — 40+ recon modules in 4 concurrent async waves
3. **62 External Tool Integrations** — Nmap, Nuclei, SQLMap, Subfinder, and 58 more
4. **AI-Powered Analysis** — LLM chatbot (Gemini 2.0 Flash) with 7 function-calling tools
5. **Machine Learning** — Phishing detection (GBM), malware classification (RF), false positive reduction (5-component ensemble)
6. **Educational Security Center** — 9-category article library
7. **Admin Dashboard** — User management, scan analytics, ML model monitoring

### Technical Identity

| Attribute | Value |
|:----------|:------|
| **Repository** | `0xN0RMXL/safeweb-ai` (GitHub, branch: `main`) |
| **Backend** | Django 5.0 + DRF + Celery (Python 3.11) |
| **Frontend** | React 18 + TypeScript 5 + Vite + TailwindCSS |
| **Database** | PostgreSQL 16 (Azure Flexible Server) |
| **Cloud** | Microsoft Azure (full deployment) |
| **Cache/Broker** | Azure Cache for Redis |
| **CI/CD** | GitHub Actions → Azure (blue/green slot swap) |
| **IaC** | Bicep templates |

---

# 2. System Architecture

## 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│               FRONTEND (Azure Static Web Apps)                  │
│  React 18 + TypeScript + Vite + TailwindCSS                     │
│  35 routes, 74+ source files, lazy-loaded pages                 │
│  SSE real-time scan updates, AI chatbot widget                  │
│  Azure CDN (global edge caching) + Custom Domain + SSL          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS (REST API via Axios)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│           BACKEND (Azure App Service — Linux P1v2)              │
│  Django 5.0 + DRF + Gunicorn + WhiteNoise                       │
│  6 Django apps: accounts, scanning, chatbot, ml, admin_panel,   │
│  learn                                                          │
├─────────────────────────────────────────────────────────────────┤
│  SCANNING ENGINE                                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Recon    │ │ Crawl    │ │ Analyzers│ │ Testers  │          │
│  │ 40+ mods │ │ BFS+JS   │ │ Hdr/SSL/ │ │ 85+ vuln │          │
│  │ 4 waves  │ │ Playwright│ │ Cookie   │ │ testers  │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Nuclei   │ │ Secrets  │ │ ML/AI    │ │ Exploit  │          │
│  │ Templates│ │ 200+ pat │ │ XGBoost  │ │ Generator│          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  62 external tool wrappers (nmap, sqlmap, nuclei, etc.)        │
├─────────────────────────────────────────────────────────────────┤
│  AI CHATBOT ENGINE                                              │
│  OpenRouter LLM (Gemini 2.0 Flash) + 7 function-calling tools  │
│  Local knowledge base fallback (36+ topics)                     │
├─────────────────────────────────────────────────────────────────┤
│  ML MODELS                                                      │
│  Phishing: GBM (31 features) | Malware: RF (9 features)        │
│  Attack Prioritizer: XGBoost | FP Reducer: 5-component ensemble│
└──────────────────────────┬──────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
  Azure PostgreSQL    Azure Redis Cache    Azure Blob Storage
  (Flexible Server)   (Basic C0/C1)       (Reports, ML models)
```

## 2.2 Design Patterns

| Pattern | Application |
|:--------|:------------|
| **Registry** | `ToolRegistry` for external tool management with auto-discovery |
| **Strategy** | Multiple scan depth strategies (shallow/medium/deep), scope types |
| **Observer** | SSE for real-time scan progress, webhook event notifications |
| **Factory** | Tester instantiation from registered tester classes |
| **Template Method** | `BaseTester` defines test lifecycle, subclasses override methods |
| **Pipeline** | `ScanOrchestrator` phases execute in sequence with data flowing forward |
| **Command** | Chatbot actions (`start_scan`, `navigate_to`, etc.) |
| **Facade** | API service layer in frontend abstracts 16 API namespaces |

## 2.3 Non-Functional Requirements

| Requirement | Implementation |
|:------------|:---------------|
| **Scalability** | Celery async tasks, distributed scan support, auto-scaling (1–4 instances) |
| **Resilience** | Graceful degradation (missing tools skipped), retry mechanisms, fallback modes |
| **Security** | JWT auth with rotation, CORS, CSRF protection, input validation, rate limiting |
| **Performance** | ML-prioritized testing, async scanning, lazy-loaded frontend, Redis caching |
| **Maintainability** | Modular engine (each tester/recon module is independent), typed API |
| **Observability** | Phase timing, tester results tracking, data versioning for SSE, Application Insights |

---

# 3. Technology Stack

## 3.1 Backend

| Component | Technology | Details |
|:----------|:-----------|:--------|
| Framework | Django 5.0 | Web framework |
| API | Django REST Framework | JWT auth (SimpleJWT) |
| Task Queue | Celery 5.3+ | Redis broker |
| Database | PostgreSQL 16 (prod) / SQLite (dev) | via `dj-database-url` |
| WSGI | Gunicorn | 4 workers, 120s timeout |
| Static Files | WhiteNoise | Compressed manifest |
| ML | scikit-learn, XGBoost | GBM, RF, IsolationForest |
| AI (Chatbot) | OpenRouter API | Model: `google/gemini-2.0-flash-001` |
| AI (Scanning) | Ollama | Local LLM: llama3.1:8b / mistral / gemma |
| Headless Browser | Playwright | JS rendering, SPA crawling |
| HTML Parsing | BeautifulSoup + lxml | |
| DNS | dnspython | |
| 2FA | pyotp + qrcode | TOTP-based |
| PDF Reports | ReportLab | |

## 3.2 Frontend

| Component | Technology | Version |
|:----------|:-----------|:--------|
| Core | React | 18.2.0 |
| Language | TypeScript | 5.3.3 |
| Build | Vite | 5.1.0 |
| Styling | TailwindCSS | 3.4.1 |
| Routing | React Router DOM | 6.22.0 |
| HTTP | Axios | 1.13.5 |
| Markdown | react-markdown + remark-gfm + rehype-highlight | |
| State | React Context (AuthContext) | No Redux/Zustand |

## 3.3 Infrastructure (Microsoft Azure)

| Component | Azure Service | SKU / Tier |
|:----------|:-------------|:-----------|
| Backend Hosting | Azure App Service (Linux) | B2 (dev) / P1v2 (prod) |
| Frontend Hosting | Azure Static Web Apps | Free / Standard |
| Database | Azure PostgreSQL Flexible Server | Burstable B1ms (dev) / GP D2s_v3 (prod) |
| Cache / Broker | Azure Cache for Redis | Basic C0 (dev) / Standard C1 (prod) |
| Object Storage | Azure Blob Storage | Hot tier, LRS |
| DNS / CDN | Azure Front Door + CDN | Standard |
| Secrets | Azure Key Vault | Standard |
| Monitoring | Azure Monitor + Application Insights | Log Analytics workspace |
| Container (tools) | Azure Container Instances | 2 vCPU, 4 GB (scanning tools sidecar) |
| CI/CD | GitHub Actions → Azure | Bicep IaC |

---

# 4. Frontend Architecture

## 4.1 Routing (35 routes)

| Section | Count | Pages |
|:--------|:------|:------|
| **Public** | 16 | Home, Login, Register, ForgotPassword, ResetPassword, Learn, ArticleDetail, Documentation, About, Contact, Services, Careers, Partners, Terms, Privacy, CookiePolicy, Compliance |
| **Auth-Protected** | 10 | Dashboard, ScanWebsite, ScanResults, ScanHistory, Profile, ScheduledScans, ScopeManagement, AssetInventory, WebhookSettings, ScanComparison |
| **Admin** | 7 | AdminDashboard, AdminUsers, AdminScans, AdminML, AdminSettings, AdminContacts, AdminApplications |

## 4.2 Key Patterns

- **Lazy Loading**: Every page via `React.lazy()` with per-page `ErrorBoundary` + `Suspense`
- **Token Auto-Refresh**: 401 Axios interceptor queues requests, refreshes token, replays all
- **SSE**: `useSSE` hook for real-time scan progress via EventSource
- **Custom Event Bus**: `window.dispatchEvent(new CustomEvent('safeweb-chatbot-ask', ...))` for cross-component chatbot communication
- **API Service**: 16 namespaces (`authAPI`, `userAPI`, `scanAPI`, `chatAPI`, `adminAPI`, etc.) in `src/services/api.ts`

## 4.3 Design System

### Color Palette
| Token | Value | Usage |
|:------|:------|:------|
| `bg-primary` | #050607 | Main background |
| `accent-green` | #00FF88 | Primary accent, success |
| `accent-blue` | #3AA9FF | Secondary accent, links |
| `text-gray` | grayscale | Body text hierarchy |
| `critical` | #FF3B3B | Error, critical severity |

### Typography
- **Headings**: Space Grotesk
- **Body**: Inter
- **Code**: JetBrains Mono

### Motion System
- Glitch text effect, border trace animation, typewriter headings
- Page-enter transitions, scroll reveal, Matrix-style terminal background
- Button hover glow, card elevation transitions

### Component Library
- Button (5 variants), Card (3 variants), Badge (7 severity-mapped variants)
- Input, Select, GlitchText, TypewriterText, ScrollReveal
- GlassCard, GlassButton, TerminalBackground

---

# 5. Backend Architecture

## 5.1 Django Apps

### `accounts` — Authentication & User Management
- **User model**: UUID PK, email-based login (`USERNAME_FIELD = 'email'`), roles (`user`/`admin`), plans (`free`/`pro`/`enterprise`), 2FA (TOTP), avatar, company, job_title
- **APIKey model**: Programmatic access with `sk_live_` prefix, usage tracking
- **UserSession model**: Security session tracking (IP, user agent, JTI)
- **Auth flow**: Register → JWT issued → Login → Session created → Auto-refresh on 401 → Logout blacklists token
- **2FA**: Enable generates TOTP secret + QR code → Verify with 6-digit code → Backup codes
- **JWT**: 60min access, 7d refresh (30d with `remember_me`), rotate + blacklist

### `scanning` — Core Scanning Engine
- **Scan model**: UUID PK, target URL, status lifecycle (`pending` → `pending_confirmation` → `scanning` → `completed`/`failed`), depth, scope_type, `recon_data` JSONB, `tester_results` JSONB, `data_version` for SSE, score 0–100
- **Vulnerability model**: UUID PK, name, severity, category, CWE, CVSS, affected_url, evidence, verified, false_positive_score, exploit_data JSONB
- **Other models**: AuthConfig, ScheduledScan, AssetMonitorRecord, ScanReport, Webhook/WebhookDelivery, NucleiTemplate, ScopeDefinition, MultiTargetScan, DiscoveredAsset
- **SSE streaming**: `ScanStreamView` emits progress, phase_change, finding, data_update, completed events

### `chatbot` — AI Security Assistant
- **Dual-mode**: OpenRouter LLM primary + local knowledge base fallback
- **Function calling**: 7 tools (`start_scan`, `get_recent_scans`, `get_scan_status`, `export_scan`, `get_subscription_info`, `get_vulnerability_details`, `navigate_to`)
- **Context injection**: Scan data, user profile, conversation history (last 10 messages)
- **System prompt**: Comprehensive SafeWeb AI knowledge + prompt injection protection
- **Feedback**: Thumbs up/down per message, analytics tracking

### `ml` — Machine Learning Models
- **PhishingDetector**: GradientBoostingClassifier, 31 URL features
- **MalwareDetector**: RandomForestClassifier, 9 file features
- **Note**: File/URL scan types currently deactivated — focus is web app pentest

### `admin_panel` — Admin Dashboard
- **SystemAlert model**: System-wide alerts with severity and resolve tracking
- **SystemSettings model**: Key-value config store
- **Views**: Dashboard stats, user management, scan management, ML model stats, settings CRUD, contact management with reply, job application management

### `learn` — Learning Center
- **Article model**: title, slug, content, 9 categories (injection, XSS, best practices, API security, authentication, security headers, access control, cryptography, network security)

---

# 6. API Architecture

## 6.1 Overview

- **Base URL**: `https://safeweb-ai-api.azurewebsites.net/api/`
- **Authentication**: JWT Bearer token (SimpleJWT — access + refresh)
- **Rate Limits**: 30 req/min (anonymous), 120 req/min (authenticated)
- **Format**: JSON request/response
- **Pagination**: Page-based (default 20 items)

## 6.2 Endpoints

### Authentication (`/api/auth/`)
| Method | Endpoint | Auth | Purpose |
|:-------|:---------|:-----|:--------|
| POST | `/register/` | — | Register user |
| POST | `/login/` | — | Login (email+password, returns JWT pair) |
| POST | `/logout/` | ✅ | Blacklist refresh token |
| GET/POST | `/verify/` | ✅ | Verify current user |
| POST | `/refresh/` | — | Refresh access token |
| POST | `/google/` | — | Google OAuth login |
| POST | `/forgot-password/` | — | Request password reset |
| POST | `/reset-password/` | — | Reset with token |
| POST | `/change-password/` | ✅ | Change password |

### User Profile (`/api/user/`)
| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| GET/PUT | `/profile/` | Get/update profile |
| GET/POST | `/profile/api-keys/` | List/create API keys |
| DELETE | `/profile/api-keys/{id}/` | Revoke API key |
| GET | `/profile/sessions/` | List active sessions |
| POST | `/profile/2fa/enable/` | Generate TOTP secret |
| POST | `/profile/2fa/verify/` | Verify & enable 2FA |

### Scanning (`/api/scan/`)
| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| POST | `/website/` | Create website scan |
| GET | `/{id}/` | Scan detail + vulnerabilities |
| DELETE | `/{id}/delete/` | Delete scan |
| POST | `/{id}/rescan/` | Rescan target |
| GET | `/{id}/export/` | Export scan results |
| POST | `/{id}/resolve/` | Resolve wide scope |
| POST | `/{id}/confirm/` | Confirm wide scope domains |
| GET | `/{id}/findings/` | List findings |
| GET | `/{id}/stream/` | SSE progress stream |
| GET | `/compare/{id1}/{id2}/` | Compare two scans |
| POST/GET | `/scheduled/` | Manage scheduled scans |
| POST/GET | `/scopes/` | Manage scan scopes |
| GET | `/assets/` | Asset inventory |
| POST/GET | `/webhooks/` | Manage webhooks |
| POST | `/auth-configs/` | Configure authenticated scanning |
| GET/POST | `/nuclei-templates/` | Nuclei template management |

### Chatbot (`/api/chat/`)
| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| POST | `/` | Send message (returns AI response) |
| GET | `/sessions/` | List chat sessions |
| GET | `/sessions/{id}/` | Get session messages |
| POST | `/messages/{id}/feedback/` | Thumbs up/down |
| GET | `/suggestions/` | Contextual suggestions |
| GET | `/analytics/` | Chat analytics (admin) |

### Dashboard (`/api/dashboard/`)
| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| GET | `/` | Overview stats |
| GET | `/trends/` | Trend data |

### Admin (`/api/admin/`)
| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| GET | `/dashboard/` | System-wide statistics |
| GET/PUT | `/users/`, `/users/{id}/` | User management |
| GET | `/scans/` | Scan statistics |
| GET | `/ml/` | ML model stats |
| GET/PUT | `/settings/` | System settings CRUD |
| GET | `/contacts/` | Contact submissions with reply |
| GET | `/applications/` | Job applications |

### Learning (`/api/learn/`)
| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| GET | `/articles/` | List articles (search + category filter) |
| GET | `/articles/{slug}/` | Article detail |

---

# 7. Database Design (PostgreSQL 16)

## 7.1 Entity-Relationship Diagram

```
User (UUID)
  ├── has_many → Scan
  ├── has_many → APIKey
  ├── has_many → UserSession
  ├── has_many → ChatSession
  ├── has_many → ScheduledScan
  ├── has_many → Webhook
  └── has_many → ScopeDefinition

Scan (UUID)
  ├── belongs_to → User
  ├── has_many → Vulnerability
  ├── has_many → AuthConfig
  ├── has_one → parent_scan (self-FK for child scans)
  └── has_many → child_scans (self-FK)

ChatSession (UUID)
  ├── belongs_to → User (nullable)
  ├── belongs_to → Scan (nullable, for scan-context chats)
  └── has_many → ChatMessage

Webhook (UUID)
  └── has_many → WebhookDelivery
```

## 7.2 Table Schemas

### `accounts_user`
| Column | Type | Constraints | Notes |
|:-------|:-----|:------------|:------|
| id | UUID | PK, default uuid4 | |
| email | VARCHAR(255) | UNIQUE, NOT NULL | USERNAME_FIELD |
| password | VARCHAR(128) | NOT NULL | Argon2/PBKDF2 hashed |
| first_name | VARCHAR(150) | | |
| last_name | VARCHAR(150) | | |
| role | VARCHAR(10) | DEFAULT 'user' | user / admin |
| plan | VARCHAR(20) | DEFAULT 'free' | free / pro / enterprise |
| company | VARCHAR(100) | NULLABLE | |
| job_title | VARCHAR(100) | NULLABLE | |
| avatar | VARCHAR(200) | NULLABLE | URL to avatar |
| is_2fa_enabled | BOOLEAN | DEFAULT FALSE | |
| totp_secret | VARCHAR(32) | NULLABLE | Encrypted TOTP seed |
| backup_codes | JSONB | NULLABLE | Array of hashed codes |
| google_id | VARCHAR(100) | NULLABLE | Google OAuth external ID |
| is_active | BOOLEAN | DEFAULT TRUE | |
| is_staff | BOOLEAN | DEFAULT FALSE | |
| date_joined | TIMESTAMPTZ | auto_now_add | |
| last_login | TIMESTAMPTZ | NULLABLE | |

**Indexes**: `email` (unique), `role`, `plan`, `date_joined`

### `accounts_apikey`
| Column | Type | Constraints |
|:-------|:-----|:------------|
| id | UUID | PK |
| user_id | UUID | FK → accounts_user |
| key | VARCHAR(64) | UNIQUE, `sk_live_` prefix |
| name | VARCHAR(100) | |
| is_active | BOOLEAN | DEFAULT TRUE |
| last_used | TIMESTAMPTZ | NULLABLE |
| usage_count | INTEGER | DEFAULT 0 |
| created_at | TIMESTAMPTZ | auto_now_add |

### `accounts_usersession`
| Column | Type | Constraints |
|:-------|:-----|:------------|
| id | UUID | PK |
| user_id | UUID | FK → accounts_user |
| jti | VARCHAR(255) | UNIQUE (JWT ID) |
| ip_address | INET | |
| user_agent | TEXT | |
| created_at | TIMESTAMPTZ | |
| last_active | TIMESTAMPTZ | |

### `scanning_scan`
| Column | Type | Constraints | Notes |
|:-------|:-----|:------------|:------|
| id | UUID | PK | |
| user_id | UUID | FK → accounts_user | |
| target | VARCHAR(500) | NOT NULL | Target URL |
| status | VARCHAR(25) | DEFAULT 'pending' | pending/pending_confirmation/scanning/completed/failed |
| scan_type | VARCHAR(20) | DEFAULT 'website' | website/file/url |
| depth | VARCHAR(10) | DEFAULT 'medium' | shallow/medium/deep |
| scope_type | VARCHAR(20) | DEFAULT 'single_domain' | single_domain/wildcard/wide_scope |
| score | INTEGER | DEFAULT 100 | 0–100 security score |
| recon_data | JSONB | DEFAULT {} | Full recon results |
| tester_results | JSONB | DEFAULT {} | Per-tester results |
| phase_timings | JSONB | DEFAULT {} | Duration per phase |
| data_version | INTEGER | DEFAULT 0 | Incremented per SSE push |
| error_message | TEXT | NULLABLE | Failure reason |
| parent_scan_id | UUID | FK → self, NULLABLE | For child scans |
| created_at | TIMESTAMPTZ | auto_now_add | |
| updated_at | TIMESTAMPTZ | auto_now | |
| completed_at | TIMESTAMPTZ | NULLABLE | |

**Indexes**: `user_id`, `status`, `created_at DESC`, `target` (hash), composite `(user_id, status)`

### `scanning_vulnerability`
| Column | Type | Constraints |
|:-------|:-----|:------------|
| id | UUID | PK |
| scan_id | UUID | FK → scanning_scan (CASCADE) |
| name | VARCHAR(200) | NOT NULL |
| severity | VARCHAR(10) | critical/high/medium/low/info |
| category | VARCHAR(100) | |
| cwe | VARCHAR(20) | NULLABLE (e.g., CWE-79) |
| cvss | DECIMAL(3,1) | NULLABLE (0.0–10.0) |
| affected_url | VARCHAR(2000) | |
| evidence | TEXT | |
| description | TEXT | |
| remediation | TEXT | |
| verified | BOOLEAN | DEFAULT FALSE |
| false_positive_score | FLOAT | DEFAULT 0.0 |
| exploit_data | JSONB | NULLABLE |
| attack_chain | TEXT | NULLABLE |
| created_at | TIMESTAMPTZ | auto_now_add |

**Indexes**: `scan_id`, `severity`, composite `(scan_id, severity)`, `cwe`

### `chatbot_chatsession` / `chatbot_chatmessage`
| Table | Key Columns |
|:------|:------------|
| chatsession | id (UUID PK), user_id (FK nullable), scan_id (FK nullable), title, created_at, updated_at |
| chatmessage | id (UUID PK), session_id (FK), role (user/assistant/system), content (TEXT), tokens_used (INT), feedback (VARCHAR nullable), action_data (JSONB nullable), created_at |

### Other Tables
| Table | Key Columns |
|:------|:------------|
| scanning_authconfig | id, scan_id (FK), auth_type, credentials (JSONB encrypted) |
| scanning_scheduledscan | id, user_id (FK), target, cron_expr, scan_config (JSONB), next_run, last_run, is_active |
| scanning_webhook | id, user_id (FK), url, events (JSONB), secret (VARCHAR), is_active |
| scanning_webhookdelivery | id, webhook_id (FK), event, payload (JSONB), status_code, response_time, created_at |
| scanning_nucleitemplate | id, name, category, severity, template_data (JSONB), is_custom |
| scanning_scopedefinition | id, user_id (FK), name, scope_type, targets (JSONB) |
| scanning_multitargetscan | id, user_id (FK), name, targets (JSONB), status |
| scanning_discoveredasset | id, scan_id (FK), asset_type, value, first_seen, last_seen |
| scanning_scanreport | id, scan_id (FK), format, file_path, created_at |
| admin_panel_systemalert | id, title, message, severity, is_resolved, created_at |
| admin_panel_systemsettings | id, key (UNIQUE), value (TEXT) |
| learn_article | id, title, slug (UNIQUE), content, category, created_at, updated_at |
| accounts_contactmessage | id, name, email, subject, message, is_read, replied, created_at |
| accounts_jobapplication | id, name, email, position, resume, cover_letter, status, created_at |

## 7.3 PostgreSQL Optimizations

- **JSONB** for `recon_data`, `tester_results`, `exploit_data` — GIN indexes for fast `@>` queries
- **UUID primary keys** — `gen_random_uuid()` default, no sequential ID exposure
- **TIMESTAMPTZ** for all timestamps — timezone-aware
- **Connection pooling**: PgBouncer (transaction mode, 20 pool size)
- **Read replicas** (future): For dashboard analytics, report generation
- **pg_stat_statements**: Query performance monitoring
- **Vacuum/Analyze**: Autovacuum tuned for heavy-write scan tables
- **Partitioning roadmap**: Monthly range partition on `scanning_scan.created_at` when > 100K rows

## 7.4 Security Score Calculation

Starts at **100**, deductions per vulnerability severity:

| Severity | Deduction | CVSS Range |
|:---------|:----------|:-----------|
| Critical | −25 | 9.0–10.0 |
| High | −15 | 7.0–8.9 |
| Medium | −8 | 4.0–6.9 |
| Low | −3 | 0.1–3.9 |
| Info | −1 | 0.0 |

Minimum score: **0**. Score is computed after all vulnerability testing phases complete.

---

# 8. Vulnerability Scanning System

## 8.1 Phase Pipeline

| Phase | Name | Progress | Key Components |
|:------|:-----|:---------|:---------------|
| 0 (Wave 0a) | Independent Recon | 5% | DNS, WHOIS, certs, WAF, CT logs, subdomains, ASN, ports |
| 0 (Wave 0b) | Response-Dependent Recon | 8% | Tech fingerprint, headers, cookies, CORS, JS analysis, cloud, CMS |
| 0 (Wave 0c) | Cross-Module Recon | 12% | Email, subdomain takeover, secrets, OSINT, content/param/API discovery |
| 0 (Wave 0d) | Analytics Recon | 15% | Vuln correlator, attack surface, threat intel, risk scoring |
| 0.5 | Auth Setup | 16% | Form login, OAuth/OIDC/SAML, headless SPA auth, JWT analysis |
| 1 | Crawling | 20% | BFS crawler + Playwright JS rendering + SPA crawler |
| 1.1 | Form Interaction | 22% | Headless browser form detection and auto-fill |
| 1.5 | Attack Surface Model | 25% | LLM attack strategy via Ollama |
| 2–4 | Analyzers | 40% | Header, SSL, Cookie analyzers (parallel) |
| 5 | Vulnerability Testing | 55% | 85+ testers × all pages (ML-prioritized) |
| 5.1 | OOB Polling | 70% | Interactsh blind vuln confirmation |
| 5b | Nuclei Templates | 72% | CLI binary primary, Python engine fallback |
| 5c | Secret Scanning | 74% | 200+ regex patterns + entropy + Git dumper |
| 5d | Integrated Scanners | 76% | sqlmap, dalfox, nikto, testssl, etc. |
| 5.5 | Verification | 80% | Re-confirmation + ML classifier + Evidence verifier |
| 5.7 | Exploit Generation | 83% | PoC exploit + Bug Bounty report drafting |
| 6 | Correlation | 85% | AttackGraph, MITRE ATT&CK mapping, Mermaid diagrams |
| 6.1 | Vulnerability Chaining | 85% | ChainDetector: 10+ multi-step attack chain patterns |
| 6.5 | False Positive Reduction | 88% | 5-component ensemble (classifier 35%, anomaly 20%, heuristic 15%, historical 10%, LLM 20%) |
| 7 | Learning | 92% | ScanMemory + KnowledgeUpdater |

## 8.2 85+ Vulnerability Testers

**Core**: SQLi, XSS, Command Injection, SSTI, XXE, CSRF, Auth, Misconfig, Data Exposure, Access Control, SSRF
**Advanced**: Deserialization, Host Header, HTTP Smuggling, CRLF, JWT
**Modern**: Race Condition, WebSocket, GraphQL, File Upload, NoSQL, Cache Poisoning
**Infrastructure**: CORS, Clickjacking, LDAP/XPath, Subdomain Takeover, Cloud Storage
**AI/LLM**: Prompt Injection, AI Endpoint, AI Data Poisoning
**Extended**: IDOR, Mass Assignment, Path Traversal, SSI, HTTP/2, Prototype Pollution, Open Redirect, Business Logic, API
**Batch 1**: OAuth, SAML, CSS Injection, CSV Injection, DNS Rebinding, HPP, Type Juggling, ReDoS
**Batch 2**: Web Cache Deception, XS-Leak, XSLT, Zip Slip, VHost, Insecure Randomness, Reverse Proxy, Dependency Confusion
**Specialized**: 403 Bypass, CMS Deep, Exploit Verification, WAF Evasion, Supply Chain, Network, JS Intelligence, ML Enhancement
**OWASP WSTG**: INFO, CONF, IDNT, ATHN, SESS, INPV, ERRH, CRYP, BUSL, CLNT (full coverage)

## 8.3 62 External Tool Integrations

| Category | Tools |
|:---------|:------|
| **Subdomain/DNS** | subfinder, amass, assetfinder, findomain, chaos, sublist3r, asnmap, mapcidr, dnsx, puredns, massdns, dnsrecon |
| **Port Scan** | nmap, naabu, rustscan, masscan |
| **Web Crawl/Fuzz** | ffuf, feroxbuster, gobuster, dirsearch, katana, gospider, hakrawler |
| **Vuln Scan** | nuclei, sqlmap, ghauri, dalfox, xsstrike, tplmap, commix, crlfuzz, nikto |
| **CMS** | wpscan, joomscan, whatweb, wappalyzer |
| **SSL/TLS** | testssl, sslyze, tlsx |
| **JS/Links** | getjs, linkfinder, secretfinder, gf, qsreplace |
| **URLs** | gau, waybackurls, paramspider, arjun, x8 |
| **Secrets** | trufflehog, gitleaks |
| **Cloud** | cloudenum, s3scanner, awsbucketdump |
| **Takeover** | subjack, subover |
| **Screenshots** | eyewitness, aquatone |
| **HTTP** | httpx, httprobe |
| **OOB** | interactsh |

## 8.4 Scan Modes & Scopes

| Scope | Example | Coverage |
|:------|:--------|:---------|
| Single Domain | `example.com` | One domain only |
| Wildcard | `*.example.com` | All subdomains |
| Wide Scope | Multiple targets | Multi-domain, IP ranges, CIDR blocks |

| Depth | Recon | Testers |
|:------|:------|:--------|
| Shallow | Basic (DNS, tech fingerprint) | Top 20 common tests |
| Medium | Standard (full recon waves) | 50+ targeted tests |
| Deep | Comprehensive (all 40+ modules) | All 85+ testers + Nuclei |

---

# 9. Machine Learning Module

## 9.1 Models

| Model | Algorithm | Features | Purpose |
|:------|:----------|:---------|:--------|
| PhishingDetector | GradientBoostingClassifier | 31 URL features (length, counts, entropy, boolean flags) | URL phishing classification |
| MalwareDetector | RandomForestClassifier | 9 file features (entropy, extension, patterns) | File malware classification |
| AttackPrioritizer | XGBoost | Contextual recon data | ML-prioritized tester execution order |
| FP Reducer | 5-component ensemble | Classifier (35%), anomaly (20%), heuristic (15%), historical (10%), LLM (20%) | False positive filtering |

## 9.2 Output Format
```json
{
  "prediction": "malicious",
  "confidence": 0.93,
  "model": "PhishingDetector",
  "features_used": 31
}
```

---

# 10. AI Chatbot Assistant

## 10.1 Architecture

- **Primary**: OpenRouter API → `google/gemini-2.0-flash-001` with function calling
- **Fallback**: Local knowledge base (36+ topics) for offline/degraded operation
- **Context**: Scan data (auto-detected from URL), user profile, conversation history (last 10 messages)
- **Security**: Prompt injection protection in system prompt

## 10.2 Function-Calling Tools

| Tool | Parameters | Action |
|:-----|:-----------|:-------|
| `start_scan` | target, scan_type, depth | Launch a new security scan |
| `get_recent_scans` | count | Retrieve recent scan history |
| `get_scan_status` | scan_id | Check live scan progress & phase |
| `export_scan` | scan_id, format | Generate download link (PDF/CSV/JSON/SARIF/HTML) |
| `get_subscription_info` | — | Show plan details & usage limits |
| `get_vulnerability_details` | vuln_id | Full vulnerability data with remediation |
| `navigate_to` | destination | Navigate to dashboard, scans, settings |

## 10.3 Features
- Rich Markdown responses with code blocks, tables, syntax highlighting
- Thumbs up/down feedback per message
- Per-message token usage monitoring
- Admin analytics (sessions, messages, satisfaction rate, top topics)

---

# 11. Admin System

Admin capabilities (all protected by `IsAdmin` permission):

- **Dashboard**: System-wide statistics (users, scans, vulnerabilities, resource usage)
- **User Management**: List, edit, activate/deactivate users
- **Scan Management**: View scan statistics and performance metrics
- **ML Model Monitoring**: Model accuracy, prediction counts, performance stats
- **System Settings**: Key-value configuration store
- **Contact Management**: View and reply to contact form submissions
- **Job Applications**: Review and manage applications
- **System Alerts**: Create, track, and resolve system-wide alerts

---

# 12. Deployment Architecture (Microsoft Azure)

## 12.1 Azure Resource Group Layout

```
safeweb-ai-rg/
├── safeweb-ai-api          (App Service — Linux P1v2)
├── safeweb-ai-frontend     (Static Web App)
├── safeweb-ai-db           (PostgreSQL Flexible Server)
├── safeweb-ai-redis        (Azure Cache for Redis)
├── safeweb-ai-storage      (Storage Account — Blob)
├── safeweb-ai-kv           (Key Vault)
├── safeweb-ai-insights     (Application Insights)
├── safeweb-ai-log          (Log Analytics Workspace)
├── safeweb-ai-tools-aci    (Container Instance — scanning tools)
└── safeweb-ai-cdn          (Front Door / CDN profile)
```

## 12.2 Backend — Azure App Service (Linux)

- **Runtime**: Python 3.11
- **WSGI**: Gunicorn (4 workers, 120s timeout)
- **Static Files**: WhiteNoise (collected on deploy)
- **Startup**: `cd backend && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4 --timeout 120`
- **Health check**: `/api/health/` (responds 200 OK)
- **Deployment slots**: `staging` slot for blue/green deploys
- **Auto-scale**: 1–4 instances (CPU > 70% trigger)
- **Always On**: Enabled (prevents cold starts)
- **Managed Identity**: System-assigned → accesses Key Vault, Blob, PostgreSQL

## 12.3 Frontend — Azure Static Web Apps

- **Build**: Vite → `npm run build` → `dist/`
- **Routing**: SPA fallback via `staticwebapp.config.json`
- **Custom domain**: `safeweb-ai.com` (planned) with auto-SSL
- **API proxy**: Routes `/api/*` to backend App Service
- **Edge**: Global CDN distribution, Brotli/gzip compression

## 12.4 Networking & Security

- **VNet Integration**: App Service → VNet → Private Endpoint → PostgreSQL/Redis
- **NSG rules**: Allow only App Service outbound to DB subnet
- **Azure Front Door**: WAF policies (OWASP 3.2 ruleset), DDoS protection, geo-filtering
- **SSL/TLS**: Azure-managed certificates, TLS 1.2+ enforced everywhere
- **Key rotation**: Automated via Key Vault + Event Grid (90-day cycle)

## 12.5 CI/CD Pipeline (GitHub Actions)

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌───────────┐     ┌──────┐
│  Push   │────▶│  Lint +  │────▶│  Build   │────▶│  Deploy   │────▶│ Swap │
│  main   │     │  Test    │     │ Artifacts│     │  Staging  │     │ Slots│
└─────────┘     └──────────┘     └──────────┘     └───────────┘     └──────┘
                  pytest           collectstatic     App Service       blue/green
                  tsc --noEmit     npm build          slot: staging     → production
                  pip-audit        Docker image       smoke tests
```

**Post-deploy**: Run `manage.py migrate`, invalidate CDN cache, notify via webhook.

## 12.6 Environment Strategy

| Environment | Resources | Purpose |
|:------------|:----------|:--------|
| **Local (dev)** | SQLite + local Redis | Developer machine |
| **Staging** | Azure B1ms Postgres, C0 Redis | Pre-production validation |
| **Production** | Azure D2s_v3 Postgres, C1 Redis | Live application, auto-scaled |

## 12.7 Disaster Recovery

| Metric | Target |
|:-------|:-------|
| **RPO** | 1 hour (PostgreSQL PITR) |
| **RTO** | 15 minutes (slot swap from healthy instance) |
| **Backup** | Daily automated, 35-day retention, geo-redundant storage |
| **Failover** | Zone-redundant PostgreSQL, multi-instance App Service |

## 12.8 Secrets Management

All secrets stored in **Azure Key Vault**, referenced via App Service configuration:

| Secret | Description |
|:-------|:------------|
| `SECRET-KEY` | Django secret key |
| `DATABASE-URL` | PostgreSQL connection string |
| `REDIS-URL` | Redis connection string (TLS, port 6380) |
| `OPENROUTER-API-KEY` | LLM API key |
| `STORAGE-CONNECTION-STRING` | Blob storage connection |

---

# 13. Performance Engineering

## 13.1 Backend Performance
- **Gunicorn workers**: `2 × vCPU + 1` = 5 workers on P1v2 (2 vCPU)
- **Database optimization**: `select_related()` / `prefetch_related()` on Scan→Vulnerability joins
- **Bulk operations**: `bulk_create()` for vulnerability batch insertion (50–200 vulns per scan)
- **Scan result caching**: Redis cache for completed scan data (TTL 1 hour)
- **Streaming responses**: SSE generator yields progress without blocking workers

## 13.2 Frontend Performance
- **Code splitting**: Vite chunk splitting per route (lazy loading all 35 pages)
- **Tree shaking**: Unused imports eliminated at build time
- **Asset optimization**: Brotli compression, image optimization, font subsetting
- **Cache strategy**: Immutable hashed assets (1-year cache), HTML no-cache
- **Bundle targets**: < 200 KB initial JS, < 50 KB per lazy chunk
- **SSE management**: Auto-reconnect with exponential backoff

## 13.3 Database Performance
- **Indexing**: B-tree on FKs, GIN on JSONB, composite indexes on hot queries
- **Query plans**: `EXPLAIN ANALYZE` on scan listing, vulnerability filtering, dashboard aggregation
- **Connection limits**: 100 max (Flexible Server B1ms), PgBouncer pool = 20
- **Slow query logging**: `log_min_duration_statement = 500ms`

## 13.4 Monitoring & Alerting

| Metric | Threshold | Alert |
|:-------|:----------|:------|
| HTTP 5xx rate | > 5% over 5min | PagerDuty / email |
| P95 response time | > 5 seconds | Warning |
| P99 response time | > 10 seconds | Critical |
| Celery queue depth | > 50 tasks | Scale workers |
| PostgreSQL connections | > 80% capacity | Investigate |
| Disk usage (Postgres) | > 80% | Auto-grow or cleanup |
| CPU (App Service) | > 70% sustained | Auto-scale out |
| Memory (App Service) | > 85% | Investigate leaks |

---

# 14. Related Work & References

## Vulnerability Scanners
- OWASP Vulnerability Scanning Tools, ProjectDiscovery (Nuclei), Burp Suite Scanner, OWASP ZAP, Acunetix

## Reference Books (48+ in project library)
- *The Web Application Hacker's Handbook 2nd Ed*, *The Hacker Playbook 3*, *Bug Bounty Hunting*
- *Black Hat Python/Bash/Go*, *Hacking APIs*, *BlackHat GraphQL*
- *OWASP WSTG*, *PortSwigger Web Security Academy*

## Online Resources
- OWASP WSTG v4.2, OWASP API Security Top 10, HackerOne Hacktivity
- PayloadsAllTheThings, SecLists, PortSwigger Research

---

# 15. Security Considerations

- **Authentication**: JWT with rotation and blacklisting, 2FA (TOTP), API keys with `sk_live_` prefix
- **Transport**: HTTPS only, TLS 1.2+ enforced, Azure-managed certificates
- **Input validation**: DRF serializer validation, parameterized queries (Django ORM), rate limiting
- **Access control**: Role-based (user/admin), plan-based feature gating, `IsOwner` permission
- **Secrets**: Azure Key Vault with Managed Identity, no hardcoded credentials
- **Network**: VNet integration, private endpoints, NSG rules, Azure Front Door WAF
- **Monitoring**: Application Insights, log analytics, alert rules on 5xx rates and anomalies
- **Dependencies**: `pip-audit` for vulnerability scanning, `bandit` for Python static analysis

---

# 16. Future Features & Enhancements

## Phase 1 — Platform Hardening
- Google OAuth complete flow, WebSocket upgrade, PDF report redesign, SMTP email integration

## Phase 2 — Scanning Enhancement
- Distributed scanning workers (ACI), scan queue management, authenticated scanning UI, custom Nuclei templates, compliance mapping (PCI DSS, SOC 2, ISO 27001)

## Phase 3 — AI & ML Expansion
- RAG-powered chatbot, AI-generated vulnerability patches, smart scan scheduling, threat intelligence feed, LLM fine-tuning

## Phase 4 — Enterprise Features
- Team workspaces with RBAC, SSO (SAML/OIDC), audit logging, API rate limiting tiers, tenant isolation, white-label support

## Phase 5 — Cloud & Infrastructure
- Kubernetes migration (AKS), multi-region deployment, serverless functions, Data Lake analytics

## Phase 6 — Community & Ecosystem
- Public API + SDK (OpenAPI 3.0), plugin marketplace, bug bounty integration, Slack/Discord bot, mobile app

---

# 17. Known Limitations

| Area | Current Limitation | Planned Resolution |
|:-----|:-------------------|:-------------------|
| Scanning tools | CLI tools not in App Service sandbox | ACI sidecar container with all tools |
| File/URL scanning | ML models preserved but deactivated | Re-enable with dedicated upload pipeline |
| Google OAuth | UI present but flow not connected | Complete with Azure AD B2C |
| Email | No SMTP configured | Azure Communication Services |
| Real-time | SSE can be unreliable through CDN | WebSocket upgrade (Azure Web PubSub) |
| Reports | PDF needs system fonts | Docker sidecar with fonts + WeasyPrint |
| Search | No full-text search on vulnerabilities | PostgreSQL `tsvector` + GIN index |
| Rate limiting | Basic Django throttle | Azure Front Door + Redis sliding window |

---

# End of Technical System Documentation
```

