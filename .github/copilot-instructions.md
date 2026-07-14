# SafeWeb AI — Complete Project Context & Knowledge Base

> **Purpose**: This file serves as the authoritative, always-loaded context for any AI assistant working on the SafeWeb AI project. It encapsulates the full system architecture, codebase structure, database design, cloud deployment strategy, DevOps pipeline, performance engineering, domain knowledge from 48+ cybersecurity books, system analysis & design principles, research references, future roadmap, and all technical decisions — enabling the assistant to provide expert-level guidance on any project task: development, research, system design, cybersecurity, cloud engineering, deployment, or documentation.

---

## 1. PROJECT IDENTITY

**SafeWeb AI** is a professional-grade **AI-powered web application vulnerability scanner and penetration testing platform** built as a graduation project. It combines automated security scanning with machine learning, LLM-powered reasoning, and 62 external tool integrations to deliver comprehensive web application security assessments.

- **Repository**: `0xN0RMXL/safeweb-ai` (GitHub, branch: `main`)
- **Workspace**: `D:\My Files\Graduation Project\safeweb-ai`
- **Backend**: Django 5.0 + DRF + Celery (Python 3.11)
- **Frontend**: React 18 + TypeScript 5 + Vite + TailwindCSS
- **Database**: PostgreSQL 16 (Azure Database for PostgreSQL Flexible Server)
- **Cloud Platform**: Microsoft Azure (full deployment)
- **Deployment**: Azure App Service (backend) + Azure Static Web Apps (frontend)
- **Live URLs**: Backend `https://safeweb-ai-api.azurewebsites.net` | Frontend `https://safeweb-ai.azurestaticapps.net`

---

## 2. SYSTEM ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│               FRONTEND (Azure Static Web Apps)                  │
│  React 18 + TypeScript + Vite + TailwindCSS                     │
│  35 routes, 74+ source files, lazy-loaded pages                 │
│  SSE real-time scan updates, AI chatbot widget                  │
│  Azure CDN (global edge caching) + Custom Domain + SSL          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS (VITE_API_URL)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│           BACKEND (Azure App Service — Linux B2/P1v2)           │
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
│  Local knowledge base fallback (25+ topics)                     │
├─────────────────────────────────────────────────────────────────┤
│  ML MODELS                                                      │
│  Phishing: GBM (31 features) | Malware: RF (9 features)        │
│  Attack Prioritizer: XGBoost | FP Reducer: 5-component ensemble│
└──────────────────────────┬──────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
  Azure PostgreSQL    Azure Redis Cache    Ollama (optional)
  (Flexible Server)   (Basic C0/C1)       (ACI container)
        │
        ▼
  Azure Blob Storage (scan reports, exports, ML model artifacts)
```

---

## 3. COMPLETE TECH STACK

### Backend
| Component | Technology | Version/Details |
|-----------|-----------|-----------------|
| Framework | Django | 5.0 |
| API | Django REST Framework | JWT auth (SimpleJWT) |
| Task Queue | Celery | 5.3+ with Redis broker |
| Database | PostgreSQL (prod) / SQLite (dev) | via `dj-database-url` |
| WSGI | Gunicorn | 2 workers, 120s timeout |
| Static Files | WhiteNoise | Compressed manifest |
| ML | scikit-learn, XGBoost | GBM, RF, IsolationForest |
| AI (Chatbot) | OpenRouter API | Model: `google/gemini-2.0-flash-001` |
| AI (Scanning) | Ollama | Local LLM: llama3.1:8b / mistral / gemma |
| Headless Browser | Playwright | JS rendering, SPA crawling |
| HTML Parsing | BeautifulSoup + lxml | |
| DNS | dnspython | |
| 2FA | pyotp + qrcode | TOTP-based |
| PDF Reports | ReportLab | |

### Frontend
| Component | Technology | Version |
|-----------|-----------|---------|
| Core | React | 18.2.0 |
| Language | TypeScript | 5.3.3 |
| Build | Vite | 5.1.0 |
| Styling | TailwindCSS | 3.4.1 |
| Routing | React Router DOM | 6.22.0 |
| HTTP | Axios | 1.13.5 |
| Markdown | react-markdown + remark-gfm + rehype-highlight | |
| State | React Context (AuthContext) | No Redux/Zustand |

### Infrastructure (Microsoft Azure)
| Component | Azure Service | SKU / Tier |
|-----------|--------------|------------|
| Backend Hosting | Azure App Service (Linux) | B2 (dev) / P1v2 (prod) |
| Frontend Hosting | Azure Static Web Apps | Free / Standard |
| Database | Azure Database for PostgreSQL — Flexible Server | Burstable B1ms (dev) / GP D2s_v3 (prod) |
| Cache / Broker | Azure Cache for Redis | Basic C0 (dev) / Standard C1 (prod) |
| Object Storage | Azure Blob Storage | Hot tier, LRS |
| DNS / CDN | Azure Front Door + CDN | Standard |
| Secrets | Azure Key Vault | Standard |
| Monitoring | Azure Monitor + Application Insights | Log Analytics workspace |
| Container (tools) | Azure Container Instances | 2 vCPU, 4 GB (scanning tools sidecar) |
| CI/CD | GitHub Actions → Azure | Bicep IaC |
| Domain | Custom domain with Azure DNS | safeweb-ai.com (planned) |

---

## 4. DJANGO APPS — DETAILED REFERENCE

### 4.1 `accounts` — Authentication & User Management
- **User model**: UUID PK, email-based login (`USERNAME_FIELD = 'email'`), roles (`user`/`admin`), plans (`free`/`pro`/`enterprise`), 2FA (TOTP), avatar, company, job_title
- **APIKey model**: Programmatic access with `sk_live_` prefix, usage tracking
- **UserSession model**: Security session tracking (IP, user agent, JTI)
- **Auth flow**: Register → JWT issued → Login (email+password or Google OAuth) → Session created → Auto-refresh on 401 → Logout blacklists token
- **2FA**: Enable generates TOTP secret + QR code → Verify with 6-digit code → Backup codes
- **Password**: 8+ chars, upper, lower, number, special char required
- **JWT**: 60min access, 7d refresh (30d with remember_me), rotate + blacklist
- **Key files**: `models.py`, `views.py`, `serializers.py`, `backends.py` (EmailBackend), `permissions.py` (IsAdmin, IsOwner)

### 4.2 `scanning` — Core Scanning Engine
- **Scan model**: UUID PK, target URL, status lifecycle (`pending` → `pending_confirmation` → `scanning` → `completed`/`failed`), depth (`shallow`/`medium`/`deep`), scope_type (`single_domain`/`wildcard`/`wide_scope`), `recon_data` JSONField, `tester_results` JSONField, `data_version` for SSE, `phase_timings`, score 0-100
- **Vulnerability model**: UUID PK, name, severity (critical/high/medium/low/info), category, CWE, CVSS, affected_url, evidence, verified, false_positive_score, exploit_data JSONField, attack_chain
- **Other models**: AuthConfig, ScheduledScan, AssetMonitorRecord, ScanReport, Webhook/WebhookDelivery, NucleiTemplate, ScopeDefinition, MultiTargetScan, DiscoveredAsset
- **SSE streaming**: `ScanStreamView` emits progress, phase_change, finding, data_update, completed events
- **Key files**: `models.py` (~500 lines), `views.py` (~600 lines), `serializers.py`, `tasks.py`, `engine/` (entire scanning pipeline)

### 4.3 `chatbot` — AI Security Assistant
- **Dual-mode**: OpenRouter LLM primary + local knowledge base fallback
- **Function calling**: 7 tools (start_scan, get_recent_scans, get_scan_status, export_scan, get_subscription_info, get_vulnerability_details, navigate_to)
- **Context injection**: Scan data, user profile, conversation history (last 10 messages)
- **System prompt**: Comprehensive SafeWeb AI knowledge + prompt injection protection
- **Feedback**: Thumbs up/down per message, analytics tracking
- **Key files**: `engine.py` (main logic), `actions.py` (tool implementations), `models.py`, `views.py`

### 4.4 `ml` — Machine Learning Models
- **PhishingDetector**: GradientBoostingClassifier, 31 URL features (length, counts, entropy, boolean flags)
- **MalwareDetector**: RandomForestClassifier, 9 file features (entropy, extension, patterns)
- **Note**: File/URL scan types DEACTIVATED — focus is web app pentest. ML models preserved.
- **Key files**: `phishing_detector.py`, `malware_detector.py`, `feature_extractors.py`, `model_trainer.py`

### 4.5 `admin_panel` — Admin Dashboard
- **SystemAlert model**: System-wide alerts with severity and resolve tracking
- **SystemSettings model**: Key-value config store
- **Views**: Dashboard stats, user management, scan management, ML model management, settings CRUD, contact management with reply, job application management
- **All protected by IsAdmin permission**

### 4.6 `learn` — Learning Center
- **Article model**: title, slug, content, category (9 choices: injection, XSS, best_practices, API security, authentication, security headers, access control, cryptography, network security)
- **URLs**: Public listing with search + category filter, detail by slug

---

## 5. SCANNING ENGINE — COMPLETE PIPELINE

### Phase Execution Order

| Phase | Name | Progress | Key Components |
|-------|------|----------|----------------|
| 0-pre | Tool Health Check | 1% | SecLists check, ScanMemory recall, ContextAnalyzer init |
| 0 (Wave 0a) | Independent Recon | 5% | DNS, WHOIS, certs, WAF, CT logs, subdomains, ASN, ports, wildcard |
| 0 (Wave 0b) | Response-Dependent Recon | 8% | Tech fingerprint, headers, cookies, CORS, JS analysis, cloud, CMS |
| 0 (Wave 0c) | Cross-Module Recon | 12% | Email, subdomain takeover, secrets, OSINT, content/param/API discovery |
| 0 (Wave 0d) | Analytics Recon | 15% | Vuln correlator, attack surface, threat intel, risk scoring |
| 0.5 | Auth Setup | 16% | Form login, OAuth/OIDC/SAML, headless SPA auth, JWT analysis |
| 1 | Crawling | 20% | BFS crawler + Playwright JS rendering + SPA crawler |
| 1.1 | Form Interaction | 22% | Headless browser form detection and auto-fill |
| 1.5 | Attack Surface Model | 25% | LLM attack strategy via Ollama |
| 2-4 | Analyzers | 40% | Header, SSL, Cookie analyzers (parallel) |
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

### 62 External Tool Integrations

**Subdomain/DNS**: subfinder, amass, assetfinder, findomain, chaos, sublist3r, asnmap, mapcidr, dnsx, puredns, massdns, dnsrecon
**Port Scan**: nmap, naabu, rustscan, masscan
**Web Crawl/Fuzz**: ffuf, feroxbuster, gobuster, dirsearch, katana, gospider, hakrawler
**Vuln Scan**: nuclei, sqlmap, ghauri, dalfox, xsstrike, tplmap, commix, crlfuzz, nikto
**CMS**: wpscan, joomscan, whatweb, wappalyzer
**SSL/TLS**: testssl, sslyze, tlsx
**JS/Links**: getjs, linkfinder, secretfinder, gf, qsreplace
**URLs**: gau, waybackurls, paramspider, arjun, x8
**Secrets**: trufflehog, gitleaks
**Cloud**: cloudenum, s3scanner, awsbucketdump
**Takeover**: subjack, subover
**Screenshots**: eyewitness, aquatone
**HTTP**: httpx, httprobe
**OOB**: interactsh

### 85+ Vulnerability Testers

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

---

## 6. FRONTEND ARCHITECTURE

### Routing (35 routes)
- **Public (16)**: Home, Login, Register, ForgotPassword, ResetPassword, Learn, ArticleDetail, Documentation, About, Contact, Services, Careers, Partners, Terms, Privacy, CookiePolicy, Compliance
- **Auth-Protected (10)**: Dashboard, ScanWebsite, ScanResults, ScanHistory, Profile, ScheduledScans, ScopeManagement, AssetInventory, WebhookSettings, ScanComparison
- **Admin (7)**: AdminDashboard, AdminUsers, AdminScans, AdminML, AdminSettings, AdminContacts, AdminApplications

### Key Patterns
- **Lazy Loading**: Every page via `React.lazy()` with per-page `ErrorBoundary` + `Suspense`
- **Token Auto-Refresh**: 401 Axios interceptor queues requests, refreshes token, replays all
- **SSE**: `useSSE` hook for real-time scan progress via EventSource
- **Custom Event Bus**: `window.dispatchEvent(new CustomEvent('safeweb-chatbot-ask', ...))` for cross-component chatbot communication
- **API Service**: 16 namespaces (authAPI, userAPI, scanAPI, chatAPI, adminAPI, etc.) in `src/services/api.ts`

### Design System
- **Theme**: Dark cybersecurity aesthetic — `bg-primary` #050607, `accent-green` #00FF88, `accent-blue` #3AA9FF
- **Fonts**: Inter (body), Space Grotesk (headings), JetBrains Mono (code)
- **Animations**: Glitch text, border trace, typewriter, page-enter, scroll reveal, Matrix-style terminal background
- **Components**: Button (5 variants), Card (3 variants), Badge (7 severity-mapped variants), Input, Select, GlitchText, TypewriterText, ScrollReveal

---

## 7. API REFERENCE (ALL ENDPOINTS)

### Authentication (`/api/auth/`)
| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| POST | `/register/` | Public | Register user |
| POST | `/login/` | Public | Login (email+password) |
| POST | `/logout/` | Auth | Blacklist refresh token |
| GET/POST | `/verify/` | Auth | Verify current user |
| POST | `/refresh/` | Public | Refresh access token |
| POST | `/google/` | Public | Google OAuth login |
| POST | `/forgot-password/` | Public | Request password reset |
| POST | `/reset-password/` | Public | Reset with token |
| POST | `/change-password/` | Auth | Change password |

### User Profile (`/api/user/`)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET/PUT | `/profile/` | Get/update profile |
| GET/POST | `/profile/api-keys/` | List/create API keys |
| DELETE | `/profile/api-keys/{id}/` | Revoke API key |
| GET | `/profile/sessions/` | List active sessions |
| POST | `/profile/2fa/enable/` | Generate TOTP secret |
| POST | `/profile/2fa/verify/` | Verify & enable 2FA |

### Scanning (`/api/scan/`)
| Method | Endpoint | Purpose |
|--------|----------|---------|
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

### Chatbot (`/api/chat/`)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/` | Send message |
| GET | `/sessions/` | List chat sessions |
| GET | `/sessions/{id}/` | Get session messages |
| POST | `/messages/{id}/feedback/` | Send feedback |
| GET | `/suggestions/` | Get suggestions |
| GET | `/analytics/` | Chat analytics |

### Dashboard (`/api/dashboard/`)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/` | Overview stats |
| GET | `/trends/` | Trend data |

### Admin (`/api/admin/`)
Dashboard, Users CRUD, Scans, ML models, Settings, Contacts with reply, Job Applications

---

## 8. DEPLOYMENT CONFIGURATION (MICROSOFT AZURE)

### Azure Resource Group Layout
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

### Backend — Azure App Service (Linux)
- **Runtime**: Python 3.11
- **WSGI**: Gunicorn (2–4 workers, 120s timeout)
- **Static Files**: WhiteNoise (collected on deploy)
- **Startup command**: `cd backend && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4 --timeout 120`
- **Health check**: `/api/health/` (responds 200 OK)
- **Deployment slots**: `staging` slot for blue/green deploys
- **Auto-scale**: 1–4 instances (CPU > 70% trigger)
- **Always On**: Enabled (prevents cold starts)
- **Managed Identity**: System-assigned → accesses Key Vault, Blob, PostgreSQL

### Frontend — Azure Static Web Apps
- **Framework**: Vite → `npm run build` → `dist/`
- **Routing**: SPA fallback via `staticwebapp.config.json`
- **Custom domain**: `safeweb-ai.com` (planned) with auto-SSL
- **API proxy**: Routes `/api/*` to backend App Service
- **Edge**: Global CDN distribution, Brotli/gzip compression

### Database — Azure PostgreSQL Flexible Server
- **Version**: PostgreSQL 16
- **SKU**: Burstable B1ms (dev) → General Purpose D2s_v3 (prod)
- **Storage**: 32 GB (auto-grow enabled, max 1 TB)
- **Backup**: Automated daily, 7-day retention (35-day prod)
- **HA**: Zone-redundant in production
- **Connection**: SSL enforced, private endpoint (VNet integration)
- **Connection string**: via `DATABASE_URL` in Key Vault → App Service config

### Cache — Azure Cache for Redis
- **SKU**: Basic C0 (dev, 250 MB) → Standard C1 (prod, 1 GB)
- **Purpose**: Celery task broker, session cache, rate-limit counters
- **TLS**: Enforced, port 6380
- **Connection**: via `REDIS_URL` in Key Vault

### Storage — Azure Blob Storage
- **Account**: Standard LRS (dev) → Standard GRS (prod)
- **Containers**: `scan-reports`, `exports`, `ml-models`, `nuclei-templates`
- **Access**: Private (Managed Identity auth via `azure-identity` SDK)
- **Lifecycle**: Move reports older than 90 days to Cool tier, delete after 365 days

### Secrets — Azure Key Vault
All secrets stored in Key Vault, referenced via App Service configuration:
- `SECRET-KEY` — Django secret key
- `DATABASE-URL` — PostgreSQL connection string
- `REDIS-URL` — Redis connection string
- `OPENROUTER-API-KEY` — LLM API key
- `STORAGE-CONNECTION-STRING` — Blob storage

### Monitoring — Azure Monitor + Application Insights
- **Application Insights**: Request tracing, dependency tracking, exception logging
- **Log Analytics**: KQL queries on Django logs, scan metrics, Celery task durations
- **Alerts**: HTTP 5xx > 5% (5min), response time P95 > 5s, Celery queue depth > 50
- **Dashboards**: Azure Portal dashboard with scan throughput, error rate, active users

### CI/CD — GitHub Actions
```yaml
# .github/workflows/deploy.yml
on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r backend/requirements.txt
      - run: cd backend && pytest

  deploy-backend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
      - uses: azure/webapps-deploy@v3
        with:
          app-name: safeweb-ai-api
          slot-name: staging
      - run: az webapp deployment slot swap ...

  deploy-frontend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
      - uses: Azure/static-web-apps-deploy@v1
```

### Infrastructure as Code (Bicep)
All Azure resources defined in `infra/main.bicep`:
- App Service Plan + App Service
- PostgreSQL Flexible Server + firewall rules
- Redis Cache
- Storage Account + containers
- Key Vault + access policies
- Application Insights + Log Analytics
- Static Web App
- Managed Identity + role assignments

### Key Config Files
- `backend/config/settings/base.py` — Django settings (shared)
- `backend/config/settings/production.py` — Production overrides (Azure-specific)
- `infra/main.bicep` — Azure infrastructure definition
- `infra/parameters.json` — Environment-specific values
- `.github/workflows/deploy.yml` — CI/CD pipeline
- `staticwebapp.config.json` — Azure Static Web Apps routing
- `vite.config.ts` — Vite dev proxy + chunk splitting

---

## 9. SECURITY SCORE CALCULATION

Starts at **100**, deductions per vulnerability severity:
| Severity | Deduction | CVSS Range |
|----------|-----------|------------|
| Critical | −25 | 9.0-10.0 |
| High | −15 | 7.0-8.9 |
| Medium | −8 | 4.0-6.9 |
| Low | −3 | 0.1-3.9 |
| Info | −1 | 0.0 |

Minimum score: **0**. Score is computed after all vulnerability testing phases complete.

---

## 10. CYBERSECURITY DOMAIN KNOWLEDGE

### Reference Library (48+ books in `CyberSecurity Books/`)
The project's security testing methodology and vulnerability detection are informed by these authoritative sources:

**Web Application Security**:
- *The Web Application Hacker's Handbook 2nd Ed* — Comprehensive WAPT methodology (input handling, auth, session, access control, app logic, server-side, client-side)
- *Web Hacking 101* — Real-world bug bounty write-ups teaching practical exploitation
- *Real-World Bug Hunting* by Peter Yaworski — Field guide to web hacking with HackerOne examples
- *Mastering Modern Web Penetration Testing* — Modern WAPT techniques
- *Web Security for Developers* — Developer-focused security primer
- *Web Security Testing Cookbook* — Practical WAPT recipes
- *Web Hacking Arsenal* — Tools and techniques catalog

**Penetration Testing**:
- *The Hacker Playbook 3* by Peter Kim — OSINT, scanning, exploitation, post-exploitation methodology
- *Bug Bounty Hunting* — Complete bug bounty workflow
- *Bug Bounty Playbook* — Structured bug hunting methodology
- *Bug Hunting Reconnaissance Guide* — Comprehensive recon methodology
- *Bounty Tips 100+* — 100+ practical bug bounty tips
- *zseano's Methodology* — Professional bug bounty hunting methodology
- *OWASP Web Application Security Testing Checklist* — WSTG checklist
- *OWASP Web Application Penetration Checklist v1.1* — OWASP pentest procedures

**Specific Vulnerability Classes**:
- *Brute Logic - XSS* — Advanced XSS exploitation techniques
- *Advanced XSS* — Deep XSS exploitation
- *Mastering XSS: A Beginner's Roadmap* — XSS from basics to advanced
- *BlackHat GraphQL* — GraphQL security testing
- *Hacking APIs / Hacking APIs Early Access* by Corey Ball — API security testing
- *JWT Security Checklist (DeepStrike)* — JWT attack vectors
- *Bypassing Cloudflare WAF in Bug Bounty* — WAF bypass techniques

**Programming & Scripting**:
- *Black Hat Python 2nd Ed* — Python for security tools
- *Black Hat Bash* — Bash for security operations
- *Black Hat Go* — Go for security tools
- *JavaScript for Hackers* by Gareth Heyes — JS exploitation
- *Linux Basics for Hackers* — Kali Linux fundamentals
- *Linux Command Line and Shell Scripting Bible* — Shell scripting

**Tools & Methodology**:
- *Burp Suite Cookbook* — Burp Suite recipes
- *Awesome Bug Bounty Tools* — Tool catalog
- *Introduction to Recon Methodology* — Recon mind maps and workflows
- *The Recon Methodology* — Structured recon process
- *Cyber Security Playbooks 2025* — Modern security playbooks
- *HackerPowered Security Report 2024-2025* — Industry trends
- *The YesWeHack Bug Bounty Report 2025* — Bug bounty statistics

**Additional Security Topics**:
- *The Tangled Web* — Browser security model
- *2FA Bypass* — Two-factor authentication bypass techniques
- *OWASP API Security Top 10* — API-specific vulnerabilities

### Online Knowledge Sources
**OWASP & Standards**: OWASP WSTG v4.2, OWASP API Security Top 10, OWASP Testing Guide
**Bug Bounty Platforms**: HackerOne Hacktivity, YesWeHack, Intigriti
**Research & Methodologies**: PortSwigger Web Security Academy (all topics), PortSwigger Research, ars0nsecurity methodology, zseano's methodology, jhaddix TBHM, R-s0n recon methodology
**Payload Databases**: PayloadsAllTheThings, SecLists, Awesome Bug Bounty Writeups
**Tool Ecosystems**: ProjectDiscovery (nuclei, subfinder, httpx, katana, etc.), vavkamil/awesome-bugbounty-tools, pentest-tools.com, cyver-core/ultimate-pentest-tools-list
**Exploitation References**: exploit-db.com, HackTheBox guides
**Recon Techniques**: CT log enumeration, ASN recon, Shodan/Censys OSINT, Google dorking, GitHub recon, subdomain enumeration, wayback machine analysis

---

## 11. SYSTEM ANALYSIS & DESIGN KNOWLEDGE

### Reference Sources
- *MIT OCW — Engineering Systems Analysis for Design* — Systematic requirements analysis
- *Systems Analysis and Design with UML 2.0* (Dennis, Wixom, Roth) — Full SA&D lifecycle
- *OpenStax — Foundations of Information Systems* — SA&D for application development
- *System Design Primer* (GitHub) — Large-scale system design patterns
- *System Design Handbook* — Architecture patterns and trade-offs

### Applied Design Principles in SafeWeb AI

**Architecture Pattern**: Layered architecture with clear separation:
- **Presentation Layer**: React SPA with component-based UI
- **API Layer**: Django REST Framework with serializers, permissions, throttling
- **Business Logic Layer**: Scanning engine orchestrator, AI chatbot engine, ML models
- **Data Layer**: Django ORM with PostgreSQL/SQLite
- **Integration Layer**: 62 external tool wrappers with graceful degradation

**Design Patterns Used**:
- **Registry Pattern**: `ToolRegistry` for external tool management with auto-discovery
- **Strategy Pattern**: Multiple scan depth strategies (shallow/medium/deep), scope types
- **Observer Pattern**: SSE for real-time scan progress, webhook event notifications
- **Factory Pattern**: Tester instantiation from registered tester classes
- **Template Method**: `BaseTester` defines test lifecycle, subclasses override specific methods
- **Pipeline Pattern**: ScanOrchestrator phases execute in sequence with data flowing forward
- **Command Pattern**: Chatbot actions (start_scan, navigate_to, etc.)
- **Facade Pattern**: API service layer in frontend abstracts 16 API namespaces

**Non-Functional Requirements Met**:
- **Scalability**: Celery for async task execution, distributed scan support
- **Resilience**: Graceful degradation (missing tools skipped), retry mechanisms, fallback modes
- **Security**: JWT auth with rotation, CORS, CSRF protection, input validation, rate limiting
- **Performance**: ML-prioritized testing order, async scanning, lazy-loaded frontend
- **Maintainability**: Modular engine (each tester/recon module is independent), typed API
- **Observability**: Phase timing, tester results tracking, data versioning for SSE

### UML Diagrams That Can Be Generated

Based on the codebase, the following UML diagrams are relevant:
1. **Use Case Diagram**: User (scan, view results, manage profile), Admin (manage users/scans/settings), System (scheduled scans, asset monitoring)
2. **Class Diagram**: User → Scan → Vulnerability, ChatSession → ChatMessage, ScheduledScan, Webhook
3. **Sequence Diagram**: Scan lifecycle (create → dispatch → recon → crawl → test → verify → complete)
4. **Activity Diagram**: Scanning pipeline phases with parallel branches
5. **Component Diagram**: Frontend ↔ API ↔ Engine ↔ Tools/DB
6. **Deployment Diagram**: Vercel → Railway → PostgreSQL/Redis
7. **State Machine**: Scan status transitions (pending → scanning → completed/failed)
8. **Entity-Relationship Diagram**: All Django models with relationships

---

## 12. PREVIOUS GRADUATION PROJECT REFERENCES

### Previous Project Books (in `Previous Graduation Project Books/`)
- **Evolvify** — Graduation project documentation
- **Healthy Life** — Information system for exercising-based graduation project
- **Phirus** — Previous graduation project

These provide structural templates for:
- Project documentation format and chapter organization
- Requirements specification methodology
- Testing and validation approaches
- Presentation structure

### Previous Project Presentations (in `Previous Projects Presentations/`)
- `1.pptx`, `2.pptx` — Presentation templates and structure references

---

## 13. KEY TECHNICAL DECISIONS

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Auth | JWT (SimpleJWT) with refresh rotation | Stateless, scalable, blacklist on logout |
| Database | Azure PostgreSQL Flexible Server | Managed, HA, automated backups, SSL, VNet |
| Task queue | Celery with Azure Redis | Async scans, reliable broker with persistence |
| LLM (Chatbot) | OpenRouter (Gemini 2.0 Flash) | Cloud-based, function calling support, fast |
| LLM (Scanning) | Ollama (local) | Privacy, no API costs for pentesting reasoning |
| ML | scikit-learn + XGBoost | Lightweight, fast inference on scan data |
| Frontend state | React Context only | Simple, no Redux overhead needed |
| Styling | TailwindCSS dark theme | Consistent cybersecurity aesthetic, JIT compilation |
| Cloud | Microsoft Azure (full stack) | Enterprise-grade, PaaS, compliance, Bicep IaC |
| Tool integration | CLI wrapper pattern | Graceful degradation — works without any tools installed |
| Real-time | SSE + polling fallback | SSE for live updates, 8s polling as safety net |
| Secrets | Azure Key Vault | Centralized, audited, Managed Identity access |
| CI/CD | GitHub Actions + Azure Deploy | Automated test → build → staging → swap slots |
| IaC | Bicep | Native Azure, type-safe, modular, no Terraform state |

---

## 14. DATABASE DESIGN (PostgreSQL 16)

### Entity-Relationship Diagram

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
  ├── has_many → child_scans (self-FK)
  └── fields: target, status, depth, scope_type, recon_data (JSON),
              tester_results (JSON), phase_timings (JSON), score, data_version

Vulnerability (UUID)
  └── belongs_to → Scan
      fields: name, severity, category, CWE, CVSS, affected_url,
              evidence, verified, false_positive_score, exploit_data (JSON)

ChatSession (UUID)
  ├── belongs_to → User (nullable)
  ├── belongs_to → Scan (nullable, for scan-context chats)
  └── has_many → ChatMessage

ChatMessage (UUID)
  └── belongs_to → ChatSession
      fields: role (user/assistant/system), content, tokens_used, feedback, action_data

ScheduledScan
  └── belongs_to → User
      fields: cron_expr, scan_config (JSON), next_run, last_run, is_active

Webhook
  └── belongs_to → User
      has_many → WebhookDelivery
      fields: url, events[], secret, is_active
```

### Complete Table Schema

#### `accounts_user`
| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
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

#### `accounts_apikey`
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| user_id | UUID | FK → accounts_user |
| key | VARCHAR(64) | UNIQUE, `sk_live_` prefix |
| name | VARCHAR(100) | |
| is_active | BOOLEAN | DEFAULT TRUE |
| last_used | TIMESTAMPTZ | NULLABLE |
| usage_count | INTEGER | DEFAULT 0 |
| created_at | TIMESTAMPTZ | auto_now_add |

#### `accounts_usersession`
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| user_id | UUID | FK → accounts_user |
| jti | VARCHAR(255) | UNIQUE (JWT ID) |
| ip_address | INET | |
| user_agent | TEXT | |
| created_at | TIMESTAMPTZ | |
| last_active | TIMESTAMPTZ | |

#### `scanning_scan`
| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
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
**Partitioning** (future): Range partition on `created_at` (monthly)

#### `scanning_vulnerability`
| Column | Type | Constraints |
|--------|------|-------------|
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

#### `chatbot_chatsession` / `chatbot_chatmessage`
| Table | Key Columns |
|-------|-------------|
| chatsession | id (UUID PK), user_id (FK nullable), scan_id (FK nullable), title, created_at, updated_at |
| chatmessage | id (UUID PK), session_id (FK), role (user/assistant/system), content (TEXT), tokens_used (INT), feedback (VARCHAR nullable), action_data (JSONB nullable), created_at |

#### Other Tables
| Table | Key Columns |
|-------|-------------|
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

### PostgreSQL-Specific Optimizations
- **JSONB** for `recon_data`, `tester_results`, `exploit_data` — GIN indexes for fast `@>` queries
- **UUID primary keys** — `gen_random_uuid()` default, no sequential ID exposure
- **TIMESTAMPTZ** for all timestamps — timezone-aware
- **Connection pooling**: PgBouncer (transaction mode) in front of Flexible Server
- **Read replicas** (future): For dashboard analytics, report generation
- **pg_stat_statements**: Query performance monitoring
- **Vacuum/Analyze**: Autovacuum tuned for heavy-write scan tables

---

## 15. CLOUD ENGINEERING & DevOps

### Azure Architecture Principles
- **Well-Architected Framework pillars**: Reliability, Security, Cost Optimization, Operational Excellence, Performance Efficiency
- **Zero-trust networking**: All services behind VNet, private endpoints, no public DB access
- **Managed Identity everywhere**: No stored credentials for Azure-to-Azure communication
- **Infrastructure as Code**: 100% Bicep — reproducible, version-controlled, PR-reviewed

### DevOps Pipeline (GitHub Actions)

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌───────────┐     ┌──────┐
│  Push   │────▶│  Lint +  │────▶│  Build   │────▶│  Deploy   │────▶│ Swap │
│  main   │     │  Test    │     │ Artifacts│     │  Staging  │     │ Slots│
└─────────┘     └──────────┘     └──────────┘     └───────────┘     └──────┘
                  pytest           collectstatic     App Service       blue/green
                  eslint/tsc       npm build          slot: staging     → production
                  safety check     Docker image       smoke tests
```

**Workflow stages**:
1. **Lint & Test**: `pytest` (backend), `tsc --noEmit` (frontend), `pip-audit` (dependency security)
2. **Build**: `collectstatic`, `npm run build`, Docker image for scanning tools sidecar
3. **Deploy to Staging**: Push to App Service staging slot, run smoke tests against staging URL
4. **Slot Swap**: If smoke tests pass → swap staging ↔ production (zero-downtime)
5. **Post-deploy**: Run `manage.py migrate`, invalidate CDN cache, notify via webhook

### Environment Strategy
| Environment | Azure Resources | Purpose |
|-------------|----------------|---------|
| **Local (dev)** | SQLite + local Redis | Developer machine, `python manage.py runserver` |
| **Staging** | Azure B1ms Postgres, C0 Redis | Pre-production validation, PR previews |
| **Production** | Azure D2s_v3 Postgres, C1 Redis | Live application, auto-scaled |

### Networking & Security
- **VNet Integration**: App Service → VNet → Private Endpoint → PostgreSQL/Redis
- **NSG rules**: Allow only App Service outbound to DB subnet
- **Azure Front Door**: WAF policies (OWASP 3.2 ruleset), DDoS protection, geo-filtering
- **SSL/TLS**: Azure-managed certificates, TLS 1.2+ enforced everywhere
- **Key rotation**: Automated via Key Vault + Event Grid (90-day cycle)

### Disaster Recovery
- **RPO**: 1 hour (PostgreSQL PITR)
- **RTO**: 15 minutes (slot swap from healthy instance)
- **Backup strategy**: Daily automated backups (35-day retention), geo-redundant storage
- **Failover**: Zone-redundant PostgreSQL, multi-instance App Service

---

## 16. PERFORMANCE ENGINEERING

### Backend Performance
- **Gunicorn workers**: `2 × vCPU + 1` = 5 workers on P1v2 (2 vCPU)
- **Database connection pooling**: PgBouncer (transaction mode, 20 pool size)
- **Django query optimization**: `select_related()` / `prefetch_related()` on Scan→Vulnerability joins
- **Scan result caching**: Redis cache for completed scan data (TTL 1 hour)
- **Bulk operations**: `bulk_create()` for vulnerability batch insertion (50–200 vulns per scan)
- **Async scanning**: Celery tasks with 120s soft timeout, 300s hard timeout
- **Streaming responses**: SSE generator yields progress without blocking workers

### Frontend Performance
- **Code splitting**: Vite chunk splitting per route (lazy loading all 35 pages)
- **Tree shaking**: Unused imports eliminated at build time
- **Asset optimization**: Brotli compression, image optimization, font subsetting
- **Cache strategy**: Immutable hashed assets (1-year cache), HTML no-cache
- **Bundle analysis**: Target < 200 KB initial JS, < 50 KB per lazy chunk
- **SSE connection management**: Auto-reconnect with exponential backoff

### Database Performance
- **Indexing strategy**: B-tree on FKs, GIN on JSONB, composite indexes on hot queries
- **Query plans**: `EXPLAIN ANALYZE` on scan listing, vulnerability filtering, dashboard aggregation
- **Connection limits**: 100 max (Flexible Server B1ms), PgBouncer pool = 20
- **Slow query logging**: PostgreSQL `log_min_duration_statement = 500ms`
- **Partitioning roadmap**: Monthly range partition on `scanning_scan.created_at` when > 100K rows

### Monitoring & Alerting
| Metric | Threshold | Alert |
|--------|-----------|-------|
| HTTP 5xx rate | > 5% over 5min | PagerDuty / email |
| P95 response time | > 5 seconds | Warning |
| P99 response time | > 10 seconds | Critical |
| Celery queue depth | > 50 tasks | Scale workers |
| PostgreSQL connections | > 80% capacity | Investigate |
| Disk usage (Postgres) | > 80% | Auto-grow or cleanup |
| CPU (App Service) | > 70% sustained | Auto-scale out |
| Memory (App Service) | > 85% | Investigate leaks |

---

## 17. ENVIRONMENT VARIABLES REFERENCE

### Azure (Backend — App Service Configuration)
| Variable | Required | Source | Description |
|----------|----------|--------|-------------|
| `SECRET_KEY` | Yes | Key Vault | Django secret key |
| `DEBUG` | Yes | App Setting | `False` for production |
| `DATABASE_URL` | Yes | Key Vault | PostgreSQL connection string |
| `REDIS_URL` | Yes | Key Vault | Redis connection string (TLS, port 6380) |
| `FRONTEND_URL` | Yes | App Setting | Static Web App URL (CORS) |
| `OPENROUTER_API_KEY` | Yes | Key Vault | LLM API key |
| `ALLOWED_HOSTS` | Yes | App Setting | `.azurewebsites.net,safeweb-ai.com` |
| `DJANGO_SETTINGS_MODULE` | Yes | App Setting | `config.settings.production` |
| `AZURE_STORAGE_CONNECTION_STRING` | Yes | Key Vault | Blob storage |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Yes | App Setting | Monitoring |

### Azure (Frontend — Static Web App)
| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_API_URL` | Yes | Backend App Service URL |

---

## 18. COMMON DEVELOPMENT TASKS

### Running Locally
```bash
# Backend
cd backend
python manage.py runserver 8000

# Frontend
npm run dev  # Vite dev server on :5173 with proxy to :8000
```

### Adding a New Vulnerability Tester
1. Create `backend/apps/scanning/engine/testers/new_tester.py`
2. Inherit from `BaseTester` in `base_tester.py`
3. Implement `run(self, page, scan_depth, recon_data)` method
4. Register in `testers/__init__.py`
5. Create vulnerabilities via `self._create_vulnerability(scan, name, severity, ...)`

### Adding a New Recon Module
1. Create `backend/apps/scanning/engine/recon/new_module.py`
2. Implement async function returning dict of results
3. Add to appropriate wave in `orchestrator.py` `_run_recon_async()`
4. Add result rendering in `src/components/scan/ReconTab.tsx`

### Adding a New External Tool
1. Create wrapper in `backend/apps/scanning/engine/tools/wrappers/new_tool.py`
2. Inherit from `ExternalTool` in `tools/base.py`
3. Register in tool registry (auto-discovered on worker_ready)

### Adding a New Frontend Page
1. Create `src/pages/NewPage.tsx`
2. Add lazy import in `src/App.tsx`
3. Add route with appropriate protection (public/auth/admin)
4. Add API calls in `src/services/api.ts` if needed

---

## 19. TESTING & QUALITY

- **Backend tests**: `backend/tests/` directory, pytest with Django test client
- **Test config**: `backend/pytest.ini`
- **Coverage areas**: API endpoints, scanning tasks, model operations
- **CI gate**: All tests must pass before deploy (GitHub Actions)
- **Frontend**: No test framework configured (recommend Vitest + React Testing Library)
- **Security scanning**: `pip-audit` for dependency vulnerabilities, `bandit` for Python static analysis

---

## 20. FUTURE FEATURES & ENHANCEMENTS ROADMAP

### Phase 1 — Platform Hardening (Near-term)
| Feature | Description | Priority |
|---------|-------------|----------|
| **Google OAuth** | Complete OAuth 2.0 flow with Google sign-in | High |
| **WebSocket upgrade** | Replace SSE with WebSocket for bidirectional real-time | Medium |
| **PDF report redesign** | Professional branded PDF with charts, executive summary | High |
| **Dark/light theme toggle** | User preference for UI theme | Low |
| **Email notifications** | Scan completion, scheduled scan alerts, weekly digest | Medium |
| **Password reset email** | Full SMTP integration with Azure Communication Services | High |

### Phase 2 — Scanning Engine Enhancement
| Feature | Description | Priority |
|---------|-------------|----------|
| **Distributed scanning workers** | Celery workers on Azure Container Instances, auto-scaled | High |
| **Scan queue management** | Priority queue, concurrency limits per plan tier | High |
| **Authenticated scanning UI** | Frontend form for cookie/bearer/form-auth configs | Medium |
| **Custom nuclei templates** | Upload, edit, test custom Nuclei YAML templates | Medium |
| **Scan diffing timeline** | Visual timeline of vulnerability changes across rescans | Medium |
| **Compliance mapping** | Map findings to PCI DSS, SOC 2, ISO 27001 controls | Low |
| **DAST + SAST hybrid** | Static analysis for uploaded source code repos | Future |

### Phase 3 — AI & ML Expansion
| Feature | Description | Priority |
|---------|-------------|----------|
| **RAG-powered chatbot** | Retrieve-Augmented Generation using scan data + knowledge base | High |
| **Vulnerability auto-remediation** | AI-generated code patches with diff preview | Medium |
| **Smart scan scheduling** | ML model predicts optimal scan frequency per target | Low |
| **Threat intelligence feed** | Real-time CVE/exploit feed integration (NVD, ExploitDB) | Medium |
| **Custom LLM fine-tuning** | Fine-tune open model on cybersecurity Q&A dataset | Future |
| **Re-enable ML scan types** | Phishing URL scanner, malware file scanner in production | Medium |

### Phase 4 — Enterprise Features
| Feature | Description | Priority |
|---------|-------------|----------|
| **Team workspaces** | Multi-user organizations with shared scans and RBAC | High |
| **SSO (SAML/OIDC)** | Enterprise SSO integration via Azure AD / Okta | Medium |
| **Audit logging** | Immutable audit trail for all user/admin actions | High |
| **API rate limiting tiers** | Plan-based API quotas with usage dashboard | Medium |
| **Tenant isolation** | Per-tenant data isolation for enterprise customers | Future |
| **SLA dashboard** | Uptime, scan throughput, response time SLA metrics | Low |
| **White-label support** | Custom branding for resellers/MSSPs | Future |

### Phase 5 — Cloud & Infrastructure
| Feature | Description | Priority |
|---------|-------------|----------|
| **Kubernetes migration** | AKS for scanning workers, Helm charts | Future |
| **Multi-region deployment** | Azure Front Door + geo-distributed backends | Future |
| **Serverless functions** | Azure Functions for report generation, webhook delivery | Medium |
| **Data Lake analytics** | Azure Data Explorer for scan trend analytics | Low |
| **Terraform alternative** | Dual IaC support (Bicep + Terraform) | Low |

### Phase 6 — Community & Ecosystem
| Feature | Description | Priority |
|---------|-------------|----------|
| **Public API + SDK** | REST API documentation (OpenAPI 3.0) + Python/JS SDK | High |
| **Plugin marketplace** | Community-contributed testers, recon modules, templates | Future |
| **Bug bounty integration** | Direct submission to HackerOne/Bugcrowd from findings | Medium |
| **Slack/Discord bot** | Scan notifications and chatbot access via messaging | Low |
| **Mobile app** | React Native companion app for scan monitoring | Future |

---

## 21. KNOWN LIMITATIONS

| Area | Current Limitation | Planned Resolution |
|------|-------------------|-------------------|
| Scanning tools | CLI tools not available in App Service sandbox | ACI sidecar container with all tools pre-installed |
| File/URL scanning | ML models preserved but scan types deactivated | Re-enable with dedicated upload pipeline |
| Google OAuth | UI present but flow not connected | Complete with Azure AD B2C or direct Google OAuth |
| Email | No SMTP configured | Azure Communication Services or SendGrid |
| Real-time | SSE can be unreliable through CDN/proxy | WebSocket upgrade with Azure Web PubSub |
| Reports | PDF generation needs system fonts | Docker sidecar with fonts + WeasyPrint |
| Search | No full-text search on vulnerabilities | PostgreSQL `tsvector` + GIN index |
| Rate limiting | Basic Django throttle | Azure Front Door rate limiting + Redis sliding window |

---

*This document is the single source of truth for the SafeWeb AI project. It should be consulted for any task involving development, debugging, architecture decisions, cybersecurity testing methodology, system design, cloud engineering, performance optimization, documentation, or deployment.*
