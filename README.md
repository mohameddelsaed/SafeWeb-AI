<div align="center">

# 🛡️ SafeWeb AI

### Enterprise-Grade AI-Powered Web Application Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.0+-092E20?style=for-the-badge&logo=django&logoColor=white)](https://djangoproject.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Azure](https://img.shields.io/badge/Microsoft_Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com)
[![License](https://img.shields.io/badge/License-University_Project-orange?style=for-the-badge)]()

**A professional cybersecurity SaaS platform that combines 62+ security tools, 85+ vulnerability testers, 40+ reconnaissance modules, and AI-powered analysis into a unified scanning engine — deployed on Microsoft Azure with PostgreSQL, Redis, and a full CI/CD pipeline.**

[Features](#-features) • [Architecture](#-architecture) • [Tech Stack](#-tech-stack) • [Installation](#-installation) • [Scanning Engine](#-scanning-engine) • [AI Chatbot](#-ai-chatbot-assistant) • [API Reference](#-api-reference) • [Azure Deployment](#-azure-deployment) • [Database Design](#-database-design) • [Roadmap](#-roadmap)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Project Structure](#-project-structure)
- [Scanning Engine](#-scanning-engine)
- [AI Chatbot Assistant](#-ai-chatbot-assistant)
- [API Reference](#-api-reference)
- [Azure Deployment](#-azure-deployment)
- [Database Design](#-database-design)
- [Performance Engineering](#-performance-engineering)
- [Frontend Pages](#-frontend-pages)
- [Security Tools](#-security-tools)
- [Roadmap](#-roadmap)
- [Team](#-team)

---

## ✨ Features

### Core Scanning
- **87+ Vulnerability Testers** — SQL injection, XSS, SSRF, SSTI, command injection, IDOR, JWT attacks, GraphQL exploitation, and 80+ more
- **37 Reconnaissance Modules** — DNS enumeration, subdomain discovery, technology fingerprinting, WAF detection, cloud storage scanning, threat intelligence
- **60+ Integrated Security Tools** — Nmap, Nuclei, SQLMap, FFUF, Subfinder, Amass, WhatWeb, and more with custom wrappers
- **Real-Time SSE Streaming** — Live scan progress updates via Server-Sent Events
- **Multi-Scope Scanning** — Single domain, wildcard, and wide-scope modes
- **3 Scan Depths** — Shallow, medium, and deep analysis levels
- **Scan Comparison** — Side-by-side diff of two scans to track remediation progress

### AI-Powered Intelligence
- **LLM Chat Assistant** — OpenRouter-powered chatbot (Gemini 2.0 Flash) with 36-entry knowledge base
- **7 Action Tools** — Start scans, check status, export reports, navigate — all from chat
- **Scan-Aware Context** — Auto-detects scan context from URL, provides vulnerability-specific advice
- **ML Models** — Malware detection, phishing analysis, and anomaly detection with confidence scoring
- **LLM Attack Strategy** — AI-generated testing strategies based on reconnaissance findings

### Platform Features
- **JWT Authentication** — Email/password + Google OAuth + 2FA (TOTP with QR code)
- **Role-Based Access** — User, Admin roles with plan-based feature gating
- **Subscription Tiers** — Free (5 scans/month), Pro, Enterprise with graduated feature access
- **Scheduled Scans** — Hourly, daily, weekly, monthly, or custom cron scheduling
- **Webhook Notifications** — Real-time alerts on scan completion to external services
- **Asset Inventory** — Automatic tracking of discovered assets across scans
- **Export Formats** — PDF, CSV, JSON, SARIF, HTML report generation
- **Nuclei Templates** — Custom and community template management
- **Admin Dashboard** — User management, system stats, scan analytics, ML model monitoring, chat analytics
- **Learning Center** — 9-category cybersecurity article library

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│               FRONTEND (Azure Static Web Apps)                  │
│  React 18 + TypeScript + Vite + TailwindCSS                     │
│  35 routes · 74+ source files · SSE streaming · JWT auth        │
│  Azure CDN (global edge) + Custom Domain + SSL                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│           BACKEND (Azure App Service — Linux P1v2)              │
│  Django 5.0 + DRF + Gunicorn + WhiteNoise                       │
│  6 Django apps · JWT auth · Rate limiting · CORS                │
├──────────┬──────────┬───────────┬───────────┬───────────────────┤
│ accounts │ scanning │  chatbot  │    ml     │ learn · admin     │
│  (auth)  │ (engine) │   (AI)    │ (models)  │ (articles/panel)  │
├──────────┴──────────┴───────────┴───────────┴───────────────────┤
│              TASK QUEUE (Celery + Azure Redis)                   │
│  Async scan execution · Tool registry · Rate-limit counters     │
├─────────────────────────────────────────────────────────────────┤
│               SCANNING ENGINE (7 Phases)                        │
│  40+ recon modules → crawler → 85+ testers → ML verify         │
│  62+ tool wrappers · SecLists payloads · Nuclei engine          │
├─────────────────────────────────────────────────────────────────┤
│                  AI / ML LAYER                                  │
│  OpenRouter LLM (Gemini 2.0 Flash) · scikit-learn · XGBoost    │
│  7 function-calling tools · Knowledge base · Ollama (optional)  │
├─────────────────────────────────────────────────────────────────┤
│              INFRASTRUCTURE (Microsoft Azure)                   │
│  Azure PostgreSQL Flexible Server · Azure Redis Cache           │
│  Azure Blob Storage · Azure Key Vault · App Insights            │
│  Azure Container Instances (tools sidecar)                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠 Tech Stack

### Backend
| Technology | Purpose |
|:-----------|:--------|
| **Python 3.11+** | Core language |
| **Django 5.0** | Web framework |
| **Django REST Framework** | API layer |
| **Celery 5.3** | Async task queue |
| **Redis** | Message broker & cache |
| **PostgreSQL** | Production database |
| **SimpleJWT** | JWT authentication |
| **OpenAI SDK** | LLM integration (OpenRouter) |
| **scikit-learn / XGBoost** | ML models |
| **Playwright** | Browser automation for JS-heavy targets |
| **BeautifulSoup4 / lxml** | HTML parsing |
| **ReportLab** | PDF report generation |
| **Gunicorn** | WSGI HTTP server |

### Frontend
| Technology | Purpose |
|:-----------|:--------|
| **React 18** | UI framework |
| **TypeScript 5** | Type safety |
| **Vite** | Build tool & dev server |
| **TailwindCSS 3.4** | Utility-first styling |
| **React Router v6** | Client-side routing |
| **Axios** | HTTP client |
| **react-markdown** | Markdown rendering (chatbot) |
| **remark-gfm** | GitHub Flavored Markdown |
| **rehype-highlight** | Code syntax highlighting |

### DevOps & Cloud
| Technology | Purpose |
|:-----------|:--------|
| **Microsoft Azure** | Full cloud deployment platform |
| **Azure App Service** | Backend hosting (Linux P1v2) |
| **Azure Static Web Apps** | Frontend hosting + CDN |
| **Azure PostgreSQL Flexible Server** | Production database (v16) |
| **Azure Cache for Redis** | Task broker + cache |
| **Azure Blob Storage** | Scan reports, exports, ML models |
| **Azure Key Vault** | Secrets management |
| **Azure Monitor + App Insights** | APM, logging, alerting |
| **Azure Container Instances** | Scanning tools sidecar |
| **Azure Front Door + CDN** | WAF, DDoS protection, edge caching |
| **GitHub Actions** | CI/CD pipeline |
| **Bicep** | Infrastructure as Code |

---

## 📦 Installation

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Redis** (for Celery task queue)
- **Git**

### 1. Clone & Setup

```bash
git clone https://github.com/0xN0RMXL/safeweb-ai.git
cd safeweb-ai
```

### 2. Backend Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source .venv/bin/activate

# Install Python dependencies
pip install -r backend/requirements.txt

# Run migrations
cd backend
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser

# Start Django server
python manage.py runserver 8000
```

### 3. Frontend Setup

```bash
# From project root
npm install

# Start Vite dev server
npm run dev
```

### 4. Celery Worker (for async scanning)

```bash
cd backend
celery -A celery_app worker --loglevel=info
```

### 5. Security Tools (Optional)

Install 60+ bug bounty tools for full scanning capability:

```powershell
# Windows — PowerShell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\install-tools.ps1

# Selective installation
.\scripts\install-tools.ps1 -SkipRuby -SkipRust
```

**Skip flags:** `-SkipGo`, `-SkipPython`, `-SkipRuby`, `-SkipRust`, `-SkipNode`, `-SkipNmap`, `-SkipSecLists`

### Environment Variables

Create a `.env` file in `backend/` for local development:

```env
SECRET_KEY=your-django-secret-key
DEBUG=True
DATABASE_URL=sqlite:///db.sqlite3
REDIS_URL=redis://localhost:6379/0
OPENROUTER_API_KEY=your-openrouter-api-key
OPENROUTER_MODEL=google/gemini-2.0-flash-001
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

In production (Azure), all secrets are stored in **Azure Key Vault** and referenced via App Service configuration:

| Variable | Source | Description |
|:---------|:-------|:------------|
| `SECRET_KEY` | Key Vault | Django secret key |
| `DATABASE_URL` | Key Vault | PostgreSQL connection string |
| `REDIS_URL` | Key Vault | Redis TLS connection (port 6380) |
| `OPENROUTER_API_KEY` | Key Vault | LLM API key |
| `AZURE_STORAGE_CONNECTION_STRING` | Key Vault | Blob storage |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | App Setting | Monitoring |
| `DJANGO_SETTINGS_MODULE` | App Setting | `config.settings.production` |
| `ALLOWED_HOSTS` | App Setting | `.azurewebsites.net,safeweb-ai.com` |
| `FRONTEND_URL` | App Setting | Static Web App URL (CORS) |

---

## 📁 Project Structure

```
safeweb-ai/
├── backend/                          # Django backend
│   ├── manage.py                     # Django management
│   ├── celery_app.py                 # Celery configuration
│   ├── Procfile                      # Railway process config
│   ├── requirements.txt              # Python dependencies
│   ├── apps/
│   │   ├── accounts/                 # User auth & management
│   │   │   ├── models.py            # User, APIKey, UserSession, ContactMessage
│   │   │   ├── views.py             # Auth views (register, login, 2FA, OAuth)
│   │   │   ├── serializers.py       # DRF serializers
│   │   │   └── urls.py              # Auth + user API routes
│   │   ├── scanning/                 # Core scanning engine
│   │   │   ├── models.py            # Scan, Vulnerability, AuthConfig, ScheduledScan
│   │   │   ├── views.py             # Scan CRUD, SSE stream, export, compare
│   │   │   ├── tasks.py             # Celery scan tasks
│   │   │   └── engine/              # The scanning engine
│   │   │       ├── orchestrator.py  # 7-phase scan pipeline
│   │   │       ├── crawler.py       # Web crawler with form interaction
│   │   │       ├── recon/           # 37 reconnaissance modules
│   │   │       ├── testers/         # 87+ vulnerability testers
│   │   │       ├── tools/           # 61 external tool wrappers
│   │   │       │   ├── base.py      # ExternalTool base class
│   │   │       │   ├── registry.py  # Tool registration system
│   │   │       │   └── wrappers/    # Individual tool wrappers
│   │   │       └── payloads/        # Attack payloads + SecLists
│   │   ├── chatbot/                  # AI chat assistant
│   │   │   ├── engine.py            # LLM engine + KB + function calling
│   │   │   ├── actions.py           # 7 action handlers
│   │   │   ├── models.py            # ChatSession, ChatMessage
│   │   │   └── views.py             # Chat, suggestions, analytics views
│   │   ├── ml/                       # Machine learning models
│   │   │   └── models.py            # MLModel, MLPrediction
│   │   ├── admin_panel/              # Admin dashboard backend
│   │   │   ├── models.py            # SystemAlert, SystemSettings
│   │   │   └── views.py             # Admin stats, user mgmt, settings
│   │   └── learn/                    # Learning center
│   │       └── models.py            # Article model (9 categories)
│   └── config/
│       ├── urls.py                   # Root URL configuration
│       └── settings/
│           ├── base.py               # Shared settings
│           └── development.py        # Dev overrides
├── src/                              # React frontend
│   ├── App.tsx                       # Routes & app shell
│   ├── main.tsx                      # Entry point
│   ├── index.css                     # Global styles + Tailwind
│   ├── components/
│   │   ├── layout/                   # Navbar, Footer, ChatbotWidget
│   │   ├── home/                     # Landing page sections
│   │   ├── scan/                     # Scan result tabs
│   │   └── ui/                       # 14 reusable UI components
│   ├── contexts/                     # React context providers
│   ├── hooks/                        # Custom hooks (useSSE, useScanTimer)
│   ├── pages/                        # 28 page components
│   │   └── admin/                    # 7 admin pages
│   ├── services/
│   │   └── api.ts                    # 16 API service modules
│   ├── types/
│   │   └── index.ts                  # TypeScript type definitions
│   └── utils/                        # Utility functions
├── tools/                            # Installed security tools
│   └── bin/                          # 55+ tool binaries & scripts
├── scripts/                          # Setup & utility scripts
│   └── install-tools.ps1            # Bug bounty tool installer
├── vite.config.ts                    # Vite configuration
├── tailwind.config.js                # Tailwind theme config
├── staticwebapp.config.json          # Azure Static Web Apps routing
└── infra/
    ├── main.bicep                    # Azure infrastructure definition
    └── parameters.json               # Environment-specific values
```

---

## 🔍 Scanning Engine

The scanning engine is an advanced autonomous pipeline that orchestrates reconnaissance, crawling, vulnerability testing, and verification. Powered by PostgreSQL `pgvector` vector embeddings (`ExploitMemory`), Headless Browser MCP navigation, and multi-provider AI routing, it operates continuously without blocking asynchronous event loops.

### Phase Pipeline

```
Phase 0     Reconnaissance          37 modules in 4 async waves
Phase 0.5   Auth Setup              Form / OAuth / JWT / cookie analysis
Phase 1     Crawling                Web crawler + form interaction + seed injection
Phase 1.5   Attack Surface Model    LLM-generated testing strategy
Phase 2–4   Analysis                Headers, SSL/TLS, cookies, technologies
Phase 5     Vulnerability Testing   87+ testers, ML-prioritized execution
Phase 5.1   OOB Callback Polling    Out-of-band interaction verification
Phase 5b    Nuclei Engine           Template-based vulnerability scanning
Phase 5c    Secret Scanning         API keys, tokens, credentials in source
Phase 5.5   Evidence Verification   Confirm exploitability with proof
Phase 5.7   Exploit Generation      PoC code + bug bounty report drafting
Phase 6     Vulnerability Chaining  Multi-step attack path discovery
Phase 6.5   False Positive Reduction  5-component ensemble verification
Phase 7     Learning & Update       Knowledge base refinement
```

### Reconnaissance Modules (37)

Organized into 4 concurrent async waves for maximum speed:

| Wave | Modules | Purpose |
|:-----|:--------|:--------|
| **0a — Network** | DNS enumeration, WHOIS, port scanning, subdomain discovery, ASN mapping | Network topology & infrastructure |
| **0b — Response** | Technology fingerprinting, header analysis, cookie audit, SSL/TLS check, WAF detection, CORS testing | Server configuration & defenses |
| **0c — Content** | Parameter fuzzing, directory brute-force, API discovery, JS analysis, cloud bucket detection, CMS fingerprint, email enumeration, social recon | Application surface mapping |
| **0d — Analytics** | Attack surface scoring, threat intelligence (abuse.ch, OTX), risk scoring, vulnerability correlation | Prioritization & strategy |

### Vulnerability Testers (87+)

Detailed testers across Injection, Authentication, API, Network, File Upload, Business Logic, Data Exposure, App-specific, and Advanced categories.

### Scan Modes

| Mode | Description |
|:-----|:------------|
| **Standard** | Full pipeline execution, single target |
| **Continuous** | Recurring scheduled scans with change detection |
| **Hunting** | Bug bounty mode — wide scope, maximum depth, exploit generation |

### Scan Scopes

| Scope | Example | Coverage |
|:------|:--------|:---------|
| **Single Domain** | `example.com` | One domain only |
| **Wildcard** | `*.example.com` | All subdomains |
| **Wide Scope** | Multiple targets | Multi-domain, IP ranges, CIDR blocks |

### Scan Depth

| Depth | Recon | Testers |
|:------|:------|:--------|
| **Shallow** | Basic (DNS, tech fingerprint) | Top 20 common tests |
| **Medium** | Standard (full recon waves) | 50+ targeted tests |
| **Deep** | Comprehensive (all 37 modules) | All 87+ testers + Nuclei |

---

## 🤖 AI Chatbot Assistant

A context-aware AI assistant powered by OpenRouter LLM (Gemini 2.0 Flash) with function calling capabilities.

### Features

- **36-Entry Knowledge Base** — App features, cybersecurity topics, conversational flows
- **7 Action Tools** — Execute platform actions directly from chat
- **Scan-Aware Context** — Auto-detects scan ID from URL, links conversations to scans
- **Rich Markdown** — Code blocks, tables, lists with syntax highlighting
- **Feedback System** — Thumbs up/down per message for quality tracking
- **Token Tracking** — Per-message token usage monitoring
- **Admin Analytics** — Sessions, messages, satisfaction rate, top topics

### Action Tools

| Tool | Parameters | Action |
|:-----|:-----------|:-------|
| `start_scan` | target, scan_type, depth | Launch a new security scan |
| `get_recent_scans` | count | Retrieve user's recent scan history |
| `get_scan_status` | scan_id | Check live scan progress & phase |
| `export_scan` | scan_id, format | Generate download link (PDF/CSV/JSON/SARIF/HTML) |
| `get_subscription_info` | — | Show plan details & usage limits |
| `get_vulnerability_details` | vuln_id | Full vulnerability data with remediation |
| `navigate_to` | destination | Navigate to dashboard, scans, settings |

---

## 📡 API Reference

**Base URL:** `http://localhost:8000/api/`

**Authentication:** JWT Bearer token (access + refresh tokens)

**Rate Limits:** 30 req/min (anonymous) · 120 req/min (authenticated)

### Authentication (`/api/auth/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/auth/register/` | Create account (email, password, name) | — |
| POST | `/auth/login/` | Login (returns JWT pair) | — |
| POST | `/auth/logout/` | Blacklist refresh token | ✅ |
| GET | `/auth/verify/` | Validate current JWT | ✅ |
| POST | `/auth/refresh/` | Refresh access token | — |
| POST | `/auth/google/` | Google OAuth login | — |
| POST | `/auth/forgot-password/` | Request reset email | — |
| POST | `/auth/reset-password/` | Complete password reset | — |
| POST | `/auth/change-password/` | Change current password | ✅ |

### User (`/api/user/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| GET | `/user/` | Get profile | ✅ |
| PUT | `/user/` | Update profile | ✅ |

### Scanning (`/api/scan/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/scan/website/` | Create new scan | ✅ |
| GET | `/scan/<id>/` | Get scan details | ✅ |
| DELETE | `/scan/<id>/` | Delete scan | ✅ |
| POST | `/scan/<id>/rescan/` | Re-scan target | ✅ |
| GET | `/scan/<id>/stream/` | SSE live progress stream | ✅ |
| GET | `/scan/<id>/findings/` | Paginated vulnerability list | ✅ |
| GET | `/scan/<id>/export/<fmt>/` | Export (pdf/csv/json/sarif/html) | ✅ |
| GET | `/scan/compare/<id1>/<id2>/` | Compare two scans | ✅ |
| POST/GET | `/scan/scheduled/` | Manage scheduled scans | ✅ |
| POST/GET | `/scan/scopes/` | Manage scan scopes | ✅ |
| GET | `/scan/assets/` | Asset inventory | ✅ |
| POST/GET | `/scan/webhooks/` | Manage webhooks | ✅ |
| POST | `/scan/auth-configs/` | Configure authenticated scanning | ✅ |
| GET/POST | `/scan/nuclei-templates/` | Nuclei template management | ✅ |

### AI Chatbot (`/api/chat/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/chat/` | Send message, get AI response | ✅ |
| GET | `/chat/sessions/` | List user chat sessions | ✅ |
| GET | `/chat/sessions/<id>/` | Get session with message history | ✅ |
| GET | `/chat/suggestions/` | Contextual AI suggestions | ✅ |
| GET | `/chat/analytics/` | Chat analytics (admin only) | ✅ 👑 |

### Admin (`/api/admin/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| GET | `/admin/dashboard/` | System-wide statistics | ✅ 👑 |
| GET | `/admin/users/` | List all users | ✅ 👑 |
| GET/PUT | `/admin/users/<id>/` | User detail & management | ✅ 👑 |
| GET | `/admin/scans/` | Scan statistics | ✅ 👑 |
| GET | `/admin/ml/` | ML model stats | ✅ 👑 |
| GET/PUT | `/admin/settings/` | System settings | ✅ 👑 |
| GET | `/admin/contacts/` | Contact submissions | ✅ 👑 |
| GET | `/admin/applications/` | Job applications | ✅ 👑 |

### Learning (`/api/learn/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| GET | `/learn/articles/` | Paginated article list with search/category/tag/difficulty filters | — |
| GET | `/learn/articles/<slug>/` | Article detail | — |
| GET | `/learn/categories/` | Active taxonomy categories | — |
| GET | `/learn/tags/` | Active taxonomy tags | — |

### Other

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/contact/` | Submit contact form | — |
| POST/GET | `/careers/` | Job applications | — |

---

## � Azure Deployment

SafeWeb AI is deployed on **Microsoft Azure** with a full production-grade architecture.

### Azure Resource Group

```
safeweb-ai-rg/
├── safeweb-ai-api          Azure App Service (Linux P1v2)
├── safeweb-ai-frontend     Azure Static Web App
├── safeweb-ai-db           Azure PostgreSQL Flexible Server (v16)
├── safeweb-ai-redis        Azure Cache for Redis
├── safeweb-ai-storage      Azure Blob Storage
├── safeweb-ai-kv           Azure Key Vault
├── safeweb-ai-insights     Application Insights
├── safeweb-ai-log          Log Analytics Workspace
├── safeweb-ai-tools-aci    Azure Container Instances (scanning tools)
└── safeweb-ai-cdn          Azure Front Door + CDN
```

### Backend — Azure App Service

| Setting | Value |
|:--------|:------|
| **Runtime** | Python 3.11 |
| **WSGI** | Gunicorn (4 workers, 120s timeout) |
| **Static Files** | WhiteNoise (compressed manifest) |
| **Auto-scale** | 1–4 instances (CPU > 70% trigger) |
| **Deployment Slots** | `staging` slot for blue/green deploys |
| **Managed Identity** | System-assigned → Key Vault, Blob, PostgreSQL |
| **Health Check** | `/api/health/` (HTTP 200) |

**Startup command:**
```bash
cd backend && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4 --timeout 120
```

### Frontend — Azure Static Web Apps

- **Build**: `npm run build` → `dist/`
- **Routing**: SPA fallback via `staticwebapp.config.json`
- **API Proxy**: Routes `/api/*` to backend App Service
- **CDN**: Global edge distribution with Brotli/gzip compression
- **SSL**: Auto-managed certificate

### Database — Azure PostgreSQL Flexible Server

| Setting | Dev | Production |
|:--------|:----|:-----------|
| **Version** | PostgreSQL 16 | PostgreSQL 16 |
| **SKU** | Burstable B1ms | General Purpose D2s_v3 |
| **Storage** | 32 GB | 32 GB (auto-grow, max 1 TB) |
| **Backup** | 7-day retention | 35-day retention |
| **HA** | — | Zone-redundant |
| **Connection** | SSL enforced | SSL + Private endpoint |

### CI/CD — GitHub Actions

```
Push to main → Lint + Test (pytest) → Build artifacts → Deploy to staging → Smoke tests → Slot swap → Production
```

All infrastructure is defined in **Bicep** templates (`infra/main.bicep`) for reproducible, version-controlled deployments.

### Disaster Recovery

| Metric | Target |
|:-------|:-------|
| **RPO** | 1 hour (PostgreSQL PITR) |
| **RTO** | 15 minutes (slot swap from healthy instance) |
| **Backup** | Daily automated, 35-day retention, geo-redundant storage |

---

## 🗃 Database Design

### Entity-Relationship Overview

```
User (UUID)
  ├── has_many → Scan → has_many → Vulnerability
  ├── has_many → APIKey
  ├── has_many → UserSession
  ├── has_many → ChatSession → has_many → ChatMessage
  ├── has_many → ScheduledScan
  ├── has_many → Webhook → has_many → WebhookDelivery
  └── has_many → ScopeDefinition
```

### Key Tables

| Table | Key Columns | Notes |
|:------|:------------|:------|
| `accounts_user` | UUID PK, email (unique), password, role, plan, 2FA fields, Google OAuth | EMAIL as USERNAME_FIELD |
| `accounts_apikey` | UUID PK, `sk_live_` prefix key, usage_count, last_used | Programmatic API access |
| `accounts_usersession` | UUID PK, jti, ip_address, user_agent | Security session tracking |
| `scanning_scan` | UUID PK, target, status, depth, scope_type, `recon_data` JSONB, `tester_results` JSONB, score, `phase_timings` JSONB, data_version | Core scan record |
| `scanning_vulnerability` | UUID PK, name, severity, CWE, CVSS, affected_url, evidence, `exploit_data` JSONB, false_positive_score | GIN indexes on JSONB |
| `chatbot_chatsession` | UUID PK, user FK, scan FK (nullable), title | Scan-context chats |
| `chatbot_chatmessage` | UUID PK, role, content, tokens_used, feedback, `action_data` JSONB | Token tracking per message |
| `scanning_scheduledscan` | cron_expr, `scan_config` JSONB, next_run, last_run, is_active | Automated recurring scans |
| `scanning_webhook` | url, events JSONB, secret, is_active | Event notifications |
| `scanning_webhookdelivery` | event, payload JSONB, status_code, response_time | Delivery audit trail |
| `admin_panel_systemalert` | title, message, severity, is_resolved | System-wide alerts |
| `learn_article` | title, slug (unique), content, legacy category + status/difficulty/references metadata | Learning center core content |
| `learn_category` | slug, label, parent, depth, sort_order, is_active | Learning center taxonomy hierarchy |
| `learn_tag` | slug, label, tag_type, is_active | Cross-cutting filtering and mapping |

### Learning Center Content Operations

Run these commands from the repository root:

```powershell
# 1) Apply schema updates
"D:/My Files/Graduation Project/safeweb-ai/.venv/Scripts/python.exe" backend/manage.py migrate

# 2) Seed taxonomy data (categories + tags)
"D:/My Files/Graduation Project/safeweb-ai/.venv/Scripts/python.exe" backend/manage.py seed_learning_taxonomy

# 3) Generate draft article payload from outlines
"D:/My Files/Graduation Project/safeweb-ai/.venv/Scripts/python.exe" backend/manage.py generate_article_drafts \
  --outlines backend/apps/learn/data/article_batches/outlines_foundation_batch_a.json \
  --output backend/apps/learn/data/article_batches/generated_foundation_batch_a.json

# 4) Validate article quality gates
"D:/My Files/Graduation Project/safeweb-ai/.venv/Scripts/python.exe" backend/manage.py validate_articles \
  --source backend/apps/learn/data/article_batches/generated_foundation_batch_a.json \
  --strict --min-score 75

# 5) Bulk load validated batch
"D:/My Files/Graduation Project/safeweb-ai/.venv/Scripts/python.exe" backend/manage.py bulk_load_articles \
  --source backend/apps/learn/data/article_batches/generated_foundation_batch_a.json

# 6) Promote workflow state (draft/review/published)
"D:/My Files/Graduation Project/safeweb-ai/.venv/Scripts/python.exe" backend/manage.py publish_articles \
  --slug your-article-slug --status published --touch-reviewed-at --min-quality-score 75
```

### PostgreSQL Optimizations

- **UUID primary keys** — `gen_random_uuid()`, no sequential ID exposure
- **JSONB + GIN indexes** — Fast `@>` queries on `recon_data`, `tester_results`, `exploit_data`
- **Connection pooling** — PgBouncer in transaction mode (20 pool size)
- **Indexing** — B-tree on FKs, composite `(user_id, status)`, hash on `target`
- **Partitioning roadmap** — Monthly range partition on `scanning_scan.created_at` (when > 100K rows)
- **Performance monitoring** — `pg_stat_statements`, autovacuum tuned for heavy-write tables

---

## ⚡ Performance Engineering

### Backend
- **Gunicorn**: `2 × vCPU + 1` workers on P1v2 (2 vCPU)
- **DB optimization**: `select_related()` / `prefetch_related()` on Scan→Vulnerability joins
- **Bulk operations**: `bulk_create()` for vulnerability batch insertion (50–200 per scan)
- **Redis caching**: Completed scan data cached (TTL 1 hour)
- **SSE streaming**: Generator yields progress without blocking workers

### Frontend
- **Code splitting**: Lazy-loaded routes via `React.lazy()` (35 pages)
- **Bundle targets**: < 200 KB initial JS, < 50 KB per lazy chunk
- **Compression**: Brotli + gzip via Azure CDN
- **Cache**: Immutable hashed assets (1-year cache), HTML no-cache

### Monitoring & Alerting

| Metric | Threshold | Action |
|:-------|:----------|:-------|
| HTTP 5xx rate | > 5% (5min) | Alert (email/PagerDuty) |
| P95 response time | > 5 seconds | Warning |
| Celery queue depth | > 50 tasks | Scale workers |
| PostgreSQL connections | > 80% capacity | Investigate |
| CPU (App Service) | > 70% sustained | Auto-scale out |
| Disk (PostgreSQL) | > 80% | Auto-grow or cleanup |

---

## �🖥 Frontend Pages

35 routes across public, authenticated, and admin sections — all lazy loaded with per-page error boundaries.

| Section | Count | Examples |
|:--------|:------|:--------|
| **Public** | 16 | Home, Login, Register, Learn, Documentation, About, Contact, Services, Careers, Legal pages |
| **Auth-Protected** | 10 | Dashboard, ScanWebsite, ScanResults, ScanHistory, Profile, ScheduledScans, ScopeManagement, AssetInventory, WebhookSettings, ScanComparison |
| **Admin** | 7 | AdminDashboard, AdminUsers, AdminScans, AdminML, AdminSettings, AdminContacts, AdminApplications |

---

## 🔧 Security Tools

**62+ integrated external tools** organized by function:

| Category | Tools |
|:---------|:------|
| **Subdomain/DNS** | subfinder, amass, assetfinder, findomain, chaos, dnsx, puredns, massdns, dnsrecon |
| **Port Scan** | nmap, naabu, rustscan, masscan |
| **Web Crawl/Fuzz** | ffuf, feroxbuster, gobuster, dirsearch, katana, gospider, hakrawler |
| **Vuln Scan** | nuclei, sqlmap, ghauri, dalfox, xsstrike, tplmap, commix, crlfuzz, nikto |
| **CMS** | wpscan, joomscan, whatweb, wappalyzer |
| **SSL/TLS** | testssl, sslyze, tlsx |
| **JS/Links** | getjs, linkfinder, secretfinder, gf, qsreplace |
| **URLs** | gau, waybackurls, paramspider, arjun, x8 |
| **Secrets** | trufflehog, gitleaks |
| **Cloud** | cloudenum, s3scanner, awsbucketdump |
| **HTTP** | httpx, httprobe |
| **OOB** | interactsh |

---

## 🗺 Roadmap

### Phase 1 — Platform Hardening
- [ ] Google OAuth complete flow
- [ ] WebSocket upgrade (replace SSE)
- [ ] Professional PDF report redesign with charts
- [ ] Full SMTP email integration (Azure Communication Services)
- [ ] Dark/light theme toggle

### Phase 2 — Scanning Enhancement
- [ ] Distributed scanning workers (ACI auto-scaled)
- [ ] Scan queue management with priority per plan tier
- [ ] Authenticated scanning UI (cookie/bearer/form configs)
- [ ] Custom Nuclei template editor
- [ ] Scan diffing visual timeline
- [ ] Compliance mapping (PCI DSS, SOC 2, ISO 27001)

### Phase 3 — AI & ML Expansion
- [ ] RAG-powered chatbot with scan data retrieval
- [ ] AI-generated code patches for vulnerabilities
- [ ] Smart scan scheduling (ML-predicted optimal frequency)
- [ ] Real-time threat intelligence feed (NVD, ExploitDB)
- [ ] Re-enable phishing URL + malware file scanning

### Phase 4 — Enterprise Features
- [ ] Team workspaces with shared scans and RBAC
- [ ] SSO integration (SAML/OIDC via Azure AD / Okta)
- [ ] Immutable audit logging
- [ ] Plan-based API rate limiting with usage dashboard
- [ ] White-label support for MSSPs

### Phase 5 — Cloud & Infrastructure
- [ ] Kubernetes migration (AKS + Helm)
- [ ] Multi-region deployment (Azure Front Door)
- [ ] Serverless functions for report generation
- [ ] Data Lake analytics (Azure Data Explorer)

### Phase 6 — Community & Ecosystem
- [ ] Public REST API with OpenAPI 3.0 docs + Python/JS SDK
- [ ] Plugin marketplace (community testers/modules)
- [ ] Bug bounty platform integration (HackerOne/Bugcrowd)
- [ ] Slack/Discord bot for scan notifications
- [ ] React Native mobile companion app

---

## 👥 Team

**SafeWeb AI** — University Graduation Project

---

<div align="center">

**Built with ❤️ for cybersecurity**

[![Azure](https://img.shields.io/badge/Deployed_on-Microsoft_Azure-0078D4?style=flat-square&logo=microsoftazure)](https://azure.microsoft.com)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL_16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)

</div>

Built with 🛡️ for web security

**[⬆ Back to Top](#-safeweb-ai)**

</div>
