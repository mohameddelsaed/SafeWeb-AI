# SafeWeb AI — Complete Scanner Documentation

> **Auto-generated comprehensive documentation of every file in the `scanning` application.**
> Covers architecture, models, views, engine core, 37 recon modules, 38 vulnerability testers,
> 12 payload libraries, 3 analyzers, and 9 data files.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Scanning App Core](#2-scanning-app-core)
   - 2.1 [Models](#21-models)
   - 2.2 [Serializers](#22-serializers)
   - 2.3 [Views & API Endpoints](#23-views--api-endpoints)
   - 2.4 [URL Routing](#24-url-routing)
   - 2.5 [Celery Tasks](#25-celery-tasks)
   - 2.6 [Admin Registration](#26-admin-registration)
   - 2.7 [App Configuration](#27-app-configuration)
3. [Engine Core](#3-engine-core)
   - 3.1 [Orchestrator](#31-orchestrator)
   - 3.2 [Web Crawler](#32-web-crawler)
   - 3.3 [Security Scoring](#33-security-scoring)
   - 3.4 [Report Generator](#34-report-generator)
   - 3.5 [Async Engine](#35-async-engine)
   - 3.6 [Async HTTP Client](#36-async-http-client)
   - 3.7 [Rate Limiter](#37-rate-limiter)
4. [Reconnaissance Modules (37 Modules)](#4-reconnaissance-modules)
   - 4.1 [Base & Registry](#41-base--registry)
   - 4.2 [DNS Recon](#42-dns-recon)
   - 4.3 [WHOIS Recon](#43-whois-recon)
   - 4.4 [Certificate Analysis](#44-certificate-analysis)
   - 4.5 [WAF Detection](#45-waf-detection)
   - 4.6 [Port Scanner](#46-port-scanner)
   - 4.7 [Technology Fingerprinting](#47-technology-fingerprinting)
   - 4.8 [Subdomain Enumeration](#48-subdomain-enumeration)
   - 4.9 [Email Enumeration](#49-email-enumeration)
   - 4.10 [Certificate Transparency](#410-certificate-transparency)
   - 4.11 [Content Discovery](#411-content-discovery)
   - 4.12 [Parameter Discovery](#412-parameter-discovery)
   - 4.13 [API Discovery](#413-api-discovery)
   - 4.14 [JavaScript Analyzer](#414-javascript-analyzer)
   - 4.15 [URL Harvester](#415-url-harvester)
   - 4.16 [Cloud Detection](#416-cloud-detection)
   - 4.17 [CORS Analyzer](#417-cors-analyzer)
   - 4.18 [Social Recon](#418-social-recon)
   - 4.19 [CMS Fingerprinting](#419-cms-fingerprinting)
   - 4.20 [AI Recon](#420-ai-recon)
   - 4.21 [Header Analyzer (Recon)](#421-header-analyzer-recon)
   - 4.22 [Cookie Analyzer (Recon)](#422-cookie-analyzer-recon)
   - 4.23 [Subdomain Brute-Force](#423-subdomain-brute-force)
   - 4.24 [Subdomain Permutation](#424-subdomain-permutation)
   - 4.25 [Passive Subdomain Discovery](#425-passive-subdomain-discovery)
   - 4.26 [Wildcard DNS Detector](#426-wildcard-dns-detector)
   - 4.27 [ASN Recon](#427-asn-recon)
   - 4.28 [Cloud Recon (Active)](#428-cloud-recon-active)
   - 4.29 [Network Mapper](#429-network-mapper)
   - 4.30 [Scope Analyzer](#430-scope-analyzer)
   - 4.31 [Attack Surface Mapping](#431-attack-surface-mapping)
   - 4.32 [Threat Intelligence](#432-threat-intelligence)
   - 4.33 [Risk Scorer](#433-risk-scorer)
   - 4.34 [Vulnerability Correlator](#434-vulnerability-correlator)
   - 4.35 [URL Intelligence](#435-url-intelligence)
   - 4.36 [Favicon Hash](#436-favicon-hash)
   - 4.37 [GitHub Recon](#437-github-recon)
   - 4.38 [Google Dorking](#438-google-dorking)
   - 4.39 [Reverse DNS](#439-reverse-dns)
5. [Vulnerability Testers (38 Modules)](#5-vulnerability-testers)
   - 5.1 [Base Tester](#51-base-tester)
   - 5.2 [Tester Registry](#52-tester-registry)
   - 5.3 [XSS Tester](#53-xss-tester)
   - 5.4 [SQL Injection Tester](#54-sql-injection-tester)
   - 5.5 [SSRF Tester](#55-ssrf-tester)
   - 5.6 [SSTI Tester](#56-ssti-tester)
   - 5.7 [Command Injection Tester](#57-command-injection-tester)
   - 5.8 [XXE Tester](#58-xxe-tester)
   - 5.9 [CSRF Tester](#59-csrf-tester)
   - 5.10 [CORS Tester](#510-cors-tester)
   - 5.11 [Authentication Tester](#511-authentication-tester)
   - 5.12 [Access Control Tester](#512-access-control-tester)
   - 5.13 [API Security Tester](#513-api-security-tester)
   - 5.14 [API Discovery Tester](#514-api-discovery-tester)
   - 5.15 [File Upload Tester](#515-file-upload-tester)
   - 5.16 [Deserialization Tester](#516-deserialization-tester)
   - 5.17 [Clickjacking Tester](#517-clickjacking-tester)
   - 5.18 [Cache Poisoning Tester](#518-cache-poisoning-tester)
   - 5.19 [CRLF Injection Tester](#519-crlf-injection-tester)
   - 5.20 [Data Exposure Tester](#520-data-exposure-tester)
   - 5.21 [Business Logic Tester](#521-business-logic-tester)
   - 5.22 [Component Tester](#522-component-tester)
   - 5.23 [Cloud Storage Tester](#523-cloud-storage-tester)
   - 5.24 [Content Discovery Tester](#524-content-discovery-tester)
   - 5.25 [AI Endpoint Tester](#525-ai-endpoint-tester)
   - 5.26 [Misconfiguration Tester](#526-misconfiguration-tester)
   - 5.27 [GraphQL Tester](#527-graphql-tester)
   - 5.28 [Host Header Tester](#528-host-header-tester)
   - 5.29 [HTTP Smuggling Tester](#529-http-smuggling-tester)
   - 5.30 [JWT Tester](#530-jwt-tester)
   - 5.31 [LDAP/XPath Injection Tester](#531-ldapxpath-injection-tester)
   - 5.32 [Logging Tester](#532-logging-tester)
   - 5.33 [NoSQL Injection Tester](#533-nosql-injection-tester)
   - 5.34 [Open Redirect Tester](#534-open-redirect-tester)
   - 5.35 [Prompt Injection Tester](#535-prompt-injection-tester)
   - 5.36 [Prototype Pollution Tester](#536-prototype-pollution-tester)
   - 5.37 [Race Condition Tester](#537-race-condition-tester)
   - 5.38 [Subdomain Takeover Tester](#538-subdomain-takeover-tester)
   - 5.39 [WebSocket Tester](#539-websocket-tester)
6. [Payload Libraries (12 Modules)](#6-payload-libraries)
   - 6.1 [XSS Payloads](#61-xss-payloads)
   - 6.2 [SQL Injection Payloads](#62-sql-injection-payloads)
   - 6.3 [SSRF Payloads](#63-ssrf-payloads)
   - 6.4 [SSTI Payloads](#64-ssti-payloads)
   - 6.5 [Command Injection Payloads](#65-command-injection-payloads)
   - 6.6 [XXE Payloads](#66-xxe-payloads)
   - 6.7 [Path Traversal Payloads](#67-path-traversal-payloads)
   - 6.8 [NoSQL Payloads](#68-nosql-payloads)
   - 6.9 [Prompt Injection Payloads](#69-prompt-injection-payloads)
   - 6.10 [Fuzz Vectors](#610-fuzz-vectors)
   - 6.11 [Default Credentials](#611-default-credentials)
   - 6.12 [Sensitive Paths](#612-sensitive-paths)
7. [Analyzers (3 Modules)](#7-analyzers)
   - 7.1 [Header Analyzer](#71-header-analyzer)
   - 7.2 [SSL Analyzer](#72-ssl-analyzer)
   - 7.3 [Cookie Analyzer](#73-cookie-analyzer)
8. [Data Files (9 Files)](#8-data-files)
9. [Complete File Inventory](#9-complete-file-inventory)
10. [OWASP Coverage Matrix](#10-owasp-coverage-matrix)

---

## 1. Architecture Overview

SafeWeb AI's scanning engine follows a **6-phase pipeline** architecture:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        SCAN ORCHESTRATOR (orchestrator.py)                    │
│                                                                              │
│  Phase 1: RECONNAISSANCE                                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Wave 0a: Network Probes (DNS, WHOIS, Ports, Subdomains, ASN)        │  │
│  │  Wave 0b: Response Analysis (Headers, Cookies, Certs, WAF, Tech)     │  │
│  │  Wave 0c: Cross-Module (Cloud, CMS, AI, CORS, Email, Content)        │  │
│  │  Wave 0d: Analytics (Attack Surface, Threat Intel, Risk Score)       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Phase 2: CRAWLING                                                           │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  BFS Web Crawler + Playwright JS Rendering + Sitemap/Robots Parsing   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Phase 3: ANALYSIS                                                           │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Header Analyzer · SSL Analyzer · Cookie Analyzer                     │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Phase 4: VULNERABILITY TESTING                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  38 Testers × All Crawled Pages (recon-aware, WAF-adaptive, depth-   │  │
│  │  controlled) — XSS, SQLi, SSRF, SSTI, CMDi, XXE, CSRF, JWT, etc.    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Phase 5: CORRELATION                                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  5 Attack Chain Patterns · Vuln Deduplication · CVSS Alignment        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Phase 6: SCORING & REPORTING                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Security Score (0-100) · Letter Grade (A-F) · PDF/CSV/JSON Export   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Depth-Controlled**: All modules respect `shallow` / `medium` / `deep` scan depth
- **WAF-Aware**: Testers adapt payloads and strategies based on detected WAF
- **Tech-Stack Aware**: Payload selection prioritized by detected framework/CMS
- **Async-First**: Recon and testing use bounded-concurrency parallel execution
- **Rate-Limited**: Per-host adaptive token-bucket rate limiting
- **Standardized Output**: All modules produce consistent result dicts via shared helpers

### Directory Structure

```
apps/scanning/
├── __init__.py                  # App package marker
├── admin.py                     # Django admin registration
├── apps.py                      # AppConfig
├── models.py                    # Scan, Vulnerability, ScanReport
├── serializers.py               # DRF serializers
├── views.py                     # API views
├── urls.py                      # URL routing
├── dashboard_urls.py            # Dashboard URL routing
├── list_urls.py                 # List URL routing
├── tasks.py                     # Celery tasks
├── tests.py                     # Placeholder (tests in backend/tests/)
└── engine/
    ├── __init__.py
    ├── orchestrator.py          # Central scan coordinator
    ├── crawler.py               # BFS web crawler
    ├── scoring.py               # CVSS 3.1 + security scoring
    ├── report_generator.py      # PDF/CSV/JSON export
    ├── async_engine.py          # Parallel task execution
    ├── async_http.py            # aiohttp client with pooling
    ├── rate_limiter.py          # Adaptive rate limiter
    ├── recon/                   # 37 reconnaissance modules
    │   ├── __init__.py
    │   ├── _base.py
    │   ├── dns_recon.py
    │   ├── whois_recon.py
    │   ├── ... (35 more)
    │   └── data/                # Wordlists & signatures
    ├── testers/                 # 38 vulnerability testers
    │   ├── __init__.py
    │   ├── base_tester.py
    │   ├── xss_tester.py
    │   ├── ... (36 more)
    ├── payloads/                # 12 payload libraries
    │   ├── __init__.py
    │   ├── xss_payloads.py
    │   ├── ... (11 more)
    └── analyzers/               # 3 response analyzers
        ├── __init__.py
        ├── header_analyzer.py
        ├── ssl_analyzer.py
        └── cookie_analyzer.py
```

---

## 2. Scanning App Core

### 2.1 Models

**File:** `models.py`

#### `Scan` Model
| Field | Type | Description |
|---|---|---|
| `id` | `UUIDField` (PK) | Auto-generated UUID primary key |
| `user` | `ForeignKey(User)` | Owner of the scan |
| `scan_type` | `CharField` | `website`, `file`, or `url` |
| `target` | `URLField` | Target URL |
| `status` | `CharField` | `pending` → `running` → `completed` / `failed` |
| `depth` | `CharField` | `shallow`, `medium`, or `deep` |
| `score` | `IntegerField` | Security score 0–100 (nullable) |
| `recon_data` | `JSONField` | All reconnaissance data |
| `scan_options` | `JSONField` | Custom scan options |
| `ml_result` | `JSONField` | ML analysis results |
| `created_at` | `DateTimeField` | Auto-set on creation |
| `completed_at` | `DateTimeField` | Set on completion |

**Properties:**
- `vulnerability_summary` → Returns `{total, critical, high, medium, low, info}` counts

#### `Vulnerability` Model
| Field | Type | Description |
|---|---|---|
| `scan` | `ForeignKey(Scan)` | Parent scan |
| `name` | `CharField` | Vulnerability name |
| `severity` | `CharField` | `critical`, `high`, `medium`, `low`, `info` |
| `category` | `CharField` | OWASP category |
| `description` | `TextField` | Detailed description |
| `cvss` | `FloatField` | CVSS 3.1 base score |
| `cwe` | `CharField` | CWE identifier |
| `affected_url` | `URLField` | Affected URL |
| `evidence` | `TextField` | Evidence/proof |

#### `ScanReport` Model
| Field | Type | Description |
|---|---|---|
| `scan` | `ForeignKey(Scan)` | Parent scan |
| `format` | `CharField` | `json`, `csv`, or `pdf` |
| `file` | `FileField` | Generated report file |
| `generated_at` | `DateTimeField` | Auto-set |

---

### 2.2 Serializers

**File:** `serializers.py`

| Serializer | Purpose |
|---|---|
| `VulnerabilitySerializer` | Full vulnerability detail serialization |
| `ScanCreateSerializer` | Input: `url`, `depth`, `options` |
| `ScanURLCreateSerializer` | Input: URL-only scan creation |
| `ScanDetailSerializer` | Output: Full scan with vulnerabilities, summary, ML result |
| `ScanListSerializer` | Output: Compact scan list (id, target, status, score, dates) |

---

### 2.3 Views & API Endpoints

**File:** `views.py`

| View | Method | Path | Description |
|---|---|---|---|
| `WebsiteScanCreateView` | `POST` | `/scans/website/` | Create website scan |
| `FileScanCreateView` | `POST` | `/scans/file/` | Create file scan (50MB limit) |
| `URLScanCreateView` | `POST` | `/scans/url/` | Create URL scan |
| `ScanDetailView` | `GET` | `/scans/<uuid>/` | Get scan details |
| `ScanDeleteView` | `DELETE` | `/scans/<uuid>/delete/` | Delete scan |
| `RescanView` | `POST` | `/scans/<uuid>/rescan/` | Clone config, new scan |
| `ScanExportView` | `GET` | `/scans/<uuid>/export/` | Export as JSON/CSV/PDF |
| `ScanListView` | `GET` | `/scans/` | List user's scans (filterable) |
| `DashboardView` | `GET` | `/dashboard/` | Stats + 7-day changes |

---

### 2.4 URL Routing

**Files:** `urls.py`, `dashboard_urls.py`, `list_urls.py`

All URL patterns wire to the views described above with UUID-based scan identification.

---

### 2.5 Celery Tasks

**File:** `tasks.py`

```python
@shared_task(bind=True, max_retries=3)
def execute_scan_task(self, scan_id):
    """Bridges Celery to ScanOrchestrator.execute_scan()"""
```

---

### 2.6 Admin Registration

**File:** `admin.py`

| Admin Class | Model | `list_display` | `list_filter` |
|---|---|---|---|
| `ScanAdmin` | `Scan` | id, user, scan_type, target, status, score, created_at | scan_type, status, depth |
| `VulnerabilityAdmin` | `Vulnerability` | name, severity, category, cvss, scan, created_at | severity, category |
| `ScanReportAdmin` | `ScanReport` | scan, format, generated_at | format |

---

### 2.7 App Configuration

**File:** `apps.py`

```python
class ScanningConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scanning'
    verbose_name = 'Scanning'
```

---

## 3. Engine Core

### 3.1 Orchestrator

**File:** `engine/orchestrator.py`

The central coordinator implementing the 6-phase scan pipeline.

#### Class: `ScanOrchestrator`

**Entry Point:**
```python
def execute_scan(self, scan_id: str) -> dict
```

**Phase Pipeline:**
1. **`_scan_website_async()`** — Main async coordinator
2. **`_run_recon_async()`** — 4-wave parallel reconnaissance
3. **Crawling** — BFS crawl with the `WebCrawler`
4. **Analysis** — Header/SSL/Cookie analyzers
5. **Testing** — All 38 testers per crawled page
6. **`_correlate_vulnerabilities()`** — 5 attack chain patterns
7. **`_calculate_security_score()`** — Final 0–100 score

**4-Wave Recon Architecture:**

| Wave | Name | Modules | Dependencies |
|---|---|---|---|
| Wave 0a | Network Probes | DNS, WHOIS, Ports, Subdomains (passive + brute + permutation), ASN, Wildcard, Reverse DNS | None |
| Wave 0b | Response Analysis | Headers, Cookies, Certs, WAF, Tech Fingerprint, CMS, Social, Favicon Hash | HTTP response |
| Wave 0c | Cross-Module | Cloud Detect, Cloud Recon, AI Recon, CORS, Email, Content Discovery, Param Discovery, API Discovery, JS Analyzer, URL Harvester, URL Intelligence, GitHub Recon, Google Dorking | Wave 0a + 0b data |
| Wave 0d | Analytics | Network Mapper, Scope Analyzer, Attack Surface, Threat Intel, Vuln Correlator, Risk Scorer | All prior waves |

**Configuration:**
- Max concurrency: **15** parallel tasks
- Per-task timeout: **120 seconds**
- Uses `AsyncTaskRunner` for bounded concurrency

**5 Attack Chain Patterns:**
1. Authentication chain vulnerabilities
2. Data exfiltration chains
3. Privilege escalation chains
4. Remote code execution chains
5. Information disclosure chains

---

### 3.2 Web Crawler

**File:** `engine/crawler.py`

#### Class: `WebCrawler`

BFS web crawler with JavaScript rendering support.

**Page Limits by Depth:**
| Depth | Max Pages |
|---|---|
| `shallow` | 10 |
| `medium` | 50 |
| `deep` | 200 |

**Dataclasses:**
- `FormInput` — name, type, value, required
- `Form` — action, method, inputs list
- `Page` — url, status_code, headers, body, forms, links

**Features:**
- Playwright JS rendering for SPAs
- `robots.txt` and `sitemap.xml` parsing
- AI/API endpoint probing (20+ paths)
- URL extraction from JavaScript (7 regex patterns)
- Form parsing with input type detection

---

### 3.3 Security Scoring

**File:** `engine/scoring.py`

**CVSS 3.1 Base Score Calculator:**
Full implementation of the CVSS 3.1 specification with:
- Attack Vector, Attack Complexity, Privileges Required, User Interaction
- Scope, Confidentiality/Integrity/Availability Impact
- ISS (Impact Sub Score) and Impact calculations

**Security Score (0–100):**
- Diminishing returns model — each subsequent vulnerability of the same severity contributes less
- Letter grading: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40

---

### 3.4 Report Generator

**File:** `engine/report_generator.py`

**Export Formats:**
| Format | Library | Features |
|---|---|---|
| JSON | stdlib | Full scan data + vulnerabilities |
| CSV | stdlib | Tabular vulnerability list |
| PDF | `reportlab` | Professional layout with color-coded severity, executive summary, charts |

---

### 3.5 Async Engine

**File:** `engine/async_engine.py`

#### Class: `AsyncTaskRunner`

Bounded-concurrency parallel execution engine.

**Features:**
- Auto-detects async vs sync functions
- Semaphore-based concurrency limiting
- Per-task timeout enforcement
- Critical task failure propagation
- Cancellation support

**Convenience Function:**
```python
async def run_parallel(tasks, max_concurrency=10, timeout=60) -> list[dict]
```

---

### 3.6 Async HTTP Client

**File:** `engine/async_http.py`

#### Class: `AsyncHttpClient`

aiohttp-based HTTP client with:
- Connection pooling (100 total, 10 per host)
- Retries with exponential backoff
- Response caching (LRU)
- User-Agent rotation (5 UAs)
- Rate limiter integration

---

### 3.7 Rate Limiter

**File:** `engine/rate_limiter.py`

#### Class: `RateLimiter`

Per-host adaptive token-bucket rate limiter.

- Thread-safe + asyncio-safe (dual lock)
- Adaptive backoff on 429/5xx responses
- Recovery on 2xx responses
- Configurable tokens per second and burst size

---

## 4. Reconnaissance Modules

All 37 recon modules live in `engine/recon/` and follow a standardized pattern using `_base.py` helpers.

### 4.1 Base & Registry

**Files:** `recon/__init__.py`, `recon/_base.py`

**`__init__.py`** — Package init that imports and re-exports all 37 recon module functions.

**`_base.py`** — Standardized result helpers:

| Function | Returns | Purpose |
|---|---|---|
| `create_result(module_name)` | `dict` | Creates result dict with `findings`, `metadata`, `errors`, `stats` |
| `add_finding(result, title, severity, details)` | — | Appends finding to result |
| `finalize_result(result)` | `dict` | Sets completion time, finding count |
| `extract_hostname(url)` | `str` | URL → hostname |
| `extract_root_domain(url)` | `str` | URL → root domain |

**Standardized Result Format:**
```python
{
    "findings": [...],
    "metadata": {"module": "...", "target": "..."},
    "errors": [...],
    "stats": {"duration": 0.0, "requests": 0},
    # + module-specific legacy keys
}
```

---

### 4.2 DNS Recon

**File:** `recon/dns_recon.py`

**Entry Point:** `run_dns_recon(target_url, depth='medium')`

**Record Types:** A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, BIMI, TLSA

**Features:**
- AXFR zone transfer attempt
- DNSSEC validation
- DMARC record parsing
- SPF record analysis
- CAA record checking

---

### 4.3 WHOIS Recon

**File:** `recon/whois_recon.py`

**Entry Point:** `run_whois_recon(target_url)`

**Features:**
- RDAP (modern) + python-whois (fallback)
- Registrant analysis
- Privacy detection
- Domain expiry checking
- Registrar info extraction

---

### 4.4 Certificate Analysis

**File:** `recon/cert_analysis.py`

**Entry Point:** `run_cert_analysis(target_url, depth='medium')`

**Features:**
- SSL/TLS certificate inspection
- Cipher suite analysis
- Weak protocol detection (SSLv2, SSLv3, TLSv1, TLSv1.1)
- Vulnerability checks: BEAST, POODLE, SWEET32, CRIME, Heartbleed, FREAK, Logjam
- CT (Certificate Transparency) compliance
- **JARM TLS Fingerprinting** — Pure-Python 10-probe implementation with known C2 framework hash database
- **OCSP Stapling Detection** — Raw TLS handshake with `status_request` extension

---

### 4.5 WAF Detection

**File:** `recon/waf_detection.py`

**Entry Point:** `run_waf_detection(target_url, depth='medium')`

**Database:** 112 WAF signatures (from `data/waf_signatures.json`)

**Detection Methods:**
- HTTP header analysis
- Cookie inspection
- Response body patterns
- Error page fingerprinting
- Challenge page detection
- Confidence scoring

---

### 4.6 Port Scanner

**File:** `recon/port_scanner.py`

**Entry Point:** `run_port_scan(target_url, depth='medium')`

**Port Tiers:**

| Depth | Port Count | Description |
|---|---|---|
| `shallow` | 48 | Critical services only |
| `medium` | 148 | Common services |
| `deep` | 1,214 | Extended comprehensive scan |

**Features:**
- TCP SYN scanning with banner grabbing
- Service version detection
- **UDP scanning** with protocol-specific probes (DNS, NTP, SNMP, TFTP)
- Service annotation

---

### 4.7 Technology Fingerprinting

**File:** `recon/tech_fingerprint.py`

**Entry Point:** `run_tech_fingerprint(target_url, response_body, response_headers)`

**Database:** 728 technology signatures (from `data/tech_signatures.json`) across 30 categories

**Detection Signals:**
- HTTP headers
- Meta tags
- Script sources
- Cookies
- HTML body patterns
- JS globals

---

### 4.8 Subdomain Enumeration

**File:** `recon/subdomain_enum.py`

**Entry Point:** `run_subdomain_enum(target_url, depth='medium')`

**Sources:**
- crt.sh (Certificate Transparency)
- HackerTarget API
- DNS brute-force with common-subs wordlist

---

### 4.9 Email Enumeration

**File:** `recon/email_enum.py`

**Entry Point:** `run_email_enum(target_url, depth='medium')`

**Sources (depth-gated):**
- HTML scraping
- DNS MX/TXT records
- WHOIS contact data
- Common format patterns (first.last, f.last, etc.)
- **PGP keyservers** (openpgp.org + pgp.mit.edu)
- **crt.sh certificate emails**
- Format inference

---

### 4.10 Certificate Transparency

**File:** `recon/ct_log_enum.py`

**Entry Point:** `run_ct_log_enum(target_url, depth='medium')`

Enumerates Certificate Transparency logs via crt.sh API to discover subdomains and certificate history.

---

### 4.11 Content Discovery

**File:** `recon/content_discovery.py`

**Entry Point:** `run_content_discovery(target_url, depth='medium')`

**Wordlists:**
- Common: 501 entries (`data/content_wordlist_common.txt`)
- Extended: 2,000+ entries (`data/content_wordlist_extended.txt`)

Path brute-forcing with response analysis and status code interpretation.

---

### 4.12 Parameter Discovery

**File:** `recon/param_discovery.py`

**Entry Point:** `run_param_discovery(target_url, depth='medium')`

**Sources:**
- URL mining
- HTML form extraction
- JavaScript analysis
- Wordlist brute-force (277 parameters from `data/param_wordlist.txt`)

---

### 4.13 API Discovery

**File:** `recon/api_discovery.py`

**Entry Point:** `run_api_discovery(target_url, depth='medium')`

**Features:**
- 302-entry API route wordlist (`data/api_route_wordlist.txt`)
- OpenAPI/Swagger specification detection
- GraphQL introspection
- REST endpoint enumeration

---

### 4.14 JavaScript Analyzer

**File:** `recon/js_analyzer.py`

**Entry Point:** `run_js_analysis(target_url, depth='medium')`

**Features:**
- LinkFinder-style regex patterns for endpoint extraction
- Source map detection
- **80+ secret/credential patterns** (AWS keys, API tokens, private keys, etc.)
- Internal URL extraction

---

### 4.15 URL Harvester

**File:** `recon/url_harvester.py`

**Entry Point:** `run_url_harvester(target_url, depth='medium')`

**4 Passive URL Sources:**
1. Wayback Machine (CDX API)
2. Common Crawl
3. AlienVault OTX
4. URLScan.io

Plus parameter extraction from discovered URLs.

---

### 4.16 Cloud Detection

**File:** `recon/cloud_detect.py`

**Entry Point:** `run_cloud_detect(target_url)`

**Passive detection** of cloud providers (AWS, Azure, GCP, DigitalOcean, Heroku) via:
- HTTP headers
- DNS records
- Response patterns

---

### 4.17 CORS Analyzer

**File:** `recon/cors_analyzer.py`

**Entry Point:** `run_cors_analysis(target_url, depth='medium')`

**Tests:**
- Origin reflection
- Null origin acceptance
- Wildcard CORS
- Subdomain trust
- Credential inclusion

---

### 4.18 Social Recon

**File:** `recon/social_recon.py`

**Entry Point:** `run_social_recon(target_url, response_body='')`

**Pure HTML parsing — no outbound requests.**

| Detection Category | Count |
|---|---|
| Social platforms | 20 (Twitter/X, Facebook, LinkedIn, GitHub, etc.) |
| Linked services | 19 (Slack, Discord, Jira, HubSpot, etc.) |
| Repositories | GitHub repo extraction |
| Schema.org `sameAs` | JSON-LD social link extraction |

---

### 4.19 CMS Fingerprinting

**File:** `recon/cms_fingerprint.py`

**Entry Point:** `run_cms_fingerprint(target_url, response_body, response_headers, make_request_fn)`

**Supported CMS (Deep):** WordPress, Drupal, Joomla + 13 generic CMS indicators

**Features:**
- Version detection
- Plugin/theme enumeration (WordPress)
- Active probe paths (wp-login, wp-json, xmlrpc, etc.)
- CMS-specific security issue detection

---

### 4.20 AI Recon

**File:** `recon/ai_recon.py`

**Entry Point:** `run_ai_recon(target_url, depth='medium')`

**Novel module** extending traditional recon into the AI/ML domain. References OWASP LLM Top 10.

| Category | Count |
|---|---|
| AI API paths probed | ~130 |
| Framework fingerprints | 26 (OpenAI, Ollama, vLLM, LiteLLM, etc.) |
| Chat widget patterns | 8 |
| Safety layer detectors | 5 (Azure Content Safety, NeMo Guardrails, etc.) |

**Covers:** LLM gateways, model serving (TF Serving, TorchServe, Triton), vector databases (Chroma, Weaviate, Qdrant, Pinecone, Milvus), agentic frameworks (Flowise, Dify, AutoGen, LangGraph, Langflow).

---

### 4.21 Header Analyzer (Recon)

**File:** `recon/header_analyzer.py`

**Entry Point:** `run_header_analysis(target_url, response_headers=None)`

**7-Phase Analysis:**
1. Security header presence (11 headers — 6 required, 5 optional)
2. CSP deep parse (directive analysis, nonce/hash detection, unsafe-inline/eval)
3. Cross-origin isolation (COOP + COEP + CORP)
4. Permissions-Policy analysis (12 sensitive features)
5. Dangerous header detection (7 info-leaking headers)
6. HSTS analysis (max-age, includeSubDomains, preload)
7. Score computation (0–100 with letter grade)

---

### 4.22 Cookie Analyzer (Recon)

**File:** `recon/cookie_analyzer.py`

**Entry Point:** `run_cookie_analysis(target_url, cookies, set_cookie_headers)`

**10-Check Per-Cookie Analysis:**
1. Session cookie identification (name-based + heuristic)
2. `__Host-` / `__Secure-` prefix validation
3. Secure flag
4. HttpOnly flag
5. SameSite attribute
6. Domain scope (public suffix supercookie check)
7. Path scope
8. Sensitive data in name
9. Sensitive data in value (SSN, credit card regex)
10. Session fixation indicators + excessive size

**Framework Detection:** 13 known session cookies (PHPSESSID → PHP, JSESSIONID → Java, connect.sid → Express.js, sessionid → Django, etc.)

---

### 4.23 Subdomain Brute-Force

**File:** `recon/subdomain_brute.py`

**Entry Point:** `run_subdomain_brute(target_url, known_subdomains, depth)`

**Permutation-based DNS brute-forcing:**
- 26 common prefixes (dev, staging, test, qa, prod, etc.)
- 19 common suffixes (-dev, -staging, -backup, etc.)
- Number variants (1–5)
- Parallel DNS resolution (20 threads)
- Wildcard DNS detection (>80% same IP)

---

### 4.24 Subdomain Permutation

**File:** `recon/subdomain_permutation.py`

**Entry Point:** `run_subdomain_permutation(domain, known_subdomains, depth, max_permutations)`

**AlterX/dnsgen-style permutation generator** (pure generation — no DNS resolution):
- 62 prefixes across environments, APIs, CDNs, CI/CD, databases, regions
- 25 suffixes
- Numeric increment (±3)
- Word-level cross-product (deep only)

---

### 4.25 Passive Subdomain Discovery

**File:** `recon/passive_subdomain.py`

**Entry Point:** `run_passive_subdomain(target_url, depth='medium')`

**8 Free OSINT Sources (zero traffic to target):**

| Source | Depth Required |
|---|---|
| crt.sh | shallow+ |
| HackerTarget | shallow+ |
| AlienVault OTX | medium+ |
| Cert Spotter | medium+ |
| Anubis DB | medium+ |
| ThreatCrowd | deep |
| URLScan.io | deep |
| RapidDNS | deep |

Concurrent querying via `ThreadPoolExecutor(max_workers=8)`.

---

### 4.26 Wildcard DNS Detector

**File:** `recon/wildcard_detector.py`

**Entry Point:** `run_wildcard_detection(domain, depth, resolver_ips)`

**puredns-style wildcard DNS detection:**
- Generates 5–7 random non-existent subdomains
- Resolves each via `dnspython` (preferred) or `socket`
- Classifies: `ip` (all resolve to same IP), `ip_roundrobin` (all resolve, different IPs), `partial` (N-1 resolve), `none`

---

### 4.27 ASN Recon

**File:** `recon/asn_recon.py`

**Entry Point:** `run_asn_recon(target_url)`

**4 Free Data Sources:**
1. Team Cymru DNS-based ASN lookup
2. BGPView REST API
3. ip-api.com geolocation
4. ASN prefix enumeration

Returns: ASN, organization, CIDR blocks, geolocation.

---

### 4.28 Cloud Recon (Active)

**File:** `recon/cloud_recon.py`

**Entry Point:** `run_cloud_recon(target_url, depth='medium', make_request_fn=None)`

**Active cloud storage enumeration** (distinct from passive `cloud_detect.py`):
- 10 cloud providers (AWS S3, Azure Blob, GCP, DigitalOcean, Wasabi, Linode, etc.)
- 20 prefixes × 58 suffixes candidate generation
- Access level classification: public_list (critical), public_read (high), redirect (medium), exists_no_read (info)
- Caps: 25 (shallow), 80 (medium), 250 (deep)

---

### 4.29 Network Mapper

**File:** `recon/network_mapper.py`

**Entry Point:** `run_network_mapper(target_url, dns_results, subdomain_results, port_results, cert_results)`

**Pure aggregation module — no network requests.**

Builds unified network topology from DNS, subdomain, port, and cert data:
- Host → IP mapping
- Reverse IP → hostname mapping
- CDN detection (22 indicators: Cloudflare, CloudFront, Fastly, Vercel, Google, Azure, AWS)
- Shared hosting detection
- Topology summary

---

### 4.30 Scope Analyzer

**File:** `recon/scope_analyzer.py`

**Entry Point:** `run_scope_analysis(domain, depth, in_scope_domains, ...)`

**Amass-style scope management:**
- Domain wildcard matching
- CIDR range validation
- Third-party detection (~45 known CDN/SaaS/analytics domains)
- Scope expansion recommendations (alt-TLDs, WHOIS registrant)

---

### 4.31 Attack Surface Mapping

**File:** `recon/attack_surface.py`

**Entry Point:** `run_attack_surface(target_url, recon_data=None)`

**Aggregates ALL prior recon findings:**
- Entry point extraction (12 patterns: forms, APIs, GraphQL, WebSocket, file upload, etc.)
- Exposed service enumeration
- Trust boundary identification
- Attack vector derivation
- Surface score (0–100)

---

### 4.32 Threat Intelligence

**File:** `recon/threat_intel.py`

**Entry Point:** `run_threat_intel(target_url, recon_data=None)`

**7 Intelligence Checks:**
1. DGA (Domain Generation Algorithm) detection via Shannon entropy
2. Suspicious TLD check (15 TLDs: .tk, .ml, .ga, etc.)
3. Domain age analysis (WHOIS-based)
4. Phishing keyword matching (18 patterns)
5. IP reputation scoring
6. Cryptominer script detection (14 patterns)
7. WHOIS privacy analysis

---

### 4.33 Risk Scorer

**File:** `recon/risk_scorer.py`

**Entry Point:** `run_risk_scorer(target_url, recon_data=None)`

**Final scoring module** — synthesizes all recon into 5 weighted categories:

| Category | Weight | Checks |
|---|---|---|
| Infrastructure | 0.25 | SSL/TLS, WAF, cloud misconfig |
| Application | 0.25 | Security headers, cookies, CORS, exposed paths |
| Information | 0.15 | Version disclosure, email exposure, JS issues |
| Network | 0.20 | Non-standard ports, DNSSEC, SPF, DMARC, subdomains |
| Compliance | 0.15 | HTTPS, HSTS, CT, Referrer-Policy, Permissions-Policy |

**Output:** Overall score (0–100), grade (A–F), risk level, top 10 risks, prioritized recommendations.

---

### 4.34 Vulnerability Correlator

**File:** `recon/vuln_correlator.py`

**Entry Point:** `run_vuln_correlator(target_url, recon_data=None)`

**Phase 1 — Tech-Version Matching:**
12 known vulnerable technologies (WordPress <6.0, jQuery <3.5, Angular <1.6, Apache <2.4.50, etc.)

**Phase 2 — Dangerous Combinations (10 patterns):**
| Pattern | Severity | Confidence |
|---|---|---|
| Exposed Admin Without WAF | Critical | 0.9 |
| Debug Mode Public Access | Critical | 0.95 |
| Deprecated TLS with Sensitive Cookies | High | 0.85 |
| Missing CSP with Detected Framework | Medium | 0.7 |
| Self-Signed Cert on Public Site | High | 0.9 |
| Version Disclosure with Known Vulns | High | 0.85 |
| Missing HSTS with Login Forms | High | 0.8 |
| Open CORS with Authentication | High | 0.85 |
| Directory Listing with Sensitive Files | High | 0.9 |
| Outdated CMS with Public Plugins | High | 0.8 |

---

### 4.35 URL Intelligence

**File:** `recon/url_intelligence.py`

**Entry Point:** `run_url_intelligence(target_url, depth='medium')`

Mines historical URLs from:
- Wayback Machine (CDX API)
- Common Crawl
- AlienVault OTX

Classifies URLs by 47 interesting extensions and 16 interesting path patterns. Extracts parameter frequency data.

---

### 4.36 Favicon Hash

**File:** `recon/favicon_hash.py`

**Entry Point:** `run_favicon_hash(target_url, depth, make_request_fn, response_body)`

**FavFreak/Shodan-style fingerprinting:**
- Pure-Python MurmurHash3 32-bit implementation
- ~40 known favicon hashes (servers, CMS, security appliances, C2 frameworks, IoT)
- **C2 framework detection** (Cobalt Strike, Metasploit, Sliver) triggers critical alerts
- Generates Shodan dork queries

---

### 4.37 GitHub Recon

**File:** `recon/github_recon.py`

**Entry Point:** `run_github_recon(target_url)`

**Features:**
- `.git` directory exposure check on target (critical)
- GitHub code search with 24 dork templates (credentials, configs, infrastructure, databases)
- Repository discovery via GitHub Search API
- No API key required for basic operations

---

### 4.38 Google Dorking

**File:** `recon/google_dorking.py`

**Entry Point:** `run_google_dorking(target_url, depth='medium', make_request_fn=None)`

**49 dork templates** across 7 categories: subdomain_enum, sensitive_file, admin_panel, param_discovery, info_disclosure, api_discovery, third_party_leak.

**Search engines:** Bing (primary) + DuckDuckGo (fallback). Google intentionally avoided to prevent captcha gating.

---

### 4.39 Reverse DNS

**File:** `recon/reverse_dns.py`

**Entry Point:** `run_reverse_dns(target_url, ip_addresses=None, cidrs=None)`

**Features:**
- PTR record lookups via `socket.gethostbyaddr()`
- HackerTarget reverse-IP API for virtual host discovery
- CIDR expansion (max 256 IPs, /24+ only)
- Concurrent resolution (30 threads)
- Same-org vs related-domain classification

---

## 5. Vulnerability Testers

All 38 testers live in `engine/testers/` and inherit from `BaseTester`.

### 5.1 Base Tester

**File:** `testers/base_tester.py`

#### Class: `BaseTester`

**HTTP Helpers:**
| Method | Description |
|---|---|
| `_make_request(method, url, **kwargs)` | HTTP request with 10s timeout, 0.3s rate limit delay |
| `_build_vuln(name, severity, category, ...)` | Standardized vulnerability dict builder with CVSS auto-alignment |
| `_vuln_signature(tester, name, url)` | MD5 deduplication hash |

**Recon Intelligence Helpers:**
| Method | Returns |
|---|---|
| `_get_waf_info(recon_data)` | WAF detection status, products, confidence |
| `_get_tech_stack(recon_data)` | Detected technologies list |
| `_should_use_waf_bypass(recon_data)` | Boolean: WAF detected? |
| `_has_technology(recon_data, name)` | Boolean: tech present? |
| `_get_ai_info(recon_data)` | AI/LLM endpoint info |
| `_get_cloud_info(recon_data)` | Cloud provider info |
| `_get_cors_info(recon_data)` | CORS configuration |
| `_get_cert_info(recon_data)` | Certificate details |

---

### 5.2 Tester Registry

**File:** `testers/__init__.py`

**`get_all_testers()`** → Returns list of all 38 tester instances organized by phase:

| Phase | Testers |
|---|---|
| Existing (Upgraded) | SQLi, XSS, CSRF, Auth, Misconfig, DataExposure, AccessControl, SSRF, Component, Logging |
| Phase 1 — Core Injection | CMDi, SSTI, XXE |
| Phase 2 — Advanced | Deserialization, HostHeader, HTTPSmuggling, CRLF, JWT |
| Phase 3 — Modern | RaceCondition, WebSocket, GraphQL, FileUpload, NoSQL, CachePoisoning |
| Phase 4 — Infrastructure | CORS, Clickjacking, LDAP/XPath, SubdomainTakeover, CloudStorage |
| Phase 5 — AI/LLM | PromptInjection, AIEndpoint |
| Phase 6 — Missing | PrototypePollution, OpenRedirect, BusinessLogic, API |
| Phase 3 Upgrade | ContentDiscovery, APIDiscovery |

---

### 5.3 XSS Tester

**File:** `testers/xss_tester.py` — OWASP A03:2021

**Class:** `XSSTester` — 250+ payloads across 11 attack categories

| Test | Depth | Severity | CVSS |
|---|---|---|---|
| Reflected XSS (URL params) | all | High | 6.1 |
| Form-based XSS | all | High | 6.1 |
| DOM-based XSS (source/sink) | all | High/Medium | 6.1/5.4 |
| Context-aware XSS | medium+ | High | 6.1 |
| CSP analysis | medium+ | Medium | 5.0–5.8 |
| Stored XSS | deep | Critical | 8.1 |
| Mutation XSS | deep | High | 7.1 |
| CSP bypass | deep | High | 7.1 |
| DOM clobbering | deep | Medium | 5.4 |
| Header-based XSS | deep | High | 6.1 |

---

### 5.4 SQL Injection Tester

**File:** `testers/sqli_tester.py` — OWASP A03:2021

**Class:** `SQLInjectionTester` — Multi-database support (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

| Test | Depth | Severity | CVSS |
|---|---|---|---|
| Error-based SQLi | all | Critical | 9.8 |
| Boolean blind (statistical) | medium+ | High | 8.6 |
| Time-based blind (per-DB) | medium+ | High | 8.6 |
| UNION-based | deep | Critical | 9.8 |
| Stacked queries | deep | Critical/High | 9.8/8.6 |
| Header injection | deep | Critical/High | 9.8/8.6 |
| Second-order SQLi | deep | Critical | 9.8 |

---

### 5.5 SSRF Tester

**File:** `testers/ssrf_tester.py` — OWASP A10:2021

**Class:** `SSRFTester`

| Test | Depth | Severity | CVSS |
|---|---|---|---|
| URL param SSRF | all | High | 7.5 |
| Blind SSRF (timing) | medium+ | High | 6.5 |
| Cloud metadata (AWS/GCP/Azure/DO/Alibaba) | medium+ | Critical | 9.8 |
| AWS IMDSv2 fallback | medium+ | Critical/High | 9.8/8.0 |
| IP bypass (decimal/hex/octal) | deep | High | 7.5 |
| Protocol smuggling (file/gopher/dict) | deep | High | 8.0 |
| Internal port scan | deep | High | 7.5 |
| DNS rebinding | deep | High | 7.5 |
| Header SSRF | deep | High | 7.5 |
| Redirect chain | deep | High | 7.5 |

---

### 5.6 SSTI Tester

**File:** `testers/ssti_tester.py` — OWASP A03:2021

**Class:** `SSTITester` — 9 template engines (Jinja2, Twig, Freemarker, Pebble, Mako, Velocity, Smarty, ERB, Handlebars)

- Math-based probes (`{{7*7}}` → `49`)
- Engine fingerprinting via differential probes
- Tech-stack aware (Flask → Jinja2, Symfony → Twig, Java → Freemarker)
- Severity: **Critical** (CVSS 9.8, CWE-1336)

---

### 5.7 Command Injection Tester

**File:** `testers/cmdi_tester.py` — OWASP A03:2021

**Class:** `CommandInjectionTester` — 70+ payloads

- 26 command-parameter name patterns
- WAF-aware: blind payloads first when WAF detected
- Time-based blind (threshold: 4.0s)
- Severity: **Critical** (CVSS 9.8, CWE-78)

---

### 5.8 XXE Tester

**File:** `testers/xxe_tester.py` — OWASP A05:2021

**Class:** `XXETester`

| Test | Depth | Severity | CVSS |
|---|---|---|---|
| Classic DTD XXE | all | Critical | 9.1 |
| XInclude | medium+ | High | 7.5 |
| SVG file upload XXE | medium+ | High | 7.5 |
| SOAP endpoint XXE | deep | Critical | 9.1 |

---

### 5.9 CSRF Tester

**File:** `testers/csrf_tester.py` — OWASP A01:2021

**Class:** `CSRFTester`

- Missing CSRF token detection (14 known token names)
- Token quality analysis
- Origin/Referer bypass testing
- JSON CSRF
- SameSite cookie analysis

---

### 5.10 CORS Tester

**File:** `testers/cors_tester.py` — OWASP A05:2021

**Class:** `CORSTester`

| Test | Severity | CVSS |
|---|---|---|
| Wildcard + credentials | Critical | 9.1 |
| Reflected origin + credentials | Critical | 9.1 |
| Null origin + credentials | High | 8.1 |
| Subdomain bypass | High | 7.5 |
| Protocol downgrade | Medium | 5.3 |

---

### 5.11 Authentication Tester

**File:** `testers/auth_tester.py` — OWASP A07:2021

**Class:** `AuthTester`

- Default credentials (100+ pairs, depth-gated)
- Brute force protection testing
- Account enumeration
- Session fixation
- Insecure session cookies
- Password policy
- HTTP login detection

---

### 5.12 Access Control Tester

**File:** `testers/access_control_tester.py` — OWASP A01:2021

**Class:** `AccessControlTester`

- IDOR detection
- Path traversal (40+ payloads)
- Forced browsing (200+ sensitive paths)
- HTTP method override
- Privilege escalation
- HTTP verb tampering

---

### 5.13 API Security Tester

**File:** `testers/api_tester.py` — OWASP API Top 10

**Class:** `APITester`

| OWASP API | Test | Severity |
|---|---|---|
| API1 — BOLA | Object-level authorization | High |
| API3 — Mass Assignment | Property-level injection | Critical/High |
| API4 — Unrestricted Resource | Rate limiting | High |
| API5 — BFLA | Function-level auth | Critical |
| API8 — Misconfiguration | Swagger/debug/CORS | Medium/High |
| API9 — Shadow APIs | Deprecated versions | Medium |
| API3 — Excessive Data | Sensitive field exposure | High |

---

### 5.14 API Discovery Tester

**File:** `testers/api_discovery_tester.py`

**Class:** `APIDiscoveryTester`

- OpenAPI/Swagger spec discovery (30 paths)
- API base path enumeration (18 paths)
- REST resource discovery (48 resources)
- Dangerous HTTP method detection
- Rate limiting check

---

### 5.15 File Upload Tester

**File:** `testers/file_upload_tester.py` — OWASP A04:2021

**Class:** `FileUploadTester`

- 13 upload payloads (PHP/JSP/ASPX webshells, SVG/HTML XSS, .htaccess, null-byte)
- Path traversal filenames (`../../../test.php`)
- Oversized upload testing (10MB)
- Client-side vs server-side validation detection

---

### 5.16 Deserialization Tester

**File:** `testers/deserialization_tester.py` — OWASP A08:2021

**Class:** `DeserializationTester`

- Cookie/hidden-field serialization format detection (Java, .NET, PHP, Python pickle)
- Parameter-based payload injection
- ASP.NET ViewState MAC validation check
- 13 error patterns for deserialization detection

---

### 5.17 Clickjacking Tester

**File:** `testers/clickjacking_tester.py` — OWASP A05:2021

**Class:** `ClickjackingTester`

- Missing X-Frame-Options + CSP frame-ancestors
- Deprecated ALLOW-FROM
- Wildcard frame-ancestors
- JavaScript-only frame-busting detection

---

### 5.18 Cache Poisoning Tester

**File:** `testers/cache_poisoning_tester.py` — OWASP A05:2021

**Class:** `CachePoisoningTester`

- Cache detection (Varnish, Cloudflare, Fastly)
- 12 unkeyed header injection tests
- Web cache deception
- Parameter cloaking

---

### 5.19 CRLF Injection Tester

**File:** `testers/crlf_tester.py` — OWASP A03:2021

**Class:** `CRLFInjectionTester`

- 10 CRLF payloads (URL-encoded, raw, Unicode)
- URL parameter testing
- Redirect parameter targeting
- Path-based CRLF injection

---

### 5.20 Data Exposure Tester

**File:** `testers/data_exposure_tester.py` — OWASP A02:2021

**Class:** `DataExposureTester`

- HTTPS enforcement
- Sensitive URL parameters (14 patterns)
- Source code data patterns (8 regex: email, CC, SSN, AWS key, etc.)
- Source map exposure
- Backup file discovery
- Cache header analysis

---

### 5.21 Business Logic Tester

**File:** `testers/business_logic_tester.py`

**Class:** `BusinessLogicTester`

| Test | Severity | CWE |
|---|---|---|
| Negative/zero price manipulation | Critical | CWE-20 |
| Negative quantity | High | CWE-20 |
| Workflow bypass | High | CWE-841 |
| Parameter tampering (role escalation) | Critical | CWE-269 |
| Coupon stacking | Medium | CWE-840 |
| Race conditions | High | CWE-362 |
| Numeric overflow (INT_MAX, 1e308) | Medium/High | CWE-190 |

---

### 5.22 Component Tester

**File:** `testers/component_tester.py` — OWASP A06:2021

**Class:** `ComponentTester`

- 30+ known CVE database (Apache, nginx, jQuery, Angular, React, etc.)
- Server header version detection
- Client-side JS library scanning
- CDN dependency checking (SRI validation)
- CMS fingerprinting
- Deprecated feature detection

---

### 5.23 Cloud Storage Tester

**File:** `testers/cloud_storage_tester.py` — OWASP A05:2021

**Class:** `CloudStorageTester`

- 4 providers: AWS S3, GCS, Azure Blob, DigitalOcean Spaces
- Public listing detection (Critical, CVSS 9.1)
- Write access testing (Critical, CVSS 9.8)
- Bucket name enumeration from domain

---

### 5.24 Content Discovery Tester

**File:** `testers/content_discovery_tester.py` — OWASP A01/A05:2021

**Class:** `ContentDiscoveryTester`

| Category | Path Count | Severity |
|---|---|---|
| Backup files | 14 extensions | High |
| Admin panels | 25 paths | Medium/High |
| Debug endpoints | 22 paths | Critical/High |
| Database dumps | 21 paths | Critical |
| Sensitive files | 40+ paths | Medium/Low |
| Source archives | 6 paths | Critical |

---

### 5.25 AI Endpoint Tester

**File:** `testers/ai_endpoint_tester.py` — OWASP LLM Top 10

**Class:** `AIEndpointTester`

| Test | OWASP LLM | Severity | CVSS |
|---|---|---|---|
| Model theft (exposed /models) | LLM10 | High | 7.5 |
| Insecure output (XSS/SQLi via AI) | LLM02 | High | 7.5–8.0 |
| Sensitive disclosure (PII in responses) | LLM06 | Critical | 9.0 |
| Model DoS (token exhaustion) | LLM04 | Medium | 5.3 |
| Rate limiting | — | Medium | 5.3 |
| Auth enforcement | — | High | 8.0 |

---

### 5.26 Misconfiguration Tester

**File:** `testers/misconfig_tester.py` — OWASP A05:2021

**Class:** `MisconfigTester`

9 checks: security headers, server banners (10 patterns), directory listing, HTTP methods, sensitive paths, verbose errors (19 patterns), CSP analysis, HSTS config, HTML comments.

---

### 5.27 GraphQL Tester

**File:** `testers/graphql_tester.py` — OWASP A01/A03:2021

**Class:** `GraphQLTester`

- Endpoint discovery (10 paths)
- Introspection exposure
- Query depth DoS (7-level bomb)
- Batch query abuse
- Field suggestion info leak
- Verbose error detection
- SQL injection via GraphQL arguments (deep)

---

### 5.28 Host Header Tester

**File:** `testers/host_header_tester.py` — OWASP A05:2021

**Class:** `HostHeaderTester`

- Host header injection
- X-Forwarded-Host / X-Host / X-Forwarded-Server / X-Original-URL
- Duplicate host values
- Absolute URL override

---

### 5.29 HTTP Smuggling Tester

**File:** `testers/http_smuggling_tester.py` — OWASP A05:2021

**Class:** `HTTPSmugglingTester`

| Test | Depth | Severity | CVSS |
|---|---|---|---|
| CL.TE desync | all | Critical | 9.1 |
| TE.CL desync | medium+ | Critical | 9.1 |
| TE.TE obfuscation | deep | High | 8.1 |
| HTTP/2 downgrade (h2c) | deep | Medium | 5.3 |

---

### 5.30 JWT Tester

**File:** `testers/jwt_tester.py` — OWASP A02:2021

**Class:** `JWTTester`

| Test | Depth | Severity | CVSS |
|---|---|---|---|
| Algorithm `none` bypass | all | Critical | 9.8 |
| Weak HMAC secret (20 passwords) | medium+ | Critical | 9.8 |
| Sensitive payload data | all | High | 6.5 |
| Missing expiration | all | Medium | 5.3 |
| JWK injection | deep | High | 8.1 |
| kid path traversal / SQLi | deep | Critical | 9.8 |
| x5u/x5c injection | deep | High | 8.1 |
| RS256→HS256 confusion | medium+ | Critical | 9.8 |
| Token replay | deep | Medium | 5.3 |
| Claim escalation | deep | Medium | 5.3 |

---

### 5.31 LDAP/XPath Injection Tester

**File:** `testers/ldap_xpath_tester.py` — OWASP A03:2021

**Class:** `LDAPXPathTester`

- 12 LDAP injection payloads + 15 error patterns
- 11 XPath injection payloads + 16 error patterns
- Form-based and URL parameter injection
- Boolean-based blind XPath (response size ratio)

---

### 5.32 Logging Tester

**File:** `testers/logging_tester.py` — OWASP A09:2021

**Class:** `LoggingTester`

- Error verbosity (12 verbose error indicators)
- CRLF-based log injection
- Missing security reporting headers (Report-To, NEL, CSP report-uri)
- Soft 404 detection

---

### 5.33 NoSQL Injection Tester

**File:** `testers/nosql_tester.py` — OWASP A03:2021

**Class:** `NoSQLInjectionTester`

- MongoDB operator injection (`$ne`, `$gt`, `$regex`, `$exists`)
- URL parameter injection
- JSON body injection on API endpoints
- Authentication bypass via NoSQL operators
- Severity: **Critical** (CVSS 9.8, CWE-943)

---

### 5.34 Open Redirect Tester

**File:** `testers/open_redirect_tester.py`

**Class:** `OpenRedirectTester`

- 35 redirect parameter names
- 24 bypass payloads (protocol-relative, backslash, @-trick, data: URI, double encoding)
- Path-based redirects
- Header-based redirects
- Post-authentication redirect abuse
- JavaScript/data URI reflection

---

### 5.35 Prompt Injection Tester

**File:** `testers/prompt_injection_tester.py` — OWASP LLM01

**Class:** `PromptInjectionTester`

- Direct injection via OpenAI-compatible and simple JSON formats
- Form-based chat interface injection
- URL parameter injection for AI endpoints
- Indirect injection via user-controllable content fields
- System prompt extraction detection
- Tool/function abuse detection
- 129+ payloads from `prompt_injection_payloads`

---

### 5.36 Prototype Pollution Tester

**File:** `testers/prototype_pollution_tester.py`

**Class:** `PrototypePollutionTester`

- 11 server-side `__proto__`/`constructor.prototype` payloads
- Express/EJS/Pug RCE gadget detection
- 8 client-side query parameter payloads
- 13 susceptible JS pattern detectors
- Dot-path parameter traversal
- Tech-stack aware severity (Node.js → Critical)

---

### 5.37 Race Condition Tester

**File:** `testers/race_condition_tester.py` — OWASP A04:2021

**Class:** `RaceConditionTester`

- 26 race-sensitive keywords
- 10 concurrent POST requests via ThreadPoolExecutor
- ≥80% success ratio = vulnerability
- Rate limit bypass testing (sequential 429 → concurrent bypass)

---

### 5.38 Subdomain Takeover Tester

**File:** `testers/subdomain_takeover_tester.py` — OWASP A05:2021

**Class:** `SubdomainTakeoverTester`

**15 Service Fingerprint Definitions:**
GitHub, Heroku, AWS S3, AWS CloudFront, Azure (9 CNAME patterns), Shopify, Fastly, Pantheon, Netlify, Zendesk, WordPress, Surge, Bitbucket, Ghost, Tumblr

- CNAME pattern matching
- Response body fingerprinting
- Linked subdomain extraction and verification
- DNS dangling detection (NXDOMAIN)

---

### 5.39 WebSocket Tester

**File:** `testers/websocket_tester.py` — OWASP A03:2021

**Class:** `WebSocketTester`

- Endpoint discovery (3 regex patterns in page source)
- Insecure `ws://` protocol detection
- Cross-Site WebSocket Hijacking (CSWSH)
- Origin header validation bypass
- Uses `websocket-client` library for actual WS handshake

---

## 6. Payload Libraries

All payload modules live in `engine/payloads/` and provide depth-gated access functions.

### 6.1 XSS Payloads

**File:** `payloads/xss_payloads.py` — **~149 payloads + 45 regex patterns**

| Category | Count | Description |
|---|---|---|
| `BASIC_REFLECTED` | 18 | `<script>`, `<img>`, `<svg>`, `<iframe>` |
| `EVENT_HANDLERS` | 30 | onerror, onload, onfocus, onclick, etc. |
| `TAG_INJECTION` | 11 | Break out of HTML tags |
| `ATTRIBUTE_INJECTION` | 10 | Break out of attributes |
| `JS_CONTEXT` | 11 | Break out of JS strings |
| `URL_CONTEXT` | 8 | javascript:, data: URIs |
| `POLYGLOTS` | 8 | Multi-context payloads |
| `TEMPLATE_INJECTION` | 8 | SSTI probes via XSS |
| `FILTER_BYPASS` | 25 | Encoding, case variation, null bytes |
| `DOM_SOURCES` | 20 | DOM XSS source patterns (regex) |
| `DOM_SINKS` | 25 | DOM XSS sink patterns (regex) |
| `MUTATION_XSS` | 12 | Browser parser quirks |
| `CSP_BYPASS` | 11 | AngularJS gadgets, JSONP, base |
| `DOM_CLOBBERING` | 5 | Property override via elements |

**Depth Access:** `shallow` (8) → `medium` (~40) → `deep` (all ~149)

---

### 6.2 SQL Injection Payloads

**File:** `payloads/sqli_payloads.py` — **~155 payloads + 30 error patterns + 8 WAF signatures**

| Category | Count | Targets |
|---|---|---|
| `ERROR_BASED` | 29 | Generic |
| `MYSQL_ERROR` | 7 | EXTRACTVALUE, UPDATEXML |
| `POSTGRESQL_ERROR` | 6 | CAST, CURRENT_USER |
| `MSSQL_ERROR` | 6 | CONVERT, xp_cmdshell |
| `ORACLE_ERROR` | 4 | UTL_INADDR, XMLType |
| `SQLITE_ERROR` | 4 | sqlite_version() |
| `UNION_BASED` | 15 | 1–8 column NULL enumeration |
| `BOOLEAN_BLIND` | 14 | AND 1=1/1=2, SUBSTRING |
| `TIME_BLIND_*` | 20 | MySQL/MSSQL/PostgreSQL/Oracle SLEEP |
| `WAF_BYPASS` | 20 | Case toggling, comments, encoding |
| `STACKED_QUERIES` | 12 | Multi-statement |
| `SECOND_ORDER` | 8 | Stored payloads |
| `NOSQL_INJECTION` | 10 | MongoDB operators |

**Depth Access:** `shallow` (10) → `medium` (~56) → `deep` (all ~155)

---

### 6.3 SSRF Payloads

**File:** `payloads/ssrf_payloads.py` — **~77 payloads + 42 param names + 33 indicators**

| Category | Count |
|---|---|
| `BASIC_INTERNAL` | 7 |
| `IP_BYPASS` | 26 |
| `AWS_METADATA` | 6 |
| `GCP_METADATA` | 4 |
| `AZURE_METADATA` | 2 |
| `DIGITALOCEAN_METADATA` | 2 |
| `ALIBABA_METADATA` | 2 |
| `PROTOCOL_SMUGGLING` | 11 |
| `INTERNAL_PORTS` | 17 |

---

### 6.4 SSTI Payloads

**File:** `payloads/ssti_payloads.py` — **~65 payloads + 6 engine indicator dicts**

Covers 10 engines: Jinja2 (14), Twig (10), Freemarker (9), Pebble (4), Mako (4), Velocity (4), Smarty (4), ERB (4), Handlebars (1), Generic (11).

---

### 6.5 Command Injection Payloads

**File:** `payloads/cmdi_payloads.py` — **~91 payloads + 14 output patterns**

| Category | Count |
|---|---|
| `BASH_PAYLOADS` | 25 |
| `WINDOWS_PAYLOADS` | 15 |
| `BLIND_PAYLOADS` | 13 |
| `FILTER_BYPASS` | 24 |
| `OOB_PAYLOADS` | 6 |
| `INFO_PAYLOADS` | 8 |

---

### 6.6 XXE Payloads

**File:** `payloads/xxe_payloads.py` — **~20 payloads + 14 success patterns**

Categories: CLASSIC_XXE (6), BLIND_OOB (2), PARAMETER_ENTITY (2), SSRF_VIA_XXE (5), BILLION_LAUGHS_SAFE (1), XINCLUDE (2), SVG_XXE (1), SOAP_XXE (1).

---

### 6.7 Path Traversal Payloads

**File:** `payloads/traversal_payloads.py` — **~41 payloads + 24 param names + 18 targets**

Categories: BASIC_UNIX (10), BASIC_WINDOWS (7), URL_ENCODED (5), DOUBLE_ENCODED (3), NULL_BYTE (6), UNICODE_BYPASS (4), NORMALIZATION_BYPASS (6).

---

### 6.8 NoSQL Payloads

**File:** `payloads/nosql_payloads.py` — **~36 payloads + 14 error patterns**

Categories: MONGO_OPERATORS (12), URL_PARAM_INJECTION (7), JSON_INJECTION (7), JS_INJECTION (10).

---

### 6.9 Prompt Injection Payloads

**File:** `payloads/prompt_injection_payloads.py` — **~129 payloads + 45 indicators** (OWASP LLM01)

| Category | Count |
|---|---|
| `DIRECT_INJECTION` | 30 |
| `INDIRECT_INJECTION` | 20 |
| `JAILBREAK_PROMPTS` | 15 |
| `ENCODING_BYPASS` | 15 |
| `DATA_EXFILTRATION` | 15 |
| `TOOL_ABUSE` | 10 |
| `MULTI_LANGUAGE` | 10 |
| `OUTPUT_MANIPULATION` | 10 |
| `CONTEXT_OVERFLOW` | 4 |

---

### 6.10 Fuzz Vectors

**File:** `payloads/fuzz_vectors.py` — **~105 vectors**

Categories: BOUNDARY_VALUES (26), SPECIAL_CHARS (37), LONG_STRINGS (9), FORMAT_STRINGS (18), ENCODING_EDGE_CASES (11), CRLF_VECTORS (8).

---

### 6.11 Default Credentials

**File:** `payloads/default_credentials.py` — **~95 raw / ~70–80 deduplicated pairs**

| Category | Count |
|---|---|
| Generic Admin | 20 |
| CMS Defaults | 10 |
| Database Defaults | 17 |
| Network Defaults | 15 |
| Server Defaults | 17 |
| IoT Defaults | 10 |
| Cloud Defaults | 6 |

---

### 6.12 Sensitive Paths

**File:** `payloads/sensitive_paths.py` — **~200 unique paths**

| Category | Count |
|---|---|
| VCS Paths | 11 |
| Config Paths | 42 |
| Admin Paths | 30 |
| Debug Paths | 38 |
| API Doc Paths | 27 |
| Backup Paths | 21 |
| Cloud Paths | 13 |
| Sensitive Data Paths | 18 |

**Depth Access:** `shallow` (19) → `medium` (~66) → `deep` (all ~200)

---

## 7. Analyzers

Three lightweight analyzers in `engine/analyzers/` used during Phase 3 of the scan pipeline.

### 7.1 Header Analyzer

**File:** `analyzers/header_analyzer.py`

**Class:** `HeaderAnalyzer`

Checks 6 required security headers + 4 information disclosure headers:

| Header | Severity | CVSS | CWE |
|---|---|---|---|
| Strict-Transport-Security | High | 7.4 | CWE-319 |
| Content-Security-Policy | Medium | 5.4 | CWE-79 |
| X-Frame-Options | Medium | 4.3 | CWE-1021 |
| X-Content-Type-Options | Low | 3.1 | CWE-16 |
| Referrer-Policy | Low | 3.1 | CWE-200 |
| Permissions-Policy | Low | 2.6 | CWE-16 |

---

### 7.2 SSL Analyzer

**File:** `analyzers/ssl_analyzer.py`

**Class:** `SSLAnalyzer`

4 checks:
1. HTTPS enforcement (High, CVSS 7.5)
2. Protocol version — weak: SSLv2, SSLv3, TLSv1, TLSv1.1 (High, CVSS 7.4)
3. Cipher strength — weak: RC4, DES, 3DES, NULL, EXPORT, anon (Medium, CVSS 5.9)
4. Certificate validity — expired (Critical, CVSS 9.1) or verification failure (High, CVSS 7.4)

---

### 7.3 Cookie Analyzer

**File:** `analyzers/cookie_analyzer.py`

**Class:** `CookieAnalyzer`

Per-cookie checks: `Secure` flag, `HttpOnly` flag, `SameSite` attribute.
Severity: Medium (missing Secure) or Low (missing HttpOnly/SameSite). CWE-614.

---

## 8. Data Files

All data files live in `engine/recon/data/`.

| File | Entries | Purpose |
|---|---|---|
| `api_route_wordlist.txt` | 311 | API endpoint discovery paths |
| `content_wordlist_common.txt` | 554 | Common hidden file/directory paths |
| `content_wordlist_extended.txt` | 1,223 | Extended content discovery paths |
| `param_wordlist.txt` | 285 | Common HTTP parameter names |
| `subdomain_wordlist_100.txt` | 100 | Top 100 subdomains (shallow scans) |
| `subdomain_wordlist_1000.txt` | 984 | Top 1,000 subdomains (medium scans) |
| `subdomain_wordlist_10000.txt` | 10,000 | Large subdomain list (deep scans) |
| `tech_signatures.json` | 728 | Technology fingerprinting signatures (30 categories) |
| `waf_signatures.json` | 108 | WAF detection signatures with bypass hints |

---

## 9. Complete File Inventory

### Top-Level App Files (7 files)
| File | Lines | Purpose |
|---|---|---|
| `__init__.py` | 1 | Package marker with `default_app_config` |
| `admin.py` | 24 | Django admin registration (3 models) |
| `apps.py` | 7 | `ScanningConfig` AppConfig |
| `models.py` | ~100 | Scan, Vulnerability, ScanReport models |
| `serializers.py` | ~80 | DRF serializers |
| `views.py` | ~200 | 9 API views |
| `tasks.py` | ~30 | Celery scan execution task |

### URL Files (3 files)
| File | Purpose |
|---|---|
| `urls.py` | Main scanning URL patterns |
| `dashboard_urls.py` | Dashboard URL patterns |
| `list_urls.py` | Scan list URL patterns |

### Engine Core (7 files)
| File | Primary Class/Function |
|---|---|
| `engine/__init__.py` | Empty package marker |
| `engine/orchestrator.py` | `ScanOrchestrator` |
| `engine/crawler.py` | `WebCrawler` |
| `engine/scoring.py` | CVSS 3.1 calculator + security scorer |
| `engine/report_generator.py` | JSON/CSV/PDF export |
| `engine/async_engine.py` | `AsyncTaskRunner` |
| `engine/async_http.py` | `AsyncHttpClient` |
| `engine/rate_limiter.py` | `RateLimiter` |

### Recon Modules (37 files + 1 init + 1 base = 39 files)
| # | File | Entry Point |
|---|---|---|
| 1 | `recon/__init__.py` | Package registry |
| 2 | `recon/_base.py` | `create_result()`, `add_finding()`, `finalize_result()` |
| 3 | `recon/dns_recon.py` | `run_dns_recon()` |
| 4 | `recon/whois_recon.py` | `run_whois_recon()` |
| 5 | `recon/cert_analysis.py` | `run_cert_analysis()` |
| 6 | `recon/waf_detection.py` | `run_waf_detection()` |
| 7 | `recon/port_scanner.py` | `run_port_scan()` |
| 8 | `recon/tech_fingerprint.py` | `run_tech_fingerprint()` |
| 9 | `recon/subdomain_enum.py` | `run_subdomain_enum()` |
| 10 | `recon/email_enum.py` | `run_email_enum()` |
| 11 | `recon/ct_log_enum.py` | `run_ct_log_enum()` |
| 12 | `recon/content_discovery.py` | `run_content_discovery()` |
| 13 | `recon/param_discovery.py` | `run_param_discovery()` |
| 14 | `recon/api_discovery.py` | `run_api_discovery()` |
| 15 | `recon/js_analyzer.py` | `run_js_analysis()` |
| 16 | `recon/url_harvester.py` | `run_url_harvester()` |
| 17 | `recon/cloud_detect.py` | `run_cloud_detect()` |
| 18 | `recon/cors_analyzer.py` | `run_cors_analysis()` |
| 19 | `recon/social_recon.py` | `run_social_recon()` |
| 20 | `recon/cms_fingerprint.py` | `run_cms_fingerprint()` |
| 21 | `recon/ai_recon.py` | `run_ai_recon()` |
| 22 | `recon/header_analyzer.py` | `run_header_analysis()` |
| 23 | `recon/cookie_analyzer.py` | `run_cookie_analysis()` |
| 24 | `recon/subdomain_brute.py` | `run_subdomain_brute()` |
| 25 | `recon/subdomain_permutation.py` | `run_subdomain_permutation()` |
| 26 | `recon/passive_subdomain.py` | `run_passive_subdomain()` |
| 27 | `recon/wildcard_detector.py` | `run_wildcard_detection()` |
| 28 | `recon/asn_recon.py` | `run_asn_recon()` |
| 29 | `recon/cloud_recon.py` | `run_cloud_recon()` |
| 30 | `recon/network_mapper.py` | `run_network_mapper()` |
| 31 | `recon/scope_analyzer.py` | `run_scope_analysis()` |
| 32 | `recon/attack_surface.py` | `run_attack_surface()` |
| 33 | `recon/threat_intel.py` | `run_threat_intel()` |
| 34 | `recon/risk_scorer.py` | `run_risk_scorer()` |
| 35 | `recon/vuln_correlator.py` | `run_vuln_correlator()` |
| 36 | `recon/url_intelligence.py` | `run_url_intelligence()` |
| 37 | `recon/favicon_hash.py` | `run_favicon_hash()` |
| 38 | `recon/github_recon.py` | `run_github_recon()` |
| 39 | `recon/google_dorking.py` | `run_google_dorking()` |
| 40 | `recon/reverse_dns.py` | `run_reverse_dns()` |

### Tester Modules (38 files + 1 init + 1 base = 40 files)
| # | File | Class | OWASP |
|---|---|---|---|
| 1 | `testers/__init__.py` | Registry + `get_all_testers()` | — |
| 2 | `testers/base_tester.py` | `BaseTester` | — |
| 3 | `testers/xss_tester.py` | `XSSTester` | A03 |
| 4 | `testers/sqli_tester.py` | `SQLInjectionTester` | A03 |
| 5 | `testers/ssrf_tester.py` | `SSRFTester` | A10 |
| 6 | `testers/ssti_tester.py` | `SSTITester` | A03 |
| 7 | `testers/cmdi_tester.py` | `CommandInjectionTester` | A03 |
| 8 | `testers/xxe_tester.py` | `XXETester` | A05 |
| 9 | `testers/csrf_tester.py` | `CSRFTester` | A01 |
| 10 | `testers/cors_tester.py` | `CORSTester` | A05 |
| 11 | `testers/auth_tester.py` | `AuthTester` | A07 |
| 12 | `testers/access_control_tester.py` | `AccessControlTester` | A01 |
| 13 | `testers/api_tester.py` | `APITester` | API Top 10 |
| 14 | `testers/api_discovery_tester.py` | `APIDiscoveryTester` | A01 |
| 15 | `testers/file_upload_tester.py` | `FileUploadTester` | A04 |
| 16 | `testers/deserialization_tester.py` | `DeserializationTester` | A08 |
| 17 | `testers/clickjacking_tester.py` | `ClickjackingTester` | A05 |
| 18 | `testers/cache_poisoning_tester.py` | `CachePoisoningTester` | A05 |
| 19 | `testers/crlf_tester.py` | `CRLFInjectionTester` | A03 |
| 20 | `testers/data_exposure_tester.py` | `DataExposureTester` | A02 |
| 21 | `testers/business_logic_tester.py` | `BusinessLogicTester` | A04 |
| 22 | `testers/component_tester.py` | `ComponentTester` | A06 |
| 23 | `testers/cloud_storage_tester.py` | `CloudStorageTester` | A05 |
| 24 | `testers/content_discovery_tester.py` | `ContentDiscoveryTester` | A01/A05 |
| 25 | `testers/ai_endpoint_tester.py` | `AIEndpointTester` | LLM Top 10 |
| 26 | `testers/misconfig_tester.py` | `MisconfigTester` | A05 |
| 27 | `testers/graphql_tester.py` | `GraphQLTester` | A01/A03 |
| 28 | `testers/host_header_tester.py` | `HostHeaderTester` | A05 |
| 29 | `testers/http_smuggling_tester.py` | `HTTPSmugglingTester` | A05 |
| 30 | `testers/jwt_tester.py` | `JWTTester` | A02 |
| 31 | `testers/ldap_xpath_tester.py` | `LDAPXPathTester` | A03 |
| 32 | `testers/logging_tester.py` | `LoggingTester` | A09 |
| 33 | `testers/nosql_tester.py` | `NoSQLInjectionTester` | A03 |
| 34 | `testers/open_redirect_tester.py` | `OpenRedirectTester` | A01 |
| 35 | `testers/prompt_injection_tester.py` | `PromptInjectionTester` | LLM01 |
| 36 | `testers/prototype_pollution_tester.py` | `PrototypePollutionTester` | A03 |
| 37 | `testers/race_condition_tester.py` | `RaceConditionTester` | A04 |
| 38 | `testers/subdomain_takeover_tester.py` | `SubdomainTakeoverTester` | A05 |
| 39 | `testers/websocket_tester.py` | `WebSocketTester` | A03 |

### Payload Modules (12 files + 1 init = 13 files)
| File | Payload Count |
|---|---|
| `payloads/__init__.py` | — |
| `payloads/xss_payloads.py` | ~149 |
| `payloads/sqli_payloads.py` | ~155 |
| `payloads/ssrf_payloads.py` | ~77 |
| `payloads/ssti_payloads.py` | ~65 |
| `payloads/cmdi_payloads.py` | ~91 |
| `payloads/xxe_payloads.py` | ~20 |
| `payloads/traversal_payloads.py` | ~41 |
| `payloads/nosql_payloads.py` | ~36 |
| `payloads/prompt_injection_payloads.py` | ~129 |
| `payloads/fuzz_vectors.py` | ~105 |
| `payloads/default_credentials.py` | ~95 |
| `payloads/sensitive_paths.py` | ~200 |

### Analyzer Modules (3 files + 1 init = 4 files)
| File | Class |
|---|---|
| `analyzers/__init__.py` | — |
| `analyzers/header_analyzer.py` | `HeaderAnalyzer` |
| `analyzers/ssl_analyzer.py` | `SSLAnalyzer` |
| `analyzers/cookie_analyzer.py` | `CookieAnalyzer` |

### Data Files (9 files)
| File | Entries |
|---|---|
| `recon/data/api_route_wordlist.txt` | 311 |
| `recon/data/content_wordlist_common.txt` | 554 |
| `recon/data/content_wordlist_extended.txt` | 1,223 |
| `recon/data/param_wordlist.txt` | 285 |
| `recon/data/subdomain_wordlist_100.txt` | 100 |
| `recon/data/subdomain_wordlist_1000.txt` | 984 |
| `recon/data/subdomain_wordlist_10000.txt` | 10,000 |
| `recon/data/tech_signatures.json` | 728 signatures |
| `recon/data/waf_signatures.json` | 108 signatures |

**Total Files:** ~113 Python files + 9 data files = **~122 files**

---

## 10. OWASP Coverage Matrix

### OWASP Top 10 (2021)

| OWASP ID | Category | Testers | CWEs Covered |
|---|---|---|---|
| A01 | Broken Access Control | AccessControl, CSRF, OpenRedirect, APIDiscovery, ContentDiscovery | CWE-22, CWE-269, CWE-352, CWE-425, CWE-601, CWE-639, CWE-650 |
| A02 | Cryptographic Failures | DataExposure, JWT, Deserialization | CWE-200, CWE-295, CWE-319, CWE-326, CWE-327, CWE-345, CWE-502, CWE-598 |
| A03 | Injection | XSS, SQLi, SSTI, CMDi, CRLF, NoSQL, LDAP/XPath, GraphQL, WebSocket, PrototypePollution | CWE-77, CWE-78, CWE-79, CWE-89, CWE-90, CWE-113, CWE-643, CWE-943, CWE-1321, CWE-1336 |
| A04 | Insecure Design | FileUpload, BusinessLogic, RaceCondition | CWE-20, CWE-190, CWE-362, CWE-434, CWE-770, CWE-840, CWE-841 |
| A05 | Security Misconfiguration | XXE, CORS, Clickjacking, CachePoisoning, Misconfig, CloudStorage, SubdomainTakeover, HostHeader, HTTPSmuggling | CWE-284, CWE-444, CWE-525, CWE-548, CWE-611, CWE-693, CWE-749, CWE-942, CWE-1021 |
| A06 | Vulnerable Components | Component | CWE-200, CWE-477, CWE-1104 |
| A07 | Auth Failures | Auth | CWE-204, CWE-307, CWE-319, CWE-384, CWE-521, CWE-522, CWE-614, CWE-798 |
| A08 | Software Integrity | Deserialization | CWE-502 |
| A09 | Logging Failures | Logging | CWE-117, CWE-209, CWE-756, CWE-778 |
| A10 | SSRF | SSRF | CWE-918 |

### OWASP API Security Top 10 (2023)

| API ID | Category | Tester |
|---|---|---|
| API1 | BOLA | APITester |
| API3 | Broken Property Level Auth | APITester (mass assignment + excessive data) |
| API4 | Unrestricted Resource Consumption | APITester |
| API5 | BFLA | APITester |
| API8 | Security Misconfiguration | APITester + APIDiscoveryTester |
| API9 | Improper Inventory Management | APITester (shadow APIs) |

### OWASP LLM Top 10

| LLM ID | Category | Tester |
|---|---|---|
| LLM01 | Prompt Injection | PromptInjectionTester |
| LLM02 | Insecure Output Handling | AIEndpointTester |
| LLM04 | Model DoS | AIEndpointTester |
| LLM06 | Sensitive Information Disclosure | AIEndpointTester |
| LLM10 | Model Theft | AIEndpointTester |

---

### Statistics Summary

| Metric | Count |
|---|---|
| Total Python files | ~113 |
| Total data files | 9 |
| Recon modules | 37 |
| Vulnerability testers | 38 |
| Payload libraries | 12 |
| Analyzers | 3 |
| Total unique payloads | ~1,163 |
| Tech signatures | 728 |
| WAF signatures | 108 |
| Default credential pairs | ~95 |
| Sensitive paths | ~200 |
| CWE IDs covered | 50+ |
| OWASP Top 10 coverage | 10/10 |
| OWASP API Top 10 coverage | 6/10 |
| OWASP LLM Top 10 coverage | 5/10 |
