# SafeWeb AI Testing Framework Overview

## Purpose
This framework defines the absolute standards, hierarchies, and prompts required to automatically validate the correctness, security, multi-tenancy isolation, and performance of SafeWeb AI.

## Architecture & Toolchain
- **Backend (Python/Django):** `pytest`, `pytest-django`, `pytest-cov`, `responses` (for API mocking).
- **Frontend (React/Vite):** `Vitest`, `React Testing Library`.
- **End-to-End (E2E):** `Playwright`.
- **Performance/Load:** `Locust`.
- **Security:** `Bandit` (SAST), `OWASP ZAP` (DAST pipeline integration).

## File Hierarchy
```
safeweb-ai-test-framework/
├── 00-MASTER-TESTING-PROMPT.md        # The prompt to kick off the AI QA agent
├── 00-TESTING-FRAMEWORK-OVERVIEW.md   # This file
├── 01-unit-test-suite.md              # Unit test definitions
├── 02-integration-test-suite.md       # API & Endpoints
├── 03-e2e-test-suite.md               # Browser automation
├── 04-security-test-suite.md          # Platform self-security
├── 05-performance-test-suite.md       # Load testing
├── 06-tenant-isolation-test-suite.md  # Multi-tenant data leakage checks
├── 07-ai-gateway-test-suite.md        # AI Provider overrides & fallbacks
├── 08-scanner-engine-test-suite.md    # Celery, wrappers, logic
├── 09-regression-test-suite.md        # Bug-fix regressions
├── 10-accessibility-test-suite.md     # WCAG compliance for frontend
└── 11-qa-report-template.md           # The final output template
```\n