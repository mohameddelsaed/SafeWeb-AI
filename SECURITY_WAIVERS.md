# SafeWeb AI — Security Scanner & Dependency Audit Waivers
*Complies with QA Plan Phase A4: Documented justification for accepted risks.*

## 1. Backend Security Findings (Bandit)
- **B501 (`request_with_no_cert_validation`)**: Active penetration testing scanner modules (`ssl_tester.py`, `cookie_analyzer.py`, `header_analyzer.py`, `github_recon.py`, `js_intelligence.py`, `scope_resolver.py`) must connect to target web applications regardless of invalid, expired, self-signed, or untrusted SSL/TLS certificates. Waived in `.bandit`.
- **B324 (`hashlib`)**: MD5 and SHA1 are used exclusively for non-cryptographic operations including cache key generation, vulnerability fingerprint deduplication IDs, fuzzing payload hashing, and rate limiting buckets. Waived in `.bandit`.

## 2. Frontend Dependency Audit (`npm audit`)
- **Dev/Build Dependencies (`esbuild`, `vite`, `rollup`, `picomatch`, `minimatch`, `flatted`, `brace-expansion`)**: High/moderate vulnerabilities reported in frontend build toolchain dependencies affect local compilation and bundle generation (`npm run build`). These tools are not exposed or running at runtime in production container images (`Dockerfile.frontend` serves compiled static assets via nginx). Accepted risk for build pipeline until major upstream breaking upgrades are certified.
- **Axios HTTP Client**: Reported prototype pollution and proxy bypass vulnerabilities require specific untrusted config merge patterns or IPv6 proxy bypass scenarios that do not occur in standard SafeWeb AI frontend API queries (`api.ts`). Upgrades scheduled for next major client release.

## 3. Python Environment & Container Images (`pip-audit`, `trivy`/`grype`)
- Python environment dependencies isolated within dedicated Docker containers (`backend`, `celery_worker`, `agent_sandbox`). Any unpatched CVEs in transitive Python data science or scanning wrappers represent accepted operational risk constrained by container network isolation and non-root execution permissions.
