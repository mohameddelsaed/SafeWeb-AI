# 04 - Security Test Suite Specification

## Objective
Validate the platform against OWASP Top 10 vulnerabilities (Self-Security).

## Scope
- SSRF (Server-Side Request Forgery) via Scanner Engine
- IDOR (Insecure Direct Object Reference) across Organizations
- XSS in PDF/Report Generation
- Security Headers

## Specifications & Assertions
1. **SSRF**:
   - Attempt to start scan against `http://169.254.169.254/latest/meta-data/`.
   - Assert API returns 400 Bad Request.
2. **Stored XSS**:
   - Create a Target named `<script>alert(1)</script>`.
   - Render the Dashboard E2E. Assert script does not execute (React escaping validation).
3. **Headers**:
   - GET `/api/v1/health/`.
   - Assert headers include `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security`.

## AI Prompt Instructions
"Create a `test_security.py` using `pytest`. Use the Django Test Client to systematically try to break the application logic via SSRF, SQLi payloads, and XSS strings."\n