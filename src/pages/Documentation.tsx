import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';

interface DocItem {
    title: string;
    content: string;
}

interface DocSection {
    id: string;
    title: string;
    icon: React.ReactNode;
    items: DocItem[];
}

export default function Documentation() {
    const [searchQuery, setSearchQuery] = useState('');
    const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
    const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
    const location = useLocation();

    useEffect(() => {
        if (location.hash) {
            const el = document.getElementById(location.hash.slice(1));
            if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth' }), 100);
        }
    }, [location.hash]);

    const handleCopy = (code: string, index: number) => {
        navigator.clipboard.writeText(code).then(() => {
            setCopiedIndex(index);
            setTimeout(() => setCopiedIndex(null), 2000);
        });
    };

    const toggleItem = (key: string) => {
        setExpandedItems((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    };

    const sections: DocSection[] = [
        {
            id: 'getting-started',
            title: 'Getting Started',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
            ),
            items: [
                {
                    title: 'Introduction',
                    content: `**SafeWeb AI** is an AI-powered web security platform that helps you detect vulnerabilities, analyze threats, and protect your web applications.

**Key features:**
- **Website Scanning** — Comprehensive vulnerability assessment for web applications, including OWASP Top 10 testing, security header analysis, and SSL/TLS verification.
- **File Scanning** — ML-powered malware detection that analyzes uploaded files for known and zero-day threats.
- **URL/Phishing Detection** — Real-time analysis of suspicious URLs using machine learning classifiers.
- **AI Chatbot** — An intelligent cybersecurity assistant that explains vulnerabilities and recommends fixes.
- **PDF Reports** — Generate professional security reports exportable as PDF, JSON, or CSV.

**Supported scan types:**
| Type | Description | Input |
|------|-------------|-------|
| Website | Full vulnerability scan | URL (e.g., https://example.com) |
| File | Malware & threat detection | Uploaded file (max 50 MB) |
| URL | Phishing link analysis | Any URL |`,
                },
                {
                    title: 'Quick Start Guide',
                    content: `Get up and running in 3 steps:

**1. Create an account**
Register at the [Sign Up](/register) page with your email, or use the API to create an account programmatically.

**2. Start a scan**
Navigate to the [Scan](/scan) page, enter a target URL, select scan depth, and click **Start Scan**. You can also scan files or check suspicious URLs.

**3. View results**
Once the scan completes, you'll see a detailed report with:
- A **security score** from 0–100
- Vulnerabilities grouped by severity (Critical, High, Medium, Low)
- Remediation guidance for each finding
- The option to export as PDF, JSON, or CSV

**Scan depth options:**
- **Shallow** — Quick surface-level scan (~30s)
- **Medium** — Balanced depth and speed (~2 min)
- **Deep** — Thorough analysis of all discovered pages (~5 min)

**Pro tip:** Enable notifications in your profile to receive scan completion alerts.`,
                },
                {
                    title: 'Authentication',
                    content: `SafeWeb AI uses **JWT (JSON Web Tokens)** for authentication.

**Login flow:**
1. Send a POST request to \`/api/auth/login/\` with your email and password
2. Receive an \`access\` token (short-lived) and a \`refresh\` token (long-lived)
3. Include the access token in all subsequent requests via the \`Authorization\` header

**Token format:**
\`\`\`
Authorization: Bearer <access_token>
\`\`\`

**Token refresh:**
When your access token expires (HTTP 401), send the refresh token to \`/api/auth/refresh/\` to obtain a new access token.

**Two-Factor Authentication (2FA):**
SafeWeb AI supports TOTP-based 2FA. Enable it in your [Profile → Security Settings](/profile) using any authenticator app (Google Authenticator, Authy, etc.).

**API keys:**
For programmatic access, generate API keys in your profile. API keys have the format \`sk_live_...\` and should be kept secret.`,
                },
                {
                    title: 'Making Your First Scan',
                    content: `**Via the dashboard:**
1. Go to the [Scan Website](/scan) page
2. Enter the target URL (must be a valid URL starting with http:// or https://)
3. Choose scan depth: Shallow, Medium, or Deep
4. Toggle optional settings:
   - **Include Subdomains** — Also scan subdomains (e.g., api.example.com)
   - **Check SSL** — Verify SSL/TLS certificate configuration
   - **Follow Redirects** — Follow HTTP redirects during crawling
5. Click **Start Scan**
6. You'll be redirected to the results page where the scan progress updates in real-time

**Via the API:**
\`\`\`bash
curl -X POST /api/scan/website/ \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://example.com",
    "scan_depth": "medium",
    "include_subdomains": false,
    "check_ssl": true,
    "follow_redirects": true
  }'
\`\`\`

**Response:**
\`\`\`json
{
  "id": "scan-uuid-here",
  "target": "https://example.com",
  "type": "website",
  "status": "pending"
}
\`\`\`

Poll \`GET /api/scan/{id}/\` to check progress until \`status\` is \`completed\` or \`failed\`.`,
                },
            ],
        },
        {
            id: 'api-reference',
            title: 'API Reference',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
            ),
            items: [
                {
                    title: 'Authentication Endpoints',
                    content: `All authentication endpoints are under \`/api/auth/\`.

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | \`/api/auth/register/\` | Create new account | No |
| POST | \`/api/auth/login/\` | Login & get tokens | No |
| POST | \`/api/auth/logout/\` | Logout & blacklist token | Yes |
| POST | \`/api/auth/refresh/\` | Refresh access token | No |
| GET | \`/api/auth/verify/\` | Verify token & get user | Yes |
| POST | \`/api/auth/forgot-password/\` | Request password reset | No |
| POST | \`/api/auth/reset-password/\` | Reset with token | No |
| POST | \`/api/auth/change-password/\` | Change password | Yes |

**Register — POST /api/auth/register/**
\`\`\`json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
\`\`\`

**Login — POST /api/auth/login/**
\`\`\`json
{
  "email": "john@example.com",
  "password": "SecurePass123!",
  "rememberMe": true
}
\`\`\`

**Response (both register & login):**
\`\`\`json
{
  "user": {
    "id": "uuid",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "user",
    "plan": "free",
    "twoFactorEnabled": false
  },
  "tokens": {
    "access": "eyJ...",
    "refresh": "eyJ..."
  }
}
\`\`\`

**Password requirements:** Minimum 8 characters, must include uppercase, lowercase, number, and special character.`,
                },
                {
                    title: 'Scan Endpoints',
                    content: `All scan endpoints are under \`/api/scan/\`.

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | \`/api/scan/website/\` | Start website scan | Yes |
| POST | \`/api/scan/file/\` | Upload & scan file | Yes |
| POST | \`/api/scan/url/\` | Scan URL for phishing | Yes |
| GET | \`/api/scan/{id}/\` | Get scan details | Yes |
| DELETE | \`/api/scan/{id}/delete/\` | Delete a scan | Yes |
| POST | \`/api/scan/{id}/rescan/\` | Re-run a scan | Yes |
| GET | \`/api/scan/{id}/export/\` | Export report | Yes |

**Website Scan — POST /api/scan/website/**
\`\`\`json
{
  "url": "https://example.com",
  "scan_depth": "medium",
  "include_subdomains": false,
  "check_ssl": true,
  "follow_redirects": true
}
\`\`\`

**File Scan — POST /api/scan/file/**
Send as \`multipart/form-data\` with a \`file\` field. Max file size: 50 MB.

**URL Scan — POST /api/scan/url/**
\`\`\`json
{ "url": "https://suspicious-link.com" }
\`\`\`

**Export — GET /api/scan/{id}/export/?format=pdf**
Supported formats: \`pdf\`, \`json\`, \`csv\`. PDF returns a binary download, JSON/CSV return structured data.`,
                },
                {
                    title: 'Results Endpoints',
                    content: `**Get Scan Results — GET /api/scan/{id}/**

Returns the full scan details including all discovered vulnerabilities:

\`\`\`json
{
  "id": "uuid",
  "target": "https://example.com",
  "scan_type": "website",
  "status": "completed",
  "score": 72,
  "started_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:32:45Z",
  "vulnerabilities": [
    {
      "id": "uuid",
      "name": "Missing Content-Security-Policy Header",
      "severity": "medium",
      "category": "Security Headers",
      "description": "The Content-Security-Policy header is not set...",
      "impact": "Increased risk of XSS attacks...",
      "remediation": "Add a Content-Security-Policy header...",
      "cwe": "CWE-693",
      "cvss": 5.3,
      "affected_url": "https://example.com",
      "evidence": "Response headers do not include CSP..."
    }
  ]
}
\`\`\`

**List Scans — GET /api/scans/**

Query parameters:
| Param | Type | Description |
|-------|------|-------------|
| search | string | Filter by target URL |
| status | string | Filter: all, pending, scanning, completed, failed |
| type | string | Filter: all, website, file, url |
| page | int | Page number for pagination |

**Dashboard — GET /api/dashboard/**

Returns aggregated stats for the current user: total scans, critical issues, average security score, recent scans, and vulnerability overview by severity.`,
                },
                {
                    title: 'Webhook Configuration',
                    content: `**Webhooks** allow your systems to receive automatic notifications when scan events occur.

> **Note:** Webhook support is coming in a future release. Currently, you can poll the scan detail endpoint to check for status changes.

**Planned webhook events:**
- \`scan.started\` — Triggered when a scan begins execution
- \`scan.completed\` — Triggered when a scan finishes successfully
- \`scan.failed\` — Triggered when a scan encounters an error
- \`vulnerability.critical\` — Triggered when a critical vulnerability is discovered

**Planned payload format:**
\`\`\`json
{
  "event": "scan.completed",
  "timestamp": "2025-01-15T10:32:45Z",
  "data": {
    "scan_id": "uuid",
    "target": "https://example.com",
    "status": "completed",
    "score": 72,
    "vulnerabilities_count": 5
  }
}
\`\`\`

In the meantime, use the AI chatbot or scan history to monitor your scans.`,
                },
            ],
        },
        {
            id: 'integration',
            title: 'Integration Guides',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
                </svg>
            ),
            items: [
                {
                    title: 'GitHub Actions',
                    content: `Integrate SafeWeb AI into your GitHub Actions CI/CD pipeline to automatically scan your application on every push or pull request.

**Example workflow (.github/workflows/security-scan.yml):**
\`\`\`yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger SafeWeb AI Scan
        run: |
          RESPONSE=$(curl -s -X POST \\
            https://your-safeweb-instance/api/scan/website/ \\
            -H "Authorization: Bearer SAFEWEB_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d '{"url": "https://staging.example.com", "scan_depth": "medium"}')
          SCAN_ID=$(echo $RESPONSE | jq -r '.id')

      - name: Wait for Scan Completion
        run: |
          for i in {1..60}; do
            STATUS=$(curl -s \\
              https://your-safeweb-instance/api/scan/$SCAN_ID/ \\
              -H "Authorization: Bearer SAFEWEB_API_KEY" | jq -r '.status')
            if [ "$STATUS" = "completed" ]; then break; fi
            sleep 10
          done

      - name: Check Score
        run: |
          SCORE=$(curl -s \\
            https://your-safeweb-instance/api/scan/$SCAN_ID/ \\
            -H "Authorization: Bearer SAFEWEB_API_KEY" | jq -r '.score')
          echo "Security Score: $SCORE"
          if [ "$SCORE" -lt 50 ]; then exit 1; fi
\`\`\`

**Setup:**
1. Generate an API key in your SafeWeb AI profile
2. Add it as \`SAFEWEB_API_KEY\` in your repository's GitHub Secrets
3. Replace the URL with your SafeWeb AI instance`,
                },
                {
                    title: 'GitLab CI/CD',
                    content: `Add security scanning to your GitLab CI/CD pipeline.

**Example .gitlab-ci.yml:**
\`\`\`yaml
security-scan:
  stage: test
  image: curlimages/curl:latest
  variables:
    SAFEWEB_URL: "https://your-safeweb-instance"
  script:
    - |
      RESPONSE=$(curl -s -X POST $SAFEWEB_URL/api/scan/website/ \\
        -H "Authorization: Bearer $SAFEWEB_API_KEY" \\
        -H "Content-Type: application/json" \\
        -d '{"url": "$CI_ENVIRONMENT_URL", "scan_depth": "medium"}')
      SCAN_ID=$(echo $RESPONSE | jq -r '.id')
      for i in $(seq 1 60); do
        STATUS=$(curl -s $SAFEWEB_URL/api/scan/$SCAN_ID/ \\
          -H "Authorization: Bearer $SAFEWEB_API_KEY" | jq -r '.status')
        [ "$STATUS" = "completed" ] && break
        sleep 10
      done
      SCORE=$(curl -s $SAFEWEB_URL/api/scan/$SCAN_ID/ \\
        -H "Authorization: Bearer $SAFEWEB_API_KEY" | jq -r '.score')
      echo "Security Score: $SCORE/100"
  only:
    - merge_requests
    - main
\`\`\`

**Setup:** Add \`SAFEWEB_API_KEY\` as a CI/CD variable in your GitLab project settings (Settings → CI/CD → Variables).`,
                },
                {
                    title: 'Jenkins Pipeline',
                    content: `Integrate SafeWeb AI into your Jenkins pipeline using a Jenkinsfile.

**Example Jenkinsfile:**
\`\`\`groovy
pipeline {
    agent any
    environment {
        SAFEWEB_API_KEY = credentials('safeweb-api-key')
        SAFEWEB_URL = 'https://your-safeweb-instance'
    }
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def response = sh(
                        script: "curl -s -X POST " +
                            "$SAFEWEB_URL/api/scan/website/ " +
                            "-H 'Authorization: Bearer $SAFEWEB_API_KEY' " +
                            "-H 'Content-Type: application/json' " +
                            "-d '{"url": "$DEPLOY_URL", "scan_depth": "medium"}'",
                        returnStdout: true
                    ).trim()
                    def scanId = readJSON(text: response).id

                    // Poll for completion
                    def status = 'pending'
                    for (int i = 0; i < 60; i++) {
                        sleep 10
                        def result = sh(
                            script: "curl -s $SAFEWEB_URL/api/scan/$scanId/ " +
                                "-H 'Authorization: Bearer $SAFEWEB_API_KEY'",
                            returnStdout: true
                        ).trim()
                        status = readJSON(text: result).status
                        if (status == 'completed') break
                    }

                    // Check score
                    def finalResult = sh(
                        script: "curl -s $SAFEWEB_URL/api/scan/$scanId/ " +
                            "-H 'Authorization: Bearer $SAFEWEB_API_KEY'",
                        returnStdout: true
                    ).trim()
                    def score = readJSON(text: finalResult).score
                    echo "Security Score: $score/100"
                    if (score < 50) {
                        error("Security score below threshold")
                    }
                }
            }
        }
    }
}
\`\`\`

**Setup:** Add the API key as a Jenkins credential (\`safeweb-api-key\`) of type "Secret text".`,
                },
                {
                    title: 'Docker Integration',
                    content: `Run SafeWeb AI security scans as part of your Docker build pipeline.

**Docker Compose for local development:**
\`\`\`yaml
version: '3.8'
services:
  safeweb-backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///db.sqlite3
      - SECRET_KEY=your-secret-key
    volumes:
      - ./backend:/app

  safeweb-frontend:
    build: .
    ports:
      - "5174:5174"
    depends_on:
      - safeweb-backend
\`\`\`

**Scan script for CI containers:**
\`\`\`bash
#!/bin/bash
# security-scan.sh — Run after deploy
API_KEY="your-api-key"
TARGET_URL="https://your-staging-url.com"
BASE_URL="https://your-safeweb-instance"

# Start scan
SCAN_ID=$(curl -s -X POST $BASE_URL/api/scan/website/ \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d "{"url": "$TARGET_URL", "scan_depth": "shallow"}" | jq -r '.id')

# Poll until done
for i in $(seq 1 60); do
  STATUS=$(curl -s $BASE_URL/api/scan/$SCAN_ID/ \\
    -H "Authorization: Bearer $API_KEY" | jq -r '.status')
  [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ] && break
  sleep 10
done

# Print results
curl -s $BASE_URL/api/scan/$SCAN_ID/ \\
  -H "Authorization: Bearer $API_KEY" | jq '{score, status}'
\`\`\`

**Tip:** For CI environments, use Docker-in-Docker or mount the Docker socket to run scans inside containers.`,
                },
            ],
        },
        {
            id: 'security',
            title: 'Security',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
            ),
            items: [
                {
                    title: 'API Key Management',
                    content: `API keys provide programmatic access to SafeWeb AI without requiring a full login flow.

**Creating an API key:**
1. Go to your [Profile](/profile) page
2. Scroll to the **API Keys** section
3. Click **Generate New Key**
4. Give it a descriptive name (e.g., "CI/CD Pipeline", "Monitoring Script")
5. **Copy the key immediately** — it won't be shown again

**API key format:** \`sk_live_<48-character-hex-string>\`

**Best practices:**
- Generate **separate keys** for each integration (CI/CD, monitoring, scripts)
- **Never** commit API keys to version control — use environment variables or secrets managers
- **Rotate keys** periodically (recommended: every 90 days)
- **Revoke unused keys** immediately — delete them from your profile
- Use the key's **last used** timestamp to identify inactive keys

**Revoking a key:**
Click the trash icon next to any API key in your profile to permanently revoke it. Any requests using that key will immediately return 401 Unauthorized.`,
                },
                {
                    title: 'Rate Limiting',
                    content: `SafeWeb AI implements rate limiting to ensure fair usage and protect the platform from abuse.

**Current limits:**

| Plan | API Requests | Concurrent Scans | Scans per Day |
|------|-------------|-------------------|---------------|
| Free | 100/hour | 1 | 10 |
| Pro | 1,000/hour | 5 | 100 |
| Enterprise | 10,000/hour | 20 | Unlimited |

**Rate limit headers:**
Every API response includes these headers:
\`\`\`
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1705312800
\`\`\`

**When rate limited:**
You'll receive a \`429 Too Many Requests\` response:
\`\`\`json
{
  "detail": "Request was throttled. Expected available in 45 seconds."
}
\`\`\`

**Best practices:**
- Implement exponential backoff in your API clients
- Cache scan results locally instead of re-fetching
- Use webhooks (when available) instead of polling
- Contact us for custom rate limits on Enterprise plans`,
                },
                {
                    title: 'IP Whitelisting',
                    content: `For enhanced security, you can restrict API access to specific IP addresses.

> **Note:** IP whitelisting is available on Pro and Enterprise plans. Free plan users can upgrade in their profile settings.

**How it works:**
1. Navigate to your Profile → Security Settings
2. Add trusted IP addresses or CIDR ranges
3. Only requests from whitelisted IPs will be accepted
4. Non-whitelisted requests receive \`403 Forbidden\`

**Supported formats:**
- Single IP: \`203.0.113.50\`
- CIDR range: \`203.0.113.0/24\`
- IPv6: \`2001:db8::1\`

**Common configurations:**
- **CI/CD runners:** Whitelist your GitHub Actions, GitLab Runner, or Jenkins server IPs
- **Office network:** Add your corporate IP range
- **VPN:** Whitelist your VPN exit node

**Emergency access:**
If you lock yourself out, contact support through the [Contact](/contact) page. We can temporarily remove IP restrictions to restore access.

**Tip:** Always include at least two IP addresses (e.g., office + personal VPN) to avoid accidental lockout.`,
                },
                {
                    title: 'Security Best Practices',
                    content: `Follow these recommendations to keep your SafeWeb AI account and integrations secure.

**Account security:**
- Enable **Two-Factor Authentication (2FA)** in [Profile → Security](/profile)
- Use a **strong, unique password** (the strength meter will guide you)
- Review your **active sessions** regularly and revoke suspicious ones
- Keep your email address up to date for security notifications

**API key security:**
- Store keys in **environment variables** or secret managers (AWS Secrets Manager, HashiCorp Vault)
- Use **separate keys** per environment (dev, staging, production)
- Rotate keys every **90 days**
- Never hardcode keys in source code
- Never share keys in chat, email, or issue trackers

**Scan safety:**
- Only scan websites you **own or have permission** to test
- Use test/staging environments for frequent scanning
- Review scan results promptly and address critical issues first
- Export and archive reports for compliance documentation

**Data handling:**
- SafeWeb AI encrypts all data in transit (TLS 1.2+) and at rest
- Scan results are stored securely and accessible only by the scan owner
- Uploaded files for malware scanning are automatically deleted after analysis
- You can delete your scan history at any time from the dashboard

**Reporting vulnerabilities:**
If you discover a security vulnerability in SafeWeb AI itself, please report it through our [Contact](/contact) page with the subject "Security Report". We follow responsible disclosure practices.`,
                },
            ],
        },
    ];

    const codeExamples = [
        {
            title: 'Initialize a Scan',
            language: 'bash',
            code: `curl -X POST https://api.safeweb.ai/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target": "https://example.com",
    "scan_depth": "medium",
    "options": {
      "include_subdomains": true,
      "check_ssl": true
    }
  }'`,
        },
        {
            title: 'Get Scan Results',
            language: 'bash',
            code: `curl -X GET https://api.safeweb.ai/v1/scan/{scan_id} \\
  -H "Authorization: Bearer YOUR_API_KEY"`,
        },
        {
            title: 'List All Scans',
            language: 'bash',
            code: `curl -X GET https://api.safeweb.ai/v1/scans \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -G -d "status=completed" -d "limit=10"`,
        },
    ];

    const lowerSearch = searchQuery.toLowerCase();
    const filteredSections = searchQuery
        ? sections
            .map((s) => ({
                ...s,
                items: s.items.filter(
                    (item) =>
                        item.title.toLowerCase().includes(lowerSearch) ||
                        item.content.toLowerCase().includes(lowerSearch)
                ),
            }))
            .filter((s) => s.items.length > 0 || s.title.toLowerCase().includes(lowerSearch))
        : sections;

    const filteredExamples = searchQuery
        ? codeExamples.filter((e) =>
            e.title.toLowerCase().includes(lowerSearch) ||
            e.code.toLowerCase().includes(lowerSearch)
        )
        : codeExamples;

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="text-center mb-12">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            Documentation
                        </h1>
                        <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                            Complete API reference and integration guides for SafeWeb AI
                        </p>
                    </div>

                    {/* Search */}
                    <div className="max-w-2xl mx-auto mb-12">
                        <Input
                            type="text"
                            placeholder="Search documentation..."
                            value={searchQuery}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                            leftIcon={
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                </svg>
                            }
                        />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-12">
                        {/* Sidebar */}
                        <div className="lg:col-span-1">
                            <Card className="p-6 sticky top-24">
                                <h3 className="text-sm font-semibold text-text-primary mb-4">Quick Navigation</h3>
                                <nav className="space-y-2">
                                    {sections.map((section) => (
                                        <a
                                            key={section.id}
                                            href={`#${section.id}`}
                                            className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-text-secondary hover:text-accent-green hover:bg-bg-hover transition-colors"
                                        >
                                            <span className="text-accent-green">{section.icon}</span>
                                            {section.title}
                                        </a>
                                    ))}
                                </nav>
                            </Card>
                        </div>

                        {/* Content */}
                        <div className="lg:col-span-3 space-y-8">
                            {filteredSections.length === 0 && filteredExamples.length === 0 && (
                                <Card className="p-8 text-center">
                                    <p className="text-text-tertiary">No results found for &quot;{searchQuery}&quot;</p>
                                </Card>
                            )}

                            {/* Sections */}
                            {filteredSections.map((section) => (
                                <Card key={section.id} id={section.id} className="p-8">
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green">
                                            {section.icon}
                                        </div>
                                        <h2 className="text-2xl font-heading font-bold text-text-primary">
                                            {section.title}
                                        </h2>
                                    </div>
                                    <div className="space-y-3">
                                        {section.items.map((item, index) => {
                                            const key = `${section.id}-${index}`;
                                            const isExpanded = expandedItems.has(key);
                                            return (
                                                <div key={index} id={key}>
                                                    <button
                                                        onClick={() => toggleItem(key)}
                                                        className="w-full p-4 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors group text-left"
                                                    >
                                                        <div className="flex items-center justify-between">
                                                            <span className="text-sm font-medium text-text-primary group-hover:text-accent-green transition-colors">
                                                                {item.title}
                                                            </span>
                                                            <svg
                                                                className={`w-5 h-5 text-text-tertiary group-hover:text-accent-green transition-all duration-200 ${isExpanded ? 'rotate-90' : ''}`}
                                                                fill="none"
                                                                stroke="currentColor"
                                                                viewBox="0 0 24 24"
                                                            >
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                                            </svg>
                                                        </div>
                                                    </button>
                                                    {isExpanded && (
                                                        <div className="mt-2 p-5 rounded-lg bg-bg-primary border border-border-primary">
                                                            <div className="prose prose-invert prose-sm max-w-none text-text-secondary leading-relaxed">
                                                                {renderMarkdown(item.content)}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                </Card>
                            ))}

                            {/* Code Examples */}
                            <Card className="p-8">
                                <h2 className="text-2xl font-heading font-bold text-text-primary mb-6">
                                    Quick Start Examples
                                </h2>
                                <div className="space-y-6">
                                    {filteredExamples.map((example, index) => (
                                        <div key={index}>
                                            <div className="flex items-center justify-between mb-3">
                                                <h3 className="text-lg font-semibold text-text-primary">
                                                    {example.title}
                                                </h3>
                                                <button
                                                    className="px-3 py-1.5 rounded-lg bg-bg-secondary text-sm text-text-secondary hover:text-accent-green transition-colors"
                                                    onClick={() => handleCopy(example.code, index)}
                                                >
                                                    {copiedIndex === index ? 'Copied!' : 'Copy'}
                                                </button>
                                            </div>
                                            <pre className="bg-bg-primary p-4 rounded-lg overflow-x-auto border border-border-primary">
                                                <code className="text-sm text-accent-green font-mono">{example.code}</code>
                                            </pre>
                                        </div>
                                    ))}
                                </div>
                            </Card>

                            {/* Support */}
                            <Card className="p-8 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                                <h3 className="text-xl font-heading font-bold text-text-primary mb-3">
                                    Need Help?
                                </h3>
                                <p className="text-text-secondary mb-6">
                                    Can&apos;t find what you&apos;re looking for? Our support team is here to help.
                                </p>
                                <div className="flex flex-wrap gap-3">
                                    <Link
                                        to="/contact"
                                        className="px-6 py-3 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors"
                                    >
                                        Contact Support
                                    </Link>
                                    <a
                                        href="https://github.com"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="px-6 py-3 rounded-lg bg-bg-secondary text-text-primary border border-border-primary font-medium hover:bg-bg-hover transition-colors"
                                    >
                                        View on GitHub
                                    </a>
                                </div>
                            </Card>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}

/**
 * Simple markdown-like renderer for documentation content.
 * Supports: **bold**, `code`, ```code blocks```, headers, tables, links, and lists.
 */
function renderMarkdown(text: string): React.ReactNode {
    const lines = text.split('\n');
    const elements: React.ReactNode[] = [];
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];

        // Code block
        if (line.trim().startsWith('```')) {
            const codeLines: string[] = [];
            i++;
            while (i < lines.length && !lines[i].trim().startsWith('```')) {
                codeLines.push(lines[i]);
                i++;
            }
            i++; // skip closing ```
            elements.push(
                <pre key={elements.length} className="bg-bg-secondary p-3 rounded-lg overflow-x-auto border border-border-primary my-2">
                    <code className="text-xs text-accent-green font-mono">{codeLines.join('\n')}</code>
                </pre>
            );
            continue;
        }

        // Table
        if (line.includes('|') && line.trim().startsWith('|')) {
            const tableRows: string[] = [];
            while (i < lines.length && lines[i].includes('|') && lines[i].trim().startsWith('|')) {
                tableRows.push(lines[i]);
                i++;
            }
            const dataRows = tableRows.filter((r) => !r.match(/^\|[\s-|]+\|$/));
            if (dataRows.length > 0) {
                const header = dataRows[0].split('|').filter(Boolean).map((c) => c.trim());
                const body = dataRows.slice(1).map((r) => r.split('|').filter(Boolean).map((c) => c.trim()));
                elements.push(
                    <div key={elements.length} className="overflow-x-auto my-2">
                        <table className="w-full text-xs border-collapse">
                            <thead>
                                <tr>
                                    {header.map((h, hi) => (
                                        <th key={hi} className="text-left p-2 border-b border-border-primary text-text-primary font-semibold">
                                            {renderInline(h)}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {body.map((row, ri) => (
                                    <tr key={ri}>
                                        {row.map((cell, ci) => (
                                            <td key={ci} className="p-2 border-b border-border-primary/50 text-text-secondary">
                                                {renderInline(cell)}
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                );
            }
            continue;
        }

        // Empty line
        if (!line.trim()) {
            i++;
            continue;
        }

        // Heading (standalone bold line)
        if (line.startsWith('**') && line.endsWith('**') && !line.slice(2, -2).includes('**')) {
            elements.push(
                <h4 key={elements.length} className="text-sm font-semibold text-text-primary mt-3 mb-1">
                    {line.slice(2, -2)}
                </h4>
            );
            i++;
            continue;
        }

        // Blockquote
        if (line.startsWith('>')) {
            elements.push(
                <div key={elements.length} className="border-l-2 border-accent-blue/50 pl-3 my-2 text-text-muted text-xs italic">
                    {renderInline(line.slice(1).trim())}
                </div>
            );
            i++;
            continue;
        }

        // List item (-, *, checkmarks)
        if (line.match(/^\s*[-*]\s/)) {
            const listItems: string[] = [];
            while (i < lines.length && lines[i].match(/^\s*[-*]\s/)) {
                listItems.push(lines[i].replace(/^\s*[-*]\s/, '').trim());
                i++;
            }
            elements.push(
                <ul key={elements.length} className="space-y-1 my-1">
                    {listItems.map((item, li) => (
                        <li key={li} className="flex items-start gap-2 text-xs text-text-secondary">
                            <span className="text-accent-green mt-0.5">•</span>
                            <span>{renderInline(item)}</span>
                        </li>
                    ))}
                </ul>
            );
            continue;
        }

        // Numbered list
        if (line.match(/^\d+\.\s/)) {
            const listItems: string[] = [];
            while (i < lines.length && lines[i].match(/^\d+\.\s/)) {
                listItems.push(lines[i].replace(/^\d+\.\s/, '').trim());
                i++;
            }
            elements.push(
                <ol key={elements.length} className="space-y-1 my-1">
                    {listItems.map((item, li) => (
                        <li key={li} className="flex items-start gap-2 text-xs text-text-secondary">
                            <span className="text-accent-green font-semibold mt-0.5">{li + 1}.</span>
                            <span>{renderInline(item)}</span>
                        </li>
                    ))}
                </ol>
            );
            continue;
        }

        // Regular paragraph
        elements.push(
            <p key={elements.length} className="text-xs text-text-secondary my-1">
                {renderInline(line)}
            </p>
        );
        i++;
    }

    return <>{elements}</>;
}

/** Render inline markdown: **bold**, `code`, [text](url) */
function renderInline(text: string): React.ReactNode {
    const parts: React.ReactNode[] = [];
    const regex = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
        if (match.index > lastIndex) {
            parts.push(text.slice(lastIndex, match.index));
        }
        const token = match[0];
        if (token.startsWith('**') && token.endsWith('**')) {
            parts.push(<strong key={parts.length} className="text-text-primary font-semibold">{token.slice(2, -2)}</strong>);
        } else if (token.startsWith('`') && token.endsWith('`')) {
            parts.push(<code key={parts.length} className="px-1 py-0.5 rounded bg-bg-secondary text-accent-green text-[11px] font-mono">{token.slice(1, -1)}</code>);
        } else if (token.startsWith('[')) {
            const linkMatch = token.match(/\[([^\]]+)\]\(([^)]+)\)/);
            if (linkMatch) {
                const [, linkText, href] = linkMatch;
                if (href.startsWith('/')) {
                    parts.push(<Link key={parts.length} to={href} className="text-accent-green hover:underline">{linkText}</Link>);
                } else {
                    parts.push(<a key={parts.length} href={href} target="_blank" rel="noopener noreferrer" className="text-accent-green hover:underline">{linkText}</a>);
                }
            }
        }
        lastIndex = match.index + match[0].length;
    }

    if (lastIndex < text.length) {
        parts.push(text.slice(lastIndex));
    }

    return parts.length === 1 ? parts[0] : <>{parts}</>;
}
