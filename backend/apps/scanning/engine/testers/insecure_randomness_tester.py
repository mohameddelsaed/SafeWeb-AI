"""
Insecure Randomness Tester — Detects predictable token generation.

Covers:
  - Sequential token detection
  - Timestamp-based token detection
  - Low-entropy session analysis
"""
import logging
import math
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Token extraction patterns ────────────────────────────────────────────────
TOKEN_PATTERNS = [
    re.compile(r'(?:token|csrf|nonce|session|api[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{8,})["\']?', re.IGNORECASE),
    re.compile(r'(?:csrf|_token|authenticity_token)\s*value=["\']([a-zA-Z0-9_\-+/=]{8,})["\']', re.IGNORECASE),
]

# ── Set-Cookie patterns ──────────────────────────────────────────────────────
SESSION_COOKIE_NAMES = [
    'session', 'sessionid', 'sess', 'sid', 'phpsessid',
    'jsessionid', 'asp.net_sessionid', 'connect.sid',
    'token', 'auth', 'jwt',
]

# ── Timestamp hex pattern (common in weak tokens) ────────────────────────────
HEX_TIMESTAMP_RE = re.compile(r'^[0-9a-f]{8}', re.IGNORECASE)

# ── Sequential/numeric-only token pattern ────────────────────────────────────
SEQUENTIAL_RE = re.compile(r'^\d{4,}$')

# ── Minimum entropy bits for session tokens (OWASP recommends 128 bits) ──────
MIN_ENTROPY_BITS = 64  # Warn below this threshold


class InsecureRandomnessTester(BaseTester):
    """Test for predictable token generation vulnerabilities."""

    TESTER_NAME = 'Insecure Randomness'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        headers = getattr(page, 'headers', {}) or {}
        cookies = getattr(page, 'cookies', {}) or {}

        # 1. Check tokens in page body
        vuln = self._check_body_tokens(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Check session cookie entropy
        vuln = self._check_session_entropy(url, cookies, headers)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Collect multiple tokens to check sequentiality
            vuln = self._check_sequential_tokens(url, body)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of a token string."""
        if not token:
            return 0.0
        freq = {}
        for c in token:
            freq[c] = freq.get(c, 0) + 1
        length = len(token)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        # Total entropy bits = per-char entropy * length
        return entropy * length

    def _extract_tokens(self, body: str) -> list:
        """Extract tokens from page body."""
        tokens = []
        for pattern in TOKEN_PATTERNS:
            matches = pattern.findall(body)
            tokens.extend(matches)
        return tokens[:10]

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_body_tokens(self, url: str, body: str):
        """Check tokens in page body for weak randomness."""
        tokens = self._extract_tokens(body)

        for token in tokens:
            # Check for sequential/numeric-only tokens
            if SEQUENTIAL_RE.match(token):
                return self._build_vuln(
                    name='Sequential Token Detected',
                    severity='high',
                    category='Broken Authentication',
                    description=(
                        f'A numeric sequential token was detected: "{token[:20]}...". '
                        'Sequential tokens are easily guessable and can be '
                        'enumerated by attackers.'
                    ),
                    impact='Token prediction, session hijacking, CSRF bypass',
                    remediation=(
                        'Use cryptographically secure random number generators '
                        '(e.g., secrets.token_hex) for token generation.'
                    ),
                    cwe='CWE-330',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Sequential token: {token[:30]}',
                )

            # Check for timestamp-based tokens
            if HEX_TIMESTAMP_RE.match(token) and len(token) < 20:
                return self._build_vuln(
                    name='Timestamp-Based Token Detected',
                    severity='medium',
                    category='Broken Authentication',
                    description=(
                        f'Token "{token[:20]}" appears to be timestamp-based. '
                        'Tokens derived from timestamps are predictable.'
                    ),
                    impact='Token prediction, brute-force feasibility',
                    remediation='Use CSPRNG for token generation, not timestamps.',
                    cwe='CWE-330',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'Timestamp-like token: {token[:30]}',
                )

            # Check low entropy
            entropy = self._calculate_entropy(token)
            if entropy < MIN_ENTROPY_BITS and len(token) >= 8:
                return self._build_vuln(
                    name='Low-Entropy Token Detected',
                    severity='medium',
                    category='Broken Authentication',
                    description=(
                        f'Token has low entropy ({entropy:.1f} bits). '
                        'OWASP recommends minimum 128 bits for session tokens.'
                    ),
                    impact='Token prediction, brute-force attacks',
                    remediation=(
                        'Use cryptographically secure random generators. '
                        'Ensure tokens have at least 128 bits of entropy.'
                    ),
                    cwe='CWE-330',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'Low entropy token ({entropy:.1f} bits): {token[:20]}',
                )
        return None

    def _check_session_entropy(self, url: str, cookies: dict, headers: dict):
        """Check session cookie entropy."""
        # Check cookies from page data
        for name, value in cookies.items():
            if name.lower() in SESSION_COOKIE_NAMES:
                entropy = self._calculate_entropy(value)
                if entropy < MIN_ENTROPY_BITS and len(value) >= 4:
                    return self._build_vuln(
                        name='Low-Entropy Session Cookie',
                        severity='high',
                        category='Broken Authentication',
                        description=(
                            f'Session cookie "{name}" has low entropy '
                            f'({entropy:.1f} bits). This makes session '
                            'hijacking via brute-force feasible.'
                        ),
                        impact='Session hijacking, account takeover',
                        remediation=(
                            'Use framework-provided session management. '
                            'Ensure session IDs have at least 128 bits entropy.'
                        ),
                        cwe='CWE-330',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'Session cookie "{name}" entropy: {entropy:.1f} bits',
                    )

        # Also check Set-Cookie headers
        set_cookie = headers.get('Set-Cookie', '')
        for session_name in SESSION_COOKIE_NAMES:
            pattern = re.compile(
                rf'{re.escape(session_name)}=([a-zA-Z0-9_\-+/=]+)',
                re.IGNORECASE,
            )
            match = pattern.search(set_cookie)
            if match:
                value = match.group(1)
                entropy = self._calculate_entropy(value)
                if entropy < MIN_ENTROPY_BITS and len(value) >= 4:
                    return self._build_vuln(
                        name='Low-Entropy Session Cookie',
                        severity='high',
                        category='Broken Authentication',
                        description=(
                            f'Session cookie "{session_name}" from Set-Cookie '
                            f'has low entropy ({entropy:.1f} bits).'
                        ),
                        impact='Session hijacking, account takeover',
                        remediation='Use CSPRNG for session ID generation.',
                        cwe='CWE-330',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'Set-Cookie "{session_name}" entropy: {entropy:.1f} bits',
                    )
        return None

    def _check_sequential_tokens(self, url: str, body: str):
        """Collect multiple tokens to check for sequential patterns."""
        tokens = []
        for _ in range(3):
            try:
                resp = self._make_request('GET', url)
                if resp:
                    resp_body = getattr(resp, 'text', '')
                    extracted = self._extract_tokens(resp_body)
                    if extracted:
                        tokens.append(extracted[0])
            except Exception:
                continue

        if len(tokens) >= 2:
            # Check if tokens are sequential numbers
            try:
                nums = [int(t) for t in tokens]
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                if all(0 < d <= 10 for d in diffs):
                    return self._build_vuln(
                        name='Sequential Token Generation',
                        severity='high',
                        category='Broken Authentication',
                        description=(
                            'Multiple requests reveal sequentially incrementing '
                            f'tokens: {", ".join(tokens[:3])}. '
                            'An attacker can predict the next token.'
                        ),
                        impact='Token prediction, session hijacking',
                        remediation='Use cryptographically secure random token generation.',
                        cwe='CWE-330',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'Sequential tokens: {", ".join(tokens[:3])}',
                    )
            except (ValueError, TypeError):
                pass

            # Check if tokens are identical (no randomness)
            if len(set(tokens)) == 1 and len(tokens) >= 2:
                return self._build_vuln(
                    name='Static Token Detected',
                    severity='high',
                    category='Broken Authentication',
                    description=(
                        'Multiple requests return the same token. '
                        'Static tokens provide no CSRF or replay protection.'
                    ),
                    impact='CSRF bypass, replay attacks',
                    remediation='Generate unique tokens per request/session.',
                    cwe='CWE-330',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Same token in {len(tokens)} requests: {tokens[0][:20]}',
                )
        return None
