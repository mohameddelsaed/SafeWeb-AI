"""
JWT Analyzer — Deep analysis of JSON Web Tokens for security vulnerabilities.

Checks:
  - Algorithm confusion (none, HS256 with public key, RS→HS downgrade)
  - Expired / not-yet-valid tokens
  - Weak secrets (dictionary attack)
  - Missing claims (iss, aud, exp, nbf)
  - jwk / jku injection
  - kid parameter injection (path traversal, SQLi)
  - Sensitive data in payload (passwords, emails, SSNs)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Common weak secrets used in JWT signing
_WEAK_SECRETS = [
    'secret', 'password', '123456', 'admin', 'key', 'jwt_secret',
    'your-256-bit-secret', 'changeme', 'mysecretkey', 'shhhhh',
    'test', 'development', 'default', '', 'null', 'none',
]

# PII patterns that shouldn't be in JWT payloads
_SENSITIVE_PATTERNS = {
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
    'phone': re.compile(r'\b\+?\d{10,15}\b'),
}


@dataclass
class JWTFinding:
    """A single JWT security finding."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    cwe: str = ''
    evidence: str = ''


@dataclass
class JWTAnalysis:
    """Complete analysis result for a JWT."""
    token: str
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    signature: str = ''
    valid: bool = True
    findings: list[JWTFinding] = field(default_factory=list)


class JWTAnalyzer:
    """Analyze JWT tokens for security vulnerabilities."""

    def __init__(self, weak_secrets: list[str] | None = None):
        self._weak_secrets = weak_secrets or _WEAK_SECRETS

    def analyze(self, token: str) -> JWTAnalysis:
        """Perform full security analysis on a JWT."""
        result = JWTAnalysis(token=token)

        # Decode
        parts = token.split('.')
        if len(parts) not in (3, 5):  # JWS=3, JWE=5
            result.valid = False
            result.findings.append(JWTFinding(
                title='Malformed JWT',
                severity='info',
                description=f'Token has {len(parts)} parts (expected 3 or 5)',
            ))
            return result

        try:
            result.header = self._decode_part(parts[0])
            result.payload = self._decode_part(parts[1])
            result.signature = parts[2] if len(parts) >= 3 else ''
        except Exception as e:
            result.valid = False
            result.findings.append(JWTFinding(
                title='JWT decode error',
                severity='info',
                description=str(e),
            ))
            return result

        # Run all checks
        self._check_algorithm(result)
        self._check_expiration(result)
        self._check_claims(result)
        self._check_kid_injection(result)
        self._check_jku_jwk(result)
        self._check_sensitive_data(result)
        self._check_weak_secret(result)

        return result

    def _check_algorithm(self, result: JWTAnalysis) -> None:
        """Check for algorithm-related vulnerabilities."""
        alg = result.header.get('alg', '')

        if alg.lower() == 'none':
            result.findings.append(JWTFinding(
                title='JWT Algorithm None',
                severity='critical',
                description='Token uses "none" algorithm — signature not verified',
                cwe='CWE-327',
                evidence=f'alg: {alg}',
            ))

        if alg in ('HS256', 'HS384', 'HS512'):
            # Could be algorithm confusion if server expects RS*
            result.findings.append(JWTFinding(
                title='HMAC Algorithm — Potential Confusion Attack',
                severity='medium',
                description=(
                    f'Token uses {alg}. If the server has an RSA public key, '
                    'an attacker can sign with the public key using HMAC.'
                ),
                cwe='CWE-327',
                evidence=f'alg: {alg}',
            ))

    def _check_expiration(self, result: JWTAnalysis) -> None:
        """Check token expiration and validity window."""
        now = time.time()
        exp = result.payload.get('exp')
        nbf = result.payload.get('nbf')
        iat = result.payload.get('iat')

        if exp is None:
            result.findings.append(JWTFinding(
                title='Missing Expiration Claim',
                severity='medium',
                description='JWT has no "exp" claim — token never expires',
                cwe='CWE-613',
            ))
        elif isinstance(exp, (int, float)):
            if exp < now:
                result.findings.append(JWTFinding(
                    title='Expired Token Accepted',
                    severity='high',
                    description='Token has expired but is still being used',
                    cwe='CWE-613',
                    evidence=f'exp={exp}, now={int(now)}',
                ))
            # Extremely long TTL (>30 days)
            if iat and isinstance(iat, (int, float)):
                ttl = exp - iat
                if ttl > 30 * 86400:
                    result.findings.append(JWTFinding(
                        title='Excessive Token Lifetime',
                        severity='low',
                        description=f'Token TTL is {ttl / 86400:.0f} days (>30 days)',
                        cwe='CWE-613',
                    ))

        if nbf and isinstance(nbf, (int, float)) and nbf > now:
            result.findings.append(JWTFinding(
                title='Token Not Yet Valid',
                severity='info',
                description=f'nbf={nbf} is in the future',
            ))

    def _check_claims(self, result: JWTAnalysis) -> None:
        """Check for missing standard claims."""
        missing = []
        for claim in ('iss', 'aud', 'exp', 'sub'):
            if claim not in result.payload:
                missing.append(claim)
        if missing:
            result.findings.append(JWTFinding(
                title='Missing Standard Claims',
                severity='low',
                description=f'Missing claims: {", ".join(missing)}',
                cwe='CWE-284',
            ))

    def _check_kid_injection(self, result: JWTAnalysis) -> None:
        """Check for kid header parameter injection."""
        kid = result.header.get('kid', '')
        if not kid:
            return
        # Path traversal
        if any(p in kid for p in ('../', '..\\', '/etc/', 'C:\\')):
            result.findings.append(JWTFinding(
                title='JWT kid Path Traversal',
                severity='critical',
                description='kid header contains path traversal characters',
                cwe='CWE-22',
                evidence=f'kid: {kid[:100]}',
            ))
        # SQL injection
        if any(p in kid.lower() for p in ("'", '"', ' or ', ' union ', '--', ';')):
            result.findings.append(JWTFinding(
                title='JWT kid SQL Injection',
                severity='critical',
                description='kid header contains potential SQL injection',
                cwe='CWE-89',
                evidence=f'kid: {kid[:100]}',
            ))

    def _check_jku_jwk(self, result: JWTAnalysis) -> None:
        """Check for jku/jwk header injection."""
        jku = result.header.get('jku', '')
        if jku:
            result.findings.append(JWTFinding(
                title='JKU Header Present',
                severity='high',
                description=(
                    'Token references an external JWK Set URL. '
                    'An attacker could point this to their own key server.'
                ),
                cwe='CWE-345',
                evidence=f'jku: {jku[:200]}',
            ))
        jwk = result.header.get('jwk')
        if jwk:
            result.findings.append(JWTFinding(
                title='Embedded JWK in Header',
                severity='high',
                description='Token includes an embedded JWK — attacker can supply their own key',
                cwe='CWE-345',
            ))

    def _check_sensitive_data(self, result: JWTAnalysis) -> None:
        """Check if JWT payload contains sensitive data."""
        payload_str = json.dumps(result.payload)
        found = []
        for name, pattern in _SENSITIVE_PATTERNS.items():
            if pattern.search(payload_str):
                found.append(name)
        # Check for password-like keys
        for key in result.payload:
            if any(s in key.lower() for s in ('password', 'passwd', 'secret', 'ssn', 'credit')):
                found.append(f'key:{key}')
        if found:
            result.findings.append(JWTFinding(
                title='Sensitive Data in JWT Payload',
                severity='high',
                description=f'JWT payload exposes: {", ".join(found)}',
                cwe='CWE-200',
            ))

    def _check_weak_secret(self, result: JWTAnalysis) -> None:
        """Try common weak secrets against HMAC-signed tokens."""
        alg = result.header.get('alg', '')
        if alg not in ('HS256', 'HS384', 'HS512'):
            return
        if not result.signature:
            return

        parts = result.token.split('.')
        signing_input = f'{parts[0]}.{parts[1]}'.encode()
        expected_sig = parts[2]

        hash_fn = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in self._weak_secrets:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, hash_fn).digest()
            ).rstrip(b'=').decode()
            if hmac.compare_digest(sig, expected_sig):
                result.findings.append(JWTFinding(
                    title='JWT Signed with Weak Secret',
                    severity='critical',
                    description='Token is signed with a guessable secret',
                    cwe='CWE-521',
                    evidence=f'alg={alg}',
                ))
                return

    @staticmethod
    def _decode_part(part: str) -> dict:
        """Base64url-decode a JWT part."""
        padded = part + '=' * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
