"""
XXETester — XML External Entity Injection detection.
OWASP A05:2021 — Security Misconfiguration (XXE).

Tests for: classic XXE, blind OOB XXE, SSRF via XXE, parameter entity
injection, XInclude, SVG XXE, and SOAP XXE.
"""
import re
import logging
from .base_tester import BaseTester
from apps.scanning.engine.payloads.xxe_payloads import (
    get_xxe_payloads_by_depth,
    XXE_SUCCESS_PATTERNS,
    XML_CONTENT_TYPES,
    XINCLUDE,
    SVG_XXE,
    SOAP_XXE,
)

logger = logging.getLogger(__name__)


class XXETester(BaseTester):
    """Test for XML External Entity Injection vulnerabilities."""

    TESTER_NAME = 'XXE'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WAF-aware: when WAF detected, always try XInclude and parameter entities
        waf_detected = self._should_use_waf_bypass(recon_data)
        if waf_detected:
            logger.info('WAF detected — will prioritize XInclude and parameter entity XXE vectors')

        # Identify XML-accepting endpoints
        xml_endpoints = self._find_xml_endpoints(page)

        for endpoint in xml_endpoints:
            payloads = get_xxe_payloads_by_depth(depth)
            payloads = self._augment_payloads_with_seclists(payloads, 'xxe', recon_data)

            # WAF-aware: try XInclude first (often bypasses XXE filters)
            if waf_detected:
                vuln = self._test_xinclude(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

            # Test classic XXE
            vuln = self._test_xxe(endpoint, payloads)
            if vuln:
                vulnerabilities.append(vuln)
                continue

            # XInclude injection (medium/deep, or if WAF was not detected)
            if depth in ('medium', 'deep') and not waf_detected:
                vuln = self._test_xinclude(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

        # Check forms that accept file upload (SVG XXE)
        if depth in ('medium', 'deep'):
            for form in page.forms:
                vuln = self._test_svg_xxe(form, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Check for SOAP endpoints
        if depth == 'deep':
            vuln = self._test_soap_xxe(page)
            if vuln:
                vulnerabilities.append(vuln)

        # OOB blind XXE — inject callbacks for blind detection
        if depth in ('medium', 'deep'):
            self._inject_oob_xxe(page, xml_endpoints, recon_data)

        return vulnerabilities

    def _inject_oob_xxe(self, page, xml_endpoints, recon_data):
        """Inject OOB payloads for blind XXE detection."""
        oob_payloads = self._get_oob_payloads('xxe', 'xml_body', page.url, recon_data)
        if not oob_payloads:
            return
        for endpoint in xml_endpoints[:2]:
            for payload, _callback_id in oob_payloads[:2]:
                self._make_request(
                    'POST', endpoint.get('url', page.url),
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                )

    # ------------------------------------------------------------------
    def _find_xml_endpoints(self, page):
        """Identify endpoints that likely accept XML input."""
        endpoints = []

        # Check content type of page
        for form in page.forms:
            if form.method.upper() == 'POST':
                target = form.action or page.url
                endpoints.append({
                    'url': target,
                    'method': 'POST',
                    'source': 'form',
                })

        # Check if URL path suggests XML/API endpoint
        path_lower = page.url.lower()
        if any(ind in path_lower for ind in ('/api/', '/xml', '/soap', '/wsdl',
                                              '/ws/', '/service', '/upload')):
            endpoints.append({
                'url': page.url,
                'method': 'POST',
                'source': 'url_pattern',
            })

        return endpoints

    # ------------------------------------------------------------------
    def _test_xxe(self, endpoint, payloads):
        """Test endpoint for XXE by submitting XML payloads."""
        url = endpoint['url']

        for payload in payloads:
            for content_type in XML_CONTENT_TYPES[:2]:
                headers = {'Content-Type': content_type}
                response = self._make_request(
                    'POST', url, data=payload, headers=headers,
                )
                if not response:
                    continue

                if self._has_xxe_success(response.text):
                    return self._build_vuln(
                        name='XML External Entity Injection (XXE)',
                        severity='critical',
                        category='XXE Injection',
                        description='The endpoint processes XML input with external entity resolution enabled, '
                                   'allowing reading of server files and SSRF.',
                        impact='An attacker can read arbitrary files on the server (/etc/passwd, config files), '
                              'perform SSRF attacks to internal services, and potentially achieve denial of service.',
                        remediation='Disable DTD processing and external entity resolution in all XML parsers. '
                                   'Use defusedxml (Python), FEATURE_SECURE_PROCESSING (Java), '
                                   'or equivalent libraries. Prefer JSON over XML where possible.',
                        cwe='CWE-611',
                        cvss=9.1,
                        affected_url=url,
                        evidence=f'Payload type: XXE\nContent-Type: {content_type}\n'
                                f'Server file content or error detected in response.',
                    )

                # Check for XML parsing errors (indicates XML processing)
                if self._has_xml_error(response.text):
                    return self._build_vuln(
                        name='XML External Entity Processing Detected',
                        severity='high',
                        category='XXE Injection',
                        description='The endpoint parses XML input and returned XML-related errors, '
                                   'indicating that external entity injection may be possible.',
                        impact='XML processing with DTD enabled can lead to file disclosure, SSRF, '
                              'and denial of service attacks.',
                        remediation='Disable DTD and external entity processing in all XML parsers.',
                        cwe='CWE-611',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'XML parsing error detected for Content-Type: {content_type}',
                    )
        return None

    # ------------------------------------------------------------------
    def _test_xinclude(self, endpoint):
        """Test for XInclude injection."""
        url = endpoint['url']

        for payload in XINCLUDE:
            headers = {'Content-Type': 'application/xml'}
            response = self._make_request('POST', url, data=payload, headers=headers)
            if response and self._has_xxe_success(response.text):
                return self._build_vuln(
                    name='XInclude Injection',
                    severity='high',
                    category='XXE Injection',
                    description='The endpoint is vulnerable to XInclude-based file inclusion. '
                               'This variant works even when DTD is disabled if XInclude is processed.',
                    impact='Attackers can include and read arbitrary server files via XInclude directives.',
                    remediation='Disable XInclude processing in the XML parser configuration.',
                    cwe='CWE-611',
                    cvss=7.5,
                    affected_url=url,
                    evidence='XInclude payload resulted in file content disclosure.',
                )
        return None

    # ------------------------------------------------------------------
    def _test_svg_xxe(self, form, page_url):
        """Test for XXE via SVG file upload."""
        # Check if form has file input
        file_input = None
        for inp in form.inputs:
            if inp.input_type == 'file':
                file_input = inp
                break

        if not file_input:
            return None

        # Try uploading a malicious SVG
        payload = SVG_XXE[0] if SVG_XXE else None
        if not payload:
            return None

        target_url = form.action or page_url
        files = {file_input.name: ('test.svg', payload, 'image/svg+xml')}

        data = {}
        for fi in form.inputs:
            if fi.input_type != 'file' and fi.name:
                data[fi.name] = fi.value or 'test'

        try:
            response = self._make_request('POST', target_url, files=files, data=data)
        except Exception:
            return None

        if response and self._has_xxe_success(response.text):
            return self._build_vuln(
                name='XXE via SVG File Upload',
                severity='high',
                category='XXE Injection',
                description='The file upload endpoint processes SVG files with XML parsing '
                           'and external entity resolution enabled.',
                impact='Attackers can read server files by uploading malicious SVG images.',
                remediation='Sanitize uploaded SVG files. Disable external entity resolution '
                           'in the SVG/XML parser. Consider converting SVGs to raster format.',
                cwe='CWE-611',
                cvss=7.5,
                affected_url=target_url,
                evidence=f'SVG file upload with XXE payload at field: {file_input.name}',
            )
        return None

    # ------------------------------------------------------------------
    def _test_soap_xxe(self, page):
        """Test for XXE in SOAP endpoints."""
        if not SOAP_XXE:
            return None

        # Check if URL suggests SOAP
        path_lower = page.url.lower()
        if not any(ind in path_lower for ind in ('/soap', '/wsdl', '/ws/', '/service')):
            return None

        payload = SOAP_XXE[0]
        headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""'}
        response = self._make_request('POST', page.url, data=payload, headers=headers)

        if response and self._has_xxe_success(response.text):
            return self._build_vuln(
                name='XXE via SOAP Endpoint',
                severity='critical',
                category='XXE Injection',
                description='The SOAP endpoint processes XML with external entity resolution enabled.',
                impact='Attackers can read files and access internal services through the SOAP XML parser.',
                remediation='Disable DTD processing in the SOAP XML parser.',
                cwe='CWE-611',
                cvss=9.1,
                affected_url=page.url,
                evidence='SOAP XXE payload triggered file content disclosure.',
            )
        return None

    # ------------------------------------------------------------------
    def _has_xxe_success(self, body):
        """Check for XXE success indicators."""
        if not body:
            return False
        for pattern in XXE_SUCCESS_PATTERNS:
            if re.search(pattern, body):
                return True
        return False

    def _has_xml_error(self, body):
        """Check for XML parsing error messages."""
        if not body:
            return False
        xml_errors = [
            r'XML\s+pars(er|ing)\s+error',
            r'not\s+well.?formed',
            r'SAXParseException',
            r'lxml\.etree',
            r'XMLSyntaxError',
            r'unterminated\s+entity',
            r'PCDATA\s+invalid',
            r'EntityRef',
            r'DOCTYPE\s+is\s+disallowed',
        ]
        for pattern in xml_errors:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
