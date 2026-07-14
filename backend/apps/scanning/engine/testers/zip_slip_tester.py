"""
Zip Slip Tester — Detects path traversal in archive upload functionality.

Covers:
  - Detection of file upload endpoints that accept archives
  - Zip/tar upload with path traversal indicators
  - Unsafe archive extraction detection
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Archive upload indicators ────────────────────────────────────────────────
UPLOAD_ENDPOINT_PATTERNS = [
    r'/upload', r'/import', r'/install', r'/deploy',
    r'/migrate', r'/restore', r'/extract', r'/unzip',
    r'/plugin', r'/theme', r'/module', r'/package',
    r'/firmware', r'/update', r'/backup',
]

# ── Archive content types ────────────────────────────────────────────────────
ARCHIVE_CONTENT_TYPES = [
    'application/zip', 'application/x-zip-compressed',
    'application/x-tar', 'application/gzip',
    'application/x-gzip', 'application/x-compressed',
    'application/x-7z-compressed', 'application/x-rar-compressed',
]

# ── Form input indicators for file upload ────────────────────────────────────
FILE_INPUT_PATTERNS = ['file', 'upload', 'import', 'archive', 'zip', 'backup']

# ── Path traversal indicators in responses ───────────────────────────────────
TRAVERSAL_INDICATORS = [
    re.compile(r'\.\./', re.IGNORECASE),
    re.compile(r'extracted.*success', re.IGNORECASE),
    re.compile(r'files?\s+uploaded', re.IGNORECASE),
    re.compile(r'archive.*processed', re.IGNORECASE),
]

# ── Whitelist bypass extensions ──────────────────────────────────────────────
ARCHIVE_EXTENSIONS = ['.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.7z', '.rar']


class ZipSlipTester(BaseTester):
    """Test for path traversal in archive upload (Zip Slip) vulnerabilities."""

    TESTER_NAME = 'Zip Slip'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        getattr(page, 'headers', {}) or {}
        forms = getattr(page, 'forms', []) or []

        is_upload_endpoint = self._is_upload_endpoint(url)

        # 1. Check for archive upload forms
        vuln = self._check_archive_upload_forms(url, forms)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Check for unsafe extraction indicators in body
        if is_upload_endpoint:
            vuln = self._check_extraction_indicators(url, body)
            if vuln:
                vulns.append(vuln)

        if depth == 'deep':
            # 3. Probe upload endpoint with crafted filename
            vuln = self._test_filename_traversal(url, forms)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_upload_endpoint(self, url: str) -> bool:
        return any(
            re.search(p, url, re.IGNORECASE) for p in UPLOAD_ENDPOINT_PATTERNS
        )

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_archive_upload_forms(self, url: str, forms: list):
        """Check for forms that accept archive file uploads."""
        for form in forms:
            inputs = getattr(form, 'inputs', []) or []
            for inp in inputs:
                inp_type = getattr(inp, 'input_type', '')
                inp_name = getattr(inp, 'name', '').lower()

                if inp_type == 'file':
                    # Check if accept attribute allows archives
                    accept = getattr(inp, 'value', '').lower()
                    if (any(ext in accept for ext in ARCHIVE_EXTENSIONS)
                            or any(p in inp_name for p in FILE_INPUT_PATTERNS)):
                        return self._build_vuln(
                            name='Archive Upload Endpoint Detected',
                            severity='low',
                            category='Information Disclosure',
                            description=(
                                f'Form field "{inp_name}" accepts file uploads '
                                'that may include archive formats. If the server '
                                'extracts archives without path validation, '
                                'Zip Slip attacks are possible.'
                            ),
                            impact='Potential path traversal via archive extraction',
                            remediation=(
                                'Validate filenames in archives before extraction. '
                                'Reject entries containing "../" in their path. '
                                'Use a secure extraction library.'
                            ),
                            cwe='CWE-22',
                            cvss=3.7,
                            affected_url=url,
                            evidence=f'Archive upload field: {inp_name}',
                        )
        return None

    def _check_extraction_indicators(self, url: str, body: str):
        """Check for unsafe archive extraction indicators in response."""
        for pattern in TRAVERSAL_INDICATORS:
            if pattern.search(body):
                return self._build_vuln(
                    name='Unsafe Archive Extraction Indicator',
                    severity='medium',
                    category='Security Misconfiguration',
                    description=(
                        'The response indicates archive extraction is performed. '
                        'If path traversal in archive entries is not validated, '
                        'this enables Zip Slip file overwrite attacks.'
                    ),
                    impact='Arbitrary file overwrite, remote code execution',
                    remediation=(
                        'Validate all archive entry paths before extraction. '
                        'Reject entries with "../" or absolute paths.'
                    ),
                    cwe='CWE-22',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Extraction indicator: {pattern.pattern}',
                )
        return None

    def _test_filename_traversal(self, url: str, forms: list):
        """Test upload endpoint with traversal-style filename."""
        for form in forms:
            action = getattr(form, 'action', '') or url
            method = getattr(form, 'method', 'POST').upper()
            inputs = getattr(form, 'inputs', []) or []

            file_inputs = [
                inp for inp in inputs
                if getattr(inp, 'input_type', '') == 'file'
            ]
            if not file_inputs:
                continue

            inp_name = getattr(file_inputs[0], 'name', 'file')
            # Send a filename with path traversal
            traversal_name = '../../../etc/test-zipslip.txt'

            try:
                resp = self._make_request(
                    method, action,
                    files={inp_name: (traversal_name, b'zipslip-test', 'text/plain')},
                )
                if not resp:
                    continue

                resp_body = getattr(resp, 'text', '')
                # If the server accepted the traversal filename
                if (resp.status_code in (200, 201)
                        and 'error' not in resp_body.lower()
                        and 'invalid' not in resp_body.lower()):
                    return self._build_vuln(
                        name='Zip Slip Path Traversal',
                        severity='high',
                        category='Injection',
                        description=(
                            'The upload endpoint accepted a file with path '
                            'traversal characters in the filename. This may '
                            'allow arbitrary file overwrite (Zip Slip).'
                        ),
                        impact='Arbitrary file overwrite, potential RCE',
                        remediation=(
                            'Sanitize filenames: strip "../", resolve to '
                            'canonical path, and verify it stays within '
                            'the target directory.'
                        ),
                        cwe='CWE-22',
                        cvss=8.6,
                        affected_url=action,
                        evidence=f'Traversal filename accepted: {traversal_name}',
                    )
            except Exception:
                continue
        return None
