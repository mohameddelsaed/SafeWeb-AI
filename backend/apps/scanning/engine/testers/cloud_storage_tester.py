"""
CloudStorageTester — Public Cloud Storage Bucket detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: public S3 buckets, GCS buckets, Azure blob storage,
DigitalOcean Spaces referenced in the target page, and attempts
to detect listing enabled or public write access.
"""
import re
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Cloud storage URL patterns
CLOUD_PATTERNS = {
    'aws_s3': {
        'patterns': [
            r'(https?://([a-zA-Z0-9._-]+)\.s3[.-]([a-z0-9-]+)?\.?amazonaws\.com)',
            r'(https?://s3[.-]([a-z0-9-]+)?\.?amazonaws\.com/([a-zA-Z0-9._-]+))',
            r's3://([a-zA-Z0-9._-]+)',
        ],
        'list_url': 'https://{bucket}.s3.amazonaws.com/',
        'list_indicators': ['<ListBucketResult', '<Contents>', '<Key>'],
        'error_indicators': ['AccessDenied', 'NoSuchBucket', 'AllAccessDisabled'],
    },
    'gcs': {
        'patterns': [
            r'(https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+))',
            r'(https?://([a-zA-Z0-9._-]+)\.storage\.googleapis\.com)',
            r'gs://([a-zA-Z0-9._-]+)',
        ],
        'list_url': 'https://storage.googleapis.com/{bucket}',
        'list_indicators': ['<ListBucketResult', '<Contents>', '<Key>'],
        'error_indicators': ['AccessDenied', 'NoSuchBucket'],
    },
    'azure_blob': {
        'patterns': [
            r'(https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net/([a-zA-Z0-9._-]+))',
        ],
        'list_url': 'https://{account}.blob.core.windows.net/{container}?restype=container&comp=list',
        'list_indicators': ['<EnumerationResults', '<Blob>', '<Name>'],
        'error_indicators': ['AuthenticationFailed', 'ContainerNotFound', 'BlobNotFound'],
    },
    'digitalocean_spaces': {
        'patterns': [
            r'(https?://([a-zA-Z0-9._-]+)\.([a-z0-9]+)\.digitaloceanspaces\.com)',
        ],
        'list_url': 'https://{bucket}.{region}.digitaloceanspaces.com/',
        'list_indicators': ['<ListBucketResult', '<Contents>'],
        'error_indicators': ['AccessDenied', 'NoSuchBucket'],
    },
}

# Common bucket name patterns to try if domain suggests cloud usage
COMMON_BUCKET_PATTERNS = [
    '{domain}',
    '{domain}-assets',
    '{domain}-static',
    '{domain}-uploads',
    '{domain}-media',
    '{domain}-backup',
    '{domain}-data',
    '{domain}-dev',
    '{domain}-staging',
    '{domain}-prod',
    '{domain}-public',
    'assets-{domain}',
    'static-{domain}',
    'uploads-{domain}',
]


class CloudStorageTester(BaseTester):
    """Test for public cloud storage bucket misconfigurations."""

    TESTER_NAME = 'Cloud Storage'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Find cloud storage URLs in page content
        found_buckets = self._find_cloud_references(page)

        # 2. Test each found bucket
        for provider, bucket_info in found_buckets:
            vulns = self._test_bucket(provider, bucket_info, page.url)
            vulnerabilities.extend(vulns)

        # 3. Enumerate common bucket names (deep only)
        if depth == 'deep':
            vulns = self._enumerate_buckets(page)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _find_cloud_references(self, page) -> list:
        """Find cloud storage URLs in page source."""
        body = page.body or ''
        found = []

        for provider, config in CLOUD_PATTERNS.items():
            for pattern in config['patterns']:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        found.append((provider, match))
                    else:
                        found.append((provider, (match,)))

        return found

    def _test_bucket(self, provider: str, bucket_info: tuple, page_url: str) -> list:
        """Test a specific cloud storage bucket for misconfigurations."""
        vulnerabilities = []
        config = CLOUD_PATTERNS[provider]

        # Construct the bucket URL and identifier
        if provider == 'aws_s3':
            if len(bucket_info) >= 2:
                bucket_name = bucket_info[1] if len(bucket_info) > 1 else bucket_info[0]
            else:
                bucket_name = bucket_info[0]
            test_url = config['list_url'].format(bucket=bucket_name)
        elif provider == 'gcs':
            bucket_name = bucket_info[1] if len(bucket_info) > 1 else bucket_info[0]
            test_url = config['list_url'].format(bucket=bucket_name)
        elif provider == 'azure_blob':
            if len(bucket_info) >= 3:
                account = bucket_info[1]
                container = bucket_info[2]
                test_url = config['list_url'].format(account=account, container=container)
                bucket_name = f'{account}/{container}'
            else:
                return vulnerabilities
        elif provider == 'digitalocean_spaces':
            if len(bucket_info) >= 3:
                bucket_name = bucket_info[1]
                region = bucket_info[2]
                test_url = config['list_url'].format(bucket=bucket_name, region=region)
            else:
                return vulnerabilities
        else:
            return vulnerabilities

        # Test for public listing
        try:
            response = self._make_request('GET', test_url, timeout=10)
        except Exception:
            return vulnerabilities

        if not response:
            return vulnerabilities

        body = response.text

        # Check for public listing
        if response.status_code == 200 and any(ind in body for ind in config['list_indicators']):
            vulnerabilities.append(self._build_vuln(
                name=f'Public {provider.upper().replace("_", " ")} Bucket Listing',
                severity='critical',
                category='Cloud Storage',
                description=f'The {provider.replace("_", " ")} storage bucket "{bucket_name}" '
                           f'has public listing enabled. All files in the bucket can be enumerated.',
                impact='Sensitive files, credentials, backups, or proprietary data stored in the '
                      'bucket can be discovered and downloaded by anyone.',
                remediation='Disable public listing on the bucket. Review the bucket\'s '
                           'ACL/IAM policy. Enable server-side encryption. '
                           'Consider using a CDN with signed URLs for public assets.',
                cwe='CWE-200',
                cvss=9.1,
                affected_url=test_url,
                evidence=f'Provider: {provider}\nBucket: {bucket_name}\n'
                        f'Listing response includes file entries.',
            ))

            # Count files if possible
            file_count = body.count('<Key>') or body.count('<Name>')
            if file_count > 0:
                vulnerabilities[-1]['evidence'] += f'\nFiles found: {file_count}'

        elif response.status_code == 200:
            # Bucket exists and is publicly accessible but listing might be disabled
            vulnerabilities.append(self._build_vuln(
                name=f'Public {provider.upper().replace("_", " ")} Bucket',
                severity='medium',
                category='Cloud Storage',
                description=f'The {provider.replace("_", " ")} bucket "{bucket_name}" '
                           f'is publicly accessible, though directory listing may be disabled.',
                impact='Individual files may be publicly accessible if their keys are known.',
                remediation='Review bucket permissions and ensure only intended files are public.',
                cwe='CWE-200',
                cvss=5.3,
                affected_url=test_url,
                evidence=f'Provider: {provider}\nBucket: {bucket_name}\n'
                        f'Status: 200 (accessible)',
            ))

        # Test for public write access
        vuln = self._test_write_access(provider, test_url, bucket_name, page_url)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_write_access(self, provider: str, bucket_url: str, bucket_name: str, page_url: str) -> object:
        """Test if the bucket allows public writes."""
        # Only test PUT for S3-compatible storage
        test_key = 'safeweb-ai-write-test.txt'
        test_content = 'SafeWeb-AI write access test'

        if provider in ('aws_s3', 'gcs', 'digitalocean_spaces'):
            test_url = f'{bucket_url.rstrip("/")}/{test_key}'
        else:
            return None

        try:
            response = self._make_request(
                'PUT', test_url,
                data=test_content,
                headers={'Content-Type': 'text/plain'},
                timeout=10,
            )
        except Exception:
            return None

        if response and response.status_code in (200, 201, 204):
            # Try to clean up
            try:
                self._make_request('DELETE', test_url, timeout=5)
            except Exception:
                pass

            return self._build_vuln(
                name=f'Public Write Access on {provider.upper().replace("_", " ")} Bucket',
                severity='critical',
                category='Cloud Storage',
                description=f'The bucket "{bucket_name}" allows public write access. '
                           f'Any unauthenticated user can upload or overwrite files.',
                impact='Attackers can upload malicious files, overwrite legitimate content, '
                      'deface the website, or use the bucket as malware hosting.',
                remediation='Immediately disable public write access. Review the bucket '
                           'ACL/IAM policy. Enable versioning and access logging.',
                cwe='CWE-276',
                cvss=9.8,
                affected_url=test_url,
                evidence=f'Bucket: {bucket_name}\nPublic PUT succeeded.\n'
                        f'Test file: {test_key}',
            )

        return None

    def _enumerate_buckets(self, page) -> list:
        """Enumerate common bucket names based on the domain."""
        vulnerabilities = []
        parsed = urlparse(page.url)
        domain = parsed.hostname or ''

        # Clean domain for bucket naming
        domain_clean = domain.replace('www.', '').replace('.', '-')

        checked = 0
        max_checks = 10

        for bucket_template in COMMON_BUCKET_PATTERNS:
            if checked >= max_checks:
                break

            bucket_name = bucket_template.format(domain=domain_clean)

            # Test S3
            test_url = f'https://{bucket_name}.s3.amazonaws.com/'
            try:
                response = self._make_request('GET', test_url, timeout=5)
            except Exception:
                checked += 1
                continue

            if response and response.status_code == 200:
                body = response.text
                if any(ind in body for ind in CLOUD_PATTERNS['aws_s3']['list_indicators']):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Discovered Public S3 Bucket: {bucket_name}',
                        severity='high',
                        category='Cloud Storage',
                        description=f'A publicly-listable S3 bucket "{bucket_name}" was discovered '
                                   f'that appears to belong to {domain}.',
                        impact='Sensitive data in the bucket can be enumerated and downloaded.',
                        remediation='Disable public access on the S3 bucket. '
                                   'Review AWS S3 Block Public Access settings.',
                        cwe='CWE-200',
                        cvss=7.5,
                        affected_url=test_url,
                        evidence=f'Bucket: {bucket_name}\nDiscovered via domain enumeration.',
                    ))

            checked += 1

        return vulnerabilities
