"""
Cloud Enumeration — Active cloud infrastructure discovery.

Probes for AWS, Azure, GCP, and Kubernetes/container endpoints
based on target domain naming patterns.
"""
import logging
import time

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Cloud service probe templates ──────────────────────────────────────────

AWS_PATTERNS = [
    # S3
    ('{name}.s3.amazonaws.com', 'S3 Bucket (virtual-hosted)'),
    ('s3.amazonaws.com/{name}', 'S3 Bucket (path-style)'),
    ('{name}.s3.us-east-1.amazonaws.com', 'S3 Bucket (regional)'),
    ('{name}.s3.us-west-2.amazonaws.com', 'S3 Bucket (us-west-2)'),
    ('{name}.s3.eu-west-1.amazonaws.com', 'S3 Bucket (eu-west-1)'),
    # CloudFront
    ('{name}.cloudfront.net', 'CloudFront Distribution'),
    # Elastic Beanstalk
    ('{name}.elasticbeanstalk.com', 'Elastic Beanstalk'),
    # ELB
    ('{name}.elb.amazonaws.com', 'Elastic Load Balancer'),
    ('{name}.us-east-1.elb.amazonaws.com', 'ELB (us-east-1)'),
]

AZURE_PATTERNS = [
    ('{name}.blob.core.windows.net', 'Azure Blob Storage'),
    ('{name}.file.core.windows.net', 'Azure File Storage'),
    ('{name}.queue.core.windows.net', 'Azure Queue Storage'),
    ('{name}.table.core.windows.net', 'Azure Table Storage'),
    ('{name}.azurewebsites.net', 'Azure App Service'),
    ('{name}.scm.azurewebsites.net', 'Azure Kudu (SCM)'),
    ('{name}.azureedge.net', 'Azure CDN'),
    ('{name}.vault.azure.net', 'Azure Key Vault'),
    ('{name}.database.windows.net', 'Azure SQL Database'),
    ('{name}.redis.cache.windows.net', 'Azure Redis Cache'),
    ('{name}.search.windows.net', 'Azure Cognitive Search'),
    ('{name}.servicebus.windows.net', 'Azure Service Bus'),
]

GCP_PATTERNS = [
    ('{name}.storage.googleapis.com', 'GCP Cloud Storage'),
    ('storage.googleapis.com/{name}', 'GCP Storage (path)'),
    ('{name}.firebaseapp.com', 'Firebase Hosting'),
    ('{name}.web.app', 'Firebase Web App'),
    ('{name}.firebaseio.com', 'Firebase Realtime DB'),
    ('{name}.appspot.com', 'App Engine'),
    ('{name}.cloudfunctions.net', 'Cloud Functions'),
    ('{name}.run.app', 'Cloud Run'),
]

CONTAINER_PORTS = [
    (8001, 'Kubernetes Dashboard'),
    (8080, 'Kubernetes API (alt)'),
    (10250, 'Kubelet API'),
    (10255, 'Kubelet Read-Only'),
    (2379, 'etcd'),
    (2375, 'Docker API (HTTP)'),
    (2376, 'Docker API (HTTPS)'),
    (5000, 'Container Registry'),
    (6443, 'Kubernetes API'),
    (9090, 'Prometheus'),
    (3000, 'Grafana'),
]


def run_cloud_enum(target_url: str, depth: str = 'medium',
                   make_request_fn=None, **kwargs) -> dict:
    """
    Active cloud infrastructure enumeration.

    shallow : Passive check from recon_data only (AWS + Azure + GCP naming)
    medium  : + Active probes for top 20 candidate names per provider
    deep    : + Full enumeration + container service probes
    """
    start = time.time()
    result = create_result('cloud_enum', target_url, depth)
    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname) if hostname else ''
    base_name = root_domain.split('.')[0] if root_domain else ''

    if not base_name:
        result['errors'].append('Could not extract base domain name')
        return finalize_result(result, start)

    # Generate candidate names
    candidates = _generate_candidates(base_name)

    if depth == 'shallow':
        candidates = candidates[:5]
    elif depth == 'medium':
        candidates = candidates[:20]
    # deep: all candidates

    cloud_findings = []

    # AWS probes
    for name in candidates:
        for pattern, service_type in AWS_PATTERNS:
            if depth == 'shallow':
                break  # Only passive in shallow
            url = f'https://{pattern.format(name=name)}'
            result['stats']['total_checks'] += 1
            finding = _probe_url(url, service_type, 'AWS', make_request_fn)
            if finding:
                cloud_findings.append(finding)
                result['stats']['successful_checks'] += 1
            else:
                result['stats']['failed_checks'] += 1

    # Azure probes
    for name in candidates:
        for pattern, service_type in AZURE_PATTERNS:
            if depth == 'shallow':
                break
            url = f'https://{pattern.format(name=name)}'
            result['stats']['total_checks'] += 1
            finding = _probe_url(url, service_type, 'Azure', make_request_fn)
            if finding:
                cloud_findings.append(finding)
                result['stats']['successful_checks'] += 1
            else:
                result['stats']['failed_checks'] += 1

    # GCP probes
    for name in candidates:
        for pattern, service_type in GCP_PATTERNS:
            if depth == 'shallow':
                break
            url_path = pattern.format(name=name)
            if '/' in url_path and not url_path.startswith('http'):
                url = f'https://{url_path}'
            else:
                url = f'https://{url_path}'
            result['stats']['total_checks'] += 1
            finding = _probe_url(url, service_type, 'GCP', make_request_fn)
            if finding:
                cloud_findings.append(finding)
                result['stats']['successful_checks'] += 1
            else:
                result['stats']['failed_checks'] += 1

    # Deep: Container/K8s probes
    if depth == 'deep' and make_request_fn:
        for port, service_name in CONTAINER_PORTS:
            for scheme in ('http', 'https'):
                url = f'{scheme}://{hostname}:{port}/'
                result['stats']['total_checks'] += 1
                try:
                    resp = make_request_fn('GET', url, timeout=5)
                    if resp and resp.status_code < 500:
                        cloud_findings.append({
                            'provider': 'Container/K8s',
                            'service': service_name,
                            'url': url,
                            'status': resp.status_code,
                            'accessible': True,
                        })
                        result['stats']['successful_checks'] += 1
                except Exception:
                    result['stats']['failed_checks'] += 1

    # Add findings
    if cloud_findings:
        # Group by provider
        by_provider = {}
        for f in cloud_findings:
            prov = f.get('provider', 'Unknown')
            by_provider.setdefault(prov, []).append(f)

        for provider, findings in by_provider.items():
            severity = 'high' if any(f.get('public_access') for f in findings) else 'medium'
            add_finding(result, {
                'type': 'cloud_resource',
                'severity': severity,
                'title': f'{provider}: {len(findings)} cloud resource(s) found',
                'details': findings,
            })

    # ── External cloud enumeration (cloud-enum / s3scanner) ──
    try:
        from apps.scanning.engine.tools.wrappers.cloudenum_wrapper import CloudEnumTool
        from apps.scanning.engine.tools.wrappers.s3scanner_wrapper import S3ScannerTool
        _existing_resources = set()
        for _CloudCls in (CloudEnumTool, S3ScannerTool):
            try:
                _ext = _CloudCls()
                if _ext.is_available():
                    for _tr in _ext.run(base_name):
                        _res = _tr.host or ''
                        if _res and _res not in _existing_resources:
                            _existing_resources.add(_res)
                            add_finding(result, {
                                'type': 'cloud_resource',
                                'severity': _tr.severity.value if hasattr(_tr.severity, 'value') else 'medium',
                                'title': _tr.title,
                                'details': _tr.metadata,
                            })
            except Exception:
                pass
    except Exception:
        pass

    return finalize_result(result, start)


def _generate_candidates(base_name: str) -> list:
    """Generate naming candidates for cloud resource enumeration."""
    candidates = [base_name]
    suffixes = [
        '-dev', '-staging', '-prod', '-test', '-qa', '-uat',
        '-api', '-app', '-web', '-static', '-assets', '-media',
        '-backup', '-data', '-logs', '-cdn', '-internal',
    ]
    prefixes = ['dev-', 'staging-', 'prod-', 'test-', 'api-', 'app-']
    for suffix in suffixes:
        candidates.append(f'{base_name}{suffix}')
    for prefix in prefixes:
        candidates.append(f'{prefix}{base_name}')
    return candidates


def _probe_url(url: str, service_type: str, provider: str,
               make_request_fn) -> dict:
    """Probe a URL and return a finding dict if it responds."""
    if not make_request_fn:
        return None
    try:
        resp = make_request_fn('GET', url, timeout=8)
        if not resp:
            return None

        # Filter out obvious not-found
        if resp.status_code == 404:
            return None
        # S3/GCS-specific: NoSuchBucket means not found
        body = resp.text or ''
        if 'NoSuchBucket' in body or 'BucketNotFound' in body:
            return None
        if 'BlobNotFound' in body and resp.status_code == 404:
            return None

        public_access = resp.status_code == 200 and resp.text and len(resp.text) > 0
        return {
            'provider': provider,
            'service': service_type,
            'url': url,
            'status': resp.status_code,
            'accessible': resp.status_code < 400,
            'public_access': public_access and resp.status_code == 200,
        }
    except Exception:
        return None
