"""
ToolResult — Unified result model for all external tool outputs.

Every tool wrapper returns one or more ToolResult instances so that the
orchestrator can consume results from *any* tool using a single schema.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class ToolSeverity(str, enum.Enum):
    """CVSS-aligned severity buckets."""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

    @classmethod
    def from_cvss(cls, score: float) -> 'ToolSeverity':
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 0.1:
            return cls.LOW
        return cls.INFO


@dataclass
class ToolResult:
    """Canonical finding emitted by an external tool wrapper."""

    tool_name: str
    category: str                          # e.g. 'sqli', 'xss', 'port', 'subdomain'
    title: str
    description: str = ''
    severity: ToolSeverity = ToolSeverity.INFO
    confidence: float = 0.5                # 0.0 – 1.0
    url: str = ''
    host: str = ''
    port: int | None = None
    evidence: str = ''
    raw_output: str = ''                   # full tool output for debugging
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    cwe: str = ''                          # e.g. 'CWE-89'
    cvss: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            'tool_name': self.tool_name,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'url': self.url,
            'host': self.host,
            'port': self.port,
            'evidence': self.evidence[:2000],  # cap evidence size
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat(),
            'cwe': self.cwe,
            'cvss': self.cvss,
        }


# ── Default remediation templates per vuln category ──────────────────────────

_REMEDIATION_MAP: dict[str, str] = {
    'sqli':           'Use parameterised queries / prepared statements. Never interpolate user input into SQL.',
    'xss':            'Encode output context-appropriately. Implement a strict Content-Security-Policy.',
    'ssti':           'Avoid rendering user-controlled data through template engines. Sandbox templates.',
    'ssrf':           'Whitelist allowed outbound targets. Block access to internal/cloud-metadata addresses.',
    'lfi':            'Validate and whitelist file paths. Chroot or jail the application process.',
    'cmdi':           'Never pass user input to shell commands. Use library calls or allowlisted sub-process arguments.',
    'xxe':            "Disable external entity processing in your XML parser (e.g. ``FEATURE_SECURE_PROCESSING``).",
    'crlf':           'Sanitise newlines (\\r, \\n) from user-controlled HTTP headers and redirects.',
    'misconfig':      'Harden the server configuration: remove default files, disable directory listing, update software.',
    'takeover':       'Verify DNS CNAME targets are still provisioned. Remove dangling DNS records immediately.',
    'ssl':            'Keep TLS certificates and libraries up to date. Enforce TLS 1.2+ and strong cipher suites.',
    'vuln_scan':      'Review the finding details and apply the recommended patch or configuration change.',
}

_IMPACT_MAP: dict[str, str] = {
    'sqli':      'An attacker may read, modify, or delete database records; escalate privileges; or execute OS commands.',
    'xss':       'An attacker can execute arbitrary JavaScript in victim browsers, steal sessions, or perform phishing.',
    'ssti':      'Template injection can lead to remote code execution on the server.',
    'ssrf':      'Internal services, cloud metadata endpoints, and non-routable addresses may be accessed or exfiltrated.',
    'lfi':       'Sensitive files (e.g. /etc/passwd, application configs) may be read or PHP code included.',
    'cmdi':      'Arbitrary OS commands execute under the application account — full server compromise is possible.',
    'xxe':       'Internal files and SSRF-reachable endpoints may be read; DoS via entity expansion is possible.',
    'crlf':      'HTTP response headers can be injected, enabling XSS, cache poisoning, or session fixation.',
    'misconfig': 'Information disclosure or low-risk exploitation depending on the specific misconfiguration.',
    'takeover':  'An attacker can serve malicious content from the target subdomain, enabling phishing or cookie theft.',
    'ssl':       'Traffic may be intercepted or downgraded; authentication mechanisms may be weakened.',
    'vuln_scan': 'Refer to the tool evidence for specific exploitation impact.',
}


def tool_result_to_vuln(result: 'ToolResult') -> dict[str, Any]:
    """Convert a ToolResult instance to a vuln_data dict for Vulnerability.objects.create().

    This standardises the Nuclei CLI extraction pattern used in Phase 5b so that
    all VULN_SCAN-capable tool wrappers feed findings through a single, consistent
    conversion path.

    Args:
        result: A ToolResult emitted by any ExternalTool wrapper.

    Returns:
        Dict with all fields required by the Vulnerability model:
        name, severity, category, description, impact, remediation,
        cwe, cvss, affected_url, evidence, tool_name.
    """
    cat = (result.category or 'vuln_scan').lower()
    sev_str = result.severity.value if isinstance(result.severity, ToolSeverity) else str(result.severity)
    tool = result.tool_name or 'unknown_tool'

    # Build a human-readable name
    name = f'[{tool.upper()}] {result.title}' if result.title else f'[{tool.upper()}] Finding'

    # Description: prefer explicit description, fall back to title
    description = result.description or result.title or f'{tool} detected a finding'

    # Impact and remediation from category templates (with specific overrides for CWE)
    impact = _IMPACT_MAP.get(cat, _IMPACT_MAP['vuln_scan'])
    remediation = _REMEDIATION_MAP.get(cat, _REMEDIATION_MAP['vuln_scan'])
    if result.cwe:
        remediation = f'{remediation} (Reference: {result.cwe})'

    # Affected URL — prefer result.url, fall back to result.host
    affected_url = result.url or (f'http://{result.host}' if result.host else '')

    # Evidence — cap at 2000 chars
    evidence = str(result.evidence or result.raw_output or '')[:2000]

    return {
        'name': name,
        'severity': sev_str,
        'category': cat,
        'description': description,
        'impact': impact,
        'remediation': remediation,
        'cwe': result.cwe or '',
        'cvss': float(result.cvss or 0.0),
        'affected_url': affected_url,
        'evidence': evidence,
        'tool_name': tool,
    }
