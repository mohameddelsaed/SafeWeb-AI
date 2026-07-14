"""
Chain Detector — Identifies multi-step attack chains from individual findings.

Known chain patterns:
  1. SSRF → Internal Service Access → RCE
  2. XSS → CSRF → Account Takeover
  3. IDOR → Data Exposure → Privilege Escalation
  4. SQLi → Data Dump → Admin Access
  5. Open Redirect → OAuth Token Theft → Account Takeover
  6. LFI → Source Code Leak → Credential Exposure
  7. SSTI → RCE
  8. XXE → SSRF → Internal Network
  9. CSRF → Password Change → Account Takeover
  10. Information Disclosure → Credential Reuse → Admin Access
"""
from __future__ import annotations

import hashlib
import logging
from collections import defaultdict

from .chain_models import AttackChain, ChainStep, ChainSeverity

logger = logging.getLogger(__name__)


# Known chain templates: (vuln_type_a, vuln_type_b) → chain info
_CHAIN_TEMPLATES: list[dict] = [
    {
        'name': 'SSRF → Internal Service → RCE',
        'sequence': ['ssrf'],
        'amplifiers': ['cmdi', 'rce', 'internal_access'],
        'combined_cvss': 9.8,
        'impact': 'Remote code execution via SSRF to internal service',
    },
    {
        'name': 'XSS → CSRF → Account Takeover',
        'sequence': ['xss', 'csrf'],
        'amplifiers': ['auth'],
        'combined_cvss': 8.5,
        'impact': 'Session hijacking via XSS-delivered CSRF',
    },
    {
        'name': 'IDOR → Data Exposure → Privilege Escalation',
        'sequence': ['idor'],
        'amplifiers': ['data exposure', 'auth'],
        'combined_cvss': 8.0,
        'impact': 'Unauthorized access to other users data and escalation',
    },
    {
        'name': 'SQLi → Data Dump → Admin Access',
        'sequence': ['sqli'],
        'amplifiers': ['data exposure', 'auth'],
        'combined_cvss': 9.5,
        'impact': 'Full database access leading to admin credential extraction',
    },
    {
        'name': 'Open Redirect → OAuth Token Theft',
        'sequence': ['open redirect'],
        'amplifiers': ['auth', 'jwt'],
        'combined_cvss': 7.5,
        'impact': 'OAuth token interception via redirect manipulation',
    },
    {
        'name': 'LFI → Source Code Leak → Credential Exposure',
        'sequence': ['lfi', 'path traversal'],
        'amplifiers': ['data exposure', 'information-disclosure'],
        'combined_cvss': 8.5,
        'impact': 'Source code disclosure revealing hardcoded credentials',
    },
    {
        'name': 'SSTI → Remote Code Execution',
        'sequence': ['ssti'],
        'amplifiers': ['cmdi', 'rce'],
        'combined_cvss': 9.5,
        'impact': 'Server-side template injection leading to code execution',
    },
    {
        'name': 'XXE → SSRF → Internal Network',
        'sequence': ['xxe'],
        'amplifiers': ['ssrf'],
        'combined_cvss': 8.5,
        'impact': 'XML External Entity leading to internal network access',
    },
    {
        'name': 'CSRF → Password Change → Account Takeover',
        'sequence': ['csrf'],
        'amplifiers': ['auth'],
        'combined_cvss': 8.0,
        'impact': 'Cross-site request forgery enabling password change',
    },
    {
        'name': 'Info Disclosure → Credential Reuse → Admin Access',
        'sequence': ['information-disclosure', 'data exposure'],
        'amplifiers': ['auth'],
        'combined_cvss': 7.5,
        'impact': 'Exposed credentials leading to administrative access',
    },
]


class ChainDetector:
    """Detect multi-step attack chains from scanner findings."""

    def __init__(self):
        self._findings_by_type: dict[str, list[dict]] = defaultdict(list)
        self._findings_by_url: dict[str, list[dict]] = defaultdict(list)
        self._detected_chains: list[AttackChain] = []

    def ingest_findings(self, findings: list[dict]) -> None:
        """Import findings from the scanner for chain analysis."""
        for f in findings:
            cat = (f.get('category', '') or '').lower()
            url = f.get('affected_url', '') or f.get('url', '')
            if cat:
                self._findings_by_type[cat].append(f)
            if url:
                self._findings_by_url[url].append(f)

    def detect_chains(self) -> list[AttackChain]:
        """Analyze findings for known chain patterns."""
        self._detected_chains = []
        found_types = set(self._findings_by_type.keys())

        for template in _CHAIN_TEMPLATES:
            # Check if any sequence vuln type is present
            seq_matches = [t for t in template['sequence'] if t in found_types]
            amp_matches = [t for t in template.get('amplifiers', []) if t in found_types]

            if not seq_matches:
                continue

            # Build chain
            steps = []
            order = 1

            # Primary vuln steps
            for vt in seq_matches:
                for f in self._findings_by_type[vt][:2]:  # Max 2 per type
                    steps.append(ChainStep(
                        order=order,
                        vuln_type=vt,
                        description=f.get('name', f'{vt.upper()} vulnerability'),
                        url=f.get('affected_url', ''),
                        payload=f.get('payload', ''),
                        evidence=f.get('evidence', '')[:200],
                        severity=f.get('severity', 'medium'),
                        finding_id=f.get('id', ''),
                    ))
                    order += 1

            # Amplifier steps
            for vt in amp_matches:
                for f in self._findings_by_type[vt][:1]:
                    steps.append(ChainStep(
                        order=order,
                        vuln_type=vt,
                        description=f'Amplified by {vt}: {f.get("name", "")}',
                        url=f.get('affected_url', ''),
                        severity=f.get('severity', 'medium'),
                        finding_id=f.get('id', ''),
                    ))
                    order += 1

            if len(steps) >= 2:
                chain_id = hashlib.sha256(
                    template['name'].encode()
                ).hexdigest()[:12]
                confidence = min(0.5 + 0.15 * len(steps), 0.95)

                chain = AttackChain(
                    chain_id=chain_id,
                    name=template['name'],
                    steps=steps,
                    combined_severity=ChainSeverity.from_combined_score(
                        template['combined_cvss']
                    ),
                    combined_cvss=template['combined_cvss'],
                    impact=template.get('impact', ''),
                    confidence=confidence,
                )
                self._detected_chains.append(chain)

        # Also detect colocated chains (same URL, multiple vuln types)
        self._detect_colocated_chains()

        # Deduplicate
        seen = set()
        unique = []
        for c in self._detected_chains:
            key = (c.name, tuple(s.url for s in c.steps[:2]))
            if key not in seen:
                seen.add(key)
                unique.append(c)
        self._detected_chains = sorted(unique, key=lambda c: c.combined_cvss, reverse=True)

        return self._detected_chains

    def _detect_colocated_chains(self) -> None:
        """Detect chains where multiple vulns target the same URL/endpoint."""
        for url, findings in self._findings_by_url.items():
            if len(findings) < 2:
                continue
            types = set()
            for f in findings:
                cat = (f.get('category', '') or '').lower()
                if cat:
                    types.add(cat)

            if len(types) < 2:
                continue

            # Multiple vuln types on the same endpoint
            steps = []
            for i, f in enumerate(findings[:5], 1):
                steps.append(ChainStep(
                    order=i,
                    vuln_type=(f.get('category', '') or '').lower(),
                    description=f.get('name', ''),
                    url=url,
                    severity=f.get('severity', 'medium'),
                    finding_id=f.get('id', ''),
                ))

            # Score based on combined severity
            sev_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
            total = sum(sev_scores.get(f.get('severity', 'low'), 1) for f in findings[:5])
            combined_cvss = min(total * 0.5, 10.0)

            chain_id = hashlib.sha256(url.encode()).hexdigest()[:12]
            type_list = ', '.join(sorted(types))
            chain = AttackChain(
                chain_id=chain_id,
                name=f'Multi-Vuln Endpoint: {type_list}',
                steps=steps,
                combined_severity=ChainSeverity.from_combined_score(combined_cvss),
                combined_cvss=combined_cvss,
                impact=f'Multiple vulnerability types on {url}',
                confidence=0.60,
            )
            self._detected_chains.append(chain)

    def get_chains(self) -> list[AttackChain]:
        return self._detected_chains

    def summary(self) -> dict:
        return {
            'total_chains': len(self._detected_chains),
            'critical_chains': sum(1 for c in self._detected_chains
                                   if c.combined_severity == ChainSeverity.CRITICAL),
            'high_chains': sum(1 for c in self._detected_chains
                               if c.combined_severity == ChainSeverity.HIGH),
            'chain_names': [c.name for c in self._detected_chains],
        }
