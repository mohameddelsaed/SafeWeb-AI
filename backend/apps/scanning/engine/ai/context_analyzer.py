"""
Context Analyzer — Builds and maintains rich context about the target
application throughout the scan lifecycle.

Aggregates intelligence from:
  - Recon results (tech stack, WAF, CMS, ports, subdomains)
  - Crawl results (pages, forms, APIs, parameters)
  - Authentication state (roles, sessions, tokens)
  - Previous findings (what worked, what was blocked)
  - Tool outputs (Nmap, Nuclei, etc.)

Provides this context to the LLM Reasoning Engine and ML models
so every decision is informed by everything learned so far.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EndpointContext:
    """Rich context about a single endpoint."""
    url: str
    method: str = 'GET'
    params: list[str] = field(default_factory=list)
    headers_of_interest: dict[str, str] = field(default_factory=dict)
    response_code: int = 0
    content_type: str = ''
    requires_auth: bool = False
    auth_roles: list[str] = field(default_factory=list)
    input_types: dict[str, str] = field(default_factory=dict)  # param → type hint
    known_validations: list[str] = field(default_factory=list)  # observed filters
    tested_vulns: dict[str, str] = field(default_factory=dict)  # vuln_type → result
    framework_hints: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Global scan context that accumulates throughout the scan."""
    target: str = ''
    domain: str = ''
    tech_stack: list[str] = field(default_factory=list)
    waf: str = ''
    waf_rules_observed: list[str] = field(default_factory=list)
    cms: str = ''
    cms_version: str = ''
    open_ports: list[int] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    auth_type: str = ''  # none, form, oauth, sso, jwt, api_key
    auth_roles: list[str] = field(default_factory=list)
    endpoints: list[EndpointContext] = field(default_factory=list)
    api_patterns: list[str] = field(default_factory=list)
    blocked_payloads: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    successful_payloads: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    findings: list[dict] = field(default_factory=list)
    tool_results: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    recon_notes: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    scan_phase: str = 'init'


class ContextAnalyzer:
    """Maintains and queries the evolving scan context."""

    def __init__(self):
        self.context = ScanContext()
        self._param_vuln_matrix: dict[str, dict[str, str]] = defaultdict(dict)

    # ── Context building ──────────────────────────────────────────────────

    def set_target(self, url: str, domain: str = '') -> None:
        self.context.target = url
        self.context.domain = domain or url

    def add_tech(self, *techs: str) -> None:
        for t in techs:
            t_lower = t.lower()
            if t_lower not in [x.lower() for x in self.context.tech_stack]:
                self.context.tech_stack.append(t)

    def set_waf(self, waf: str) -> None:
        self.context.waf = waf

    def add_waf_rule(self, payload: str, vuln_type: str) -> None:
        """Record that a payload was blocked by WAF."""
        self.context.waf_rules_observed.append(f'{vuln_type}:{payload[:50]}')
        self.context.blocked_payloads[vuln_type].append(payload)

    def add_successful_payload(self, vuln_type: str, payload: str) -> None:
        self.context.successful_payloads[vuln_type].append(payload)

    def set_cms(self, cms: str, version: str = '') -> None:
        self.context.cms = cms
        self.context.cms_version = version

    def add_ports(self, ports: list[int]) -> None:
        for p in ports:
            if p not in self.context.open_ports:
                self.context.open_ports.append(p)

    def add_subdomains(self, subdomains: list[str]) -> None:
        for s in subdomains:
            if s not in self.context.subdomains:
                self.context.subdomains.append(s)

    def add_endpoint(self, url: str, method: str = 'GET',
                     params: list[str] | None = None,
                     requires_auth: bool = False) -> EndpointContext:
        ep = EndpointContext(
            url=url, method=method, params=params or [],
            requires_auth=requires_auth,
        )
        self.context.endpoints.append(ep)
        return ep

    def add_finding(self, finding: dict) -> None:
        self.context.findings.append(finding)

    def add_tool_result(self, tool_name: str, results: list[dict]) -> None:
        self.context.tool_results[tool_name].extend(results)

    def set_auth_type(self, auth_type: str) -> None:
        self.context.auth_type = auth_type

    def add_auth_role(self, role: str) -> None:
        if role not in self.context.auth_roles:
            self.context.auth_roles.append(role)

    def set_phase(self, phase: str) -> None:
        self.context.scan_phase = phase

    def record_test(self, param: str, vuln_type: str, result: str) -> None:
        """Record that a parameter was tested for a vuln type."""
        self._param_vuln_matrix[param][vuln_type] = result

    # ── Context queries ───────────────────────────────────────────────────

    def get_untested_params(self, vuln_type: str) -> list[str]:
        """Get parameters not yet tested for a specific vulnerability type."""
        all_params = set()
        for ep in self.context.endpoints:
            all_params.update(ep.params)
        tested = {p for p, tests in self._param_vuln_matrix.items()
                  if vuln_type in tests}
        return list(all_params - tested)

    def get_best_payloads(self, vuln_type: str) -> list[str]:
        """Get payloads that previously worked for this vuln type."""
        return self.context.successful_payloads.get(vuln_type, [])

    def get_waf_bypass_needed(self) -> bool:
        return bool(self.context.waf)

    def get_auth_endpoints(self) -> list[EndpointContext]:
        return [ep for ep in self.context.endpoints if ep.requires_auth]

    def get_endpoints_with_params(self) -> list[EndpointContext]:
        return [ep for ep in self.context.endpoints if ep.params]

    def to_llm_context(self) -> dict[str, Any]:
        """Export context in a format suitable for LLM prompts."""
        return {
            'target': self.context.target,
            'tech_stack': self.context.tech_stack,
            'waf': self.context.waf,
            'cms': self.context.cms,
            'open_ports': self.context.open_ports[:20],
            'subdomains_count': len(self.context.subdomains),
            'endpoint_count': len(self.context.endpoints),
            'auth_type': self.context.auth_type,
            'auth_roles': self.context.auth_roles,
            'findings_count': len(self.context.findings),
            'findings_by_severity': self._findings_by_severity(),
            'successful_vuln_types': list(self.context.successful_payloads.keys()),
            'blocked_vuln_types': list(self.context.blocked_payloads.keys()),
            'scan_phase': self.context.scan_phase,
            'api_patterns': self.context.api_patterns[:10],
        }

    def _findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for f in self.context.findings:
            sev = f.get('severity', 'info')
            counts[sev] += 1
        return dict(counts)

    def to_recon_summary(self) -> dict:
        """Compact summary for the LLM reasoning engine."""
        return {
            'target': self.context.target,
            'tech_stack': self.context.tech_stack,
            'waf': self.context.waf,
            'open_ports': self.context.open_ports,
            'subdomains': self.context.subdomains[:20],
            'endpoints': [
                {'url': ep.url, 'method': ep.method, 'params': ep.params}
                for ep in self.context.endpoints[:50]
            ],
            'auth_type': self.context.auth_type,
            'cms': self.context.cms,
        }

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on accumulated context."""
        score = 0.0
        # More endpoints = more attack surface
        score += min(len(self.context.endpoints) * 0.5, 20)
        # Open ports
        score += min(len(self.context.open_ports) * 0.3, 10)
        # Outdated CMS
        if self.context.cms and self.context.cms_version:
            score += 5
        # No WAF is riskier for the target
        if not self.context.waf:
            score += 5
        # Auth endpoints without strong auth
        if self.context.auth_type in ('none', 'form'):
            score += 3
        # Existing findings add risk
        for f in self.context.findings:
            sev = f.get('severity', 'info')
            score += {'critical': 10, 'high': 5, 'medium': 2, 'low': 0.5}.get(sev, 0)
        self.context.risk_score = min(score, 100.0)
        return self.context.risk_score
