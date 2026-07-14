"""
Attack Graph Tester — Phase 42: Advanced Graph & Chain Analysis.

Inspects existing scan findings for multi-step exploit chains using
AttackGraphV2, and surfaces quality / coverage issues:

Depth behaviour:
  quick  — Report any detected critical/RCE chains
  medium — + High-impact chains (data_breach, account_takeover)
  deep   — + All chains + remediation priority suggestions
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester
from apps.scanning.engine.attack_graph_v2 import (
    AttackGraphV2,
)

logger = logging.getLogger(__name__)

TESTER_NAME = 'Attack Graph & Chain Analysis'


class AttackGraphTester(BaseTester):
    TESTER_NAME = TESTER_NAME

    def test(
        self,
        page: dict,
        depth: str = 'quick',
        recon_data: dict | None = None,
    ) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        rd = recon_data or {}
        findings = rd.get('findings', [])
        if not findings:
            return []

        graph = AttackGraphV2(findings)
        graph.build()

        vulns: list[dict] = []

        # quick — critical/RCE chains only
        for chain in graph.get_chains_by_impact('rce'):
            vulns.extend(self._finding_for_chain(chain, url))

        if depth in ('medium', 'deep'):
            for impact in ('data_breach', 'account_takeover'):
                for chain in graph.get_chains_by_impact(impact):
                    vulns.extend(self._finding_for_chain(chain, url))

        if depth == 'deep':
            for impact in ('defacement', 'information_disclosure'):
                for chain in graph.get_chains_by_impact(impact):
                    vulns.extend(self._finding_for_chain(chain, url))

            # Remediation priority advisory (one finding per top-3 pivots)
            priority = graph.get_remediation_priority()[:3]
            for item in priority:
                if item['chain_appearances'] >= 2:
                    vulns.append(self._remediation_advisory(item, url))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    def _finding_for_chain(self, chain, url: str) -> list[dict]:
        """Convert an AttackChainV2 to a single BaseTester finding."""
        impact = chain.business_impact.replace('_', ' ').title()
        cvss = chain.chain_cvss
        if cvss >= 9.0:
            severity = 'critical'
        elif cvss >= 7.0:
            severity = 'high'
        elif cvss >= 4.0:
            severity = 'medium'
        else:
            severity = 'low'

        step_names = ' → '.join(s.name for s in chain.steps)
        mitre_ids = ', '.join(
            step.get('technique', '')
            for step in chain.mitre_chain
            if step.get('technique')
        )
        evidence = (
            f'Chain: {chain.chain_name} | '
            f'Steps confirmed: {chain.confirmed_steps}/{chain.total_steps} | '
            f'Probability: {chain.chain_probability:.1%} | '
            f'Chain CVSS: {chain.chain_cvss} | '
            f'Confidence: {chain.confidence:.0%} | '
            f'MITRE: {mitre_ids} | '
            f'Path: {step_names}'
        )

        return [self._build_vuln(
            f'Attack Chain: {chain.chain_name}',
            severity,
            'attack-chain',
            chain.description,
            f'If exploited, an attacker achieves {impact}.  '
            f'Chain probability: {chain.chain_probability:.1%} across '
            f'{chain.confirmed_steps} confirmed steps.',
            'Remediate the earliest/highest-severity step in the chain first '
            'to break the attack path.  See remediation_priority output for '
            'the recommended fix order.',
            'CWE-693',
            cvss,
            url,
            evidence,
        )]

    def _remediation_advisory(self, item: dict, url: str) -> dict:
        """Emit a single remediation-priority advisory finding."""
        return self._build_vuln(
            f'Chain Pivot: Prioritise Fixing "{item["name"]}"',
            'info',
            'attack-chain-remediation',
            f'This finding appears as a pivotal step in '
            f'{item["chain_appearances"]} attack chain(s).  Fixing it would '
            f'break multiple chains simultaneously.',
            'Pivotal vulnerabilities provide the highest return-on-investment '
            'for remediation: fixing one finding breaks several attack paths.',
            f'Fix "{item["name"]}" ({item["severity"]}) at {item["affected_url"]}.  '
            'This breaks the most attack chains with a single remediation.',
            'CWE-693', 0.0, url,
            f'Chain appearances: {item["chain_appearances"]} | '
            f'Severity: {item["severity"]} | URL: {item["affected_url"]}',
        )
