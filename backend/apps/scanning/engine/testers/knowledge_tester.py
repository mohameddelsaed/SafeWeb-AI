"""
Knowledge Tester — BaseTester wrapper for Phase 41.

Inspects the findings accumulated during a scan and cross-references them
against the Vulnerability Knowledge Base and Remediation Knowledge Base to
surface quality / coverage issues:

Depth behaviour:
  quick  — Check for findings that lack CWE classification or CVSS scores
  medium — + Compliance risk enumeration for known CWEs
  deep   — + Remediation coverage gap detection
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class KnowledgeTester(BaseTester):
    TESTER_NAME = 'Vulnerability Knowledge Base'

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
        vulns: list[dict] = []

        # ── Always: classification & CVSS completeness ────────────────────
        vulns.extend(self._check_uncategorized_findings(url, rd))
        vulns.extend(self._check_missing_cvss(url, rd))

        if depth in ('medium', 'deep'):
            # ── Compliance risk enumeration ───────────────────────────────
            vulns.extend(self._check_compliance_risks(url, rd))

        if depth == 'deep':
            # ── Remediation coverage ──────────────────────────────────────
            vulns.extend(self._check_remediation_coverage(url, rd))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Finding CWE classification check
    # ─────────────────────────────────────────────────────────────────────

    def _check_uncategorized_findings(
        self, url: str, recon_data: dict
    ) -> list[dict]:
        """Flag scan findings that are missing a CWE classification."""
        findings = recon_data.get('findings', [])
        if not findings:
            return []

        uncategorized = [
            f for f in findings
            if not f.get('cwe') or f.get('cwe', '').strip() == ''
        ]
        if not uncategorized:
            return []

        names = ', '.join(f.get('name', 'Unknown') for f in uncategorized)
        return [self._build_vuln(
            'Knowledge: Finding Missing CWE Classification',
            'info', 'knowledge-quality',
            f'{len(uncategorized)} finding(s) lack a CWE identifier, which '
            'prevents accurate compliance mapping, remediation lookup, and '
            'vulnerability trending.',
            'Without CWE classification, findings cannot be automatically '
            'cross-referenced with compliance frameworks (PCI DSS, HIPAA, '
            'GDPR) or used for knowledge-base-driven remediation guidance.',
            'Assign the appropriate CWE from https://cwe.mitre.org/ to each '
            'finding.  Use the VulnKB.search() method to look up the '
            'canonical CWE for a given vulnerability type.',
            'CWE-200', 0.0, url,
            f'Uncategorized findings: {names}',
        )]

    # ─────────────────────────────────────────────────────────────────────
    # CVSS completeness check
    # ─────────────────────────────────────────────────────────────────────

    def _check_missing_cvss(
        self, url: str, recon_data: dict
    ) -> list[dict]:
        """Flag critical/high severity findings that have a CVSS score of 0."""
        findings = recon_data.get('findings', [])
        if not findings:
            return []

        HIGH_SEVERITIES = {'critical', 'high'}
        missing = [
            f for f in findings
            if f.get('severity', '').lower() in HIGH_SEVERITIES
            and float(f.get('cvss', 0)) == 0.0
        ]
        if not missing:
            return []

        names = ', '.join(f.get('name', 'Unknown') for f in missing)
        return [self._build_vuln(
            'Knowledge: High/Critical Finding Missing CVSS Score',
            'low', 'knowledge-quality',
            f'{len(missing)} high/critical finding(s) have a CVSS score of 0, '
            'which prevents accurate risk prioritisation and SLA tracking.',
            'Missing CVSS scores impair automated risk-based prioritisation, '
            'causing high-severity vulnerabilities to appear less urgent than '
            'they are in dashboards and compliance reports.',
            'Assign a CVSS v3.1 base score using the NVD CVSS calculator '
            '(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator).  '
            'Reference the VulnKB cvss_range entry for the associated CWE '
            'as a starting point.',
            'CWE-200', 2.0, url,
            f'Affected findings: {names}',
        )]

    # ─────────────────────────────────────────────────────────────────────
    # Compliance risk enumeration
    # ─────────────────────────────────────────────────────────────────────

    def _check_compliance_risks(
        self, url: str, recon_data: dict
    ) -> list[dict]:
        """
        Enumerate compliance frameworks implicated by findings with known CWEs.

        Emits one finding per implicated compliance framework (deduplicated).
        """
        from apps.scanning.engine.knowledge.remediation_kb import (
            COMPLIANCE_MAP, _ALL_FRAMEWORKS,
        )

        findings = recon_data.get('findings', [])
        if not findings:
            return []

        # Collect triggered frameworks → set of CWEs that trigger them
        framework_cwes: dict[str, set[str]] = {f: set() for f in _ALL_FRAMEWORKS}

        for finding in findings:
            cwe = finding.get('cwe', '').strip()
            if not cwe:
                continue
            mapping = COMPLIANCE_MAP.get(cwe)
            if not mapping:
                continue
            for framework in _ALL_FRAMEWORKS:
                value = mapping.get(framework)
                if value:
                    framework_cwes[framework].add(cwe)

        results: list[dict] = []
        for framework, cwes in framework_cwes.items():
            if not cwes:
                continue
            framework_label = framework.replace('_', ' ').upper()
            results.append(self._build_vuln(
                f'Knowledge: {framework_label} Compliance Risk',
                'info', 'compliance-risk',
                f'{len(cwes)} finding(s) implicate {framework_label} controls.  '
                f'Affected CWEs: {", ".join(sorted(cwes))}.',
                f'Unresolved findings mapped to {framework_label} controls create '
                'audit findings and may indicate regulatory non-compliance.',
                f'Review the {framework_label} controls listed in the RemediationKB '
                'compliance map and ensure each finding is remediated or formally '
                'risk-accepted before the next compliance assessment.',
                'CWE-200', 0.0, url,
                f'framework={framework}, cwes={sorted(cwes)}',
            ))

        return results

    # ─────────────────────────────────────────────────────────────────────
    # Remediation coverage check
    # ─────────────────────────────────────────────────────────────────────

    def _check_remediation_coverage(
        self, url: str, recon_data: dict
    ) -> list[dict]:
        """
        Flag findings whose CWE has no entry in the Remediation Knowledge Base.

        These findings cannot benefit from automated remediation guidance or
        compliance mapping.
        """
        from apps.scanning.engine.knowledge.remediation_kb import REMEDIATION_DB

        findings = recon_data.get('findings', [])
        if not findings:
            return []

        uncovered: list[str] = []
        for finding in findings:
            cwe = finding.get('cwe', '').strip()
            if cwe and cwe not in REMEDIATION_DB:
                name = finding.get('name', cwe)
                if name not in uncovered:
                    uncovered.append(name)

        if not uncovered:
            return []

        names = ', '.join(uncovered)
        return [self._build_vuln(
            'Knowledge: No Remediation Guidance for Finding',
            'info', 'knowledge-coverage',
            f'{len(uncovered)} finding(s) have CWEs not present in the '
            'Remediation Knowledge Base: no code-level or configuration '
            'guidance can be automatically generated.',
            'Without KB coverage, development teams must manually research '
            'remediation steps, increasing the risk of incomplete or incorrect '
            'fixes and slowing the remediation cycle.',
            'Add entries to engine/knowledge/remediation_kb.py for the '
            'missing CWEs, or open a KB enhancement request and manually '
            'document the remediation steps in the finding report.',
            'CWE-200', 0.0, url,
            f'Uncovered findings: {names}',
        )]
