"""
Attack Graph v2 — Phase 42: Advanced Graph & Chain Analysis.

Extends the original AttackGraph with:

  1. Multi-step attack path detection — 10 canonical exploit chains
     (SQLi→AuthBypass→AdminPanel→RCE, SSRF→CloudMeta→AWSKeys→S3Dump, …)
  2. Probability scoring — per step, per chain; aggregated via product rule
  3. Impact amplification — chain CVSS = max(step CVSS) × chain length factor
  4. Business impact classification — 5 tiers: rce, data_breach, account_takeover,
     defacement, information_disclosure
  5. Confidence scoring — based on how many chain steps are confirmed findings
  6. MITRE ATT&CK tactic/technique mapping per chain step
  7. Mermaid.js export — enhanced with chain annotations
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

# Probability of exploitation for each vulnerability tier
STEP_PROBABILITIES: dict[str, float] = {
    'critical': 0.90,
    'high':     0.75,
    'medium':   0.50,
    'low':      0.25,
    'info':     0.05,
}

# CVSS amplification per chain length (longer chains = higher impact)
CHAIN_LENGTH_AMPLIFICATION: dict[int, float] = {
    1: 1.0,
    2: 1.15,
    3: 1.30,
    4: 1.45,
    5: 1.60,
}

# Business impact tier priorities (higher = more impactful)
BUSINESS_IMPACT_PRIORITY: dict[str, int] = {
    'rce':                      5,
    'data_breach':              4,
    'account_takeover':         3,
    'defacement':               2,
    'information_disclosure':   1,
}

SEVERITY_CVSS: dict[str, float] = {
    'critical': 9.0,
    'high':     7.5,
    'medium':   5.0,
    'low':      2.0,
    'info':     0.0,
}


# ──────────────────────────────────────────────────────────────────────────────
# Multi-step attack path patterns
# ──────────────────────────────────────────────────────────────────────────────

MULTI_STEP_CHAINS: list[dict] = [
    {
        'id': 'sqli_to_rce',
        'name': 'SQLi → Auth Bypass → Admin Panel → RCE',
        'steps': ['sqli', 'auth', 'misconfig', 'cmdi'],
        'min_steps': 2,
        'business_impact': 'rce',
        'description': (
            'SQL injection enables authentication bypass, exposing an admin panel '
            'that accepts unsanitised shell commands, leading to remote code execution.'
        ),
        'mitre_chain': [
            {'step': 'SQL Injection',     'tactic': 'Initial Access',             'technique': 'T1190'},
            {'step': 'Auth Bypass',       'tactic': 'Credential Access',          'technique': 'T1078'},
            {'step': 'Admin Panel',       'tactic': 'Discovery',                  'technique': 'T1083'},
            {'step': 'RCE',               'tactic': 'Execution',                  'technique': 'T1059'},
        ],
    },
    {
        'id': 'ssrf_to_s3',
        'name': 'SSRF → Cloud Metadata → AWS Keys → S3 Dump',
        'steps': ['ssrf', 'cloud', 'data_exposure'],
        'min_steps': 2,
        'business_impact': 'data_breach',
        'description': (
            'SSRF to the cloud metadata endpoint retrieves IAM credentials, which '
            'are then used to authenticate to AWS S3 and download all bucket contents.'
        ),
        'mitre_chain': [
            {'step': 'SSRF',              'tactic': 'Initial Access',             'technique': 'T1190'},
            {'step': 'Cloud Metadata',    'tactic': 'Credential Access',          'technique': 'T1552.005'},
            {'step': 'AWS Keys',          'tactic': 'Credential Access',          'technique': 'T1528'},
            {'step': 'S3 Dump',           'tactic': 'Exfiltration',               'technique': 'T1530'},
        ],
    },
    {
        'id': 'xss_to_account_takeover',
        'name': 'XSS → Cookie Theft → Session Hijack → Account Takeover',
        'steps': ['xss', 'csrf', 'auth'],
        'min_steps': 2,
        'business_impact': 'account_takeover',
        'description': (
            'Stored or reflected XSS steals session cookies without the HttpOnly '
            'flag, enabling session hijacking and full account takeover.'
        ),
        'mitre_chain': [
            {'step': 'XSS',               'tactic': 'Initial Access',             'technique': 'T1059.007'},
            {'step': 'Cookie Theft',      'tactic': 'Credential Access',          'technique': 'T1539'},
            {'step': 'Session Hijack',    'tactic': 'Lateral Movement',           'technique': 'T1563'},
            {'step': 'Account Takeover',  'tactic': 'Impact',                     'technique': 'T1078'},
        ],
    },
    {
        'id': 'idor_to_mass_extraction',
        'name': 'IDOR + Info Leak → Mass Data Extraction',
        'steps': ['idor', 'data_exposure'],
        'min_steps': 2,
        'business_impact': 'data_breach',
        'description': (
            'Broken object-level authorisation (IDOR) combined with information '
            'disclosure allows an attacker to iterate through all resource IDs '
            'and extract the entire data set.'
        ),
        'mitre_chain': [
            {'step': 'IDOR',              'tactic': 'Credential Access',          'technique': 'T1078'},
            {'step': 'Info Leak',         'tactic': 'Exfiltration',               'technique': 'T1530'},
            {'step': 'Mass Extraction',   'tactic': 'Exfiltration',               'technique': 'T1530'},
        ],
    },
    {
        'id': 'open_redirect_to_oauth',
        'name': 'Open Redirect → OAuth Token Theft → Account Takeover',
        'steps': ['open redirect', 'oauth', 'auth'],
        'min_steps': 2,
        'business_impact': 'account_takeover',
        'description': (
            'An open redirect on the OAuth redirect_uri parameter steals the '
            'authorization code or access token, resulting in account takeover.'
        ),
        'mitre_chain': [
            {'step': 'Open Redirect',     'tactic': 'Initial Access',             'technique': 'T1566.002'},
            {'step': 'OAuth Token Theft', 'tactic': 'Credential Access',          'technique': 'T1528'},
            {'step': 'Account Takeover',  'tactic': 'Impact',                     'technique': 'T1078'},
        ],
    },
    {
        'id': 'prototype_pollution_to_rce',
        'name': 'Prototype Pollution → RCE via Gadget Chain',
        'steps': ['prototype_pollution', 'cmdi'],
        'min_steps': 1,
        'business_impact': 'rce',
        'description': (
            'Prototype pollution in a Node.js application is chained through '
            'a known gadget (e.g. child_process.exec path override) to achieve '
            'arbitrary remote code execution.'
        ),
        'mitre_chain': [
            {'step': 'Prototype Pollution', 'tactic': 'Execution',               'technique': 'T1059.007'},
            {'step': 'RCE via Gadget',      'tactic': 'Execution',               'technique': 'T1059'},
        ],
    },
    {
        'id': 'ssti_to_rce',
        'name': 'SSTI → Template Engine Escape → RCE',
        'steps': ['ssti', 'cmdi'],
        'min_steps': 1,
        'business_impact': 'rce',
        'description': (
            'Server-Side Template Injection is exploited to escape the template '
            'sandbox and execute arbitrary OS commands with the process owner '
            'privileges.'
        ),
        'mitre_chain': [
            {'step': 'SSTI',              'tactic': 'Initial Access',             'technique': 'T1190'},
            {'step': 'Template Escape',   'tactic': 'Execution',                  'technique': 'T1059'},
        ],
    },
    {
        'id': 'lfi_to_rce',
        'name': 'LFI → Log Poisoning → RCE',
        'steps': ['path traversal', 'logging', 'cmdi'],
        'min_steps': 2,
        'business_impact': 'rce',
        'description': (
            'Local File Inclusion is used to poison an application log file with '
            'PHP code which is then included and executed, achieving RCE.'
        ),
        'mitre_chain': [
            {'step': 'LFI',               'tactic': 'Initial Access',             'technique': 'T1083'},
            {'step': 'Log Poisoning',     'tactic': 'Defense Evasion',            'technique': 'T1562.002'},
            {'step': 'RCE',               'tactic': 'Execution',                  'technique': 'T1059'},
        ],
    },
    {
        'id': 'deserialization_to_rce',
        'name': 'Insecure Deserialization → RCE',
        'steps': ['deserialization', 'cmdi'],
        'min_steps': 1,
        'business_impact': 'rce',
        'description': (
            'An attacker crafts a malicious serialised object that, when '
            'deserialised by the server, executes arbitrary commands via '
            'a known gadget chain (e.g. Apache Commons Collections).'
        ),
        'mitre_chain': [
            {'step': 'Deserialization',   'tactic': 'Initial Access',             'technique': 'T1190'},
            {'step': 'Gadget RCE',        'tactic': 'Execution',                  'technique': 'T1059'},
        ],
    },
    {
        'id': 'waf_bypass_to_sqli',
        'name': 'WAF Bypass → SQL Injection → Data Breach',
        'steps': ['waf', 'sqli', 'data_exposure'],
        'min_steps': 2,
        'business_impact': 'data_breach',
        'description': (
            'WAF bypass techniques (encoding, chunked transfer, Unicode normalisation) '
            'are used to deliver SQL injection payloads that the WAF would otherwise '
            'block, leading to full database compromise.'
        ),
        'mitre_chain': [
            {'step': 'WAF Bypass',        'tactic': 'Defense Evasion',            'technique': 'T1027'},
            {'step': 'SQL Injection',     'tactic': 'Initial Access',             'technique': 'T1190'},
            {'step': 'Data Breach',       'tactic': 'Exfiltration',               'technique': 'T1530'},
        ],
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    """One confirmed step inside a multi-step attack chain."""
    name: str
    severity: str
    affected_url: str
    probability: float          # likelihood this step succeeds
    cvss: float
    mitre_technique: str = ''
    mitre_tactic: str = ''


@dataclass
class AttackChainV2:
    """A fully described multi-step exploit chain."""
    chain_id: str
    chain_name: str
    steps: list[ChainStep]
    confirmed_steps: int        # how many steps matched actual findings
    total_steps: int            # total canonical steps in pattern
    chain_probability: float    # product of step probabilities
    chain_cvss: float           # max step CVSS × length amplification
    business_impact: str        # rce / data_breach / account_takeover / …
    confidence: float           # confirmed_steps / total_steps  (0–1)
    description: str
    mitre_chain: list[dict]     # full MITRE step list from pattern
    mermaid: str = ''           # pre-rendered Mermaid snippet for this chain


# ──────────────────────────────────────────────────────────────────────────────
# AttackGraphV2
# ──────────────────────────────────────────────────────────────────────────────

class AttackGraphV2:
    """
    Advanced graph & chain analysis engine (Phase 42).

    Usage::

        graph = AttackGraphV2(findings)
        graph.build()

        summary   = graph.get_summary()
        chains    = graph.get_chains()
        mermaid   = graph.to_mermaid()
    """

    def __init__(self, findings: list[dict]) -> None:
        """
        Parameters
        ----------
        findings:
            List of vulnerability dicts, each with at minimum:
            ``name``, ``severity``, ``category``, ``affected_url``, ``cvss``.
        """
        self.findings = findings or []
        self._chains: list[AttackChainV2] = []
        self._built = False

    # ── Build ─────────────────────────────────────────────────────────────

    def build(self) -> 'AttackGraphV2':
        """Detect all matching chains and score them."""
        self._chains = []

        # Pre-build a text index for fast keyword matching
        self._text_index: list[str] = [
            f'{f.get("name", "")} {f.get("category", "")}'.lower()
            for f in self.findings
        ]
        self._full_text = ' '.join(self._text_index)

        for pattern in MULTI_STEP_CHAINS:
            chain = self._evaluate_pattern(pattern)
            if chain is not None:
                self._chains.append(chain)

        # Sort by chain_cvss descending
        self._chains.sort(key=lambda c: c.chain_cvss, reverse=True)
        self._built = True
        return self

    def _evaluate_pattern(self, pattern: dict) -> Optional[AttackChainV2]:
        """
        Attempt to match a chain pattern against the current findings.
        Returns an AttackChainV2 if enough steps are matched, else None.
        """
        steps_required = pattern['steps']
        min_steps = pattern.get('min_steps', 2)

        confirmed_steps: list[ChainStep] = []
        mitre_chain = pattern.get('mitre_chain', [])

        for i, keyword in enumerate(steps_required):
            matched_finding = self._find_finding_for_keyword(keyword)
            if matched_finding is not None:
                sev = matched_finding.get('severity', 'info').lower()
                raw_cvss = matched_finding.get('cvss', 0)
                try:
                    cvss_val = float(raw_cvss)
                except (TypeError, ValueError):
                    cvss_val = SEVERITY_CVSS.get(sev, 0.0)
                if cvss_val == 0.0:
                    cvss_val = SEVERITY_CVSS.get(sev, 0.0)

                mitre_step = mitre_chain[i] if i < len(mitre_chain) else {}
                step = ChainStep(
                    name=matched_finding.get('name', keyword),
                    severity=sev,
                    affected_url=matched_finding.get('affected_url', ''),
                    probability=STEP_PROBABILITIES.get(sev, 0.25),
                    cvss=cvss_val,
                    mitre_technique=mitre_step.get('technique', ''),
                    mitre_tactic=mitre_step.get('tactic', ''),
                )
                confirmed_steps.append(step)

        if len(confirmed_steps) < min_steps:
            return None

        # Chain probability = product of individual step probabilities
        chain_probability = 1.0
        for step in confirmed_steps:
            chain_probability *= step.probability
        chain_probability = round(chain_probability, 4)

        # Chain CVSS = max step CVSS × length amplification
        max_cvss = max((s.cvss for s in confirmed_steps), default=0.0)
        amp_factor = CHAIN_LENGTH_AMPLIFICATION.get(
            len(confirmed_steps),
            CHAIN_LENGTH_AMPLIFICATION[max(CHAIN_LENGTH_AMPLIFICATION.keys())],
        )
        chain_cvss = round(min(10.0, max_cvss * amp_factor), 2)

        confidence = round(len(confirmed_steps) / max(len(steps_required), 1), 2)
        mermaid_snippet = self._build_chain_mermaid(
            pattern['id'], confirmed_steps, pattern['name'],
        )

        return AttackChainV2(
            chain_id=pattern['id'],
            chain_name=pattern['name'],
            steps=confirmed_steps,
            confirmed_steps=len(confirmed_steps),
            total_steps=len(steps_required),
            chain_probability=chain_probability,
            chain_cvss=chain_cvss,
            business_impact=pattern['business_impact'],
            confidence=confidence,
            description=pattern['description'],
            mitre_chain=mitre_chain,
            mermaid=mermaid_snippet,
        )

    def _find_finding_for_keyword(self, keyword: str) -> Optional[dict]:
        """Return the first finding whose name/category contains *keyword*."""
        kw = keyword.lower()
        for i, text in enumerate(self._text_index):
            if kw in text:
                return self.findings[i]
        return None

    # ── Scoring ───────────────────────────────────────────────────────────

    def calculate_chain_cvss(self, chain: AttackChainV2) -> float:
        """Re-compute chain CVSS for an arbitrary chain (public API)."""
        if not chain.steps:
            return 0.0
        max_cvss = max(s.cvss for s in chain.steps)
        amp = CHAIN_LENGTH_AMPLIFICATION.get(
            len(chain.steps),
            CHAIN_LENGTH_AMPLIFICATION[max(CHAIN_LENGTH_AMPLIFICATION.keys())],
        )
        return round(min(10.0, max_cvss * amp), 2)

    def classify_business_impact(self, chain: AttackChainV2) -> str:
        """Return the business impact tier for a chain."""
        return chain.business_impact

    def get_highest_impact_chain(self) -> Optional[AttackChainV2]:
        """Return the chain with the highest business impact priority."""
        if not self._chains:
            return None
        return max(
            self._chains,
            key=lambda c: (
                BUSINESS_IMPACT_PRIORITY.get(c.business_impact, 0),
                c.chain_cvss,
            ),
        )

    # ── Query ─────────────────────────────────────────────────────────────

    def get_chains(self) -> list[AttackChainV2]:
        """Return all detected chains sorted by chain_cvss descending."""
        return self._chains

    def get_chains_by_impact(self, impact: str) -> list[AttackChainV2]:
        """Filter chains by business impact tier."""
        return [c for c in self._chains if c.business_impact == impact]

    def get_summary(self) -> dict:
        """Return high-level metrics about detected chains."""
        impact_counts: dict[str, int] = {}
        for c in self._chains:
            impact_counts[c.business_impact] = impact_counts.get(c.business_impact, 0) + 1

        max_cvss = max((c.chain_cvss for c in self._chains), default=0.0)
        min_confidence = min((c.confidence for c in self._chains), default=0.0)
        avg_confidence = (
            round(sum(c.confidence for c in self._chains) / len(self._chains), 2)
            if self._chains else 0.0
        )

        return {
            'total_chains': len(self._chains),
            'total_findings_analysed': len(self.findings),
            'max_chain_cvss': max_cvss,
            'avg_confidence': avg_confidence,
            'min_confidence': min_confidence,
            'impact_breakdown': impact_counts,
            'rce_chains': impact_counts.get('rce', 0),
            'data_breach_chains': impact_counts.get('data_breach', 0),
            'account_takeover_chains': impact_counts.get('account_takeover', 0),
        }

    def get_mitre_coverage(self) -> dict[str, list[str]]:
        """Return a mapping of MITRE technique IDs → chain names that use them."""
        coverage: dict[str, list[str]] = {}
        for chain in self._chains:
            for step in chain.steps:
                if step.mitre_technique:
                    coverage.setdefault(step.mitre_technique, []).append(chain.chain_name)
        return coverage

    def get_remediation_priority(self) -> list[dict]:
        """
        Return findings sorted by remediation priority.

        Priority is determined by:
          1. Number of chains the finding participates in (most pivotal first)
          2. Finding severity
        """
        participation: dict[str, int] = {}
        for chain in self._chains:
            seen: set[str] = set()
            for step in chain.steps:
                key = step.name + step.affected_url
                if key not in seen:
                    participation[key] = participation.get(key, 0) + 1
                    seen.add(key)

        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        result = []
        for f in self.findings:
            key = f.get('name', '') + f.get('affected_url', '')
            sev = f.get('severity', 'info').lower()
            result.append({
                'name': f.get('name', ''),
                'severity': sev,
                'affected_url': f.get('affected_url', ''),
                'chain_appearances': participation.get(key, 0),
                'priority_score': (
                    participation.get(key, 0) * 10
                    + severity_order.get(sev, 0) * 3
                ),
            })
        return sorted(result, key=lambda r: r['priority_score'], reverse=True)

    # ── Mermaid Export ────────────────────────────────────────────────────

    def _build_chain_mermaid(
        self, chain_id: str, steps: list[ChainStep], chain_name: str
    ) -> str:
        """Build a Mermaid subgraph for a single chain."""
        lines = [f'  subgraph {chain_id}["{chain_name}"]']
        for i, step in enumerate(steps):
            node_id = f'{chain_id}_s{i}'
            sev = step.severity
            label = f'{step.name}\\n({sev.upper()})'
            if sev == 'critical':
                lines.append(f'    {node_id}["{label}"]:::critical')
            elif sev == 'high':
                lines.append(f'    {node_id}["{label}"]:::high')
            elif sev == 'medium':
                lines.append(f'    {node_id}["{label}"]:::medium')
            else:
                lines.append(f'    {node_id}["{label}"]')
        # Arrows between consecutive steps
        for i in range(len(steps) - 1):
            a = f'{chain_id}_s{i}'
            b = f'{chain_id}_s{i + 1}'
            lines.append(f'    {a} --> {b}')
        lines.append('  end')
        return '\n'.join(lines)

    def to_mermaid(self) -> str:
        """Export the entire graph as a Mermaid flowchart (LR)."""
        if not self._chains:
            return 'graph LR\n    NONE[No attack chains detected]'

        lines = ['graph LR']
        for chain in self._chains:
            lines.append(chain.mermaid)

        lines.append('  classDef critical fill:#ff4444,stroke:#cc0000,color:#fff')
        lines.append('  classDef high fill:#ff8800,stroke:#cc6600,color:#fff')
        lines.append('  classDef medium fill:#ffcc00,stroke:#cc9900,color:#000')
        return '\n'.join(lines)

    def to_dict(self) -> dict:
        """Serialise the full graph to a JSON-compatible dict."""
        return {
            'summary': self.get_summary(),
            'chains': [
                {
                    'chain_id': c.chain_id,
                    'chain_name': c.chain_name,
                    'confirmed_steps': c.confirmed_steps,
                    'total_steps': c.total_steps,
                    'chain_probability': c.chain_probability,
                    'chain_cvss': c.chain_cvss,
                    'business_impact': c.business_impact,
                    'confidence': c.confidence,
                    'description': c.description,
                    'mitre_chain': c.mitre_chain,
                    'steps': [
                        {
                            'name': s.name,
                            'severity': s.severity,
                            'affected_url': s.affected_url,
                            'probability': s.probability,
                            'cvss': s.cvss,
                            'mitre_technique': s.mitre_technique,
                            'mitre_tactic': s.mitre_tactic,
                        }
                        for s in c.steps
                    ],
                }
                for c in self._chains
            ],
            'mermaid': self.to_mermaid(),
            'mitre_coverage': self.get_mitre_coverage(),
            'remediation_priority': self.get_remediation_priority(),
        }
