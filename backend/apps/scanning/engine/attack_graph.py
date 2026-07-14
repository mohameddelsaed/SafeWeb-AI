"""
Attack Graph Engine — Model vulnerability relationships, identify attack
chains, and map findings to MITRE ATT&CK techniques.

Builds a directed graph where nodes are individual vulnerabilities and
edges represent exploitation relationships (one vuln enables another).
Supports chain detection, blast-radius analysis, and Mermaid/DOT export.
"""
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    """Single vulnerability node in the attack graph."""
    vuln_id: str
    name: str
    severity: str
    category: str
    affected_url: str


@dataclass
class AttackChain:
    """Ordered sequence of vulnerabilities forming an attack path."""
    chain_id: str
    chain_name: str
    nodes: list[AttackNode]
    severity: str              # highest severity among nodes
    confidence: float          # 0.0 – 1.0
    description: str
    mitre_techniques: list[str] = field(default_factory=list)
    blast_radius: str = ''     # what an attacker could achieve


# ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────

MITRE_MAP: dict[str, list[str]] = {
    'sqli':                ['T1190'],
    'sql injection':       ['T1190'],
    'xss':                 ['T1059.007'],
    'cross-site scripting':['T1059.007'],
    'ssrf':                ['T1090', 'T1552.005'],
    'ssti':                ['T1190', 'T1059'],
    'cmdi':                ['T1059'],
    'command injection':   ['T1059'],
    'path traversal':      ['T1083'],
    'lfi':                 ['T1083'],
    'open redirect':       ['T1566.002'],
    'csrf':                ['T1185'],
    'idor':                ['T1078'],
    'broken auth':         ['T1078'],
    'auth':                ['T1078'],
    'jwt':                 ['T1078', 'T1528'],
    'deserialization':     ['T1059', 'T1190'],
    'file upload':         ['T1105'],
    'xxe':                 ['T1190', 'T1083'],
    'cors':                ['T1557'],
    'clickjacking':        ['T1185'],
    'http smuggling':      ['T1090.002'],
    'subdomain takeover':  ['T1584.001'],
    'prompt injection':    ['T1059'],
    'ai data exfil':       ['T1530'],
    'data exposure':       ['T1530'],
    'misconfig':           ['T1562.001'],
    'component':           ['T1195.002'],
    'ssi':                 ['T1190', 'T1059'],
    'mass assignment':     ['T1078'],
    'race condition':      ['T1499'],
    'crlf':                ['T1190'],
    'nosql':               ['T1190'],
    'cache poisoning':     ['T1557'],
    'prototype pollution': ['T1059.007'],
}

# ── Chain Pattern Definitions ────────────────────────────────────────────

CHAIN_PATTERNS: list[dict] = [
    {
        'name': 'Authentication Bypass → Data Theft',
        'keys': ['auth', 'sqli', 'data_exposure'],
        'severity': 'critical',
        'blast': 'Full database compromise via auth bypass + SQL injection',
        'mitre': ['T1078', 'T1190', 'T1530'],
    },
    {
        'name': 'SSRF → RCE',
        'keys': ['ssrf', 'cloud', 'cmdi'],
        'severity': 'critical',
        'blast': 'Remote code execution via SSRF to cloud metadata + command injection',
        'mitre': ['T1090', 'T1552.005', 'T1059'],
    },
    {
        'name': 'XSS → Account Takeover',
        'keys': ['xss', 'csrf'],
        'severity': 'critical',
        'blast': 'Account takeover via XSS stealing session + CSRF for state changes',
        'mitre': ['T1059.007', 'T1185'],
    },
    {
        'name': 'LFI → RCE',
        'keys': ['path_traversal', 'log'],
        'severity': 'critical',
        'blast': 'RCE via path traversal reading logs with injected commands',
        'mitre': ['T1083', 'T1059'],
    },
    {
        'name': 'Prototype Pollution → RCE',
        'keys': ['prototype_pollution', 'rce'],
        'severity': 'critical',
        'blast': 'Remote code execution via Node.js prototype pollution gadgets',
        'mitre': ['T1059.007'],
    },
    {
        'name': 'JWT Confusion → Impersonation',
        'keys': ['jwt'],
        'severity': 'critical',
        'blast': 'Identity impersonation via JWT algorithm confusion or none alg',
        'mitre': ['T1078', 'T1528'],
    },
    {
        'name': 'Cache Poison → Stored XSS Delivery',
        'keys': ['cache', 'xss'],
        'severity': 'high',
        'blast': 'Mass-exploitation via poisoned cache serving stored XSS to all users',
        'mitre': ['T1557', 'T1059.007'],
    },
    {
        'name': 'Subdomain Takeover → Cookie Theft',
        'keys': ['subdomain_takeover', 'cookie'],
        'severity': 'high',
        'blast': 'Session theft via subdomain takeover reading parent-domain cookies',
        'mitre': ['T1584.001', 'T1185'],
    },
    {
        'name': 'HTTP Smuggling → Auth Bypass',
        'keys': ['smuggling', 'auth'],
        'severity': 'high',
        'blast': 'Authentication bypass via HTTP request smuggling',
        'mitre': ['T1090.002', 'T1078'],
    },
    {
        'name': 'API BOLA → Data Exfiltration',
        'keys': ['idor', 'auth', 'data_exposure'],
        'severity': 'high',
        'blast': 'Mass data exfiltration via broken object-level authorization',
        'mitre': ['T1078', 'T1530'],
    },
    {
        'name': 'Prompt Injection → Data Exfiltration',
        'keys': ['prompt_injection', 'ai'],
        'severity': 'high',
        'blast': 'AI-powered data exfiltration via prompt injection',
        'mitre': ['T1059', 'T1530'],
    },
    {
        'name': 'Supply Chain → RCE',
        'keys': ['component', 'cve'],
        'severity': 'high',
        'blast': 'RCE via known vulnerability in outdated third-party component',
        'mitre': ['T1195.002'],
    },
    {
        'name': 'CORS → Credential Theft',
        'keys': ['cors', 'auth'],
        'severity': 'high',
        'blast': 'Credential theft via CORS misconfiguration on authenticated endpoints',
        'mitre': ['T1557', 'T1078'],
    },
    {
        'name': 'Mass Assignment → Privilege Escalation',
        'keys': ['mass_assignment', 'auth'],
        'severity': 'high',
        'blast': 'Privilege escalation via mass assignment setting admin/role fields',
        'mitre': ['T1078'],
    },
    {
        'name': 'SSI → RCE',
        'keys': ['ssi', 'exec'],
        'severity': 'critical',
        'blast': 'Remote code execution via SSI exec directive injection',
        'mitre': ['T1190', 'T1059'],
    },
    {
        'name': 'XSS + Missing CSP = Higher Exploitability',
        'keys': ['xss', 'csp'],
        'severity': 'high',
        'blast': 'XSS exploitation unmitigated by Content Security Policy',
        'mitre': ['T1059.007'],
    },
    {
        'name': 'SSRF + Cloud Metadata = Credential Theft',
        'keys': ['ssrf', 'cloud'],
        'severity': 'critical',
        'blast': 'Cloud credential theft via SSRF accessing metadata service',
        'mitre': ['T1090', 'T1552.005'],
    },
    {
        'name': 'SQLi + Data Exposure = Database Compromise',
        'keys': ['sqli', 'data_exposure'],
        'severity': 'critical',
        'blast': 'Full database compromise via SQL injection + exposed data endpoints',
        'mitre': ['T1190', 'T1530'],
    },
    {
        'name': 'Prompt Injection + Insecure AI Output = AI RCE',
        'keys': ['prompt_injection', 'insecure_output'],
        'severity': 'critical',
        'blast': 'RCE via prompt injection exploiting insecure AI output handling',
        'mitre': ['T1059'],
    },
    {
        'name': 'CSRF + Auth Weakness = Account Takeover',
        'keys': ['csrf', 'auth'],
        'severity': 'high',
        'blast': 'Account takeover via CSRF exploiting weak authentication',
        'mitre': ['T1185', 'T1078'],
    },
]


class AttackGraph:
    """Build and analyze vulnerability relationship graphs."""

    def __init__(self, vulnerabilities: list, recon_data: dict = None):
        self.vulnerabilities = vulnerabilities
        self.recon_data = recon_data or {}
        self._nodes: list[AttackNode] = []
        self._edges: list[tuple[str, str]] = []
        self._chains: list[AttackChain] = []

    # ── Build ─────────────────────────────────────────────────────────────

    def build(self) -> dict:
        """Build graph: nodes=vulnerabilities, edges=exploitation relationships."""
        self._nodes = []
        self._edges = []

        # Create nodes
        for i, v in enumerate(self.vulnerabilities):
            node = AttackNode(
                vuln_id=v.get('_id', f'v{i}'),
                name=v.get('name', 'Unknown'),
                severity=v.get('severity', 'info'),
                category=(v.get('category', '') or '').lower(),
                affected_url=v.get('affected_url', ''),
            )
            self._nodes.append(node)

        # Build search index for chain matching
        self._name_set = set()
        self._category_set = set()
        for n in self._nodes:
            self._name_set.add(n.name.lower())
            self._category_set.add(n.category.lower())

        # Detect chains
        self._chains = self.find_chains()

        # Build edges from chains
        for chain in self._chains:
            for i in range(len(chain.nodes) - 1):
                self._edges.append((chain.nodes[i].vuln_id, chain.nodes[i + 1].vuln_id))

        return {
            'nodes': [
                {'vuln_id': n.vuln_id, 'name': n.name, 'severity': n.severity,
                 'category': n.category, 'affected_url': n.affected_url}
                for n in self._nodes
            ],
            'edges': [{'from': e[0], 'to': e[1]} for e in self._edges],
            'chains': [
                {'chain_id': c.chain_id, 'chain_name': c.chain_name,
                 'severity': c.severity, 'confidence': c.confidence,
                 'description': c.description, 'blast_radius': c.blast_radius,
                 'mitre_techniques': c.mitre_techniques,
                 'nodes': [n.name for n in c.nodes]}
                for c in self._chains
            ],
        }

    # ── Chain Detection ───────────────────────────────────────────────────

    def find_chains(self, max_depth: int = 5) -> list[AttackChain]:
        """Match vulnerability combinations against known chain patterns."""
        chains = []
        chain_idx = 0

        # Combined text blob for flexible matching
        all_text = ' '.join(
            f'{n.name} {n.category}' for n in self._nodes
        ).lower()

        for pattern in CHAIN_PATTERNS:
            keys = pattern['keys']
            matched_count = sum(1 for k in keys if k.lower() in all_text)

            # Require at least 2 keys matched (or all if only 2 keys)
            min_match = min(2, len(keys))
            if matched_count >= min_match:
                # Find matching nodes for this chain
                chain_nodes = []
                for k in keys:
                    k_lower = k.lower()
                    for node in self._nodes:
                        if k_lower in node.name.lower() or k_lower in node.category.lower():
                            if node not in chain_nodes:
                                chain_nodes.append(node)
                                break

                if len(chain_nodes) < min_match:
                    continue

                confidence = matched_count / len(keys)
                chain = AttackChain(
                    chain_id=f'chain_{chain_idx}',
                    chain_name=pattern['name'],
                    nodes=chain_nodes[:max_depth],
                    severity=pattern['severity'],
                    confidence=round(confidence, 2),
                    description=pattern['blast'],
                    mitre_techniques=pattern.get('mitre', []),
                    blast_radius=pattern['blast'],
                )
                chains.append(chain)
                chain_idx += 1

        return chains

    def score_chain(self, chain: AttackChain) -> float:
        """Score a chain based on severity and confidence."""
        severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        base = severity_scores.get(chain.severity, 0)
        return round(base * chain.confidence * len(chain.nodes), 2)

    # ── Query ─────────────────────────────────────────────────────────────

    def get_critical_paths(self) -> list[AttackChain]:
        """Return chains sorted by score descending."""
        return sorted(self._chains, key=lambda c: self.score_chain(c), reverse=True)

    def calculate_blast_radius(self, starting_vuln: AttackNode) -> dict:
        """Calculate what an attacker can reach starting from a given vulnerability."""
        reachable = set()
        max_impact = 'info'
        impact_priority = {'rce': 5, 'data_exfil': 4, 'account_takeover': 3, 'dos': 2, 'info': 1}

        for chain in self._chains:
            node_ids = [n.vuln_id for n in chain.nodes]
            if starting_vuln.vuln_id in node_ids:
                idx = node_ids.index(starting_vuln.vuln_id)
                for n in chain.nodes[idx:]:
                    reachable.add(n.affected_url)

                # Determine impact from blast_radius text
                blast = chain.blast_radius.lower()
                if 'rce' in blast or 'code execution' in blast:
                    candidate = 'rce'
                elif 'data' in blast or 'exfil' in blast or 'database' in blast:
                    candidate = 'data_exfil'
                elif 'account' in blast or 'takeover' in blast or 'impersonat' in blast:
                    candidate = 'account_takeover'
                elif 'dos' in blast or 'denial' in blast:
                    candidate = 'dos'
                else:
                    candidate = 'info'

                if impact_priority.get(candidate, 0) > impact_priority.get(max_impact, 0):
                    max_impact = candidate

        blast_score = min(100, len(reachable) * 15 + impact_priority.get(max_impact, 0) * 10)

        return {
            'reachable_systems': list(reachable),
            'max_impact': max_impact,
            'blast_score': blast_score,
        }

    def get_remediation_order(self) -> list[dict]:
        """Return vulnerabilities sorted by remediation priority.

        Priority:
          1. Vulns that appear as prerequisite in the most chains
          2. Vulns with highest severity
          3. Vulns with lowest estimated remediation effort
        """
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        chain_count: dict[str, int] = {}

        for chain in self._chains:
            for node in chain.nodes:
                chain_count[node.vuln_id] = chain_count.get(node.vuln_id, 0) + 1

        results = []
        for node in self._nodes:
            results.append({
                'vuln_id': node.vuln_id,
                'name': node.name,
                'severity': node.severity,
                'category': node.category,
                'affected_url': node.affected_url,
                'chain_appearances': chain_count.get(node.vuln_id, 0),
                'severity_score': severity_scores.get(node.severity, 0),
                'priority_score': (
                    chain_count.get(node.vuln_id, 0) * 10
                    + severity_scores.get(node.severity, 0) * 3
                ),
            })

        return sorted(results, key=lambda r: r['priority_score'], reverse=True)

    # ── MITRE Mapping ─────────────────────────────────────────────────────

    def map_mitre(self, vuln: dict) -> list[str]:
        """Map a vulnerability to MITRE ATT&CK technique IDs."""
        category = (vuln.get('category', '') or '').lower()
        name = (vuln.get('name', '') or '').lower()

        techniques = set()
        for key, tech_ids in MITRE_MAP.items():
            if key in category or key in name:
                techniques.update(tech_ids)
        return sorted(techniques)

    def get_mitre_summary(self) -> dict:
        """Return summary of MITRE ATT&CK techniques covered by findings."""
        technique_map: dict[str, list[str]] = {}
        for node in self._nodes:
            for key, tech_ids in MITRE_MAP.items():
                if key in node.category or key in node.name.lower():
                    for tid in tech_ids:
                        technique_map.setdefault(tid, []).append(node.name)

        return {
            'techniques': {tid: list(set(names)) for tid, names in technique_map.items()},
            'technique_count': len(technique_map),
            'finding_count': len(self._nodes),
        }

    # ── Export ────────────────────────────────────────────────────────────

    def to_mermaid(self) -> str:
        """Export as Mermaid graph LR diagram string."""
        if not self._chains:
            return 'graph LR\n    NONE[No attack chains detected]'

        lines = ['graph LR']
        node_labels: dict[str, str] = {}
        for node in self._nodes:
            safe_id = node.vuln_id.replace('-', '_')
            label = f'{node.name} ({node.severity.upper()})'
            node_labels[node.vuln_id] = safe_id
            # Style by severity
            if node.severity == 'critical':
                lines.append(f'    {safe_id}["{label}"]:::critical')
            elif node.severity == 'high':
                lines.append(f'    {safe_id}["{label}"]:::high')
            else:
                lines.append(f'    {safe_id}["{label}"]')

        for src, dst in self._edges:
            src_id = node_labels.get(src, src.replace('-', '_'))
            dst_id = node_labels.get(dst, dst.replace('-', '_'))
            lines.append(f'    {src_id} --> {dst_id}')

        # Add styles
        lines.append('    classDef critical fill:#ff4444,stroke:#cc0000,color:#fff')
        lines.append('    classDef high fill:#ff8800,stroke:#cc6600,color:#fff')

        return '\n'.join(lines)

    def to_dot(self) -> str:
        """Export as Graphviz DOT format."""
        lines = ['digraph AttackGraph {', '    rankdir=LR;', '    node [shape=box];']

        severity_colors = {
            'critical': '#ff4444', 'high': '#ff8800',
            'medium': '#ffcc00', 'low': '#44cc44', 'info': '#4488ff',
        }

        for node in self._nodes:
            color = severity_colors.get(node.severity, '#cccccc')
            safe_id = node.vuln_id.replace('-', '_')
            label = f'{node.name}\\n({node.severity})'
            lines.append(f'    {safe_id} [label="{label}" fillcolor="{color}" style=filled];')

        for src, dst in self._edges:
            src_id = src.replace('-', '_')
            dst_id = dst.replace('-', '_')
            lines.append(f'    {src_id} -> {dst_id};')

        lines.append('}')
        return '\n'.join(lines)
