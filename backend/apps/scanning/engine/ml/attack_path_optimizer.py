"""
Attack Path Optimizer — Graph-based vulnerability chaining and EPSS-inspired
risk prioritization for multi-stage attack scenario generation.

Known attack progressions encode how one vulnerability class can enable
another, forming directed edges in the attack graph.  The optimizer:

  1. Builds a directed vulnerability graph from a list of findings
  2. Finds all valid attack chains up to `max_length` steps
  3. Prioritizes findings by composite risk (CVSS + chain bonus + tech risk)
  4. Suggests the most impactful exploit chain with narrative steps

EPSS estimates are synthetic — approximated from CWE characteristics since
real EPSS data requires daily CVE feed access.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── Known vulnerability progressions ─────────────────────────────────────────
# Format: (source_category, target_category, edge_label, probability)

_PROGRESSIONS: list[tuple[str, str, str, float]] = [
    # SQL Injection chains
    ('sqli',              'auth',             'auth bypass via SQLi',         0.85),
    ('sqli',              'data exposure',    'data dump via SQLi',           0.90),
    ('auth',              'misconfig',        'admin panel access',           0.70),
    ('misconfig',         'cmdi',             'RCE via misconfigured admin',  0.60),

    # SSRF chains
    ('ssrf',              'data exposure',    'cloud metadata via SSRF',      0.80),
    ('ssrf',              'cmdi',             'internal service exploitation', 0.55),
    ('data exposure',     'auth',             'credential theft → login',     0.75),

    # XSS chains
    ('xss',               'csrf',             'CSRF via XSS',                 0.70),
    ('xss',               'auth',             'session/cookie theft via XSS', 0.75),
    ('auth',              'idor',             'horizontal privilege escalation', 0.65),

    # LFI / Path Traversal chains
    ('lfi',               'data exposure',    'config file read',             0.85),
    ('path traversal',    'data exposure',    'sensitive file disclosure',    0.90),
    ('data exposure',     'auth',             'credential theft',             0.75),

    # Open Redirect → OAuth
    ('open redirect',     'auth',             'OAuth token theft',            0.65),

    # File Upload → RCE
    ('file upload',       'cmdi',             'webshell → RCE',               0.80),

    # Deserialization → RCE
    ('deserialization',   'cmdi',             'RCE via deserialization',      0.90),

    # IDOR chains
    ('idor',              'data exposure',    'mass data extraction via IDOR', 0.80),
    ('idor',              'auth',             'account takeover via IDOR',    0.65),

    # Supply chain
    ('supply chain',      'cmdi',             'compromised dependency → RCE', 0.70),

    # JWT / Auth chains
    ('jwt',               'auth',             'auth bypass via JWT exploit',  0.80),
    ('jwt',               'idor',             'privilege escalation via JWT', 0.65),

    # SSTI → RCE
    ('ssti',              'cmdi',             'RCE via SSTI',                 0.90),

    # XXE chains
    ('xxe',               'ssrf',             'SSRF via XXE',                 0.75),
    ('xxe',               'data exposure',    'file disclosure via XXE',      0.85),

    # Prototype pollution
    ('prototype pollution', 'auth',           'privilege escalation',         0.55),
    ('prototype pollution', 'cmdi',           'RCE via polluted property',    0.50),

    # Host header injection
    ('host header',       'ssrf',             'internal SSRF via host header', 0.65),
    ('host header',       'auth',             'password reset poisoning',     0.70),

    # Cache poisoning
    ('cache poisoning',   'xss',              'stored XSS via cache',         0.60),
    ('cache poisoning',   'auth',             'session fixation via cache',   0.55),
]

# Build fast lookup sets
_OUTGOING: dict[str, list[tuple[str, str, float]]] = {}
for src, dst, label, prob in _PROGRESSIONS:
    _OUTGOING.setdefault(src, []).append((dst, label, prob))

# High-impact terminal categories (end of chain markers)
_TERMINAL_CATEGORIES = frozenset({'cmdi', 'ssrf', 'data exposure', 'auth'})

# Tech stack risk multipliers
_TECH_RISK: dict[str, float] = {
    'php':      1.20,  # PHP has high legacy vulnerability density
    'java':     1.15,
    'aspnet':   1.10,
    'python':   0.95,
    'nodejs':   1.05,
    'ruby':     1.00,
    'golang':   0.85,
    'unknown':  1.00,
}

# Synthetic EPSS base scores per CWE (approximated from NVD statistics)
_EPSS_BY_CWE: dict[str, float] = {
    'CWE-89':   0.72,   # SQL Injection
    'CWE-79':   0.65,   # XSS
    'CWE-78':   0.85,   # OS Command Injection
    'CWE-306':  0.60,   # Missing Authentication
    'CWE-502':  0.78,   # Deserialization
    'CWE-22':   0.68,   # Path Traversal
    'CWE-611':  0.55,   # XXE
    'CWE-918':  0.70,   # SSRF
    'CWE-352':  0.45,   # CSRF
    'CWE-94':   0.80,   # Code Injection
    'CWE-434':  0.75,   # Unrestricted Upload
    'CWE-862':  0.62,   # IDOR / Missing Authorization
    'CWE-601':  0.50,   # SSTI (same bucket as code injection)
    'CWE-287':  0.65,   # Improper Authentication
    'CWE-200':  0.55,   # Information Exposure
    'CWE-798':  0.82,   # Hard-coded Credentials
    'CWE-1021': 0.40,   # Clickjacking
    'CWE-116':  0.45,   # Encoding Issues (prototype pollution proxy)
    'CWE-312':  0.60,   # Cleartext Storage
    'CWE-540':  0.50,   # Source Map / Info Disclosure
    'CWE-489':  0.55,   # Debug Code in Production
}


# ── Public API ────────────────────────────────────────────────────────────────

def build_attack_graph(vulns: list[dict]) -> dict:
    """Build a directed attack graph from a list of vulnerability findings.

    Returns:
        {
            'nodes': list[dict],     # {id, name, category, severity, cvss}
            'edges': list[dict],     # {src_id, dst_id, label, probability}
            'adjacency': dict,       # category → list of dst categories
        }
    """
    nodes = []
    edges = []
    cat_to_node_ids: dict[str, list[int]] = {}

    for i, v in enumerate(vulns):
        cat = (v.get('category', '') or '').lower().strip()
        node = {
            'id': i,
            'name': v.get('name', f'vuln_{i}'),
            'category': cat,
            'severity': v.get('severity', 'info'),
            'cvss': v.get('cvss', 0.0),
            'cwe': v.get('cwe', ''),
        }
        nodes.append(node)
        cat_to_node_ids.setdefault(cat, []).append(i)

    # Build edges from known progressions
    for src_cat, dst_cat, label, prob in _PROGRESSIONS:
        src_ids = cat_to_node_ids.get(src_cat, [])
        dst_ids = cat_to_node_ids.get(dst_cat, [])
        for s in src_ids:
            for d in dst_ids:
                if s != d:
                    edges.append({
                        'src_id': s,
                        'dst_id': d,
                        'label': label,
                        'probability': prob,
                    })

    adjacency = {
        cat: [dst for dst, _, _ in out]
        for cat, out in _OUTGOING.items()
    }

    return {'nodes': nodes, 'edges': edges, 'adjacency': adjacency}


def find_attack_chains(
    graph: dict,
    max_length: int = 5,
) -> list[dict]:
    """Find all attack chains via DFS over the vulnerability graph.

    Returns:
        list of {
            'steps': list[str],          # human-readable chain labels
            'categories': list[str],     # vulnerability categories
            'total_cvss': float,         # sum of CVSS scores
            'min_probability': float,    # chain likelihood (product of edge probs)
            'impact': str,               # classification
        }
    """
    nodes = graph.get('nodes', [])
    edges = graph.get('edges', [])

    if not nodes or not edges:
        return []

    # Build adjacency by node id
    adj: dict[int, list[tuple[int, str, float]]] = {}
    for e in edges:
        adj.setdefault(e['src_id'], []).append(
            (e['dst_id'], e['label'], e['probability'])
        )

    chains: list[dict] = []

    def dfs(node_id: int, path: list[int], labels: list[str], prob: float):
        if len(path) >= max_length:
            return
        for dst_id, label, edge_prob in adj.get(node_id, []):
            if dst_id in path:
                continue  # avoid cycles
            new_prob = prob * edge_prob
            new_path = path + [dst_id]
            new_labels = labels + [label]
            if len(new_path) >= 2:
                chain_cats = [nodes[i]['category'] for i in new_path]
                total_cvss = sum(nodes[i].get('cvss', 0.0) for i in new_path)
                chains.append({
                    'steps': new_labels,
                    'categories': chain_cats,
                    'total_cvss': round(total_cvss, 1),
                    'min_probability': round(new_prob, 3),
                    'impact': _classify_chain_impact(chain_cats),
                })
            dfs(dst_id, new_path, new_labels, new_prob)

    for node in nodes:
        dfs(node['id'], [node['id']], [], 1.0)

    # De-duplicate and sort by total CVSS descending
    seen: set[tuple] = set()
    unique: list[dict] = []
    for c in chains:
        key = tuple(c['categories'])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    unique.sort(key=lambda x: (x['total_cvss'], x['min_probability']), reverse=True)
    return unique[:20]  # Return top 20 chains


def prioritize_by_risk(vulns: list[dict], tech_stack: str = 'unknown') -> list[dict]:
    """Rank vulnerabilities by composite risk score.

    Risk = CVSS_base × tech_multiplier × EPSS_weight × chain_bonus

    Returns:
        list of vuln dicts with added 'risk_score' field, sorted descending
    """
    if not vulns:
        return []

    tech = (tech_stack or 'unknown').lower().strip()
    tech_mult = _TECH_RISK.get(tech, 1.00)

    # Build a quick chain set for chain bonus
    graph = build_attack_graph(vulns)
    chains = find_attack_chains(graph)
    chain_cats: set[str] = set()
    for chain in chains:
        chain_cats.update(chain.get('categories', []))

    scored = []
    for v in vulns:
        cvss = float(v.get('cvss', 0.0))
        cwe = v.get('cwe', '')
        cat = (v.get('category', '') or '').lower().strip()

        epss = get_epss_estimate(cwe)
        chain_bonus = 1.20 if cat in chain_cats else 1.00
        risk = cvss * tech_mult * (0.5 + 0.5 * epss) * chain_bonus

        v_copy = dict(v)
        v_copy['risk_score'] = round(risk, 3)
        v_copy['epss_estimate'] = epss
        v_copy['in_attack_chain'] = cat in chain_cats
        scored.append(v_copy)

    scored.sort(key=lambda x: x['risk_score'], reverse=True)
    return scored


def get_epss_estimate(cwe_id: str) -> float:
    """Return a synthetic EPSS estimate for a given CWE.

    Returns float 0.0–1.0 (higher = more likely to be exploited in the wild)
    """
    if not cwe_id:
        return 0.50
    score = _EPSS_BY_CWE.get(cwe_id.strip().upper(), 0.50)
    return round(score, 3)


def suggest_exploit_chain(vulns: list[dict]) -> dict:
    """Suggest the single most impactful exploit chain from given findings.

    Returns:
        {
            'found': bool,
            'chain': list[str],       # step descriptions
            'categories': list[str],
            'impact': str,
            'total_cvss': float,
            'narrative': str,         # single-sentence description
        }
    """
    if not vulns:
        return {'found': False, 'chain': [], 'categories': [], 'impact': 'none', 'total_cvss': 0.0, 'narrative': 'No vulnerabilities to chain.'}

    graph = build_attack_graph(vulns)
    chains = find_attack_chains(graph)

    if not chains:
        # Fall back: highest single finding
        best = max(vulns, key=lambda v: float(v.get('cvss', 0.0)))
        cat = best.get('category', 'unknown')
        return {
            'found': False,
            'chain': [best.get('name', cat)],
            'categories': [cat],
            'impact': _classify_chain_impact([cat]),
            'total_cvss': float(best.get('cvss', 0.0)),
            'narrative': f'No chaining possible; highest risk: {best.get("name", cat)}.',
        }

    best = chains[0]
    steps = best.get('steps', [])
    cats = best.get('categories', [])
    narrative = _build_narrative(cats, steps)

    return {
        'found': True,
        'chain': steps,
        'categories': cats,
        'impact': best.get('impact', 'unknown'),
        'total_cvss': best.get('total_cvss', 0.0),
        'narrative': narrative,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _classify_chain_impact(categories: list[str]) -> str:
    """Classify the overall impact of an attack chain."""
    cats = set(categories)
    if 'cmdi' in cats:
        return 'Remote Code Execution'
    if 'ssrf' in cats and 'data exposure' in cats:
        return 'Cloud Compromise / Data Breach'
    if 'auth' in cats and ('sqli' in cats or 'jwt' in cats):
        return 'Authentication Bypass'
    if 'data exposure' in cats:
        return 'Data Breach'
    if 'xss' in cats and 'auth' in cats:
        return 'Account Takeover'
    if 'idor' in cats and 'data exposure' in cats:
        return 'Mass Data Extraction'
    if len(categories) >= 3:
        return 'Multi-Stage Compromise'
    return 'Privilege Escalation'


def _build_narrative(categories: list[str], steps: list[str]) -> str:
    """Build a human-readable attack chain narrative."""
    if not categories:
        return 'No attack chain identified.'
    start = categories[0].upper()
    categories[-1].upper() if len(categories) > 1 else start
    impact = _classify_chain_impact(categories)
    n_steps = len(steps)
    return (
        f'Attacker exploits {start} ({n_steps}-step chain) '
        f'escalating through {" → ".join(categories)} '
        f'leading to {impact}.'
    )
