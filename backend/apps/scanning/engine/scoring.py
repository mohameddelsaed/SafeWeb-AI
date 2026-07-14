"""
CVSS 3.1 base score calculator and security score utilities.
"""
import math


# CVSS 3.1 Base Score metrics and weights
ATTACK_VECTOR = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
ATTACK_COMPLEXITY = {'L': 0.77, 'H': 0.44}
PRIVILEGES_REQUIRED = {
    'N': {'U': 0.85, 'C': 0.85},  # Scope Unchanged / Changed
    'L': {'U': 0.62, 'C': 0.68},
    'H': {'U': 0.27, 'C': 0.50},
}
USER_INTERACTION = {'N': 0.85, 'R': 0.62}
CONFIDENTIALITY = {'N': 0.0, 'L': 0.22, 'H': 0.56}
INTEGRITY = {'N': 0.0, 'L': 0.22, 'H': 0.56}
AVAILABILITY = {'N': 0.0, 'L': 0.22, 'H': 0.56}

# Severity to CVSS mapping (defaults)
SEVERITY_CVSS_MAP = {
    'critical': 9.5,
    'high': 7.5,
    'medium': 5.0,
    'low': 3.0,
    'info': 0.0,
}


def calculate_cvss_base(
    av='N', ac='L', pr='N', ui='N', scope='U',
    c='N', i='N', a='N'
) -> float:
    """
    Calculate CVSS 3.1 base score.

    Parameters:
    - av: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
    - ac: Attack Complexity (L=Low, H=High)
    - pr: Privileges Required (N=None, L=Low, H=High)
    - ui: User Interaction (N=None, R=Required)
    - scope: Scope (U=Unchanged, C=Changed)
    - c: Confidentiality Impact (N=None, L=Low, H=High)
    - i: Integrity Impact (N=None, L=Low, H=High)
    - a: Availability Impact (N=None, L=Low, H=High)
    """
    scope_key = 'U' if scope == 'U' else 'C'

    iss = 1 - (
        (1 - CONFIDENTIALITY.get(c, 0)) *
        (1 - INTEGRITY.get(i, 0)) *
        (1 - AVAILABILITY.get(a, 0))
    )

    if scope == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = (
        8.22 *
        ATTACK_VECTOR.get(av, 0.85) *
        ATTACK_COMPLEXITY.get(ac, 0.77) *
        PRIVILEGES_REQUIRED.get(pr, {}).get(scope_key, 0.85) *
        USER_INTERACTION.get(ui, 0.85)
    )

    if impact <= 0:
        return 0.0

    if scope == 'U':
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)

    return math.ceil(score * 10) / 10


def severity_from_cvss(cvss: float) -> str:
    """Get severity label from CVSS score."""
    if cvss >= 9.0:
        return 'critical'
    elif cvss >= 7.0:
        return 'high'
    elif cvss >= 4.0:
        return 'medium'
    elif cvss >= 0.1:
        return 'low'
    return 'info'


def calculate_security_score(vulnerabilities: list) -> int:
    """
    Calculate an overall security score (0-100) from vulnerabilities.
    100 = perfect security, 0 = severely compromised.

    Applies diminishing returns: each subsequent vulnerability of the same
    severity deducts 80% of the previous one, preventing a single category
    from flooding the score to zero.
    """
    if not vulnerabilities:
        return 100

    # Weight deductions by severity
    base_deductions = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3,
        'info': 0,
    }

    # Count vulns per severity for diminishing returns
    severity_counts = {}
    total_deduction = 0.0

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info') if isinstance(vuln, dict) else getattr(vuln, 'severity', 'info')
        base = base_deductions.get(severity, 0)
        if base == 0:
            continue

        count = severity_counts.get(severity, 0)
        # Diminishing returns: each subsequent vuln deducts 80% of the previous
        deduction = base * (0.8 ** count)
        total_deduction += deduction
        severity_counts[severity] = count + 1

    score = max(0, round(100 - total_deduction))
    return score


def categorize_score(score: int) -> str:
    """Get a letter grade from security score."""
    if score >= 90:
        return 'A'
    elif score >= 80:
        return 'B'
    elif score >= 70:
        return 'C'
    elif score >= 50:
        return 'D'
    return 'F'
