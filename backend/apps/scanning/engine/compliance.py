"""
Compliance Mapping — Phase 17.
Maps vulnerability categories to OWASP Top 10 2021 and PCI DSS v4 requirements.
"""

# ── OWASP Top 10 2021 ────────────────────────────────────────────────────

COMPLIANCE_MAP = {
    'owasp_top10_2021': {
        'A01': ['IDOR', 'CSRF', 'AccessControl', 'OpenRedirect', 'Insecure Direct Object Reference',
                'Cross-Site Request Forgery', 'Open Redirect'],
        'A02': ['DataExposure', 'JWT', 'Deserialization', 'JWT Vulnerability',
                'Sensitive Data Exposure', 'Weak Cipher'],
        'A03': ['XSS', 'SQLi', 'SSTI', 'CMDi', 'CRLF', 'NoSQL', 'LDAPXPath',
                'Cross-Site Scripting', 'SQL Injection', 'Server-Side Template Injection',
                'Command Injection', 'CRLF Injection', 'NoSQL Injection', 'LDAP Injection',
                'XPath Injection', 'HTML Injection'],
        'A04': ['FileUpload', 'BusinessLogic', 'RaceCondition', 'PathTraversal', 'SSI',
                'File Upload', 'Race Condition', 'Path Traversal', 'Server-Side Include',
                'Mass Assignment', 'Business Logic Vulnerability'],
        'A05': ['Misconfig', 'CORS', 'Clickjacking', 'XXE', 'HostHeader', 'HTTPSmuggling',
                'Security Misconfiguration', 'Clickjacking', 'HTTP Smuggling',
                'X-Powered-By Disclosure', 'Server Version Disclosure',
                'HTTP Security Headers Missing'],
        'A06': ['Component', 'Outdated Component', 'Vulnerable Dependency'],
        'A07': ['Auth', 'Authentication Bypass', 'Weak Password', 'Session Fixation',
                'Broken Authentication'],
        'A08': ['Deserialization', 'Unsafe Deserialization'],
        'A09': ['Logging', 'Error Disclosure', 'Stack Trace Exposure'],
        'A10': ['SSRF', 'Server-Side Request Forgery'],
    },
    'pci_dss_v4': {
        '6.2.4': ['SQLi', 'XSS', 'CMDi', 'SQL Injection', 'Cross-Site Scripting',
                  'Command Injection', 'SSTI', 'Server-Side Template Injection'],
        '6.3.2': ['Component', 'Outdated Component', 'Vulnerable Dependency'],
        '6.4.1': ['Misconfig', 'Logging', 'Security Misconfiguration',
                  'Error Disclosure', 'Stack Trace Exposure'],
    },
}


def get_owasp_coverage(vulnerabilities: list) -> dict:
    """
    Given a list of vulnerability objects or dicts, return a dict mapping
    OWASP category ID → count of matching findings.
    e.g. {'A01': 2, 'A03': 5, ...}
    """
    categories = COMPLIANCE_MAP['owasp_top10_2021']
    counts = {cat: 0 for cat in categories}

    for v in vulnerabilities:
        cat = v.category if hasattr(v, 'category') else v.get('category', '')
        name = v.name if hasattr(v, 'name') else v.get('name', '')
        for owasp_cat, cat_list in categories.items():
            if cat in cat_list or name in cat_list:
                counts[owasp_cat] += 1

    return counts


def get_pci_coverage(vulnerabilities: list) -> dict:
    """
    Return a dict mapping PCI DSS requirement → count of matching findings.
    e.g. {'6.2.4': 3, '6.3.2': 0, '6.4.1': 1}
    """
    requirements = COMPLIANCE_MAP['pci_dss_v4']
    counts = {req: 0 for req in requirements}

    for v in vulnerabilities:
        cat = v.category if hasattr(v, 'category') else v.get('category', '')
        name = v.name if hasattr(v, 'name') else v.get('name', '')
        for req, cat_list in requirements.items():
            if cat in cat_list or name in cat_list:
                counts[req] += 1

    return counts


def get_compliance_summary(vulnerabilities: list) -> dict:
    """Return a combined compliance summary dict."""
    return {
        'owasp_top10_2021': get_owasp_coverage(vulnerabilities),
        'pci_dss_v4': get_pci_coverage(vulnerabilities),
    }
