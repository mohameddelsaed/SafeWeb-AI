"""
Vulnerability Knowledge Base — Phase 41.

Provides structured, machine-readable records for 12 common web vulnerability
classes.  Each record contains:

  - Human-readable description
  - MITRE ATT&CK tactic / technique mapping
  - Real-world exploitation examples
  - Canonical CVE reference examples
  - OWASP Testing Guide (WSTG) references
  - OWASP Top 10 2021 category
  - CVSS score range (min / max)

Lookups are keyed by CWE string ('CWE-89', etc.).  An alternative lookup by
short ``id`` ('sqli', 'xss', …) is also supported via :func:`get_by_id`.
"""
from __future__ import annotations

from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Vulnerability Database
# ──────────────────────────────────────────────────────────────────────────────

VULNERABILITY_DB: dict[str, dict] = {

    'CWE-89': {
        'id': 'sqli',
        'name': 'SQL Injection',
        'cwe': 'CWE-89',
        'description': (
            'SQL Injection occurs when user-supplied input is incorporated into '
            'an SQL query without adequate sanitisation or parameterisation.  An '
            'attacker can alter the query logic to bypass authentication, exfiltrate '
            'data, modify or delete records, and, in some database configurations, '
            'execute operating-system commands.'
        ),
        'mitre_attack': {
            'tactic': 'Initial Access / Credential Access / Exfiltration',
            'technique': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'url': 'https://attack.mitre.org/techniques/T1190/',
        },
        'cvss_range': {'min': 5.0, 'max': 9.8},
        'real_world_examples': [
            {
                'title': 'Heartland Payment Systems (2008)',
                'description': 'Attackers used SQL Injection to compromise 134 million '
                               'credit cards via malicious SQL commands injected through '
                               'the payment processing web form.',
            },
            {
                'title': 'British Airways (2018)',
                'description': 'Skimming malware was planted via an SQLi entry point, '
                               'compromising 500 000 customer records and payment details.',
            },
            {
                'title': 'Yahoo! (2012)',
                'description': 'The hacker group D33Ds extracted 450 000 credentials '
                               'from Yahoo! Voices via a UNION-based SQL Injection.',
            },
        ],
        'cve_examples': ['CVE-2012-2122', 'CVE-2019-19781', 'CVE-2021-27101'],
        'owasp_testing_guide': ['WSTG-INPV-05'],
        'owasp_top10_2021': 'A03:2021 — Injection',
    },

    'CWE-79': {
        'id': 'xss',
        'name': 'Cross-Site Scripting (XSS)',
        'cwe': 'CWE-79',
        'description': (
            'Cross-Site Scripting allows attackers to inject client-side scripts '
            'into web pages viewed by other users.  Reflected XSS is delivered via '
            'a crafted URL; Stored XSS is persisted in the database; DOM XSS arises '
            'from unsafe DOM manipulation.  All variants can lead to session '
            'hijacking, credential theft, malware distribution, and defacement.'
        ),
        'mitre_attack': {
            'tactic': 'Credential Access / Lateral Movement',
            'technique': 'T1059.007',
            'technique_name': 'Command and Scripting Interpreter: JavaScript',
            'url': 'https://attack.mitre.org/techniques/T1059/007/',
        },
        'cvss_range': {'min': 3.1, 'max': 8.8},
        'real_world_examples': [
            {
                'title': 'Twitter worm (2010)',
                'description': 'The "onMouseOver" XSS worm spread to hundreds of '
                               'thousands of Twitter accounts in hours via a stored XSS '
                               'payload embedded in tweets.',
            },
            {
                'title': 'eBay (2015–2016)',
                'description': 'Stored XSS in item listings allowed attackers to redirect '
                               'buyers to phishing pages to harvest PayPal credentials.',
            },
            {
                'title': 'British Airways Magecart (2018)',
                'description': 'A DOM-based XSS vector was exploited to host a card '
                               'skimmer script on BA\'s booking page.',
            },
        ],
        'cve_examples': ['CVE-2021-44228', 'CVE-2020-11022', 'CVE-2019-16278'],
        'owasp_testing_guide': ['WSTG-CLNT-01', 'WSTG-CLNT-02', 'WSTG-CLNT-03'],
        'owasp_top10_2021': 'A03:2021 — Injection',
    },

    'CWE-918': {
        'id': 'ssrf',
        'name': 'Server-Side Request Forgery (SSRF)',
        'cwe': 'CWE-918',
        'description': (
            'SSRF forces the server to make HTTP requests on the attacker\'s behalf. '
            'Targets include internal services (databases, admin panels), cloud '
            'metadata endpoints (AWS IMDSv1 at 169.254.169.254), and intranet '
            'resources that are not reachable from the public internet.  Impact '
            'ranges from information disclosure to full cloud account takeover.'
        ),
        'mitre_attack': {
            'tactic': 'Discovery / Credential Access',
            'technique': 'T1526',
            'technique_name': 'Cloud Service Discovery',
            'url': 'https://attack.mitre.org/techniques/T1526/',
        },
        'cvss_range': {'min': 5.8, 'max': 9.8},
        'real_world_examples': [
            {
                'title': 'Capital One (2019)',
                'description': 'A misconfigured WAF allowed an SSRF request to the AWS '
                               'IMDSv1 endpoint, exposing IAM role credentials and leading '
                               'to the exfiltration of 100 million customer records.',
            },
            {
                'title': 'GitLab (2021 — CVE-2021-22214)',
                'description': 'SSRF in the CI/CD pipeline webhook feature allowed '
                               'access to internal services, including the GitLab internal '
                               'API and Redis.',
            },
        ],
        'cve_examples': ['CVE-2021-22214', 'CVE-2019-11043', 'CVE-2021-26855'],
        'owasp_testing_guide': ['WSTG-INPV-19'],
        'owasp_top10_2021': 'A10:2021 — Server-Side Request Forgery (SSRF)',
    },

    'CWE-639': {
        'id': 'idor',
        'name': 'Insecure Direct Object Reference (IDOR)',
        'cwe': 'CWE-639',
        'description': (
            'IDOR occurs when an application uses user-controllable input to access '
            'objects directly without authorisation checks.  Attackers increment or '
            'alter numeric IDs, UUIDs, filenames, or other references to access '
            'records belonging to other users.  Impact includes mass data extraction '
            'and privilege escalation.'
        ),
        'mitre_attack': {
            'tactic': 'Collection / Exfiltration',
            'technique': 'T1213',
            'technique_name': 'Data from Information Repositories',
            'url': 'https://attack.mitre.org/techniques/T1213/',
        },
        'cvss_range': {'min': 4.3, 'max': 8.6},
        'real_world_examples': [
            {
                'title': 'Facebook (2015)',
                'description': 'An IDOR in the Facebook business manager allowed any '
                               'user to read another user\'s business payment methods by '
                               'changing a numeric account ID in the API request.',
            },
            {
                'title': 'Parler (2021)',
                'description': 'Sequential video IDs exposed via an IDOR allowed '
                               'researchers to download 80 TB of data, including metadata '
                               'with GPS coordinates of deleted posts.',
            },
        ],
        'cve_examples': ['CVE-2020-9373', 'CVE-2021-43858'],
        'owasp_testing_guide': ['WSTG-ATHZ-04'],
        'owasp_top10_2021': 'A01:2021 — Broken Access Control',
    },

    'CWE-22': {
        'id': 'path_traversal',
        'name': 'Path Traversal',
        'cwe': 'CWE-22',
        'description': (
            'Path Traversal exploits insufficient validation of file path inputs to '
            'read (or write) files outside the intended directory.  Using sequences '
            'such as "../" or URL-encoded variants, attackers access configuration '
            'files, private keys, /etc/passwd, and application source code.'
        ),
        'mitre_attack': {
            'tactic': 'Collection',
            'technique': 'T1083',
            'technique_name': 'File and Directory Discovery',
            'url': 'https://attack.mitre.org/techniques/T1083/',
        },
        'cvss_range': {'min': 5.3, 'max': 9.8},
        'real_world_examples': [
            {
                'title': 'Citrix ADC (CVE-2019-19781)',
                'description': 'A path traversal vulnerability allowed unauthenticated '
                               'remote code execution on Citrix ADC / Gateway devices, '
                               'affecting ≈80 000 companies globally.',
            },
            {
                'title': 'Apache HTTP Server (CVE-2021-41773)',
                'description': 'A path traversal and RCE flaw in Apache 2.4.49 allowed '
                               'directory traversal attacks outside the document root.',
            },
        ],
        'cve_examples': ['CVE-2019-19781', 'CVE-2021-41773', 'CVE-2020-1938'],
        'owasp_testing_guide': ['WSTG-ATHZ-01'],
        'owasp_top10_2021': 'A01:2021 — Broken Access Control',
    },

    'CWE-611': {
        'id': 'xxe',
        'name': 'XML External Entity Injection (XXE)',
        'cwe': 'CWE-611',
        'description': (
            'XXE injection exploits XML parsers that process external entity '
            'declarations.  Attackers define a SYSTEM entity referencing local '
            'files or internal URLs, enabling arbitrary file read, SSRF, port '
            'scanning, and in extreme cases, denial of service via billion-laughs '
            'attacks.'
        ),
        'mitre_attack': {
            'tactic': 'Initial Access / Collection',
            'technique': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'url': 'https://attack.mitre.org/techniques/T1190/',
        },
        'cvss_range': {'min': 5.0, 'max': 9.8},
        'real_world_examples': [
            {
                'title': 'Facebook (2014)',
                'description': 'An XXE vulnerability in a Facebook image parsing library '
                               'allowed reading arbitrary local files from Facebook\'s '
                               'internal servers.',
            },
        ],
        'cve_examples': ['CVE-2021-23839', 'CVE-2019-3396', 'CVE-2018-1000632'],
        'owasp_testing_guide': ['WSTG-INPV-07'],
        'owasp_top10_2021': 'A05:2021 — Security Misconfiguration',
    },

    'CWE-352': {
        'id': 'csrf',
        'name': 'Cross-Site Request Forgery (CSRF)',
        'cwe': 'CWE-352',
        'description': (
            'CSRF tricks an authenticated victim into submitting a malicious '
            'request to a web application where they are logged in.  Since the '
            'browser automatically sends session cookies, the application processes '
            'the fraudulent request as legitimate, allowing attackers to perform '
            'state-changing actions on behalf of the victim.'
        ),
        'mitre_attack': {
            'tactic': 'Impact',
            'technique': 'T1565',
            'technique_name': 'Data Manipulation',
            'url': 'https://attack.mitre.org/techniques/T1565/',
        },
        'cvss_range': {'min': 4.3, 'max': 8.8},
        'real_world_examples': [
            {
                'title': 'Gmail CSRF (2007)',
                'description': 'A CSRF vulnerability in Gmail allowed attackers to '
                               'create email forwarding filters by tricking users into '
                               'visiting a malicious page.',
            },
        ],
        'cve_examples': ['CVE-2019-14273', 'CVE-2020-11710'],
        'owasp_testing_guide': ['WSTG-SESS-05'],
        'owasp_top10_2021': 'A01:2021 — Broken Access Control',
    },

    'CWE-601': {
        'id': 'open_redirect',
        'name': 'Open Redirect',
        'cwe': 'CWE-601',
        'description': (
            'Open Redirect allows attackers to specify an arbitrary destination URL '
            'via a user-controlled parameter (e.g., ?next=, ?redirect=).  Attackers '
            'use trusted domain names to lend legitimacy to phishing links, bypass '
            'referrer-based allow-listing, and steal OAuth tokens when the redirect '
            'URI is used in token delivery.'
        ),
        'mitre_attack': {
            'tactic': 'Initial Access',
            'technique': 'T1192',
            'technique_name': 'Spearphishing Link',
            'url': 'https://attack.mitre.org/techniques/T1192/',
        },
        'cvss_range': {'min': 3.1, 'max': 6.1},
        'real_world_examples': [
            {
                'title': 'Google (2019)',
                'description': 'An open redirect in Google\'s login flow allowed OAuth '
                               'token theft by redirecting access tokens to attacker '
                               'infrastructure.',
            },
        ],
        'cve_examples': ['CVE-2019-10743', 'CVE-2021-28918'],
        'owasp_testing_guide': ['WSTG-CLNT-04'],
        'owasp_top10_2021': 'A01:2021 — Broken Access Control',
    },

    'CWE-287': {
        'id': 'broken_auth',
        'name': 'Broken Authentication',
        'cwe': 'CWE-287',
        'description': (
            'Broken authentication encompasses weak credential policies, insecure '
            'session management, predictable token generation, missing brute-force '
            'protection, insecure password recovery flows, and failure to invalidate '
            'sessions after logout.  Successful exploitation grants arbitrary account '
            'access, including administrator accounts.'
        ),
        'mitre_attack': {
            'tactic': 'Credential Access',
            'technique': 'T1110',
            'technique_name': 'Brute Force',
            'url': 'https://attack.mitre.org/techniques/T1110/',
        },
        'cvss_range': {'min': 4.3, 'max': 9.8},
        'real_world_examples': [
            {
                'title': 'Zoom (2020)',
                'description': 'Zoom meeting IDs were brute-forced due to absence of '
                               'meeting-join rate limiting, exposing private meetings.',
            },
        ],
        'cve_examples': ['CVE-2020-11529', 'CVE-2019-5418'],
        'owasp_testing_guide': ['WSTG-ATHN-01', 'WSTG-SESS-01'],
        'owasp_top10_2021': 'A07:2021 — Identification and Authentication Failures',
    },

    'CWE-312': {
        'id': 'sensitive_data',
        'name': 'Sensitive Data Exposure',
        'cwe': 'CWE-312',
        'description': (
            'Sensitive data exposure occurs when an application fails to adequately '
            'protect data at rest or in transit — including weak/no encryption, '
            'cleartext storage of credentials, unsalted password hashes, and '
            'transmitting sensitive data over unencrypted channels.  Impacted data '
            'types include PII, credentials, payment details, medical records, and '
            'intellectual property.'
        ),
        'mitre_attack': {
            'tactic': 'Exfiltration',
            'technique': 'T1041',
            'technique_name': 'Exfiltration Over C2 Channel',
            'url': 'https://attack.mitre.org/techniques/T1041/',
        },
        'cvss_range': {'min': 3.7, 'max': 7.5},
        'real_world_examples': [
            {
                'title': 'LinkedIn (2012)',
                'description': '6.5 million unsalted SHA-1 password hashes were leaked '
                               'and cracked within hours; a 2016 follow-up revealed 117 '
                               'million records from the same breach.',
            },
            {
                'title': 'Adobe (2013)',
                'description': '153 million user records with weakly encrypted passwords '
                               '(3DES ECB mode) were leaked, enabling rapid decryption.',
            },
        ],
        'cve_examples': ['CVE-2014-3566', 'CVE-2016-2183'],
        'owasp_testing_guide': ['WSTG-CRYP-01', 'WSTG-CRYP-04'],
        'owasp_top10_2021': 'A02:2021 — Cryptographic Failures',
    },

    'CWE-1336': {
        'id': 'ssti',
        'name': 'Server-Side Template Injection (SSTI)',
        'cwe': 'CWE-1336',
        'description': (
            'SSTI arises when user input is embedded in a template and evaluated by '
            'the server-side template engine (Jinja2, Twig, Freemarker, Pebble, '
            'Mako, Smarty, …).  Attackers inject template directives to enumerate '
            'environment variables, read arbitrary files, and achieve remote code '
            'execution on the host operating system.'
        ),
        'mitre_attack': {
            'tactic': 'Execution',
            'technique': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'url': 'https://attack.mitre.org/techniques/T1059/',
        },
        'cvss_range': {'min': 6.5, 'max': 9.8},
        'real_world_examples': [
            {
                'title': 'Uber (2016)',
                'description': 'A Jinja2 SSTI vulnerability in Uber\'s Responsive '
                               'Design Framework enabled an attacker to achieve RCE on '
                               'the Uber production server.',
            },
        ],
        'cve_examples': ['CVE-2019-8341', 'CVE-2020-28243'],
        'owasp_testing_guide': ['WSTG-INPV-18'],
        'owasp_top10_2021': 'A03:2021 — Injection',
    },

    'CWE-94': {
        'id': 'rce',
        'name': 'Remote Code Execution (Code Injection)',
        'cwe': 'CWE-94',
        'description': (
            'Code injection allows an attacker to introduce and execute '
            'arbitrary code in the context of a running application.  This is '
            'distinct from command injection in that the malicious input is '
            'interpreted by the application\'s own runtime (eval, exec, pickle, '
            'deserialization, etc.) rather than the OS shell.  RCE typically '
            'grants full host compromise.'
        ),
        'mitre_attack': {
            'tactic': 'Execution',
            'technique': 'T1203',
            'technique_name': 'Exploitation for Client Execution',
            'url': 'https://attack.mitre.org/techniques/T1203/',
        },
        'cvss_range': {'min': 7.5, 'max': 10.0},
        'real_world_examples': [
            {
                'title': 'Log4Shell (CVE-2021-44228)',
                'description': 'A JNDI lookup injected via a log message in Apache '
                               'Log4j 2 caused the JVM to download and execute arbitrary '
                               'Java classes from attacker-controlled servers.',
            },
            {
                'title': 'Confluence RCE (CVE-2022-26134)',
                'description': 'OGNL injection via an unauthenticated HTTP request '
                               'allowed RCE on Confluence Server and Data Center.',
            },
        ],
        'cve_examples': ['CVE-2021-44228', 'CVE-2022-26134', 'CVE-2021-22005'],
        'owasp_testing_guide': ['WSTG-INPV-11'],
        'owasp_top10_2021': 'A03:2021 — Injection',
    },
}

# Reverse lookup index: short id → CWE key
_ID_INDEX: dict[str, str] = {v['id']: k for k, v in VULNERABILITY_DB.items()}


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

class VulnKB:
    """
    Read-only interface to the vulnerability knowledge base.

    All methods are safe to call with unknown identifiers — they return None
    or an empty list rather than raising.
    """

    def get(self, cwe: str) -> Optional[dict]:
        """Return the full record for the given CWE string, or None."""
        return VULNERABILITY_DB.get(cwe)

    def get_by_id(self, vuln_id: str) -> Optional[dict]:
        """Return the full record for the given short id ('sqli', 'xss', …)."""
        cwe = _ID_INDEX.get(vuln_id)
        return VULNERABILITY_DB.get(cwe) if cwe else None

    def get_by_cwe(self, cwe: str) -> Optional[dict]:
        """Alias for :meth:`get`."""
        return self.get(cwe)

    def search(self, query: str) -> list[dict]:
        """
        Full-text search across name and description fields.

        Returns a list of matching records sorted by name.
        """
        q = query.lower()
        results = [
            v for v in VULNERABILITY_DB.values()
            if q in v['name'].lower() or q in v['description'].lower()
        ]
        return sorted(results, key=lambda r: r['name'])

    def all_ids(self) -> list[str]:
        """Return all short vulnerability ids in alphabetical order."""
        return sorted(_ID_INDEX.keys())

    def all_cwes(self) -> list[str]:
        """Return all CWE keys in the database."""
        return sorted(VULNERABILITY_DB.keys())

    def get_mitre(self, cwe: str) -> Optional[dict]:
        """Return the MITRE ATT&CK mapping for the given CWE, or None."""
        record = self.get(cwe)
        return record['mitre_attack'] if record else None

    def get_cve_examples(self, cwe: str) -> list[str]:
        """Return the CVE example list for the given CWE, or an empty list."""
        record = self.get(cwe)
        return record['cve_examples'] if record else []

    def get_real_world_examples(self, cwe: str) -> list[dict]:
        """Return real-world examples for the given CWE."""
        record = self.get(cwe)
        return record.get('real_world_examples', []) if record else []

    def get_owasp_testing_guide(self, cwe: str) -> list[str]:
        """Return WSTG test case references for the given CWE."""
        record = self.get(cwe)
        return record.get('owasp_testing_guide', []) if record else []

    def get_cvss_range(self, cwe: str) -> Optional[dict]:
        """Return the CVSS range dict {'min': float, 'max': float} or None."""
        record = self.get(cwe)
        return record.get('cvss_range') if record else None
