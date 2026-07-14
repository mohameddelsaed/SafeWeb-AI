"""
CMS Deep Tester — Detects WordPress, Drupal, and Joomla installations
and runs CMS-specific security checks.

Wraps the CMS scanner engines into the BaseTester interface.
"""
import logging

from apps.scanning.engine.testers.base_tester import BaseTester
from apps.scanning.engine.cms.wordpress import WordPressScanner
from apps.scanning.engine.cms.drupal import DrupalScanner
from apps.scanning.engine.cms.joomla import JoomlaScanner

logger = logging.getLogger(__name__)

# Severity → CVSS mapping for CMS findings
_SEVERITY_CVSS = {
    'critical': 9.8,
    'high': 7.5,
    'medium': 5.3,
    'low': 3.1,
    'info': 0.0,
}


class CMSTester(BaseTester):
    """Detect CMS type and run deep CMS-specific security scans."""

    TESTER_NAME = 'CMS Deep Scanner'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '')
        headers = getattr(page, 'headers', {})

        if not url or not body:
            return vulns

        # Detect which CMS and run the appropriate scanner
        if WordPressScanner.is_wordpress(body, headers):
            scanner = WordPressScanner(self._make_request)
            findings = scanner.scan(url, body, depth=depth)
            cms = 'WordPress'
        elif DrupalScanner.is_drupal(body, headers):
            scanner = DrupalScanner(self._make_request)
            findings = scanner.scan(url, body, depth=depth)
            cms = 'Drupal'
        elif JoomlaScanner.is_joomla(body, headers):
            scanner = JoomlaScanner(self._make_request)
            findings = scanner.scan(url, body, depth=depth)
            cms = 'Joomla'
        else:
            return vulns

        # Convert findings to _build_vuln format
        for finding in findings:
            vuln = self._finding_to_vuln(finding, url, cms)
            if vuln:
                vulns.append(vuln)

        return vulns

    def _finding_to_vuln(self, finding: dict, url: str, cms: str) -> dict:
        """Convert a CMS scanner finding dict to a BaseTester vuln dict."""
        check = finding.get('check', '')
        detail = finding.get('detail', '')
        severity = finding.get('severity', 'info')
        evidence = finding.get('evidence', '')

        return self._build_vuln(
            name=f'{cms}: {detail}',
            severity=severity,
            category='cms',
            description=f'{cms} CMS finding — {detail}',
            impact=self._impact_for_severity(severity),
            remediation=self._remediation_for_check(check, cms),
            cwe=self._cwe_for_check(check),
            cvss=_SEVERITY_CVSS.get(severity, 0.0),
            affected_url=url,
            evidence=evidence,
        )

    @staticmethod
    def _impact_for_severity(severity: str) -> str:
        return {
            'critical': 'Full system compromise, credential exposure',
            'high': 'Sensitive data exposure, unauthorized admin access',
            'medium': 'Information disclosure, user enumeration',
            'low': 'Minor information leak, version disclosure',
            'info': 'Informational finding, no direct security impact',
        }.get(severity, 'Unknown impact')

    @staticmethod
    def _remediation_for_check(check: str, cms: str) -> str:
        remediations = {
            'wordpress_version': 'Keep WordPress updated to the latest stable release.',
            'wordpress_plugin': 'Audit installed plugins, remove unused ones, keep all updated.',
            'wordpress_theme': 'Use themes from trusted sources, keep updated.',
            'wordpress_user_enum': 'Disable REST API user listing and block author enumeration.',
            'wordpress_xmlrpc': 'Disable xmlrpc.php or restrict access via .htaccess.',
            'wordpress_wp_cron': 'Disable wp-cron.php and use server-side cron jobs instead.',
            'wordpress_config_backup': 'Remove backup config files from the web root immediately.',
            'wordpress_debug_log': 'Disable WP_DEBUG_LOG in production or restrict access.',
            'drupal_version': 'Keep Drupal updated to the latest stable release.',
            'drupalgeddon2': 'Update Drupal core immediately — SA-CORE-2018-002.',
            'drupalgeddon3': 'Update Drupal core immediately — SA-CORE-2018-004.',
            'drupal_user_enum': 'Restrict user profile visibility to authenticated users.',
            'drupal_module': 'Audit modules, remove unused ones, keep all updated.',
            'drupal_sensitive_path': 'Deny access to sensitive files via server configuration.',
            'joomla_version': 'Keep Joomla updated to the latest stable release.',
            'joomla_admin_panel': 'Restrict access to /administrator/ via IP allowlist.',
            'joomla_component': 'Audit components, remove unused, keep updated.',
            'joomla_registration': 'Disable registration if not needed.',
            'joomla_sensitive_path': 'Deny access to sensitive files via server configuration.',
            'joomla_config_backup': 'Remove backup config files from the web root immediately.',
        }
        return remediations.get(check, f'Review and harden {cms} configuration.')

    @staticmethod
    def _cwe_for_check(check: str) -> str:
        cwe_map = {
            'wordpress_version': 'CWE-200',
            'wordpress_plugin': 'CWE-200',
            'wordpress_theme': 'CWE-200',
            'wordpress_user_enum': 'CWE-200',
            'wordpress_xmlrpc': 'CWE-16',
            'wordpress_wp_cron': 'CWE-16',
            'wordpress_config_backup': 'CWE-538',
            'wordpress_debug_log': 'CWE-532',
            'drupal_version': 'CWE-200',
            'drupalgeddon2': 'CWE-20',
            'drupalgeddon3': 'CWE-20',
            'drupal_user_enum': 'CWE-200',
            'drupal_module': 'CWE-200',
            'drupal_sensitive_path': 'CWE-538',
            'joomla_version': 'CWE-200',
            'joomla_admin_panel': 'CWE-16',
            'joomla_component': 'CWE-200',
            'joomla_registration': 'CWE-16',
            'joomla_sensitive_path': 'CWE-538',
            'joomla_config_backup': 'CWE-538',
        }
        return cwe_map.get(check, 'CWE-200')
