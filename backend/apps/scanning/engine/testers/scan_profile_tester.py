"""
Scan Profile Tester — BaseTester wrapper for Phase 39.

Integrates the Scan Profile & Template System (engine/profiles/scan_profiles.py).
This tester inspects the active scan configuration and raises findings when
profiles are missing, misconfigured, or mismatched with the target.

Depth behaviour:
  quick  — Profile recommendation + coverage check
  medium — + configuration gap analysis (depth mismatch, CMS profile mismatch)
  deep   — + stealth/RPS configuration assessment
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class ScanProfileTester(BaseTester):
    TESTER_NAME = 'Scan Profile Engine'

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

        # ── Always: profile selection & recommendation ────────────────────
        vulns.extend(self._check_profile_selection(url, rd))

        # ── Always: essential-tester coverage ────────────────────────────
        vulns.extend(self._check_coverage(url, rd))

        if depth in ('medium', 'deep'):
            # ── Configuration gap analysis ────────────────────────────────
            vulns.extend(self._check_config_gaps(url, rd))

        if depth == 'deep':
            # ── Stealth / RPS assessment ──────────────────────────────────
            vulns.extend(self._check_stealth_config(url, rd))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Profile Selection
    # ─────────────────────────────────────────────────────────────────────

    def _check_profile_selection(self, url: str, recon_data: dict) -> list[dict]:
        """Detect missing profile and emit a recommendation finding."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.profiles.scan_profiles import (
                recommend_profile, list_builtin_profiles,
            )

            active_profile_id = recon_data.get('scan_profile')
            profiles = list_builtin_profiles()

            if not active_profile_id:
                recommended = recommend_profile(recon_data)
                vulns.append(self._build_vuln(
                    'Scan Profile: No Profile Selected',
                    'info', 'scan-configuration',
                    f'No scan profile is configured. Recommended profile: '
                    f'"{recommended.name}" — {recommended.description}',
                    'Without a profile, scans may be executed inconsistently, '
                    'leading to coverage gaps and reproducibility issues.',
                    f'Select an appropriate scan profile before initiating scans. '
                    f'Recommended: {recommended.id} '
                    f'(depth={recommended.depth}, rps={recommended.rps}).',
                    'CWE-693', 0.0, url,
                    f'Available profiles: {", ".join(p.id for p in profiles)}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_profile_selection error: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Coverage Check
    # ─────────────────────────────────────────────────────────────────────

    def _check_coverage(self, url: str, recon_data: dict) -> list[dict]:
        """Flag when an active profile omits essential security testers."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.profiles.scan_profiles import (
                REGISTRY, STANDARD_SCAN,
            )

            active_id = recon_data.get('scan_profile', STANDARD_SCAN)
            profile = REGISTRY.get(active_id)
            if not profile:
                return vulns

            # Profiles that use all testers never have gaps.
            if profile.includes_all_testers():
                return vulns

            essential = {
                'SQL Injection Tester', 'XSS Tester', 'Auth Tester',
                'SSRF Tester', 'Access Control Tester',
            }
            missing = essential - set(profile.testers)

            if missing:
                vulns.append(self._build_vuln(
                    'Scan Profile: Missing Essential Testers',
                    'medium', 'scan-configuration',
                    f'Profile "{profile.name}" omits essential security testers: '
                    f'{", ".join(sorted(missing))}.',
                    'Missing essential testers creates coverage gaps that may allow '
                    'critical vulnerabilities to go undetected during security assessments.',
                    f'Update profile "{profile.id}" to include the missing testers, '
                    'or switch to standard_scan / deep_scan.',
                    'CWE-693', 4.3, url,
                    f'Profile: {profile.id} | missing: {sorted(missing)}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_coverage error: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Configuration Gaps
    # ─────────────────────────────────────────────────────────────────────

    def _check_config_gaps(self, url: str, recon_data: dict) -> list[dict]:
        """Identify depth mismatch and CMS-profile mismatch issues."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.profiles.scan_profiles import (
                REGISTRY, STANDARD_SCAN, recommend_profile,
            )

            active_id = recon_data.get('scan_profile', STANDARD_SCAN)
            active = REGISTRY.get(active_id)
            if not active:
                return vulns

            recommended = recommend_profile(recon_data)
            depth_rank = {
                'quick': 0,
                'medium': 1,
                'deep': 2,
            }
            rec_rank = depth_rank.get(recommended.depth, 0)
            act_rank = depth_rank.get(active.depth, 0)

            if rec_rank > act_rank:
                vulns.append(self._build_vuln(
                    'Scan Profile: Insufficient Depth for Target',
                    'medium', 'scan-configuration',
                    f'Current profile "{active.name}" uses {active.depth!r} depth, '
                    f'but target characteristics suggest {recommended.depth!r} depth '
                    f'(recommended: {recommended.id}).',
                    'Insufficient scan depth may leave complex vulnerabilities, '
                    'second-order injections, and chained attack paths undetected.',
                    f'Consider switching to the "{recommended.id}" profile '
                    f'for this target type.',
                    'CWE-693', 4.3, url,
                    f'Active depth: {active.depth} | recommended: {recommended.depth}',
                ))

            # WordPress fingerprinted with a non-WordPress profile
            techs: list[str] = [
                t.get('name', '').lower()
                for t in recon_data.get('technologies', {}).get('technologies', [])
            ]
            is_wp = any('wordpress' in t for t in techs)
            if is_wp and active_id != 'wordpress_scan':
                vulns.append(self._build_vuln(
                    'Scan Profile: WordPress Target Without WordPress Profile',
                    'low', 'scan-configuration',
                    'WordPress was detected on the target, but the wordpress_scan '
                    'profile is not active. Plugin and theme enumeration will be limited.',
                    'WordPress-specific checks (plugin CVEs, theme vulnerabilities, '
                    'user enumeration) may be missed without the specialised profile.',
                    'Switch to the "wordpress_scan" profile for WordPress targets.',
                    'CWE-693', 2.0, url,
                    f'Active profile: {active_id} | detected CMS: WordPress',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_config_gaps error: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Stealth / RPS Assessment
    # ─────────────────────────────────────────────────────────────────────

    def _check_stealth_config(self, url: str, recon_data: dict) -> list[dict]:
        """Detect stealth / RPS misconfigurations in active profile."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.profiles.scan_profiles import (
                REGISTRY, STANDARD_SCAN,
            )

            active_id = recon_data.get('scan_profile', STANDARD_SCAN)
            profile = REGISTRY.get(active_id)
            if not profile:
                return vulns

            # Bug-bounty profiles must enforce scope
            if active_id == 'bug_bounty_scan' and not profile.scope_aware:
                vulns.append(self._build_vuln(
                    'Scan Profile: Scope Not Enforced for Bug Bounty',
                    'medium', 'scan-configuration',
                    'The bug_bounty_scan profile has scope_aware=False. '
                    'Scanning out-of-scope assets can result in programme '
                    'disqualification or legal consequences.',
                    'Out-of-scope scanning violates bug bounty programme rules '
                    'and may have legal implications under the CFAA / Computer '
                    'Misuse Act.',
                    'Enable scope_aware=True and configure in_scope / out_of_scope '
                    'patterns before running bug-bounty scans.',
                    'CWE-693', 5.0, url,
                    f'Profile: {active_id} | scope_aware: {profile.scope_aware}',
                ))

            # Contradictory: stealth level + high RPS
            if profile.stealth_level == 'stealth' and profile.rps > 10:
                vulns.append(self._build_vuln(
                    'Scan Profile: High RPS Undermines Stealth Mode',
                    'low', 'scan-configuration',
                    f'Profile "{profile.name}" is configured with stealth_level='
                    f'stealth but rps={profile.rps}. High request rates will '
                    'trigger IDS / WAF detection, defeating the purpose of stealth.',
                    'Excessive request rates during stealth scans defeat the '
                    'evasion objective and may trigger security alerts or IP bans.',
                    'Reduce rps to ≤5 for stealth-level scans, or change '
                    'stealth_level to "normal" if high-speed scanning is required.',
                    'CWE-693', 2.5, url,
                    f'Profile: {active_id} | rps: {profile.rps} | '
                    f'stealth_level: {profile.stealth_level}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_stealth_config error: %s', exc)
        return vulns
