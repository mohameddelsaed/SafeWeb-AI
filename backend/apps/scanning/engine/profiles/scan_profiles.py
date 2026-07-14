"""
Scan Profile & Template System — Phase 39.

Provides:
  - ScanProfile           dataclass representing a complete scan configuration
  - 9 built-in profiles   (quick, standard, deep, api, compliance,
                            bug_bounty, red_team, wordpress, authentication)
  - ProfileRegistry       lookup / storage by profile id
  - ProfileBuilder        fluent builder for custom profiles
  - Convenience helpers   get_profile(), list_profiles(), recommend_profile()
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

# ── Public profile-id constants ───────────────────────────────────────────────
QUICK_SCAN      = 'quick_scan'
STANDARD_SCAN   = 'standard_scan'
DEEP_SCAN       = 'deep_scan'
API_SCAN        = 'api_scan'
COMPLIANCE_SCAN = 'compliance_scan'
BUG_BOUNTY_SCAN = 'bug_bounty_scan'
RED_TEAM_SCAN   = 'red_team_scan'
WORDPRESS_SCAN  = 'wordpress_scan'
AUTH_SCAN       = 'authentication_scan'

_BUILTIN_IDS = [
    QUICK_SCAN, STANDARD_SCAN, DEEP_SCAN, API_SCAN,
    COMPLIANCE_SCAN, BUG_BOUNTY_SCAN, RED_TEAM_SCAN,
    WORDPRESS_SCAN, AUTH_SCAN,
]

# ── Depth constants ───────────────────────────────────────────────────────────
DEPTH_QUICK  = 'quick'
DEPTH_MEDIUM = 'medium'
DEPTH_DEEP   = 'deep'

_VALID_DEPTHS = (DEPTH_QUICK, DEPTH_MEDIUM, DEPTH_DEEP)

# ── Stealth level constants ───────────────────────────────────────────────────
STEALTH_AGGRESSIVE = 'aggressive'
STEALTH_NORMAL     = 'normal'
STEALTH_STEALTH    = 'stealth'

_VALID_STEALTH = (STEALTH_AGGRESSIVE, STEALTH_NORMAL, STEALTH_STEALTH)

# ── Tester "shortlists" used by pre-built profiles ───────────────────────────
# Names match the TESTER_NAME attribute on each BaseTester subclass.

_OWASP_CORE = [
    'SQL Injection Tester', 'XSS Tester', 'Command Injection Tester',
    'SSTI Tester', 'XXE Tester', 'CSRF Tester', 'Auth Tester',
    'Misconfiguration Tester', 'Data Exposure Tester',
    'Access Control Tester', 'SSRF Tester', 'Component Vulnerability Tester',
]

_API_TESTERS = [
    'SQL Injection Tester', 'XSS Tester', 'Auth Tester', 'SSRF Tester',
    'Access Control Tester', 'IDOR Tester', 'Mass Assignment Tester',
    'API Security Tester', 'API Discovery Tester', 'JWT Tester',
    'OAuth 2.0 Security Tester', 'CORS Tester', 'NoSQL Injection Tester',
]

_COMPLIANCE_TESTERS = [
    'SQL Injection Tester', 'XSS Tester', 'CSRF Tester', 'Auth Tester',
    'Data Exposure Tester', 'Access Control Tester', 'Misconfiguration Tester',
    'Logging & Monitoring Tester', 'Component Vulnerability Tester',
    'SSRF Tester', 'Insecure Randomness Tester', 'JWT Tester',
    'IDOR Tester', 'Path Traversal Tester',
]

_WORDPRESS_TESTERS = [
    'SQL Injection Tester', 'XSS Tester', 'CSRF Tester', 'Auth Tester',
    'Data Exposure Tester', 'Component Vulnerability Tester', 'CMS Scanner',
    'Path Traversal Tester', 'File Upload Tester', 'Misconfiguration Tester',
    'Content Discovery Tester', 'Supply Chain & Dependency Scanner',
]

_AUTH_TESTERS = [
    'Auth Tester', 'JWT Tester', 'OAuth 2.0 Security Tester',
    'SAML Security Tester', 'CSRF Tester', 'Business Logic Tester',
    'Business Logic Deep Tester', 'Access Control Tester', 'IDOR Tester',
    'Mass Assignment Tester', 'Forbidden Bypass Tester',
]


# ── ScanProfile dataclass ─────────────────────────────────────────────────────

@dataclass
class ScanProfile:
    """A complete, reusable scan configuration.

    Attributes:
        id:                     Unique slug identifier (no spaces).
        name:                   Human-readable display name.
        description:            One-line summary of the profile's purpose.
        is_builtin:             True for the 9 pre-built profiles.
        depth:                  Scan depth — 'quick' | 'medium' | 'deep'.
        max_duration_minutes:   Soft time-box (-1 = unlimited).
        testers:                Tester names to enable, or ['*'] for all.
        nuclei_tags:            Nuclei template tag filters (['*'] = all).
        stealth_level:          'aggressive' | 'normal' | 'stealth'.
        rps:                    Max requests-per-second.
        scope_aware:            Enforce target in-scope / out-of-scope rules.
        config:                 Arbitrary extra configuration options.
    """

    id: str
    name: str
    description: str
    is_builtin: bool
    depth: str
    max_duration_minutes: int
    testers: list[str]
    nuclei_tags: list[str]
    stealth_level: str
    rps: int
    scope_aware: bool
    config: dict[str, Any] = field(default_factory=dict)

    # ── Property helpers ──────────────────────────────────────────────────────

    def includes_all_testers(self) -> bool:
        """Return True when the profile enables every available tester."""
        return self.testers == ['*']

    def has_tester(self, name: str) -> bool:
        """Return True if *name* is explicitly (or implicitly) enabled."""
        return self.includes_all_testers() or name in self.testers

    def uses_all_nuclei(self) -> bool:
        """Return True when all Nuclei templates are enabled."""
        return self.nuclei_tags == ['*']

    def is_unlimited(self) -> bool:
        """Return True when there is no time limit."""
        return self.max_duration_minutes == -1

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (suitable for JSON / Django model storage)."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_builtin': self.is_builtin,
            'depth': self.depth,
            'max_duration_minutes': self.max_duration_minutes,
            'testers': self.testers,
            'nuclei_tags': self.nuclei_tags,
            'stealth_level': self.stealth_level,
            'rps': self.rps,
            'scope_aware': self.scope_aware,
            'config': self.config,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'ScanProfile':
        """Deserialise from a plain dict."""
        return cls(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            is_builtin=data.get('is_builtin', False),
            depth=data.get('depth', DEPTH_MEDIUM),
            max_duration_minutes=data.get('max_duration_minutes', 30),
            testers=data.get('testers', ['*']),
            nuclei_tags=data.get('nuclei_tags', []),
            stealth_level=data.get('stealth_level', STEALTH_NORMAL),
            rps=data.get('rps', 10),
            scope_aware=data.get('scope_aware', False),
            config=data.get('config', {}),
        )

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self) -> list[str]:
        """Return a list of validation error strings; empty list means valid."""
        errors: list[str] = []
        if not self.id:
            errors.append('Profile id must not be empty')
        elif ' ' in self.id:
            errors.append('Profile id must not contain spaces (use underscores)')
        if not self.name:
            errors.append('Profile name must not be empty')
        if self.depth not in _VALID_DEPTHS:
            errors.append(
                f'Invalid depth: {self.depth!r} (must be one of {_VALID_DEPTHS})'
            )
        if self.stealth_level not in _VALID_STEALTH:
            errors.append(
                f'Invalid stealth_level: {self.stealth_level!r} '
                f'(must be one of {_VALID_STEALTH})'
            )
        if not isinstance(self.rps, int) or self.rps < 1:
            errors.append('rps must be a positive integer (≥ 1)')
        if not self.testers:
            errors.append('testers list must not be empty')
        return errors

    def is_valid(self) -> bool:
        """Return True when validate() produces no errors."""
        return len(self.validate()) == 0


# ── Built-in profile definitions ─────────────────────────────────────────────

BUILTIN_PROFILES: list[ScanProfile] = [
    ScanProfile(
        id=QUICK_SCAN,
        name='Quick Scan',
        description='OWASP Top 10 only, shallow depth — completes in ~5 minutes.',
        is_builtin=True,
        depth=DEPTH_QUICK,
        max_duration_minutes=5,
        testers=_OWASP_CORE,
        nuclei_tags=['critical', 'high'],
        stealth_level=STEALTH_AGGRESSIVE,
        rps=20,
        scope_aware=False,
        config={'follow_redirects': True, 'max_pages': 50},
    ),
    ScanProfile(
        id=STANDARD_SCAN,
        name='Standard Scan',
        description='Full testing suite at medium depth — recommended for most targets.',
        is_builtin=True,
        depth=DEPTH_MEDIUM,
        max_duration_minutes=30,
        testers=['*'],
        nuclei_tags=['critical', 'high', 'medium'],
        stealth_level=STEALTH_NORMAL,
        rps=10,
        scope_aware=False,
        config={'follow_redirects': True, 'max_pages': 200},
    ),
    ScanProfile(
        id=DEEP_SCAN,
        name='Deep Scan',
        description='All testers + all Nuclei templates, deep crawl — 2+ hours.',
        is_builtin=True,
        depth=DEPTH_DEEP,
        max_duration_minutes=-1,
        testers=['*'],
        nuclei_tags=['*'],
        stealth_level=STEALTH_NORMAL,
        rps=5,
        scope_aware=False,
        config={'follow_redirects': True, 'max_pages': -1, 'active_exploitation': True},
    ),
    ScanProfile(
        id=API_SCAN,
        name='API Scan',
        description='OWASP API Top 10 focused — REST / GraphQL / WebSocket endpoints.',
        is_builtin=True,
        depth=DEPTH_MEDIUM,
        max_duration_minutes=20,
        testers=_API_TESTERS,
        nuclei_tags=['api', 'authentication', 'injection', 'idor'],
        stealth_level=STEALTH_NORMAL,
        rps=15,
        scope_aware=False,
        config={'api_mode': True, 'discover_endpoints': True},
    ),
    ScanProfile(
        id=COMPLIANCE_SCAN,
        name='Compliance Scan',
        description='PCI DSS v4.0 & OWASP Top 10 compliance — generates compliance report.',
        is_builtin=True,
        depth=DEPTH_MEDIUM,
        max_duration_minutes=45,
        testers=_COMPLIANCE_TESTERS,
        nuclei_tags=['compliance', 'critical', 'high', 'medium'],
        stealth_level=STEALTH_NORMAL,
        rps=8,
        scope_aware=False,
        config={'compliance_mode': True, 'generate_report': True},
    ),
    ScanProfile(
        id=BUG_BOUNTY_SCAN,
        name='Bug Bounty Scan',
        description='Scope-aware, stealth mode — optimised for bug bounty submissions.',
        is_builtin=True,
        depth=DEPTH_DEEP,
        max_duration_minutes=-1,
        testers=['*'],
        nuclei_tags=['critical', 'high', 'medium', 'cves', 'exposures'],
        stealth_level=STEALTH_STEALTH,
        rps=2,
        scope_aware=True,
        config={'jitter_ms': 500, 'random_ua': True, 'avoid_noise': True},
    ),
    ScanProfile(
        id=RED_TEAM_SCAN,
        name='Red Team Scan',
        description='Full adversarial simulation — exploitation, chaining, pivoting.',
        is_builtin=True,
        depth=DEPTH_DEEP,
        max_duration_minutes=-1,
        testers=['*'],
        nuclei_tags=['*'],
        stealth_level=STEALTH_AGGRESSIVE,
        rps=30,
        scope_aware=True,
        config={'active_exploitation': True, 'chain_attacks': True, 'nuclei_full': True},
    ),
    ScanProfile(
        id=WORDPRESS_SCAN,
        name='WordPress Scan',
        description='WordPress-specific deep scan — plugins, themes, and core vulnerabilities.',
        is_builtin=True,
        depth=DEPTH_DEEP,
        max_duration_minutes=60,
        testers=_WORDPRESS_TESTERS,
        nuclei_tags=['wordpress', 'wp', 'rce', 'sqli', 'xss', 'file-upload'],
        stealth_level=STEALTH_NORMAL,
        rps=5,
        scope_aware=False,
        config={'cms': 'wordpress', 'enumerate_users': True, 'check_plugins': True},
    ),
    ScanProfile(
        id=AUTH_SCAN,
        name='Authentication Scan',
        description='Post-authentication vulnerability testing — IDOR, privilege escalation.',
        is_builtin=True,
        depth=DEPTH_MEDIUM,
        max_duration_minutes=30,
        testers=_AUTH_TESTERS,
        nuclei_tags=['authentication', 'token', 'session', 'idor', 'privilege'],
        stealth_level=STEALTH_NORMAL,
        rps=10,
        scope_aware=False,
        config={'authenticated': True, 'test_roles': True},
    ),
]


# ── ProfileRegistry ───────────────────────────────────────────────────────────

class ProfileRegistry:
    """Key-value store for ScanProfile objects, keyed by profile id.

    The module-level singleton REGISTRY is pre-loaded with all 9
    built-in profiles on import.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, ScanProfile] = {}

    # ── Mutation ──────────────────────────────────────────────────────────────

    def register(self, profile: ScanProfile) -> None:
        """Add or replace a profile in the registry."""
        self._profiles[profile.id] = profile

    def deregister(self, profile_id: str) -> bool:
        """Remove a profile by id. Returns True if it existed."""
        if profile_id in self._profiles:
            del self._profiles[profile_id]
            return True
        return False

    # ── Queries ───────────────────────────────────────────────────────────────

    def get(self, profile_id: str) -> ScanProfile | None:
        """Return the profile with the given id, or None."""
        return self._profiles.get(profile_id)

    def list_all(self) -> list[ScanProfile]:
        """Return all registered profiles (built-in + custom)."""
        return list(self._profiles.values())

    def list_builtin(self) -> list[ScanProfile]:
        """Return only the pre-built profiles."""
        return [p for p in self._profiles.values() if p.is_builtin]

    def list_custom(self) -> list[ScanProfile]:
        """Return only user-defined custom profiles."""
        return [p for p in self._profiles.values() if not p.is_builtin]

    # ── Magic methods ─────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._profiles)

    def __contains__(self, profile_id: str) -> bool:
        return profile_id in self._profiles

    def __iter__(self) -> Iterator[ScanProfile]:
        return iter(self._profiles.values())

    def __repr__(self) -> str:  # pragma: no cover
        return f'<ProfileRegistry profiles={list(self._profiles.keys())}>'


# ── Module-level singleton registry ──────────────────────────────────────────

REGISTRY: ProfileRegistry = ProfileRegistry()
for _p in BUILTIN_PROFILES:
    REGISTRY.register(_p)


# ── ProfileBuilder ────────────────────────────────────────────────────────────

class ProfileBuilder:
    """Fluent builder for constructing custom ScanProfile objects.

    Example::

        profile = (
            ProfileBuilder()
            .set_name('My Custom Scan')
            .set_depth('deep')
            .set_rps(5)
            .enable_tester('SQL Injection Tester')
            .enable_tester('XSS Tester')
            .set_nuclei_tags(['critical', 'high'])
            .build()
        )
    """

    def __init__(self) -> None:
        self._id: str = 'custom_profile'
        self._name: str = 'Custom Profile'
        self._description: str = ''
        self._depth: str = DEPTH_MEDIUM
        self._max_duration: int = 30
        self._testers: list[str] = []
        self._nuclei_tags: list[str] = []
        self._stealth_level: str = STEALTH_NORMAL
        self._rps: int = 10
        self._scope_aware: bool = False
        self._config: dict[str, Any] = {}

    # ── Fluent setters ────────────────────────────────────────────────────────

    def set_id(self, profile_id: str) -> 'ProfileBuilder':
        self._id = profile_id
        return self

    def set_name(self, name: str) -> 'ProfileBuilder':
        self._name = name
        return self

    def set_description(self, desc: str) -> 'ProfileBuilder':
        self._description = desc
        return self

    def set_depth(self, depth: str) -> 'ProfileBuilder':
        self._depth = depth
        return self

    def set_max_duration(self, minutes: int) -> 'ProfileBuilder':
        self._max_duration = minutes
        return self

    def enable_tester(self, name: str) -> 'ProfileBuilder':
        """Add *name* to the enabled-testers list (idempotent)."""
        if name not in self._testers:
            self._testers.append(name)
        return self

    def disable_tester(self, name: str) -> 'ProfileBuilder':
        """Remove *name* from the enabled-testers list."""
        self._testers = [t for t in self._testers if t != name]
        return self

    def set_testers(self, testers: list[str]) -> 'ProfileBuilder':
        """Replace the entire testers list."""
        self._testers = list(testers)
        return self

    def set_nuclei_tags(self, tags: list[str]) -> 'ProfileBuilder':
        self._nuclei_tags = list(tags)
        return self

    def set_stealth_level(self, level: str) -> 'ProfileBuilder':
        self._stealth_level = level
        return self

    def set_rps(self, rps: int) -> 'ProfileBuilder':
        self._rps = rps
        return self

    def enable_scope_awareness(self, enabled: bool = True) -> 'ProfileBuilder':
        self._scope_aware = enabled
        return self

    def set_config(self, **kwargs: Any) -> 'ProfileBuilder':
        self._config.update(kwargs)
        return self

    def from_profile(self, profile: ScanProfile) -> 'ProfileBuilder':
        """Seed builder from an existing profile (starts a copy/fork)."""
        self._id = profile.id + '_fork'
        self._name = profile.name + ' (Custom)'
        self._description = profile.description
        self._depth = profile.depth
        self._max_duration = profile.max_duration_minutes
        self._testers = list(profile.testers)
        self._nuclei_tags = list(profile.nuclei_tags)
        self._stealth_level = profile.stealth_level
        self._rps = profile.rps
        self._scope_aware = profile.scope_aware
        self._config = dict(profile.config)
        return self

    def build(self) -> ScanProfile:
        """Create and return a ScanProfile. Does not register it."""
        testers = self._testers if self._testers else ['*']
        return ScanProfile(
            id=self._id,
            name=self._name,
            description=self._description,
            is_builtin=False,
            depth=self._depth,
            max_duration_minutes=self._max_duration,
            testers=testers,
            nuclei_tags=self._nuclei_tags,
            stealth_level=self._stealth_level,
            rps=self._rps,
            scope_aware=self._scope_aware,
            config=dict(self._config),
        )


# ── Convenience functions ─────────────────────────────────────────────────────

def get_profile(profile_id: str) -> ScanProfile | None:
    """Return a profile from the global REGISTRY, or None."""
    return REGISTRY.get(profile_id)


def list_profiles() -> list[ScanProfile]:
    """Return all profiles (built-in + custom) from the global REGISTRY."""
    return REGISTRY.list_all()


def list_builtin_profiles() -> list[ScanProfile]:
    """Return only the 9 built-in profiles."""
    return REGISTRY.list_builtin()


def create_custom_profile(
    name: str,
    description: str = '',
    depth: str = DEPTH_MEDIUM,
    testers: list[str] | None = None,
    nuclei_tags: list[str] | None = None,
    stealth_level: str = STEALTH_NORMAL,
    rps: int = 10,
    scope_aware: bool = False,
    max_duration_minutes: int = 30,
    register: bool = False,
    **config: Any,
) -> ScanProfile:
    """Create a custom ScanProfile from keyword arguments.

    Args:
        name:                   Display name for the profile.
        description:            Optional one-line description.
        depth:                  'quick' | 'medium' | 'deep' (default: 'medium').
        testers:                List of tester names, or None for ['*'].
        nuclei_tags:            Nuclei tag filters (default: []).
        stealth_level:          'aggressive' | 'normal' | 'stealth'.
        rps:                    Max requests per second.
        scope_aware:            Enforce scope boundaries.
        max_duration_minutes:   Soft time-box (-1 unlimited).
        register:               If True, add to global REGISTRY immediately.
        **config:               Extra arbitrary config key/values.

    Returns:
        ScanProfile instance (not registered unless register=True).
    """
    slug = re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_') or 'custom'
    profile = (
        ProfileBuilder()
        .set_id(slug)
        .set_name(name)
        .set_description(description)
        .set_depth(depth)
        .set_max_duration(max_duration_minutes)
        .set_testers(testers if testers is not None else ['*'])
        .set_nuclei_tags(nuclei_tags if nuclei_tags is not None else [])
        .set_stealth_level(stealth_level)
        .set_rps(rps)
        .enable_scope_awareness(scope_aware)
        .set_config(**config)
        .build()
    )
    if register:
        REGISTRY.register(profile)
    return profile


def recommend_profile(recon_data: dict) -> ScanProfile:
    """Recommend the most appropriate built-in profile for this target.

    Heuristics (in priority order):
    1. WordPress fingerprinted  → wordpress_scan
    2. Only API endpoints       → api_scan
    3. Authenticated context    → authentication_scan
    4. Default                  → standard_scan

    Always returns a valid ScanProfile (falls back to STANDARD_SCAN).
    """
    techs: list[str] = [
        t.get('name', '').lower()
        for t in recon_data.get('technologies', {}).get('technologies', [])
    ]

    if any('wordpress' in t or 'wp-' in t for t in techs):
        return REGISTRY.get(WORDPRESS_SCAN) or REGISTRY.get(STANDARD_SCAN)

    if recon_data.get('api_only'):
        return REGISTRY.get(API_SCAN) or REGISTRY.get(STANDARD_SCAN)

    if recon_data.get('has_auth'):
        return REGISTRY.get(AUTH_SCAN) or REGISTRY.get(STANDARD_SCAN)

    return REGISTRY.get(STANDARD_SCAN)
