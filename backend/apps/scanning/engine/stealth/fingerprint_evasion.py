"""
Fingerprint Evasion — Phase 40: Rate Limit & Stealth Mode.

Generates diverse HTTP request fingerprints to evade:
  - WAF / IDS User-Agent detection
  - TLS fingerprinting (JA3 / JA4 correlation)
  - Header-order fingerprinting
  - HTTP version fingerprinting
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

# ── User-Agent pool ────────────────────────────────────────────────────────────

UA_POOL: list[str] = [
    # Chrome — Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Chrome — macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    # Chrome — Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    # Firefox — Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Firefox — macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0',
    # Firefox — Linux
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    # Safari — macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_3) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    # Edge — Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    # Mobile Chrome — Android
    'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
    # Mobile Safari — iOS
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
]

# ── TLS profile descriptors ───────────────────────────────────────────────────

TLS_PROFILES: list[dict] = [
    {
        'id': 'chrome_121',
        'ja3': 'a0e9f5d64349fb13191bc781f81f42e1',
        'cipher_suites': [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
        ],
        'extensions': [
            'server_name',
            'extended_master_secret',
            'renegotiation_info',
            'supported_groups',
            'application_layer_protocol_negotiation',
        ],
        'min_version': 'TLS1.2',
        'max_version': 'TLS1.3',
    },
    {
        'id': 'firefox_121',
        'ja3': 'b32309a26951912be7dba376398abc3b',
        'cipher_suites': [
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_256_GCM_SHA384',
        ],
        'extensions': [
            'server_name',
            'extended_master_secret',
            'supported_groups',
            'encrypt_then_mac',
            'renegotiation_info',
        ],
        'min_version': 'TLS1.2',
        'max_version': 'TLS1.3',
    },
    {
        'id': 'safari_17',
        'ja3': 'c8a8f377c4c4eea3ac89e0c0f68f96a6',
        'cipher_suites': [
            'TLS_AES_256_GCM_SHA384',
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
        ],
        'extensions': [
            'server_name',
            'extended_master_secret',
            'supported_groups',
            'application_layer_protocol_negotiation',
        ],
        'min_version': 'TLS1.2',
        'max_version': 'TLS1.3',
    },
    {
        'id': 'edge_121',
        'ja3': 'd9a8c5a264a4f53e2a0a531d474fabb4',
        'cipher_suites': [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
        ],
        'extensions': [
            'server_name',
            'extended_master_secret',
            'renegotiation_info',
            'supported_groups',
        ],
        'min_version': 'TLS1.2',
        'max_version': 'TLS1.3',
    },
]

# ── HTTP version constants ────────────────────────────────────────────────────

HTTP_1_1 = 'HTTP/1.1'
HTTP_2   = 'HTTP/2'
HTTP_VERSIONS = [HTTP_1_1, HTTP_2]

# ── Accept header variation pools ────────────────────────────────────────────

_ACCEPT_POOL = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
]

_ACCEPT_LANG_POOL = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9,fr;q=0.8',
]

_ACCEPT_ENCODING_POOL = [
    'gzip, deflate, br',
    'gzip, deflate, br, zstd',
    'gzip, deflate',
]


# ── FingerprintProfile ────────────────────────────────────────────────────────

@dataclass
class FingerprintProfile:
    """A complete fingerprint snapshot for a single outgoing request."""

    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    tls_profile: dict
    http_version: str
    headers: dict = field(default_factory=dict)


# ── FingerprintEvasion ────────────────────────────────────────────────────────

class FingerprintEvasion:
    """Generates randomized HTTP request fingerprints.

    Usage::

        evasion = FingerprintEvasion()
        headers = evasion.get_headers()               # headers dict
        profile = evasion.get_fingerprint_profile()   # FingerprintProfile

    Options::

        FingerprintEvasion(
            ua_rotation=True,           # rotate User-Agent per request
            header_randomization=True,  # shuffle header insertion order
            tls_variation=True,         # vary TLS profile (JA3/JA4)
            http_version_variation=False,  # vary HTTP/1.1 vs HTTP/2
        )
    """

    def __init__(
        self,
        ua_rotation: bool = True,
        header_randomization: bool = True,
        tls_variation: bool = True,
        http_version_variation: bool = False,
        ua_pool: list[str] | None = None,
        tls_profiles: list[dict] | None = None,
    ) -> None:
        self.ua_rotation = ua_rotation
        self.header_randomization = header_randomization
        self.tls_variation = tls_variation
        self.http_version_variation = http_version_variation
        self._ua_pool = ua_pool if ua_pool is not None else UA_POOL
        self._tls_profiles = tls_profiles if tls_profiles is not None else TLS_PROFILES

    # ── User-Agent ─────────────────────────────────────────────────────────────

    def get_user_agent(self) -> str:
        """Return a (randomly selected) User-Agent string."""
        if not self._ua_pool:
            return ''
        if not self.ua_rotation:
            return self._ua_pool[0]
        return random.choice(self._ua_pool)

    # ── TLS profile ────────────────────────────────────────────────────────────

    def get_tls_profile(self) -> dict:
        """Return a (randomly selected) TLS profile descriptor."""
        if not self._tls_profiles:
            return {}
        if not self.tls_variation:
            return dict(self._tls_profiles[0])
        return dict(random.choice(self._tls_profiles))

    # ── HTTP version ────────────────────────────────────────────────────────────

    def get_http_version(self) -> str:
        """Return ``'HTTP/1.1'`` or ``'HTTP/2'``.

        When *http_version_variation* is enabled the choice is random;
        otherwise ``HTTP/1.1`` is always returned.
        """
        if self.http_version_variation:
            return random.choice(HTTP_VERSIONS)
        return HTTP_1_1

    # ── Headers ─────────────────────────────────────────────────────────────────

    def get_headers(self, base_headers: dict | None = None) -> dict:
        """Build a headers dict with randomized User-Agent and Accept values.

        When *header_randomization* is ``True`` the insertion order of headers
        is also randomized, altering the resulting wire fingerprint.

        *base_headers* (if provided) is merged on top of the generated set;
        existing keys are NOT overwritten.
        """
        hdrs: dict[str, str] = {
            'User-Agent':      self.get_user_agent(),
            'Accept':          random.choice(_ACCEPT_POOL),
            'Accept-Language': random.choice(_ACCEPT_LANG_POOL),
            'Accept-Encoding': random.choice(_ACCEPT_ENCODING_POOL),
        }

        if base_headers:
            for k, v in base_headers.items():
                if k not in hdrs:
                    hdrs[k] = v

        if self.header_randomization:
            hdrs = self.randomize_header_order(hdrs)

        return hdrs

    def randomize_header_order(self, headers: dict) -> dict:
        """Return a new dict with the same entries in a random order."""
        items = list(headers.items())
        random.shuffle(items)
        return dict(items)

    # ── Full fingerprint snapshot ─────────────────────────────────────────────

    def get_fingerprint_profile(
        self,
        base_headers: dict | None = None,
    ) -> FingerprintProfile:
        """Return a complete :class:`FingerprintProfile` for one request."""
        hdrs = self.get_headers(base_headers)
        return FingerprintProfile(
            user_agent=hdrs.get('User-Agent', ''),
            accept=hdrs.get('Accept', ''),
            accept_language=hdrs.get('Accept-Language', ''),
            accept_encoding=hdrs.get('Accept-Encoding', ''),
            tls_profile=self.get_tls_profile(),
            http_version=self.get_http_version(),
            headers=hdrs,
        )
