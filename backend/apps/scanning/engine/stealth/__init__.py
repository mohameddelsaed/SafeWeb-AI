"""
Rate Limit & Stealth Mode — Phase 40 package.

Re-exports from :mod:`traffic_shaper` and :mod:`fingerprint_evasion`.
"""
from .traffic_shaper import (
    TrafficShaper,
    DEFAULT_RPS,
    MIN_RPS,
    MAX_RPS,
    DEFAULT_JITTER_PCT,
    DEFAULT_BURST_LIMIT,
    DEFAULT_COOLDOWN_SEC,
    TOR_SOCKS_DEFAULT_PORT,
    SLOWDOWN_FACTOR_429,
    SLOWDOWN_FACTOR_503,
)
from .fingerprint_evasion import (
    FingerprintEvasion,
    FingerprintProfile,
    UA_POOL,
    TLS_PROFILES,
    HTTP_1_1,
    HTTP_2,
    HTTP_VERSIONS,
)

__all__ = [
    # Traffic shaping
    'TrafficShaper',
    'DEFAULT_RPS', 'MIN_RPS', 'MAX_RPS',
    'DEFAULT_JITTER_PCT', 'DEFAULT_BURST_LIMIT',
    'DEFAULT_COOLDOWN_SEC', 'TOR_SOCKS_DEFAULT_PORT',
    'SLOWDOWN_FACTOR_429', 'SLOWDOWN_FACTOR_503',
    # Fingerprint evasion
    'FingerprintEvasion', 'FingerprintProfile',
    'UA_POOL', 'TLS_PROFILES',
    'HTTP_1_1', 'HTTP_2', 'HTTP_VERSIONS',
]
