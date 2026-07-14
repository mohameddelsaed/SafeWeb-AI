"""
Scan Profile & Template System — Phase 39.

Public API for the profiles package:
    from apps.scanning.engine.profiles import (
        get_profile, list_profiles, list_builtin_profiles,
        create_custom_profile, recommend_profile,
        ProfileBuilder, ProfileRegistry, ScanProfile,
        REGISTRY,
        QUICK_SCAN, STANDARD_SCAN, DEEP_SCAN, API_SCAN,
        COMPLIANCE_SCAN, BUG_BOUNTY_SCAN, RED_TEAM_SCAN,
        WORDPRESS_SCAN, AUTH_SCAN,
    )
"""
from .scan_profiles import (  # noqa: F401
    ScanProfile,
    ProfileRegistry,
    ProfileBuilder,
    REGISTRY,
    BUILTIN_PROFILES,
    get_profile,
    list_profiles,
    list_builtin_profiles,
    create_custom_profile,
    recommend_profile,
    QUICK_SCAN,
    STANDARD_SCAN,
    DEEP_SCAN,
    API_SCAN,
    COMPLIANCE_SCAN,
    BUG_BOUNTY_SCAN,
    RED_TEAM_SCAN,
    WORDPRESS_SCAN,
    AUTH_SCAN,
    DEPTH_QUICK,
    DEPTH_MEDIUM,
    DEPTH_DEEP,
    STEALTH_AGGRESSIVE,
    STEALTH_NORMAL,
    STEALTH_STEALTH,
)
