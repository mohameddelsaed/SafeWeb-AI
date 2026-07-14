"""
Reconnaissance Engine — 25 modules for comprehensive target intelligence.

Original (upgraded):
    dns_recon, whois_recon, port_scanner, tech_fingerprint,
    waf_detection, cert_analysis, header_analyzer, cookie_analyzer, ai_recon

P0 — Core new modules:
    ct_log_enum, subdomain_enum, url_harvester, js_analyzer

P1 — Cloud / Active:
    cloud_detect, cors_analyzer, content_discovery, param_discovery, api_discovery

P2 — Extended OSINT:
    subdomain_brute, email_enum, social_recon, cms_fingerprint, network_mapper

P3 — Intelligence / Scoring:
    vuln_correlator, attack_surface, threat_intel, risk_scorer
"""

# ── Original modules (upgraded) ──────────────────────────────────────────────
from .dns_recon import run_dns_recon
from .whois_recon import run_whois_recon
from .port_scanner import run_port_scan
from .tech_fingerprint import run_tech_fingerprint
from .waf_detection import run_waf_detection
from .cert_analysis import run_cert_analysis
from .header_analyzer import run_header_analysis
from .cookie_analyzer import run_cookie_analysis
from .ai_recon import run_ai_recon

# ── P0 — Core new modules ────────────────────────────────────────────────────
from .ct_log_enum import run_ct_log_enum
from .subdomain_enum import run_subdomain_enum
from .url_harvester import run_url_harvester
from .js_analyzer import run_js_analyzer

# ── P1 — Cloud / Active ──────────────────────────────────────────────────────
from .cloud_detect import run_cloud_detect
from .cors_analyzer import run_cors_analyzer
from .content_discovery import run_content_discovery
from .param_discovery import run_param_discovery
from .api_discovery import run_api_discovery

# ── P2 — Extended OSINT ──────────────────────────────────────────────────────
from .subdomain_brute import run_subdomain_brute
from .email_enum import run_email_enum
from .social_recon import run_social_recon
from .cms_fingerprint import run_cms_fingerprint
from .network_mapper import run_network_mapper

# ── P3 — Intelligence / Scoring ──────────────────────────────────────────────
from .vuln_correlator import run_vuln_correlator
from .attack_surface import run_attack_surface
from .threat_intel import run_threat_intel
from .risk_scorer import run_risk_scorer

# ── Phase 2 — Recon Engine 2.0 ──────────────────────────────────────────────
from .dns_zone_enum import run_dns_zone_enum
from .http_probe import run_http_probe
from .secret_scanner import run_secret_scanner
from .cloud_enum import run_cloud_enum
from .screenshot_recon import run_screenshot_recon
from .subdomain_takeover_recon import run_subdomain_takeover_recon

__all__ = [
    # Original
    'run_dns_recon', 'run_whois_recon', 'run_port_scan',
    'run_tech_fingerprint', 'run_waf_detection', 'run_cert_analysis',
    'run_header_analysis', 'run_cookie_analysis', 'run_ai_recon',
    # P0
    'run_ct_log_enum', 'run_subdomain_enum', 'run_url_harvester', 'run_js_analyzer',
    # P1
    'run_cloud_detect', 'run_cors_analyzer', 'run_content_discovery',
    'run_param_discovery', 'run_api_discovery',
    # P2
    'run_subdomain_brute', 'run_email_enum', 'run_social_recon',
    'run_cms_fingerprint', 'run_network_mapper',
    # P3
    'run_vuln_correlator', 'run_attack_surface', 'run_threat_intel', 'run_risk_scorer',
    # Phase 2 — Recon 2.0
    'run_dns_zone_enum', 'run_http_probe', 'run_secret_scanner',
    'run_cloud_enum', 'run_screenshot_recon', 'run_subdomain_takeover_recon',
]