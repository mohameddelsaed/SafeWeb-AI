"""
Vulnerability Testers Package.
Each tester implements the BaseTester interface and tests for specific OWASP vulnerabilities.

35+ professional-grade testers covering OWASP Top 10 2021, API Top 10, LLM Top 10 and beyond:
  Phase 1: Core Injection — SQLi, XSS, CMDi, SSTI, XXE
  Phase 2: Advanced — Deserialization, Host Header, HTTP Smuggling, CRLF, JWT
  Phase 3: Modern — Race Condition, WebSocket, GraphQL, File Upload, NoSQL, Cache Poisoning
  Phase 4: Infrastructure — CORS, Clickjacking, LDAP/XPath, Subdomain Takeover, Cloud Storage
  Phase 5: AI / LLM Security — Prompt Injection, AI Endpoint Security
  Phase 6: Missing Classes — Prototype Pollution, Open Redirect, Business Logic, API Security
  Existing (upgraded): SSRF, Auth, AccessControl, Misconfig, CSRF, DataExposure, Component, Logging
"""

# ── Existing testers (upgraded) ──────────────────────────────────────────────
from .sqli_tester import SQLInjectionTester
from .xss_tester import XSSTester
from .csrf_tester import CSRFTester
from .auth_tester import AuthTester
from .misconfig_tester import MisconfigTester
from .data_exposure_tester import DataExposureTester
from .access_control_tester import AccessControlTester
from .ssrf_tester import SSRFTester
from .component_tester import ComponentTester
from .logging_tester import LoggingTester

# ── Phase 1: Core Injection ──────────────────────────────────────────────────
from .cmdi_tester import CommandInjectionTester
from .ssti_tester import SSTITester
from .xxe_tester import XXETester

# ── Phase 2: Advanced ────────────────────────────────────────────────────────
from .deserialization_tester import DeserializationTester
from .host_header_tester import HostHeaderTester
from .http_smuggling_tester import HTTPSmugglingTester
from .crlf_tester import CRLFInjectionTester
from .jwt_tester import JWTTester

# ── Phase 3: Modern ─────────────────────────────────────────────────────────
from .race_condition_tester import RaceConditionTester
from .websocket_tester import WebSocketTester
from .graphql_tester import GraphQLTester
from .file_upload_tester import FileUploadTester
from .nosql_tester import NoSQLInjectionTester
from .cache_poisoning_tester import CachePoisoningTester

# ── Phase 4: Infrastructure ──────────────────────────────────────────────────
from .cors_tester import CORSTester
from .clickjacking_tester import ClickjackingTester
from .ldap_xpath_tester import LDAPXPathTester
from .subdomain_takeover_tester import SubdomainTakeoverTester
from .cloud_storage_tester import CloudStorageTester

# ── Phase 5: AI / LLM Security (OWASP LLM Top 10) ──────────────────────────
from .prompt_injection_tester import PromptInjectionTester
from .ai_endpoint_tester import AIEndpointTester

# ── Phase 6: Missing Vulnerability Classes ───────────────────────────────────
from .prototype_pollution_tester import PrototypePollutionTester
from .open_redirect_tester import OpenRedirectTester
from .business_logic_tester import BusinessLogicTester
from .api_tester import APITester

# ── Phase 3 Upgrade: New Discovery Testers ───────────────────────────────────
from .content_discovery_tester import ContentDiscoveryTester
from .api_discovery_tester import APIDiscoveryTester

# ── Phase 8: Advanced Vulnerability Engine ───────────────────────────────────
from .idor_tester import IDORTester
from .mass_assignment_tester import MassAssignmentTester
from .path_traversal_tester import PathTraversalTester
from .ssi_tester import SSITester
from .http2_tester import HTTP2Tester

# ── Phase 9: AI Security Module Expansion ────────────────────────────────────
from .ai_data_poisoning_tester import AiDataPoisoningTester

# ── Phase 26: New Vulnerability Classes (Batch 1) ────────────────────────────
from .oauth_tester import OAuthTester
from .saml_tester import SAMLTester
from .css_injection_tester import CSSInjectionTester
from .csv_injection_tester import CSVInjectionTester
from .dns_rebinding_tester import DNSRebindingTester
from .hpp_tester import HPPTester
from .type_juggling_tester import TypeJugglingTester
from .redos_tester import ReDoSTester

# ── Phase 27: New Vulnerability Classes (Batch 2) ────────────────────────────
from .web_cache_deception_tester import WebCacheDeceptionTester
from .xsleak_tester import XSLeakTester
from .xslt_injection_tester import XSLTInjectionTester
from .zip_slip_tester import ZipSlipTester
from .vhost_tester import VHostTester
from .insecure_randomness_tester import InsecureRandomnessTester
from .reverse_proxy_misconfig_tester import ReverseProxyMisconfigTester
from .dependency_confusion_tester import DependencyConfusionTester

# ── Phase 28: 403/401 Bypass Engine ──────────────────────────────────────────
from .forbidden_bypass_tester import ForbiddenBypassTester

# ── Phase 29: CMS Deep Scanner ───────────────────────────────────────────────
from .cms_tester import CMSTester

# ── Phase 30: Exploit Verification Engine ────────────────────────────────────
from .exploit_verification_tester import ExploitVerificationTester

# ── Phase 31: Business Logic Testing Engine ──────────────────────────────────
from .business_logic_deep_tester import BusinessLogicDeepTester

# ── Phase 32: Advanced WAF Evasion Engine ─────────────────────────────────────
from .advanced_waf_evasion_tester import AdvancedWAFEvasionTester

# ── Phase 33: Supply Chain & Dependency Scanner ──────────────────────────────
from .supply_chain_tester import SupplyChainTester
from .network_tester import NetworkTester

# ── Phase 35: Reporting & Integration ────────────────────────────────────────
from .reporting_integration_tester import ReportingIntegrationTester

# ── Phase 36: Active Recon Enhancement ───────────────────────────────────────
from .active_recon_tester import ActiveReconTester

# ── Phase 37: JavaScript Intelligence v2 ─────────────────────────────────────
from .js_intelligence_tester import JsIntelligenceTester

# ── Phase 38: AI/ML Enhancement ──────────────────────────────────────────────
from .ml_enhancement_tester import MLEnhancementTester

# ── Phase 39: Scan Profile & Template System ─────────────────────────────────
from .scan_profile_tester import ScanProfileTester

# ── Phase 40: Rate Limit & Stealth Mode ──────────────────────────────────────
from .stealth_tester import StealthTester

# ── Phase 41: Vulnerability Knowledge Base ───────────────────────────────────
from .knowledge_tester import KnowledgeTester

# ── Phase 42: Advanced Graph & Chain Analysis ─────────────────────────────────
from .attack_graph_tester import AttackGraphTester

# ── Phase 43: Scheduled & Continuous Scanning ──────────────────────────────
from .scheduled_scan_tester import ScheduledScanTester

# ── Phase 46: Full OWASP WSTG Coverage ───────────────────────────────────────
from .wstg_info_tester import WSTGInfoTester
from .wstg_conf_tester import WSTGConfTester
from .wstg_idnt_tester import WSTGIdentityTester
from .wstg_athn_tester import WSTGAuthTester
from .wstg_sess_tester import WSTGSessionTester
from .wstg_inpv_tester import WSTGInputValidationTester
from .wstg_errh_tester import WSTGErrorHandlingTester
from .wstg_cryp_tester import WSTGCryptographyTester
from .wstg_busl_tester import WSTGBusinessLogicTester
from .wstg_clnt_tester import WSTGClientSideTester

# ── Phase 47: Performance & Scale Engine ─────────────────────────────────────
from .performance_tester import PerformanceTester

# ── Phase 48: Testing & Quality Assurance ────────────────────────────────────
from .scan_quality_tester import ScanQualityTester


def get_all_testers():
    """Return instances of all vulnerability testers."""
    return [
        # Core Injection (Phase 1)
        SQLInjectionTester(),
        XSSTester(),
        CommandInjectionTester(),
        SSTITester(),
        XXETester(),

        # Existing (upgraded)
        CSRFTester(),
        AuthTester(),
        MisconfigTester(),
        DataExposureTester(),
        AccessControlTester(),
        SSRFTester(),
        ComponentTester(),
        LoggingTester(),

        # Advanced (Phase 2)
        DeserializationTester(),
        HostHeaderTester(),
        HTTPSmugglingTester(),
        CRLFInjectionTester(),
        JWTTester(),

        # Modern (Phase 3)
        RaceConditionTester(),
        WebSocketTester(),
        GraphQLTester(),
        FileUploadTester(),
        NoSQLInjectionTester(),
        CachePoisoningTester(),

        # Infrastructure (Phase 4)
        CORSTester(),
        ClickjackingTester(),
        LDAPXPathTester(),
        SubdomainTakeoverTester(),
        CloudStorageTester(),

        # AI / LLM Security (Phase 5)
        PromptInjectionTester(),
        AIEndpointTester(),

        # Missing Vulnerability Classes (Phase 6)
        PrototypePollutionTester(),
        OpenRedirectTester(),
        BusinessLogicTester(),
        APITester(),

        # Discovery Testers (Phase 3 Upgrade)
        ContentDiscoveryTester(),
        APIDiscoveryTester(),

        # Advanced Vulnerability Engine (Phase 8)
        IDORTester(),
        MassAssignmentTester(),
        PathTraversalTester(),
        SSITester(),
        HTTP2Tester(),

        # AI Security Module Expansion (Phase 9)
        AiDataPoisoningTester(),

        # New Vulnerability Classes — Batch 1 (Phase 26)
        OAuthTester(),
        SAMLTester(),
        CSSInjectionTester(),
        CSVInjectionTester(),
        DNSRebindingTester(),
        HPPTester(),
        TypeJugglingTester(),
        ReDoSTester(),

        # New Vulnerability Classes — Batch 2 (Phase 27)
        WebCacheDeceptionTester(),
        XSLeakTester(),
        XSLTInjectionTester(),
        ZipSlipTester(),
        VHostTester(),
        InsecureRandomnessTester(),
        ReverseProxyMisconfigTester(),
        DependencyConfusionTester(),

        # 403/401 Bypass Engine (Phase 28)
        ForbiddenBypassTester(),

        # CMS Deep Scanner (Phase 29)
        CMSTester(),

        # Exploit Verification Engine (Phase 30)
        ExploitVerificationTester(),

        # Business Logic Testing Engine (Phase 31)
        BusinessLogicDeepTester(),

        # Advanced WAF Evasion Engine (Phase 32)
        AdvancedWAFEvasionTester(),

        # Supply Chain & Dependency Scanner (Phase 33)
        SupplyChainTester(),

        # Advanced Port & Service Scanning (Phase 34)
        NetworkTester(),

        # Reporting & Integration (Phase 35)
        ReportingIntegrationTester(),

        # Active Recon Enhancement (Phase 36)
        ActiveReconTester(),

        # JavaScript Intelligence v2 (Phase 37)
        JsIntelligenceTester(),

        # AI/ML Enhancement (Phase 38)
        MLEnhancementTester(),

        # Scan Profile & Template System (Phase 39)
        ScanProfileTester(),

        # Rate Limit & Stealth Mode (Phase 40)
        StealthTester(),

        # Vulnerability Knowledge Base (Phase 41)
        KnowledgeTester(),

        # Advanced Graph & Chain Analysis (Phase 42)
        AttackGraphTester(),

        # Scheduled & Continuous Scanning (Phase 43)
        ScheduledScanTester(),

        # WSTG Coverage — Full OWASP WSTG v4.2 (Phase 46)
        WSTGInfoTester(),
        WSTGConfTester(),
        WSTGIdentityTester(),
        WSTGAuthTester(),
        WSTGSessionTester(),
        WSTGInputValidationTester(),
        WSTGErrorHandlingTester(),
        WSTGCryptographyTester(),
        WSTGBusinessLogicTester(),
        WSTGClientSideTester(),

        # Performance & Scale Engine (Phase 47)
        PerformanceTester(),

        # Scan Quality & Coverage Auditor (Phase 48)
        ScanQualityTester(),
    ]

