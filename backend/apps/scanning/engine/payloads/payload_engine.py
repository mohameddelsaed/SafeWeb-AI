"""
Payload Engine — Central payload generation and mutation engine.

Used by testers to get context-aware, WAF-adapted payloads.
Supports 10+ mutation techniques and per-WAF bypass strategies.
"""
import html
import urllib.parse


class PayloadEngine:
    """Central payload generation and mutation engine.

    Used by testers to get context-aware, WAF-adapted payloads.
    """

    def __init__(self, waf_info: dict = None, tech_stack: list = None):
        self._waf_info = waf_info or {}
        self._tech_stack = tech_stack or []

    def get_payloads(self, vuln_type: str, context: str = 'url_param',
                     depth: str = 'medium') -> list:
        """Get context-aware payloads for a vulnerability type.

        Args:
            vuln_type:  'xss', 'sqli', 'ssrf', 'ssti', 'cmdi', 'xxe',
                        'traversal', 'nosql', 'prompt_injection', 'open_redirect'
            context:    'url_param', 'form_field', 'header', 'json_body',
                        'xml_body', 'cookie', 'path_segment'
            depth:      'shallow', 'medium', 'deep'

        Returns:
            Depth-appropriate payload list with WAF mutations if WAF detected.
        """
        base = self._get_base_payloads(vuln_type, depth)

        # Apply context-specific transformations
        if context == 'json_body':
            base = [p.replace("'", '"') for p in base]
        elif context == 'xml_body':
            base = [html.escape(p) if '<' not in p else p for p in base]
        elif context == 'header':
            base = [p.replace('\n', '').replace('\r', '') for p in base]

        # Apply WAF evasion if WAF detected
        if self._waf_info.get('detected'):
            waf_products = [p.get('name', '').lower()
                            for p in self._waf_info.get('products', [])]
            mutated = []
            for payload in base:
                mutated.append(payload)
                for waf_name in waf_products:
                    mutated.extend(self.get_waf_bypass(payload, waf_name)[:3])
            base = mutated

        return base

    def mutate(self, payload: str, techniques: list = None) -> list:
        """Apply mutation techniques and return all variants.

        Args:
            payload: Original payload string.
            techniques: List of technique names. Defaults to all applicable.

        Returns:
            List of mutated payload variants (includes original).
        """
        if techniques is None:
            techniques = [
                'url_encode', 'double_url_encode', 'html_entity_decimal',
                'unicode_fullwidth', 'case_toggle', 'whitespace_variation',
                'null_byte_insert',
            ]

        variants = [payload]
        technique_map = {
            'url_encode': self._url_encode,
            'double_url_encode': self._double_url_encode,
            'triple_url_encode': self._triple_url_encode,
            'html_entity_decimal': self._html_entity_decimal,
            'html_entity_hex': self._html_entity_hex,
            'unicode_fullwidth': self._unicode_fullwidth,
            'case_toggle': self._case_toggle,
            'sql_comment_insert': self._sql_comment_insert,
            'whitespace_variation': self._whitespace_variation,
            'null_byte_insert': self._null_byte_insert,
            'concat_tricks': self._concat_tricks,
        }

        for tech in techniques:
            fn = technique_map.get(tech)
            if fn:
                result = fn(payload)
                if isinstance(result, list):
                    variants.extend(result)
                else:
                    variants.append(result)

        return list(dict.fromkeys(variants))  # Deduplicate while preserving order

    # ── Mutation techniques ─────────────────────────────────────────────────

    def _url_encode(self, payload: str, layers: int = 1) -> str:
        result = payload
        for _ in range(layers):
            result = urllib.parse.quote(result, safe='')
        return result

    def _double_url_encode(self, payload: str) -> str:
        return self._url_encode(payload, layers=2)

    def _triple_url_encode(self, payload: str) -> str:
        return self._url_encode(payload, layers=3)

    def _html_entity_decimal(self, payload: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in payload)

    def _html_entity_hex(self, payload: str) -> str:
        return ''.join(f'&#x{ord(c):x};' for c in payload)

    def _unicode_fullwidth(self, payload: str) -> str:
        result = []
        for c in payload:
            cp = ord(c)
            if 0x21 <= cp <= 0x7E:
                result.append(chr(cp + 0xFEE0))
            else:
                result.append(c)
        return ''.join(result)

    def _case_toggle(self, payload: str) -> list:
        variants = []
        # Alternating case
        alt = ''.join(c.upper() if i % 2 == 0 else c.lower()
                      for i, c in enumerate(payload))
        variants.append(alt)
        # Random uppercase keywords
        variants.append(payload.upper())
        variants.append(payload.lower())
        return variants

    def _sql_comment_insert(self, payload: str) -> list:
        variants = []
        # Insert /**/ between keywords
        for kw in ['SELECT', 'UNION', 'FROM', 'WHERE', 'OR', 'AND']:
            if kw.lower() in payload.lower():
                variants.append(payload.replace(kw, f'/**/{kw}/**/'))
                variants.append(payload.replace(kw, kw.replace('', '/**/')[4:-4]))
        if not variants:
            variants.append(f'/**/{payload}/**/')
        return variants

    def _whitespace_variation(self, payload: str) -> list:
        return [
            payload.replace(' ', '\t'),
            payload.replace(' ', '  '),
            payload.replace(' ', '%09'),
            payload.replace(' ', '%0a'),
            payload.replace(' ', '/**/'),
        ]

    def _null_byte_insert(self, payload: str) -> list:
        return [
            f'{payload}%00',
            f'{payload}\x00',
            f'%00{payload}',
        ]

    def _concat_tricks(self, payload: str, engine: str = 'generic') -> list:
        variants = []
        if engine in ('mysql', 'generic'):
            variants.append(payload.replace("'", "' '"))
            variants.append(payload.replace(' ', ' /*!*/ '))
        if engine in ('mssql', 'generic'):
            variants.append(payload.replace('+', ''))
        if engine in ('postgres', 'generic'):
            variants.append(payload.replace("'", "' || '"))
        return variants

    def get_waf_bypass(self, payload: str, waf_product: str) -> list:
        """Return WAF-specific bypass variants for a given payload."""
        try:
            from .waf_bypass_payloads import WAF_BYPASS_DB
        except ImportError:
            return []

        waf_key = waf_product.lower().replace(' ', '_')
        waf_data = WAF_BYPASS_DB.get(waf_key, {})

        # Try to detect payload type
        vuln_type = self._detect_payload_type(payload)
        type_bypasses = waf_data.get(vuln_type, [])

        if type_bypasses:
            return type_bypasses[:10]

        # Fall back to generic mutations
        return [
            self._url_encode(payload),
            self._double_url_encode(payload),
            self._unicode_fullwidth(payload),
        ]

    def _detect_payload_type(self, payload: str) -> str:
        pl = payload.lower()
        if '<script' in pl or 'alert(' in pl or 'onerror' in pl:
            return 'xss'
        if 'select' in pl or 'union' in pl or "' or " in pl:
            return 'sqli'
        if '127.0.0.1' in pl or 'localhost' in pl or '169.254' in pl:
            return 'ssrf'
        if '{{' in pl or '{%' in pl:
            return 'ssti'
        if ';' in pl and ('cat ' in pl or 'id' in pl or 'whoami' in pl):
            return 'cmdi'
        return 'generic'

    def _get_base_payloads(self, vuln_type: str, depth: str) -> list:
        """Load base payloads from the appropriate payload module.

        First tries the existing Python payload modules. For types that
        also have data/ text files (or types only in data/), augments
        with payloads from the PayloadLoader.
        """
        loaders = {
            'xss': ('xss_payloads', 'get_xss_payloads_by_depth'),
            'sqli': ('sqli_payloads', 'get_sqli_payloads_by_depth'),
            'ssrf': ('ssrf_payloads', 'get_ssrf_payloads_by_depth'),
            'ssti': ('ssti_payloads', 'get_ssti_payloads_by_depth'),
            'cmdi': ('cmdi_payloads', 'get_cmdi_payloads_by_depth'),
            'prompt_injection': ('prompt_injection_payloads', 'get_prompt_injection_payloads_by_depth'),
            'xxe': ('xxe_payloads', 'get_xxe_payloads_by_depth'),
            'traversal': ('traversal_payloads', 'get_traversal_payloads_by_depth'),
            'nosql': ('nosql_payloads', 'get_nosql_payloads_by_depth'),
        }

        base = []
        if vuln_type in loaders:
            module_name, fn_name = loaders[vuln_type]
            try:
                import importlib
                mod = importlib.import_module(f'.{module_name}', package='apps.scanning.engine.payloads')
                fn = getattr(mod, fn_name, None)
                if fn:
                    base = fn(depth)
            except (ImportError, AttributeError):
                pass

        # Augment with data/ text file payloads for deep scans,
        # or as primary source for types not in Python modules
        if depth == 'deep' or not base:
            try:
                from .payload_loader import get_payloads as load_from_files
                waf_name = None
                if self._waf_info.get('detected'):
                    products = self._waf_info.get('products', [])
                    if products:
                        waf_name = products[0].get('name', '').lower()
                tech_name = self._tech_stack[0] if self._tech_stack else None
                file_payloads = load_from_files(
                    vuln_type, depth=depth, waf=waf_name, tech=tech_name
                )
                if base:
                    # Merge — add file payloads not already in base
                    base_set = set(base)
                    base.extend(p for p in file_payloads if p not in base_set)
                else:
                    base = file_payloads
            except (ImportError, AttributeError):
                pass

        return base
