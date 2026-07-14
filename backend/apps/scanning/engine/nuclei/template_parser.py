"""
TemplateParser — Parse nuclei YAML templates into executable Python objects.

Converts YAML template definitions into NucleiTemplate dataclass instances
that the TemplateRunner can execute. Supports HTTP request templates with
matchers (word, regex, status, binary, dsl) and extractors (regex, kval,
json, xpath).
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class TemplateMatcher:
    """A single matcher from a nuclei template."""
    type: str                      # word, regex, status, binary, dsl
    values: List[Any] = field(default_factory=list)
    part: str = 'body'             # body, header, all, status
    condition: str = 'or'          # or, and
    negative: bool = False         # Invert match result
    case_insensitive: bool = False


@dataclass
class TemplateExtractor:
    """A single extractor from a nuclei template."""
    type: str                      # regex, kval, json, xpath, dsl
    values: List[str] = field(default_factory=list)
    part: str = 'body'
    name: str = ''
    group: int = 0                 # Regex capture group


@dataclass
class TemplateRequest:
    """An HTTP request definition from a nuclei template."""
    method: str = 'GET'
    path: List[str] = field(default_factory=lambda: ['/'])
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''
    matchers: List[TemplateMatcher] = field(default_factory=list)
    extractors: List[TemplateExtractor] = field(default_factory=list)
    matchers_condition: str = 'or'  # Global matcher condition
    redirects: bool = False
    max_redirects: int = 3
    cookie_reuse: bool = False


@dataclass
class TemplateInfo:
    """Metadata from the info block of a nuclei template."""
    name: str = ''
    severity: str = 'info'
    description: str = ''
    tags: List[str] = field(default_factory=list)
    reference: List[str] = field(default_factory=list)
    author: str = ''
    # Classification
    cwe_id: str = ''
    cvss_score: float = 0.0
    cve_id: str = ''


@dataclass
class NucleiTemplate:
    """Fully parsed nuclei template ready for execution."""
    id: str = ''
    info: TemplateInfo = field(default_factory=TemplateInfo)
    requests: List[TemplateRequest] = field(default_factory=list)
    template_type: str = 'http'    # http, dns, network
    file_path: str = ''            # Source YAML path

    @property
    def is_valid(self) -> bool:
        """Check if template has minimum required fields."""
        return bool(self.id and self.info.name and self.requests)


# ── Template Variables ───────────────────────────────────────────────────

TEMPLATE_VARIABLES = {
    '{{BaseURL}}', '{{RootURL}}', '{{Host}}', '{{Hostname}}',
    '{{Port}}', '{{Scheme}}', '{{Path}}',
}


def substitute_variables(text: str, base_url: str) -> str:
    """Replace nuclei template variables with actual values."""
    if not text:
        return text

    from urllib.parse import urlparse
    parsed = urlparse(base_url)

    hostname = parsed.hostname or ''
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    root_url = f'{parsed.scheme}://{parsed.netloc}'

    replacements = {
        '{{BaseURL}}': base_url.rstrip('/'),
        '{{RootURL}}': root_url,
        '{{Host}}': parsed.netloc,
        '{{Hostname}}': hostname,
        '{{Port}}': str(port),
        '{{Scheme}}': parsed.scheme,
        '{{Path}}': parsed.path or '/',
    }

    result = text
    for var, val in replacements.items():
        result = result.replace(var, val)
    return result


# ── Parser ───────────────────────────────────────────────────────────────

class TemplateParser:
    """Parse nuclei YAML template files into NucleiTemplate objects."""

    def parse_file(self, file_path: str) -> Optional[NucleiTemplate]:
        """Parse a YAML template file into a NucleiTemplate."""
        try:
            import yaml
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return None
            return self.parse_dict(data, file_path=file_path)
        except Exception as exc:
            logger.debug('Failed to parse template %s: %s', file_path, exc)
            return None

    def parse_dict(self, data: dict, file_path: str = '') -> Optional[NucleiTemplate]:
        """Parse a template from a dictionary (already loaded YAML)."""
        if not isinstance(data, dict):
            return None

        template_id = data.get('id', '')
        info = self._parse_info(data.get('info', {}))

        # Determine template type and parse requests
        requests_list = []
        template_type = 'http'

        if 'http' in data:
            template_type = 'http'
            http_items = data['http']
            if isinstance(http_items, list):
                for item in http_items:
                    req = self._parse_http_request(item)
                    if req:
                        requests_list.append(req)
            elif isinstance(http_items, dict):
                req = self._parse_http_request(http_items)
                if req:
                    requests_list.append(req)

        # Also check legacy 'requests' key
        elif 'requests' in data:
            template_type = 'http'
            req_items = data['requests']
            if isinstance(req_items, list):
                for item in req_items:
                    req = self._parse_http_request(item)
                    if req:
                        requests_list.append(req)

        elif 'dns' in data:
            template_type = 'dns'
        elif 'network' in data or 'tcp' in data:
            template_type = 'network'

        template = NucleiTemplate(
            id=template_id,
            info=info,
            requests=requests_list,
            template_type=template_type,
            file_path=file_path,
        )
        return template

    def _parse_info(self, info_data: dict) -> TemplateInfo:
        """Parse the info block of a template."""
        if not isinstance(info_data, dict):
            return TemplateInfo()

        tags_raw = info_data.get('tags', '')
        if isinstance(tags_raw, str):
            tags = [t.strip() for t in tags_raw.split(',') if t.strip()]
        elif isinstance(tags_raw, list):
            tags = tags_raw
        else:
            tags = []

        reference = info_data.get('reference', [])
        if isinstance(reference, str):
            reference = [reference]
        elif not isinstance(reference, list):
            reference = []
        # Filter out non-string items (e.g. dicts from YAML like {url: ...})
        reference = [str(r) for r in reference if isinstance(r, (str, int, float))]

        # Parse classification
        classification = info_data.get('classification', {}) or {}
        cwe_id = ''
        cvss_score = 0.0
        cve_id = ''
        if isinstance(classification, dict):
            cwe_raw = classification.get('cwe-id', '') or classification.get('cwe_id', '')
            if isinstance(cwe_raw, list):
                cwe_id = cwe_raw[0] if cwe_raw else ''
            else:
                cwe_id = str(cwe_raw)
            try:
                cvss_score = float(classification.get('cvss-score', 0) or
                                   classification.get('cvss_score', 0) or 0)
            except (ValueError, TypeError):
                cvss_score = 0.0
            cve_raw = classification.get('cve-id', '') or classification.get('cve_id', '')
            if isinstance(cve_raw, list):
                cve_id = cve_raw[0] if cve_raw else ''
            else:
                cve_id = str(cve_raw)

        return TemplateInfo(
            name=info_data.get('name', ''),
            severity=info_data.get('severity', 'info').lower(),
            description=info_data.get('description', ''),
            tags=tags,
            reference=reference,
            author=info_data.get('author', ''),
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cve_id=cve_id,
        )

    def _parse_http_request(self, req_data: dict) -> Optional[TemplateRequest]:
        """Parse a single HTTP request block."""
        if not isinstance(req_data, dict):
            return None

        method = req_data.get('method', 'GET').upper()

        # Parse paths
        path = req_data.get('path', ['/'])
        if isinstance(path, str):
            path = [path]

        # Parse headers
        headers = req_data.get('headers', {})
        if not isinstance(headers, dict):
            headers = {}

        body = req_data.get('body', '')

        # Parse matchers
        matchers = []
        matchers_condition = req_data.get('matchers-condition', 'or')
        for m in req_data.get('matchers', []):
            matcher = self._parse_matcher(m)
            if matcher:
                matchers.append(matcher)

        # Parse extractors
        extractors = []
        for e in req_data.get('extractors', []):
            extractor = self._parse_extractor(e)
            if extractor:
                extractors.append(extractor)

        return TemplateRequest(
            method=method,
            path=path,
            headers=headers,
            body=body,
            matchers=matchers,
            extractors=extractors,
            matchers_condition=matchers_condition,
            redirects=bool(req_data.get('redirects', False)),
            max_redirects=int(req_data.get('max-redirects', 3)),
            cookie_reuse=bool(req_data.get('cookie-reuse', False)),
        )

    def _parse_matcher(self, m_data: dict) -> Optional[TemplateMatcher]:
        """Parse a single matcher definition."""
        if not isinstance(m_data, dict):
            return None

        mtype = m_data.get('type', 'word')

        # Values can be in 'words', 'regex', 'status', 'binary', or 'dsl' keys
        values = []
        if mtype == 'word':
            values = m_data.get('words', [])
        elif mtype == 'regex':
            values = m_data.get('regex', [])
        elif mtype == 'status':
            values = m_data.get('status', [])
        elif mtype == 'binary':
            values = m_data.get('binary', [])
        elif mtype == 'dsl':
            values = m_data.get('dsl', [])

        if not isinstance(values, list):
            values = [values]

        return TemplateMatcher(
            type=mtype,
            values=values,
            part=m_data.get('part', 'body'),
            condition=m_data.get('condition', 'or'),
            negative=bool(m_data.get('negative', False)),
            case_insensitive=bool(m_data.get('case-insensitive', False)),
        )

    def _parse_extractor(self, e_data: dict) -> Optional[TemplateExtractor]:
        """Parse a single extractor definition."""
        if not isinstance(e_data, dict):
            return None

        etype = e_data.get('type', 'regex')

        values = []
        if etype == 'regex':
            values = e_data.get('regex', [])
        elif etype == 'kval':
            values = e_data.get('kval', [])
        elif etype == 'json':
            values = e_data.get('json', [])
        elif etype == 'xpath':
            values = e_data.get('xpath', [])
        elif etype == 'dsl':
            values = e_data.get('dsl', [])

        if not isinstance(values, list):
            values = [values]

        return TemplateExtractor(
            type=etype,
            values=values,
            part=e_data.get('part', 'body'),
            name=e_data.get('name', ''),
            group=int(e_data.get('group', 0)),
        )
