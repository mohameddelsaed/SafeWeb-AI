"""
TemplateRunner — Execute parsed nuclei templates against target URLs.

Takes NucleiTemplate objects (from TemplateParser) and executes each
HTTP request, evaluating matchers and extractors to determine if the
target is vulnerable. Results are returned in the standard _build_vuln
dict format used by the rest of the scanner.
"""
import asyncio
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from ..rate_limiter import RateLimiter
from .template_parser import (
    NucleiTemplate,
    TemplateExtractor,
    TemplateMatcher,
    TemplateRequest,
    substitute_variables,
)

logger = logging.getLogger(__name__)

# Severity → CVSS fallback (matches BaseTester.SEVERITY_CVSS_MAP)
SEVERITY_CVSS = {
    'critical': 9.5,
    'high': 7.5,
    'medium': 5.0,
    'low': 2.5,
    'info': 0.0,
}

# Max concurrent template executions
DEFAULT_MAX_CONCURRENT = 50

# Request timeout for template checks
TEMPLATE_REQUEST_TIMEOUT = 10


class TemplateRunner:
    """Execute nuclei templates against a target and return vulnerability dicts."""

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        timeout: int = TEMPLATE_REQUEST_TIMEOUT,
    ):
        self._rate_limiter = rate_limiter
        self._max_concurrent = max_concurrent
        self._timeout = timeout
        self._session: Optional[requests.Session] = None

    # ── Public API ────────────────────────────────────────────────────────

    async def run_templates(
        self,
        templates: List[NucleiTemplate],
        base_url: str,
    ) -> List[Dict[str, Any]]:
        """Execute multiple templates concurrently, return vuln dicts."""
        if not templates:
            return []

        semaphore = asyncio.Semaphore(self._max_concurrent)
        tasks = []
        for template in templates:
            tasks.append(self._run_with_semaphore(semaphore, template, base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulns = []
        for result in results:
            if isinstance(result, Exception):
                logger.debug('Template execution error: %s', result)
                continue
            if result:
                vulns.extend(result)
        return vulns

    def run_template_sync(
        self,
        template: NucleiTemplate,
        base_url: str,
    ) -> List[Dict[str, Any]]:
        """Execute a single template synchronously. Returns list of vuln dicts."""
        if not template.is_valid or template.template_type != 'http':
            return []

        session = self._get_session()
        host = urlparse(base_url).hostname or ''
        findings: List[Dict[str, Any]] = []

        for req_def in template.requests:
            for path_template in req_def.path:
                url = substitute_variables(path_template, base_url)

                # Rate limiting
                if self._rate_limiter:
                    self._rate_limiter.acquire_sync(host)

                try:
                    response = self._execute_request(session, req_def, url)
                except Exception as exc:
                    logger.debug('Template %s request failed: %s', template.id, exc)
                    if self._rate_limiter:
                        self._rate_limiter.record_response(host, 0)
                    continue

                if response is None:
                    continue

                if self._rate_limiter:
                    self._rate_limiter.record_response(host, response.status_code)

                # Evaluate matchers
                matched = self._evaluate_matchers(
                    req_def.matchers, req_def.matchers_condition, response,
                )
                if not matched:
                    continue

                # Extract evidence
                evidence = self._run_extractors(req_def.extractors, response)

                vuln = self._template_to_vuln(template, url, evidence)
                findings.append(vuln)

        return findings

    # ── Internal ──────────────────────────────────────────────────────────

    async def _run_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        template: NucleiTemplate,
        base_url: str,
    ) -> List[Dict[str, Any]]:
        """Wrap sync execution in semaphore-bounded thread."""
        async with semaphore:
            return await asyncio.to_thread(
                self.run_template_sync, template, base_url,
            )

    def _get_session(self) -> requests.Session:
        """Lazily create & return a requests.Session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.verify = False
            self._session.headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )
        return self._session

    def _execute_request(
        self,
        session: requests.Session,
        req: TemplateRequest,
        url: str,
    ) -> Optional[requests.Response]:
        """Send a single HTTP request per template spec."""
        headers = dict(req.headers)  # Copy so we don't mutate
        body = req.body or None

        try:
            resp = session.request(
                method=req.method,
                url=url,
                headers=headers,
                data=body,
                timeout=self._timeout,
                allow_redirects=req.redirects,
            )
            return resp
        except requests.exceptions.Timeout:
            logger.debug('Template request timeout: %s', url)
            return None
        except requests.exceptions.RequestException as exc:
            logger.debug('Template request error %s: %s', url, exc)
            return None

    # ── Matcher Evaluation ────────────────────────────────────────────────

    def _evaluate_matchers(
        self,
        matchers: List[TemplateMatcher],
        global_condition: str,
        response: requests.Response,
    ) -> bool:
        """Evaluate all matchers against the response."""
        if not matchers:
            return False  # No matchers = no match

        results = []
        for matcher in matchers:
            result = self._evaluate_single_matcher(matcher, response)
            # Apply negative flag
            if matcher.negative:
                result = not result
            results.append(result)

        if global_condition == 'and':
            return all(results)
        else:  # 'or'
            return any(results)

    def _evaluate_single_matcher(
        self,
        matcher: TemplateMatcher,
        response: requests.Response,
    ) -> bool:
        """Evaluate one matcher against the response."""
        body = response.text
        headers_str = '\r\n'.join(f'{k}: {v}' for k, v in response.headers.items())

        # Select part to match against
        if matcher.part == 'header':
            content = headers_str
        elif matcher.part == 'all':
            content = headers_str + '\r\n\r\n' + body
        elif matcher.part == 'status':
            content = str(response.status_code)
        else:  # 'body' default
            content = body

        if matcher.type == 'status':
            return self._match_status(matcher.values, response.status_code, matcher.condition)
        elif matcher.type == 'word':
            return self._match_words(matcher.values, content, matcher.condition, matcher.case_insensitive)
        elif matcher.type == 'regex':
            return self._match_regex(matcher.values, content, matcher.condition)
        elif matcher.type == 'binary':
            return self._match_binary(matcher.values, response.content)
        elif matcher.type == 'dsl':
            # DSL matchers need full expression evaluation — simplified support
            return self._match_dsl(matcher.values, response)

        return False

    @staticmethod
    def _match_status(values: list, status_code: int, condition: str) -> bool:
        """Check if response status code matches."""
        results = [int(v) == status_code for v in values if str(v).isdigit()]
        if condition == 'and':
            return bool(results) and all(results)
        return any(results)

    @staticmethod
    def _match_words(values: list, content: str, condition: str, case_insensitive: bool) -> bool:
        """Check if words appear in content."""
        check_content = content.lower() if case_insensitive else content
        results = []
        for word in values:
            w = str(word).lower() if case_insensitive else str(word)
            results.append(w in check_content)
        if condition == 'and':
            return bool(results) and all(results)
        return any(results)

    @staticmethod
    def _match_regex(values: list, content: str, condition: str) -> bool:
        """Check if regex patterns match content."""
        results = []
        for pattern in values:
            try:
                results.append(bool(re.search(str(pattern), content)))
            except re.error:
                results.append(False)
        if condition == 'and':
            return bool(results) and all(results)
        return any(results)

    @staticmethod
    def _match_binary(values: list, content: bytes) -> bool:
        """Check if binary patterns appear in raw content."""
        for pattern in values:
            try:
                hex_bytes = bytes.fromhex(str(pattern))
                if hex_bytes in content:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _match_dsl(values: list, response: requests.Response) -> bool:
        """Simplified DSL matcher — supports basic status_code and content_length checks."""
        for expr in values:
            expr_str = str(expr)
            # status_code == NNN
            if 'status_code' in expr_str:
                match = re.search(r'status_code\s*==\s*(\d+)', expr_str)
                if match and response.status_code == int(match.group(1)):
                    return True
            # contains(body, "...")
            if 'contains(body' in expr_str:
                match = re.search(r'contains\(body,\s*["\'](.+?)["\']\)', expr_str)
                if match and match.group(1) in response.text:
                    return True
        return False

    # ── Extractor Evaluation ──────────────────────────────────────────────

    def _run_extractors(
        self,
        extractors: List[TemplateExtractor],
        response: requests.Response,
    ) -> str:
        """Run extractors and return combined evidence string."""
        if not extractors:
            return f'Status: {response.status_code}, Length: {len(response.content)}'

        evidence_parts = []
        for extractor in extractors:
            extracted = self._run_single_extractor(extractor, response)
            if extracted:
                label = extractor.name or extractor.type
                evidence_parts.append(f'{label}: {extracted}')

        if evidence_parts:
            return ' | '.join(evidence_parts)
        return f'Status: {response.status_code}'

    def _run_single_extractor(
        self,
        extractor: TemplateExtractor,
        response: requests.Response,
    ) -> str:
        """Run a single extractor and return the result string."""
        if extractor.part == 'header':
            content = '\r\n'.join(f'{k}: {v}' for k, v in response.headers.items())
        else:
            content = response.text

        if extractor.type == 'regex':
            return self._extract_regex(extractor.values, content, extractor.group)
        elif extractor.type == 'kval':
            return self._extract_kval(extractor.values, response.headers)
        elif extractor.type == 'json':
            return self._extract_json(extractor.values, response)
        elif extractor.type == 'xpath':
            return self._extract_xpath(extractor.values, content)
        return ''

    @staticmethod
    def _extract_regex(patterns: list, content: str, group: int) -> str:
        """Extract via regex patterns."""
        for pattern in patterns:
            try:
                m = re.search(str(pattern), content)
                if m:
                    try:
                        return m.group(group)
                    except IndexError:
                        return m.group(0)
            except re.error:
                continue
        return ''

    @staticmethod
    def _extract_kval(keys: list, headers) -> str:
        """Extract header values by key."""
        parts = []
        for key in keys:
            val = headers.get(str(key), '')
            if val:
                parts.append(f'{key}={val}')
        return ', '.join(parts)

    @staticmethod
    def _extract_json(paths: list, response: requests.Response) -> str:
        """Extract values from JSON response via simple dot paths."""
        try:
            data = response.json()
        except (ValueError, TypeError):
            return ''

        parts = []
        for path in paths:
            keys = str(path).strip('.').split('.')
            current = data
            for key in keys:
                if isinstance(current, dict):
                    current = current.get(key)
                elif isinstance(current, list) and key.isdigit():
                    idx = int(key)
                    current = current[idx] if idx < len(current) else None
                else:
                    current = None
                    break
            if current is not None:
                parts.append(str(current))
        return ', '.join(parts)

    @staticmethod
    def _extract_xpath(paths: list, content: str) -> str:
        """Placeholder for XPath extraction — requires lxml."""
        # Minimal implementation: return empty for now
        return ''

    # ── Vulnerability Conversion ──────────────────────────────────────────

    @staticmethod
    def _template_to_vuln(
        template: NucleiTemplate,
        affected_url: str,
        evidence: str,
    ) -> Dict[str, Any]:
        """Convert a template match into a standard vulnerability dict."""
        info = template.info
        severity = info.severity if info.severity in SEVERITY_CVSS else 'info'
        cvss = info.cvss_score or SEVERITY_CVSS.get(severity, 0.0)

        # Category from first tag, or 'Nuclei'
        category = info.tags[0].title() if info.tags else 'Nuclei'

        # Build reference evidence
        ref_str = ''
        if info.reference:
            ref_str = ', '.join(info.reference[:3])

        combined_evidence = evidence
        if ref_str:
            combined_evidence = f'{evidence} | Refs: {ref_str}'

        return {
            'name': f'[Nuclei] {info.name}',
            'severity': severity,
            'category': category,
            'description': info.description or f'Detected by nuclei template: {template.id}',
            'impact': f'Vulnerability detected: {info.name} ({severity})',
            'remediation': f'Review nuclei template {template.id} for details. References: {ref_str}' if ref_str else f'Review nuclei template {template.id} for remediation guidance.',
            'cwe': info.cwe_id,
            'cvss': cvss,
            'affected_url': affected_url,
            'evidence': combined_evidence[:2000],
        }
