"""
Secret Scanner Engine — Phase 25.

Scans crawled page bodies, JS files and API responses for leaked secrets,
credentials, API keys, private keys, database connection strings and more.

Features:
  - 200+ regex patterns from patterns.py
  - Shannon entropy detection for high-randomness strings
  - Format validation (check if detected key matches valid format)
  - De-duplication across pages
  - Severity classification with CVSS scoring
  - Source-map-aware analysis (detects .js.map references)
  - Base64 payload decoding
"""

import hashlib
import logging
import math
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .patterns import SECRET_PATTERNS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_BODY_SIZE = 500_000          # Only scan first 500 KB of each body
MIN_ENTROPY_THRESHOLD = 4.5      # Shannon entropy threshold for random strings
MIN_SECRET_LENGTH = 16           # Minimum length for entropy-based detection
MAX_SECRET_LENGTH = 500          # Maximum captured secret length
MAX_FINDINGS_PER_PAGE = 50       # Avoid flooding from noisy pages
MAX_TOTAL_FINDINGS = 500         # Hard cap on total findings per scan

# Entropy-candidate extraction: long alphanumeric strings
_ENTROPY_CANDIDATE_RE = re.compile(
    r'(?<![A-Za-z0-9_/+-])'
    r'([A-Za-z0-9+/=_-]{20,256})'
    r'(?![A-Za-z0-9_/+-])'
)

# Context-hint keywords near a high-entropy string
_SECRET_CONTEXT_KEYWORDS = re.compile(
    r'(?i)(?:key|secret|token|password|passwd|credential|auth|bearer|private|api[_-]?key|access)',
)

# False-positive suppression patterns
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r'^[A-Za-z]+$'),                     # All-alpha (likely a word)
    re.compile(r'^\d+$'),                             # All-numeric
    re.compile(r'^(?:true|false|null|undefined)$', re.I),
    re.compile(r'^(?:function|return|const|let|var|class|import|export)\b', re.I),
    re.compile(r'^https?://'),                        # Plain URLs
    re.compile(r'^data:'),                            # Data URIs
    re.compile(r'^[A-Za-z0-9]{20,}={3,}$'),          # Padding-heavy base64 (often assets)
]

# Base64 detection for embedded secrets
_BASE64_RE = re.compile(
    r'(?:["\'`]|^)([A-Za-z0-9+/]{40,}={0,2})(?:["\'`]|$)'
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    """A single detected secret."""
    pattern_name: str
    matched_text: str
    severity: str           # critical | high | medium | low | info
    cwe: str
    description: str
    source_url: str
    line_number: int = 0
    context: str = ''       # surrounding text snippet
    entropy: float = 0.0
    is_entropy_based: bool = False
    confidence: str = 'high'  # high | medium | low

    @property
    def signature(self) -> str:
        """Unique dedup key."""
        raw = f'{self.pattern_name}:{self.matched_text[:80]}:{self.source_url}'
        return hashlib.md5(raw.encode()).hexdigest()


@dataclass
class SecretScanResult:
    """Aggregated results from scanning all pages."""
    findings: list = field(default_factory=list)
    pages_scanned: int = 0
    patterns_matched: int = 0
    entropy_detections: int = 0
    source_maps_found: list = field(default_factory=list)
    base64_secrets_found: int = 0
    errors: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shannon entropy calculation
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def _is_false_positive(text: str) -> bool:
    """Check if a matched string is likely a false positive."""
    for pattern in _FALSE_POSITIVE_PATTERNS:
        if pattern.match(text):
            return True
    return False


def _extract_context(body: str, match_start: int, match_end: int,
                     context_chars: int = 60) -> str:
    """Extract surrounding context for a match."""
    start = max(0, match_start - context_chars)
    end = min(len(body), match_end + context_chars)
    ctx = body[start:end].replace('\n', ' ').strip()
    if start > 0:
        ctx = '...' + ctx
    if end < len(body):
        ctx = ctx + '...'
    return ctx


def _estimate_line_number(body: str, position: int) -> int:
    """Estimate the line number of a character position."""
    return body[:position].count('\n') + 1


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class SecretScanner:
    """Scan page bodies for secrets, credentials and sensitive data leaks."""

    def __init__(self, extra_patterns: list | None = None,
                 entropy_threshold: float = MIN_ENTROPY_THRESHOLD,
                 max_findings: int = MAX_TOTAL_FINDINGS):
        self._patterns = list(SECRET_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)
        self._entropy_threshold = entropy_threshold
        self._max_findings = max_findings
        self._seen_signatures: set[str] = set()

    def scan_pages(self, pages) -> SecretScanResult:
        """Scan a list of Page objects and return aggregated results.

        Args:
            pages: list of crawler.Page (or any object with .url and .body)

        Returns:
            SecretScanResult with all deduplicated findings.
        """
        result = SecretScanResult()

        for page in pages:
            if len(result.findings) >= self._max_findings:
                break
            try:
                self._scan_page(page, result)
            except Exception as exc:
                result.errors.append(f'Error scanning {getattr(page, "url", "?")}: {exc}')
                logger.warning('Secret scan error on %s: %s',
                               getattr(page, 'url', '?'), exc)

        result.pages_scanned = len(pages)
        return result

    def _scan_page(self, page, result: SecretScanResult):
        """Scan a single page."""
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '')
        if not body:
            return

        # Truncate very large bodies
        body = body[:MAX_BODY_SIZE]
        page_findings = 0

        # 1. Pattern-based scanning
        for pat_info in self._patterns:
            if page_findings >= MAX_FINDINGS_PER_PAGE:
                break
            if len(result.findings) >= self._max_findings:
                break

            try:
                for match in pat_info['regex'].finditer(body):
                    matched_text = match.group(0)[:MAX_SECRET_LENGTH]

                    if _is_false_positive(matched_text):
                        continue

                    finding = SecretFinding(
                        pattern_name=pat_info['name'],
                        matched_text=self._redact(matched_text),
                        severity=pat_info['severity'],
                        cwe=pat_info['cwe'],
                        description=pat_info['description'],
                        source_url=url,
                        line_number=_estimate_line_number(body, match.start()),
                        context=_extract_context(body, match.start(), match.end()),
                        confidence='high',
                    )

                    if finding.signature not in self._seen_signatures:
                        self._seen_signatures.add(finding.signature)
                        result.findings.append(finding)
                        result.patterns_matched += 1
                        page_findings += 1

                    if page_findings >= MAX_FINDINGS_PER_PAGE:
                        break
            except Exception:
                continue

        # 2. Entropy-based detection
        if page_findings < MAX_FINDINGS_PER_PAGE:
            self._scan_entropy(body, url, result)

        # 3. Base64.decoded secret detection
        if page_findings < MAX_FINDINGS_PER_PAGE:
            self._scan_base64(body, url, result)

        # 4. Track source map references
        self._track_source_maps(body, url, result)

    def _scan_entropy(self, body: str, url: str, result: SecretScanResult):
        """Find high-entropy strings that might be secrets."""
        for match in _ENTROPY_CANDIDATE_RE.finditer(body):
            if len(result.findings) >= self._max_findings:
                break

            candidate = match.group(1)

            if len(candidate) < MIN_SECRET_LENGTH:
                continue
            if _is_false_positive(candidate):
                continue

            ent = shannon_entropy(candidate)
            if ent < self._entropy_threshold:
                continue

            # Check if surrounded by secret-related context
            ctx_start = max(0, match.start() - 80)
            ctx_end = min(len(body), match.end() + 30)
            context_text = body[ctx_start:ctx_end]

            if not _SECRET_CONTEXT_KEYWORDS.search(context_text):
                continue  # Skip high-entropy strings without secret context

            finding = SecretFinding(
                pattern_name='High-Entropy Secret',
                matched_text=self._redact(candidate),
                severity='medium',
                cwe='CWE-798',
                description=f'High-entropy string (entropy={ent:.2f}) near secret-related keyword',
                source_url=url,
                line_number=_estimate_line_number(body, match.start()),
                context=_extract_context(body, match.start(), match.end()),
                entropy=ent,
                is_entropy_based=True,
                confidence='medium',
            )

            if finding.signature not in self._seen_signatures:
                self._seen_signatures.add(finding.signature)
                result.findings.append(finding)
                result.entropy_detections += 1

    def _scan_base64(self, body: str, url: str, result: SecretScanResult):
        """Detect secrets hidden in base64-encoded blobs."""
        import base64

        for match in _BASE64_RE.finditer(body):
            if len(result.findings) >= self._max_findings:
                break

            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            except Exception:
                continue

            if len(decoded) < 10:
                continue

            # Re-scan the decoded content for patterns
            for pat_info in self._patterns:
                pat_match = pat_info['regex'].search(decoded)
                if pat_match:
                    finding = SecretFinding(
                        pattern_name=f'Base64-Encoded {pat_info["name"]}',
                        matched_text=self._redact(pat_match.group(0)[:MAX_SECRET_LENGTH]),
                        severity=pat_info['severity'],
                        cwe=pat_info['cwe'],
                        description=f'{pat_info["description"]} (found in base64-encoded data)',
                        source_url=url,
                        line_number=_estimate_line_number(body, match.start()),
                        context=f'base64 decoded: {decoded[:100]}',
                        confidence='medium',
                    )

                    if finding.signature not in self._seen_signatures:
                        self._seen_signatures.add(finding.signature)
                        result.findings.append(finding)
                        result.base64_secrets_found += 1
                    break  # One match per blob is enough

    def _track_source_maps(self, body: str, url: str,
                           result: SecretScanResult):
        """Track source map file references for the report."""
        source_map_re = re.compile(
            r'//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)'
        )
        for match in source_map_re.finditer(body):
            map_url = match.group(1)
            if map_url.startswith('data:'):
                continue
            if not map_url.startswith('http'):
                parsed = urlparse(url)
                base = f'{parsed.scheme}://{parsed.netloc}'
                if map_url.startswith('/'):
                    map_url = base + map_url
                else:
                    path = url.rsplit('/', 1)[0]
                    map_url = path + '/' + map_url
            if map_url not in result.source_maps_found:
                result.source_maps_found.append(map_url)

    @staticmethod
    def _redact(text: str) -> str:
        """Partially redact a secret for safe logging/display.

        Shows first 6 and last 4 chars, masks the middle.
        """
        if len(text) <= 12:
            return text[:3] + '*' * (len(text) - 3)
        return text[:6] + '*' * (len(text) - 10) + text[-4:]

    def findings_to_vulns(self, result: SecretScanResult,
                          target_url: str = '') -> list[dict]:
        """Convert SecretScanResult findings to vulnerability dicts
        compatible with the orchestrator's raw_vulns format.

        Args:
            result: SecretScanResult from scan_pages()
            target_url: base target URL for the scan

        Returns:
            list of vuln dicts matching BaseTester._build_vuln format
        """
        vulns = []
        seen_sigs = set()

        for finding in result.findings:
            sig = hashlib.md5(
                f'SecretScanner:{finding.pattern_name}:{finding.source_url}'.encode()
            ).hexdigest()
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)

            cvss = _severity_to_cvss(finding.severity)

            vulns.append({
                'name': f'Secret Leak: {finding.pattern_name}',
                'severity': finding.severity,
                'category': 'Secret Exposure',
                'description': (
                    f'{finding.description}\n\n'
                    f'Matched: {finding.matched_text}\n'
                    f'Confidence: {finding.confidence}'
                ),
                'impact': (
                    'Exposed secrets can be used by attackers to gain unauthorized '
                    'access to services, APIs, databases and infrastructure. '
                    'Critical secrets like AWS keys or database passwords may lead '
                    'to full account compromise.'
                ),
                'remediation': (
                    '1. Immediately rotate the exposed secret/credential.\n'
                    '2. Remove secrets from source code and use environment variables '
                    'or a secret manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).\n'
                    '3. Add the file to .gitignore and audit git history for leaked secrets.\n'
                    '4. Implement secret scanning in CI/CD pipeline.'
                ),
                'cwe': finding.cwe,
                'cvss': cvss,
                'affected_url': finding.source_url,
                'evidence': finding.context[:2000] if finding.context else finding.matched_text[:2000],
            })

        return vulns


def _severity_to_cvss(severity: str) -> float:
    """Map severity string to CVSS score."""
    return {
        'critical': 9.5,
        'high': 7.5,
        'medium': 5.5,
        'low': 3.0,
        'info': 1.0,
    }.get(severity, 5.0)
