"""
Fuzz Vectors — Boundary values, special characters, encoding edge cases,
and format string payloads for generic fuzzing.
"""

# ── Boundary Values ──────────────────────────────────────────────────────────
BOUNDARY_VALUES = [
    '',
    ' ',
    '0',
    '-1',
    '-0',
    '1',
    '2147483647',           # INT_MAX (32-bit)
    '-2147483648',          # INT_MIN (32-bit)
    '9999999999999999',     # Very large number
    '0.0',
    '0.1',
    '-0.1',
    'NaN',
    'Infinity',
    '-Infinity',
    'null',
    'undefined',
    'None',
    'true',
    'false',
    'True',
    'False',
    '[]',
    '{}',
    '[null]',
    '{"key":"value"}',
]

# ── Special Characters ───────────────────────────────────────────────────────
SPECIAL_CHARS = [
    '<',
    '>',
    '"',
    "'",
    '&',
    '\\',
    '/',
    '\x00',         # Null byte
    '\r',
    '\n',
    '\r\n',
    '\t',
    '`',
    '|',
    ';',
    '$',
    '%',
    '#',
    '@',
    '!',
    '~',
    '^',
    '*',
    '(',
    ')',
    '{',
    '}',
    '[',
    ']',
    '+',
    '=',
    '%00',
    '%0a',
    '%0d',
    '%0d%0a',
    '%09',
    '%20',
    '%25',
]

# ── Long Strings (buffer overflow detection) ─────────────────────────────────
LONG_STRINGS = [
    'A' * 256,
    'A' * 1024,
    'A' * 4096,
    'A' * 10000,
    'A' * 65536,
    '%s' * 256,
    '%n' * 128,
    '/' * 1024,
    '../' * 512,
]

# ── Format String Payloads ───────────────────────────────────────────────────
FORMAT_STRINGS = [
    '%s',
    '%d',
    '%x',
    '%n',
    '%p',
    '%s%s%s%s%s',
    '%d%d%d%d%d',
    '%x%x%x%x%x',
    '%p%p%p%p%p',
    '%n%n%n%n%n',
    '%.1024d',
    '%.2048d',
    '%99999999s',
    '{0}',
    '{0}{1}{2}',
    '${7*7}',
    '#{7*7}',
    '{{7*7}}',
]

# ── Encoding Edge Cases ──────────────────────────────────────────────────────
ENCODING_EDGE_CASES = [
    '\xc0\xaf',             # Invalid UTF-8 overlong slash
    '\xc0\xae',             # Invalid UTF-8 overlong dot
    '\xef\xbb\xbf',        # UTF-8 BOM
    '\xfe\xff',             # UTF-16 BE BOM
    '\xff\xfe',             # UTF-16 LE BOM
    '\x00\x00\xfe\xff',    # UTF-32 BE BOM
    '\xe2\x80\x8b',        # Zero-width space
    '\xe2\x80\x8c',        # Zero-width non-joiner
    '\xe2\x80\x8d',        # Zero-width joiner
    '\xe2\x80\xae',        # Right-to-left override
    '\xc2\xa0',             # Non-breaking space
]

# ── CRLF Injection Vectors ──────────────────────────────────────────────────
CRLF_VECTORS = [
    '%0d%0a',
    '%0d%0aInjected-Header:true',
    '%0d%0a%0d%0a<html>injected</html>',
    '\r\n',
    '\r\nInjected-Header: true',
    '%0d%0aSet-Cookie:injected=true',
    '%0d%0aLocation:http://evil.com',
    '%e5%98%8a%e5%98%8d',  # Unicode CRLF
]


def get_all_fuzz_vectors() -> list:
    """Return all fuzz vectors combined."""
    return (
        BOUNDARY_VALUES + SPECIAL_CHARS + LONG_STRINGS[:5] +
        FORMAT_STRINGS + ENCODING_EDGE_CASES + CRLF_VECTORS
    )
