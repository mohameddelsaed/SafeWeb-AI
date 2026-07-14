"""
Feature extractors for ML models.
Extracts numerical features from URLs, files, and HTML for classification.
"""
import re
import math
import hashlib
from urllib.parse import urlparse


def extract_url_features(url: str) -> dict:
    """
    Extract features from a URL for phishing detection.
    Returns a dict of numerical features.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    features = {
        # Length features
        'url_length': len(url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),

        # Count features
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'underscore_count': url.count('_'),
        'slash_count': url.count('/'),
        'question_count': url.count('?'),
        'equal_count': url.count('='),
        'at_count': url.count('@'),
        'ampersand_count': url.count('&'),
        'digit_count': sum(c.isdigit() for c in url),
        'letter_count': sum(c.isalpha() for c in url),
        'special_char_count': sum(not c.isalnum() and c not in '.-_/?' for c in url),

        # Ratio features
        'digit_letter_ratio': _safe_ratio(
            sum(c.isdigit() for c in url),
            sum(c.isalpha() for c in url)
        ),

        # Boolean features (as 0/1)
        'has_ip_address': 1 if _has_ip_address(hostname) else 0,
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'has_port': 1 if parsed.port and parsed.port not in (80, 443) else 0,
        'has_at_symbol': 1 if '@' in url else 0,
        'has_double_slash_redirect': 1 if '//' in path else 0,
        'has_subdomain': 1 if hostname.count('.') > 1 else 0,

        # Entropy (randomness indicator)
        'hostname_entropy': _shannon_entropy(hostname),
        'path_entropy': _shannon_entropy(path),
        'url_entropy': _shannon_entropy(url),

        # Subdomain depth
        'subdomain_count': max(0, hostname.count('.') - 1),

        # Path depth
        'path_depth': len([p for p in path.split('/') if p]),

        # Suspicious keywords
        'has_login_keyword': 1 if any(
            k in url.lower() for k in ('login', 'signin', 'sign-in', 'logon', 'auth')
        ) else 0,
        'has_secure_keyword': 1 if any(
            k in url.lower() for k in ('secure', 'account', 'update', 'verify', 'confirm')
        ) else 0,
        'has_banking_keyword': 1 if any(
            k in url.lower() for k in ('bank', 'paypal', 'wallet', 'payment', 'pay')
        ) else 0,

        # TLD features
        'tld_is_suspicious': 1 if _is_suspicious_tld(hostname) else 0,
    }

    return features


def extract_file_features(content: bytes, filename: str = '') -> dict:
    """
    Extract features from file content for malware detection.
    Returns a dict of numerical features.
    """
    # Basic file properties
    file_size = len(content)
    features = {
        'file_size': file_size,
        'file_entropy': _byte_entropy(content),
    }

    # Extension analysis
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    suspicious_exts = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'wsf', 'scr', 'pif']
    features['has_suspicious_extension'] = 1 if ext in suspicious_exts else 0

    # Double extension check
    parts = filename.split('.')
    features['has_double_extension'] = 1 if len(parts) > 2 else 0

    # Content analysis
    try:
        text = content.decode('utf-8', errors='ignore')
    except Exception:
        text = ''

    # Script/code indicators
    script_patterns = [
        r'<script', r'eval\s*\(', r'exec\s*\(', r'system\s*\(',
        r'subprocess', r'os\.system', r'Runtime\.getRuntime',
        r'powershell', r'cmd\.exe', r'WScript',
    ]
    features['script_pattern_count'] = sum(
        1 for p in script_patterns if re.search(p, text, re.IGNORECASE)
    )

    # Obfuscation indicators
    obfuscation_patterns = [
        r'\\x[0-9a-f]{2}',  # Hex encoding
        r'\\u[0-9a-f]{4}',  # Unicode encoding
        r'base64',
        r'fromCharCode',
        r'String\.fromCharCode',
        r'atob\s*\(',
        r'btoa\s*\(',
    ]
    features['obfuscation_count'] = sum(
        1 for p in obfuscation_patterns if re.search(p, text, re.IGNORECASE)
    )

    # Network indicators
    network_patterns = [
        r'http[s]?://', r'socket', r'connect\s*\(',
        r'send\s*\(', r'XMLHttpRequest', r'fetch\s*\(',
        r'curl', r'wget',
    ]
    features['network_indicator_count'] = sum(
        1 for p in network_patterns if re.search(p, text, re.IGNORECASE)
    )

    # String ratio (readable text vs binary)
    printable_count = sum(1 for c in content if 32 <= c <= 126)
    features['printable_ratio'] = printable_count / max(file_size, 1)

    # Null byte ratio (common in binary/packed files)
    null_count = content.count(b'\x00')
    features['null_byte_ratio'] = null_count / max(file_size, 1)

    # File hash (for lookup/dedup, not a feature for ML)
    features['sha256'] = hashlib.sha256(content).hexdigest()

    return features


def extract_html_features(html_content: str, url: str = '') -> dict:
    """
    Extract features from HTML content for phishing page detection.
    """
    features = {
        'html_length': len(html_content),

        # Form analysis
        'form_count': len(re.findall(r'<form', html_content, re.IGNORECASE)),
        'input_count': len(re.findall(r'<input', html_content, re.IGNORECASE)),
        'password_input_count': len(re.findall(
            r'<input[^>]*type=["\']password', html_content, re.IGNORECASE
        )),
        'hidden_input_count': len(re.findall(
            r'<input[^>]*type=["\']hidden', html_content, re.IGNORECASE
        )),

        # External resource loading
        'external_link_count': len(re.findall(
            r'href=["\']https?://', html_content, re.IGNORECASE
        )),
        'external_script_count': len(re.findall(
            r'<script[^>]*src=["\']https?://', html_content, re.IGNORECASE
        )),
        'iframe_count': len(re.findall(r'<iframe', html_content, re.IGNORECASE)),

        # JavaScript indicators
        'script_count': len(re.findall(r'<script', html_content, re.IGNORECASE)),
        'event_handler_count': len(re.findall(
            r'on(?:click|load|error|mouseover|submit|focus)\s*=', html_content, re.IGNORECASE
        )),

        # Suspicious content
        'has_favicon_mismatch': 0,  # Would need domain comparison
        'has_form_with_external_action': 0,
        'has_popup_window': 1 if 'window.open' in html_content else 0,
        'has_right_click_disabled': 1 if 'event.button==2' in html_content or 'contextmenu' in html_content else 0,
        'has_status_bar_change': 1 if 'window.status' in html_content else 0,
    }

    # Check if forms submit to different domain
    if url:
        parsed_url = urlparse(url)
        page_domain = parsed_url.hostname or ''
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)', html_content, re.IGNORECASE)
        for action in form_actions:
            if action.startswith('http'):
                action_domain = urlparse(action).hostname or ''
                if action_domain and action_domain != page_domain:
                    features['has_form_with_external_action'] = 1
                    break

    return features


def features_to_vector(features: dict, feature_names: list) -> list:
    """Convert feature dict to ordered list for ML model input."""
    return [features.get(name, 0) for name in feature_names]


# ---- Helper functions ----

def _safe_ratio(a: int, b: int) -> float:
    return a / b if b > 0 else 0.0


def _has_ip_address(hostname: str) -> bool:
    """Check if hostname is an IP address."""
    parts = hostname.split('.')
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    return False


def _is_suspicious_tld(hostname: str) -> bool:
    """Check if hostname uses a suspicious TLD."""
    suspicious_tlds = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
        'online', 'site', 'icu', 'buzz', 'rest',
    }
    parts = hostname.rsplit('.', 1)
    if len(parts) == 2:
        return parts[1].lower() in suspicious_tlds
    return False


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _byte_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)
