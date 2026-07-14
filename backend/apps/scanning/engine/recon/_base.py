"""
Recon Module Base — Shared return format factory and utilities.

All recon modules use create_result() to build their return dict in the
standardised format:
    {
        'findings': list[dict],
        'metadata': dict,
        'errors': list[str],
        'stats': dict,
        # … plus optional legacy keys for backward compatibility
    }
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Union

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


# ── Result Factory ────────────────────────────────────────────────────────────

def create_result(
    module: str,
    target: str,
    depth: str = 'medium',
) -> dict:
    """Return a skeleton result dict in the standardised recon format.

    Args:
        module: Module name (e.g. ``'dns_recon'``).
        target: Target URL or domain.
        depth:  Scan depth — ``'shallow'``, ``'medium'``, or ``'deep'``.

    Returns:
        Mutable dict that callers populate during the scan.
    """
    return {
        'findings': [],
        'metadata': {
            'module': module,
            'target': target,
            'depth': depth,
            'started_at': datetime.now(timezone.utc).isoformat(),
            'completed_at': None,
        },
        'errors': [],
        'stats': {
            'total_checks': 0,
            'successful_checks': 0,
            'failed_checks': 0,
            'duration_seconds': 0.0,
        },
        'issues': [],           # legacy compat — many testers expect this
    }


def add_finding(result: dict, finding: dict) -> None:
    """Append a finding entry to *result*.

    Args:
        result:  The dict returned by :func:`create_result`.
        finding: A dict describing the finding (structure is module-specific).
    """
    result['findings'].append(finding)


def finalize_result(result: dict, start_time: float) -> dict:
    """Fill in ``completed_at`` and ``duration_seconds``.

    Args:
        result:     The dict returned by :func:`create_result`.
        start_time: ``time.time()`` captured at module start.

    Returns:
        The same *result* dict (for convenience).
    """
    elapsed = time.time() - start_time
    result['metadata']['completed_at'] = datetime.now(timezone.utc).isoformat()
    result['stats']['duration_seconds'] = round(elapsed, 3)
    return result


# ── Data File Loaders ─────────────────────────────────────────────────────────

def load_data_file(filename: str) -> str:
    """Load a text data file from ``recon/data/``."""
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return fh.read()
    except FileNotFoundError:
        logger.warning('Data file not found: %s', path)
        return ''


def load_data_lines(filename: str) -> list[str]:
    """Load a text file and return non-empty, stripped lines."""
    raw = load_data_file(filename)
    if not raw:
        return []
    return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith('#')]


def load_json_data(filename: str) -> Union[dict, list]:
    """Load and parse a JSON data file from ``recon/data/``."""
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning('JSON data file not found: %s', path)
        return {}
    except json.JSONDecodeError as exc:
        logger.warning('Invalid JSON in %s: %s', path, exc)
        return {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_hostname(target_url: str) -> str:
    """Extract the hostname from a target URL."""
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    return parsed.hostname or ''


def extract_root_domain(hostname: str) -> str:
    """Return the registrable domain (e.g. ``example.com`` from ``sub.example.com``).

    Uses *tldextract* when available, falls back to a basic split.
    """
    try:
        import tldextract
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return f'{ext.domain}.{ext.suffix}'
    except Exception:
        pass
    # Fallback — simple last-two-labels
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname
