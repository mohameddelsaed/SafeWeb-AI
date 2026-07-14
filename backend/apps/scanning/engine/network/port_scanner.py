"""
Port Scanner — TCP connect scan with banner grabbing and service fingerprinting.

Uses plain sockets (no raw packets / no root required).
"""
from __future__ import annotations

import logging
import re
import socket

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Well-known ports → service name mapping (top 100 most common)
# ────────────────────────────────────────────────────────────────────────────

COMMON_PORTS: dict[int, str] = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios',
    143: 'imap', 443: 'https', 445: 'smb', 465: 'smtps', 587: 'submission',
    993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
    2049: 'nfs', 2181: 'zookeeper', 3306: 'mysql', 3389: 'rdp',
    5432: 'postgresql', 5672: 'amqp', 5900: 'vnc', 6379: 'redis',
    6443: 'kubernetes', 8080: 'http-proxy', 8443: 'https-alt',
    8888: 'http-alt', 9090: 'prometheus', 9200: 'elasticsearch',
    9300: 'elasticsearch-transport', 11211: 'memcached',
    27017: 'mongodb', 27018: 'mongodb', 50000: 'jenkins',
}

# Default ports to scan when none specified (top 50)
DEFAULT_PORTS: list[int] = sorted(COMMON_PORTS.keys())

# ────────────────────────────────────────────────────────────────────────────
# Banner → version extraction patterns
# ────────────────────────────────────────────────────────────────────────────

_VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('ssh', re.compile(r'SSH-[\d.]+-([\w._\-]+)', re.I)),
    ('ftp', re.compile(r'220[- ].*?(\w[\w. ]+)', re.I)),
    ('smtp', re.compile(r'220[- ].*?(\w[\w. ]+)', re.I)),
    ('http', re.compile(r'Server:\s*([\w/.\- ]+)', re.I)),
    ('mysql', re.compile(r'([\d]+\.[\d]+\.[\d]+[\w.\-]*)', re.I)),
    ('redis', re.compile(r'redis_version:([\d.]+)', re.I)),
    ('mongodb', re.compile(r'version["\s:]*([\d.]+)', re.I)),
    ('postgresql', re.compile(r'PostgreSQL\s*([\d.]+)', re.I)),
]


# ────────────────────────────────────────────────────────────────────────────
# PortScanner class
# ────────────────────────────────────────────────────────────────────────────

class PortScanner:
    """TCP connect scanner with banner grabbing."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    # ── Public API ────────────────────────────────────────────────────────

    def scan(self, host: str, ports: list[int] | None = None) -> list[dict]:
        """Scan *host* on given *ports* (or defaults).

        Returns list of ``{port, state, service, banner, version}`` for
        every port that is **open**.
        """
        ports = ports or DEFAULT_PORTS
        results: list[dict] = []
        for port in ports:
            result = self._probe_port(host, port)
            if result:
                results.append(result)
        return results

    def grab_banner(self, host: str, port: int) -> str:
        """Connect and read the initial banner (up to 1024 bytes)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                # Some services need a nudge
                if COMMON_PORTS.get(port) in ('http', 'http-proxy', 'http-alt', 'https', 'https-alt'):
                    sock.sendall(b'HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n' % host.encode())
                elif COMMON_PORTS.get(port) == 'redis':
                    sock.sendall(b'INFO server\r\n')
                else:
                    # Many services send a banner on connect
                    pass
                banner = sock.recv(1024)
                return banner.decode('utf-8', errors='replace').strip()
        except Exception:
            return ''

    # ── Internals ─────────────────────────────────────────────────────────

    def _probe_port(self, host: str, port: int) -> dict | None:
        """Return port-info dict if open, else None."""
        if not self._is_open(host, port):
            return None
        service = COMMON_PORTS.get(port, 'unknown')
        banner = self.grab_banner(host, port)
        version = self._extract_version(service, banner)
        return {
            'port': port,
            'state': 'open',
            'service': service,
            'banner': banner[:512],
            'version': version,
        }

    def _is_open(self, host: str, port: int) -> bool:
        """TCP connect check."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((host, port)) == 0
        except Exception:
            return False

    @staticmethod
    def _extract_version(service: str, banner: str) -> str:
        """Try to extract a version string from a banner."""
        if not banner:
            return ''
        for svc, pattern in _VERSION_PATTERNS:
            if svc in service or service == 'unknown':
                m = pattern.search(banner)
                if m:
                    return m.group(1).strip()
        return ''
