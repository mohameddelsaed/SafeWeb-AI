"""
Service Detector — Security tests for specific services found during port scanning.

Tests for:
  - FTP anonymous login
  - Redis unauthorized access
  - MongoDB unauthorized access
  - Elasticsearch open access
  - Jenkins / Kibana / Grafana unauthenticated dashboards
  - SMTP open relay detection
  - Memcached open access
  - MySQL / PostgreSQL weak-auth probes
"""
from __future__ import annotations

import logging
import socket
from typing import Callable, Any

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Service test registry
# ────────────────────────────────────────────────────────────────────────────

class ServiceDetector:
    """Run service-specific security probes against open ports."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        # service-name → test method
        self._tests: dict[str, Callable[..., Any]] = {
            'ftp': self._test_ftp_anon,
            'redis': self._test_redis_unauth,
            'mongodb': self._test_mongodb_unauth,
            'elasticsearch': self._test_elasticsearch_open,
            'memcached': self._test_memcached_open,
            'smtp': self._test_smtp_open_relay,
            'http-proxy': self._test_http_dashboard,
            'http-alt': self._test_http_dashboard,
            'jenkins': self._test_http_dashboard,
            'mysql': self._test_mysql_probe,
            'postgresql': self._test_postgresql_probe,
        }

    # ── Public API ────────────────────────────────────────────────────────

    def test_all(self, host: str, open_ports: list[dict]) -> list[dict]:
        """Run applicable service tests for every open port.

        *open_ports* — list from PortScanner.scan(), each with at
        least ``port`` and ``service`` keys.

        Returns list of finding dicts (may be empty).
        """
        findings: list[dict] = []
        for entry in open_ports:
            svc = entry.get('service', '')
            port = entry.get('port', 0)
            test_fn = self._tests.get(svc)
            if test_fn:
                result = test_fn(host, port)
                if result:
                    findings.append(result)
        return findings

    def get_supported_services(self) -> list[str]:
        """Return service names that have a security test."""
        return list(self._tests.keys())

    # ── FTP ───────────────────────────────────────────────────────────────

    def _test_ftp_anon(self, host: str, port: int) -> dict | None:
        """Check for FTP anonymous login."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                banner = s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'USER anonymous\r\n')
                s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'PASS anonymous@\r\n')
                resp2 = s.recv(1024).decode('utf-8', errors='replace')
                if resp2.startswith('230'):
                    return self._finding(
                        'FTP Anonymous Login', host, port, 'high',
                        'FTP server allows anonymous login, exposing files to unauthenticated users.',
                        f'Banner: {banner[:200]}, Response: {resp2[:200]}',
                    )
        except Exception as exc:
            logger.debug('FTP anon test failed for %s:%d: %s', host, port, exc)
        return None

    # ── Redis ─────────────────────────────────────────────────────────────

    def _test_redis_unauth(self, host: str, port: int) -> dict | None:
        """Check for Redis without authentication."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                s.sendall(b'PING\r\n')
                resp = s.recv(1024).decode('utf-8', errors='replace')
                if '+PONG' in resp:
                    return self._finding(
                        'Redis Unauthorized Access', host, port, 'critical',
                        'Redis instance accepts commands without authentication. '
                        'Attackers can read/write data or achieve RCE via SLAVEOF.',
                        f'PING → {resp.strip()}',
                    )
        except Exception as exc:
            logger.debug('Redis unauth test failed for %s:%d: %s', host, port, exc)
        return None

    # ── MongoDB ───────────────────────────────────────────────────────────

    def _test_mongodb_unauth(self, host: str, port: int) -> dict | None:
        """Check for MongoDB without authentication."""
        # MongoDB wire protocol: a minimal ismaster command
        # We send a lightweight OP_MSG and check for a valid reply.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                # Minimal MongoDB hello — send bytes and look for 'ismaster'
                # in the response (MongoDB 3.x+)
                hello_msg = (
                    b'\x3f\x00\x00\x00'  # messageLength
                    b'\x01\x00\x00\x00'  # requestID
                    b'\x00\x00\x00\x00'  # responseTo
                    b'\xdd\x07\x00\x00'  # opCode: OP_MSG (2013)
                    b'\x00\x00\x00\x00'  # flagBits
                    b'\x00'              # section kind 0
                    b'\x25\x00\x00\x00'  # document size
                    b'\x01ismaster\x00\x00\x00\xf0\x3f'  # ismaster: 1.0
                    b'\x02$db\x00\x06\x00\x00\x00admin\x00'  # $db: admin
                    b'\x00'              # document terminator
                )
                s.sendall(hello_msg)
                resp = s.recv(4096)
                if resp and (b'ismaster' in resp or b'isWritablePrimary' in resp):
                    return self._finding(
                        'MongoDB Unauthorized Access', host, port, 'critical',
                        'MongoDB instance responds to commands without authentication.',
                        f'Received {len(resp)} bytes containing ismaster response',
                    )
        except Exception as exc:
            logger.debug('MongoDB unauth test failed for %s:%d: %s', host, port, exc)
        return None

    # ── Elasticsearch ─────────────────────────────────────────────────────

    def _test_elasticsearch_open(self, host: str, port: int) -> dict | None:
        """Check for Elasticsearch open access."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                req = f'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode()
                s.sendall(req)
                resp = s.recv(4096).decode('utf-8', errors='replace')
                if 'cluster_name' in resp and 'version' in resp:
                    return self._finding(
                        'Elasticsearch Open Access', host, port, 'high',
                        'Elasticsearch cluster is accessible without authentication.',
                        resp[:500],
                    )
        except Exception as exc:
            logger.debug('ES open test failed for %s:%d: %s', host, port, exc)
        return None

    # ── Memcached ─────────────────────────────────────────────────────────

    def _test_memcached_open(self, host: str, port: int) -> dict | None:
        """Check for Memcached open access (stats command)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                s.sendall(b'stats\r\n')
                resp = s.recv(4096).decode('utf-8', errors='replace')
                if 'STAT' in resp:
                    return self._finding(
                        'Memcached Open Access', host, port, 'high',
                        'Memcached instance is accessible without authentication. '
                        'Can be abused for DDoS amplification or data exfiltration.',
                        resp[:500],
                    )
        except Exception as exc:
            logger.debug('Memcached test failed for %s:%d: %s', host, port, exc)
        return None

    # ── SMTP open relay ───────────────────────────────────────────────────

    def _test_smtp_open_relay(self, host: str, port: int) -> dict | None:
        """Minimal SMTP open-relay check (EHLO + MAIL FROM + RCPT TO)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                banner = s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'EHLO test.local\r\n')
                s.recv(1024)
                s.sendall(b'MAIL FROM:<test@test.local>\r\n')
                s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'RCPT TO:<test@example.com>\r\n')
                resp_to = s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'QUIT\r\n')
                if resp_to.startswith('250'):
                    return self._finding(
                        'SMTP Open Relay', host, port, 'high',
                        'SMTP server accepts relay for external recipients. '
                        'Can be abused for spam and phishing.',
                        f'Banner: {banner[:200]}, RCPT TO response: {resp_to[:200]}',
                    )
        except Exception as exc:
            logger.debug('SMTP relay test failed for %s:%d: %s', host, port, exc)
        return None

    # ── HTTP dashboards ───────────────────────────────────────────────────

    def _test_http_dashboard(self, host: str, port: int) -> dict | None:
        """Check for unauthenticated Jenkins / Kibana / Grafana dashboards."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                req = f'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode()
                s.sendall(req)
                resp = s.recv(8192).decode('utf-8', errors='replace')

                for product, indicator in [
                    ('Jenkins', 'Dashboard [Jenkins]'),
                    ('Jenkins', 'X-Jenkins:'),
                    ('Kibana', '"kbn-name"'),
                    ('Kibana', 'kibana'),
                    ('Grafana', 'grafana'),
                    ('Grafana', '"Grafana"'),
                ]:
                    if indicator.lower() in resp.lower():
                        return self._finding(
                            f'{product} Unauthenticated Access', host, port, 'high',
                            f'{product} dashboard is accessible without authentication on port {port}.',
                            resp[:500],
                        )
        except Exception as exc:
            logger.debug('HTTP dashboard test failed for %s:%d: %s', host, port, exc)
        return None

    # ── MySQL ─────────────────────────────────────────────────────────────

    def _test_mysql_probe(self, host: str, port: int) -> dict | None:
        """Read MySQL greeting packet and report version exposure."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                data = s.recv(1024)
                if data and len(data) > 5:
                    # MySQL greeting: byte 0-3 = length, byte 4 = seq
                    version_end = data.find(b'\x00', 5)
                    if version_end > 5:
                        ver = data[5:version_end].decode('utf-8', errors='replace')
                        return self._finding(
                            'MySQL Version Exposed', host, port, 'medium',
                            f'MySQL server exposes version {ver} in its greeting packet.',
                            f'Version: {ver}',
                        )
        except Exception as exc:
            logger.debug('MySQL probe failed for %s:%d: %s', host, port, exc)
        return None

    # ── PostgreSQL ────────────────────────────────────────────────────────

    def _test_postgresql_probe(self, host: str, port: int) -> dict | None:
        """Attempt PostgreSQL startup and check for version/error info."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                # SSLRequest
                s.sendall(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
                resp = s.recv(1)
                if resp in (b'N', b'S'):
                    return self._finding(
                        'PostgreSQL Exposed', host, port, 'medium',
                        'PostgreSQL server is reachable and responds to connection requests.',
                        f'SSL response: {resp!r}',
                    )
        except Exception as exc:
            logger.debug('PostgreSQL probe failed for %s:%d: %s', host, port, exc)
        return None

    # ── Helper ────────────────────────────────────────────────────────────

    @staticmethod
    def _finding(title: str, host: str, port: int, severity: str,
                 description: str, evidence: str) -> dict:
        return {
            'title': title,
            'host': host,
            'port': port,
            'severity': severity,
            'description': description,
            'evidence': evidence[:2000],
        }
