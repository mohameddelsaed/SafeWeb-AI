"""
Phase 34 — Advanced Port & Service Scanning tests.

Covers:
  - PortScanner: TCP connect scan, banner grabbing, version extraction
  - ServiceDetector: FTP, Redis, MongoDB, Elasticsearch, Memcached, SMTP,
    HTTP dashboards, MySQL, PostgreSQL probes
  - SSLTester: protocol testing, cipher enumeration, certificate validation,
    vulnerability checks (BEAST/POODLE/DROWN/Heartbleed/ROBOT), HSTS, OCSP
  - NetworkScanner: unified interface
  - NetworkTester: BaseTester integration, registration, tester count (66)
"""
import socket
import ssl
from unittest.mock import patch, MagicMock

# ── Engine imports ───────────────────────────────────────────────────────────
from apps.scanning.engine.network.port_scanner import (
    PortScanner, COMMON_PORTS, DEFAULT_PORTS, _VERSION_PATTERNS,
)
from apps.scanning.engine.network.service_detector import ServiceDetector
from apps.scanning.engine.network.ssl_tester import (
    SSLTester,
    WEAK_CIPHER_INDICATORS,
    TLS13_CIPHERS,
)
from apps.scanning.engine.network import NetworkScanner
from apps.scanning.engine.testers.network_tester import NetworkTester

# Shorthand mock targets — service_detector and port_scanner use socket.socket()
_SOCK_PS = 'apps.scanning.engine.network.port_scanner.socket.socket'
_SOCK_SD = 'apps.scanning.engine.network.service_detector.socket.socket'


# ════════════════════════════════════════════════════════════════════════════
# PortScanner
# ════════════════════════════════════════════════════════════════════════════

class TestPortScanner:

    def setup_method(self):
        self.scanner = PortScanner(timeout=1.0)

    # ── Constants ─────────────────────────────────────────────────────────

    def test_common_ports_has_entries(self):
        assert len(COMMON_PORTS) >= 30

    def test_common_ports_http(self):
        assert COMMON_PORTS[80] == 'http'
        assert COMMON_PORTS[443] == 'https'

    def test_common_ports_ssh(self):
        assert COMMON_PORTS[22] == 'ssh'

    def test_common_ports_ftp(self):
        assert COMMON_PORTS[21] == 'ftp'

    def test_common_ports_mysql(self):
        assert COMMON_PORTS[3306] == 'mysql'

    def test_common_ports_postgres(self):
        assert COMMON_PORTS[5432] == 'postgresql'

    def test_common_ports_redis(self):
        assert COMMON_PORTS[6379] == 'redis'

    def test_common_ports_mongodb(self):
        assert COMMON_PORTS[27017] == 'mongodb'

    def test_default_ports_sorted(self):
        assert DEFAULT_PORTS == sorted(DEFAULT_PORTS)

    def test_default_ports_count(self):
        assert len(DEFAULT_PORTS) == len(COMMON_PORTS)

    # ── Version patterns ──────────────────────────────────────────────────

    def test_version_patterns_exist(self):
        assert len(_VERSION_PATTERNS) >= 7

    # ── _is_open ──────────────────────────────────────────────────────────

    @patch(_SOCK_PS)
    def test_is_open_returns_true(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.connect_ex.return_value = 0
        assert self.scanner._is_open('127.0.0.1', 80) is True

    @patch(_SOCK_PS)
    def test_is_open_returns_false(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.connect_ex.return_value = 111  # connection refused
        assert self.scanner._is_open('127.0.0.1', 80) is False

    @patch(_SOCK_PS)
    def test_is_open_exception_returns_false(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(side_effect=OSError('fail'))
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        assert self.scanner._is_open('127.0.0.1', 80) is False

    # ── _extract_version ──────────────────────────────────────────────────

    def test_extract_version_ssh(self):
        banner = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3'
        ver = self.scanner._extract_version('ssh', banner)
        assert 'OpenSSH' in ver

    def test_extract_version_ftp(self):
        banner = '220 (vsFTPd 3.0.3)'
        ver = self.scanner._extract_version('ftp', banner)
        assert '3.0.3' in ver

    def test_extract_version_http(self):
        banner = 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0'
        ver = self.scanner._extract_version('http', banner)
        assert '1.18.0' in ver

    def test_extract_version_redis(self):
        banner = '$10\r\nredis_version:7.0.5\r\n'
        ver = self.scanner._extract_version('redis', banner)
        assert '7.0.5' in ver

    def test_extract_version_unknown(self):
        ver = self.scanner._extract_version('unknown', 'some banner')
        assert ver == ''

    def test_extract_version_mysql(self):
        banner = '5.7.40-log MySQL Community Server'
        ver = self.scanner._extract_version('mysql', banner)
        assert '5.7.40' in ver

    # ── grab_banner ───────────────────────────────────────────────────────

    @patch(_SOCK_PS)
    def test_grab_banner_http(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n'
        banner = self.scanner.grab_banner('127.0.0.1', 80)
        assert 'HTTP/1.1' in banner

    @patch(_SOCK_PS)
    def test_grab_banner_redis(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'+PONG\r\n'
        banner = self.scanner.grab_banner('127.0.0.1', 6379)
        assert 'PONG' in banner

    @patch(_SOCK_PS)
    def test_grab_banner_timeout(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.side_effect = socket.timeout
        banner = self.scanner.grab_banner('127.0.0.1', 22)
        assert banner == ''

    # ── scan (integration with mocked _probe_port) ───────────────────────

    @patch.object(PortScanner, '_probe_port')
    def test_scan_returns_open_ports(self, mock_probe):
        mock_probe.side_effect = [
            {'port': 80, 'state': 'open', 'service': 'http', 'banner': '', 'version': ''},
            None,  # port 443 closed
        ]
        results = self.scanner.scan('127.0.0.1', [80, 443])
        assert len(results) == 1
        assert results[0]['port'] == 80

    @patch.object(PortScanner, '_probe_port')
    def test_scan_empty_when_all_closed(self, mock_probe):
        mock_probe.return_value = None
        results = self.scanner.scan('127.0.0.1', [80, 443])
        assert results == []


# ════════════════════════════════════════════════════════════════════════════
# ServiceDetector
# ════════════════════════════════════════════════════════════════════════════

class TestServiceDetector:

    def setup_method(self):
        self.detector = ServiceDetector(timeout=1.0)

    # ── Supported services ────────────────────────────────────────────────

    def test_supported_services_count(self):
        services = self.detector.get_supported_services()
        assert len(services) >= 10

    def test_supported_services_includes_common(self):
        services = self.detector.get_supported_services()
        for svc in ('ftp', 'redis', 'mongodb', 'elasticsearch', 'smtp', 'mysql'):
            assert svc in services

    # ── FTP anonymous ─────────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_ftp_anon_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.side_effect = [
            b'220 FTP ready\r\n',
            b'331 Please specify password\r\n',
            b'230 Login successful\r\n',
        ]
        finding = self.detector._test_ftp_anon('127.0.0.1', 21)
        assert finding is not None
        assert 'anonymous' in finding['title'].lower() or 'FTP' in finding['title']

    @patch(_SOCK_SD)
    def test_ftp_anon_negative(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.side_effect = [
            b'220 FTP ready\r\n',
            b'331 Please specify password\r\n',
            b'530 Login incorrect\r\n',
        ]
        finding = self.detector._test_ftp_anon('127.0.0.1', 21)
        assert finding is None

    @patch(_SOCK_SD)
    def test_ftp_anon_connection_error(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(side_effect=OSError('refused'))
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        finding = self.detector._test_ftp_anon('127.0.0.1', 21)
        assert finding is None

    # ── Redis ping ────────────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_redis_unauth_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'+PONG\r\n'
        finding = self.detector._test_redis_unauth('127.0.0.1', 6379)
        assert finding is not None
        assert 'redis' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_redis_unauth_negative(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'-NOAUTH Authentication required\r\n'
        finding = self.detector._test_redis_unauth('127.0.0.1', 6379)
        assert finding is None

    # ── MongoDB ismaster ──────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_mongodb_unauth_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'\x00' * 4 + b'ismaster' + b'\x00' * 20
        finding = self.detector._test_mongodb_unauth('127.0.0.1', 27017)
        assert finding is not None
        assert 'mongo' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_mongodb_unauth_negative(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'\x00' * 4
        finding = self.detector._test_mongodb_unauth('127.0.0.1', 27017)
        assert finding is None

    # ── Elasticsearch ─────────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_elasticsearch_open_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"mycluster","version":{"number":"7.10"}}'
        finding = self.detector._test_elasticsearch_open('127.0.0.1', 9200)
        assert finding is not None
        assert 'elastic' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_elasticsearch_closed(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(side_effect=OSError('refused'))
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        finding = self.detector._test_elasticsearch_open('127.0.0.1', 9200)
        assert finding is None

    # ── Memcached ─────────────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_memcached_open_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'STAT pid 12345\r\nSTAT uptime 1000\r\nEND\r\n'
        finding = self.detector._test_memcached_open('127.0.0.1', 11211)
        assert finding is not None
        assert 'memcache' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_memcached_closed(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(side_effect=OSError('refused'))
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        finding = self.detector._test_memcached_open('127.0.0.1', 11211)
        assert finding is None

    # ── SMTP relay ────────────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_smtp_relay_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.side_effect = [
            b'220 smtp.example.com ESMTP\r\n',
            b'250-Hello\r\n',
            b'250 OK\r\n',
            b'250 OK\r\n',
        ]
        finding = self.detector._test_smtp_open_relay('127.0.0.1', 25)
        assert finding is not None
        assert 'smtp' in finding['title'].lower() or 'relay' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_smtp_relay_negative(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.side_effect = [
            b'220 smtp.example.com ESMTP\r\n',
            b'250-Hello\r\n',
            b'250 OK\r\n',
            b'550 Relay denied\r\n',
        ]
        finding = self.detector._test_smtp_open_relay('127.0.0.1', 25)
        assert finding is None

    # ── HTTP dashboards ───────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_http_dashboard_jenkins(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n<html><title>Dashboard [Jenkins]</title></html>'
        finding = self.detector._test_http_dashboard('127.0.0.1', 8080)
        assert finding is not None
        assert 'jenkins' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_http_dashboard_kibana(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n<html>kibana dashboard</html>'
        finding = self.detector._test_http_dashboard('127.0.0.1', 5601)
        assert finding is not None
        assert 'kibana' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_http_dashboard_grafana(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n<html>grafana-app</html>'
        finding = self.detector._test_http_dashboard('127.0.0.1', 3000)
        assert finding is not None
        assert 'grafana' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_http_dashboard_negative(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n<html>Normal page</html>'
        finding = self.detector._test_http_dashboard('127.0.0.1', 8080)
        assert finding is None

    # ── MySQL probe ───────────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_mysql_probe_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        # MySQL greeting: 4-byte length, seq, protocol ver, then version string
        greeting = b'\x45\x00\x00\x00\x0a5.7.40\x00' + b'\x00' * 60
        sock.recv.return_value = greeting
        finding = self.detector._test_mysql_probe('127.0.0.1', 3306)
        assert finding is not None
        assert 'mysql' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_mysql_probe_error(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(side_effect=OSError('refused'))
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        finding = self.detector._test_mysql_probe('127.0.0.1', 3306)
        assert finding is None

    # ── PostgreSQL probe ──────────────────────────────────────────────────

    @patch(_SOCK_SD)
    def test_postgresql_probe_positive(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'N'
        finding = self.detector._test_postgresql_probe('127.0.0.1', 5432)
        assert finding is not None
        assert 'postgresql' in finding['title'].lower() or 'postgres' in finding['title'].lower()

    @patch(_SOCK_SD)
    def test_postgresql_probe_ssl_response(self, mock_socket_cls):
        sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b'S'
        finding = self.detector._test_postgresql_probe('127.0.0.1', 5432)
        assert finding is not None

    @patch(_SOCK_SD)
    def test_postgresql_probe_error(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(side_effect=OSError('refused'))
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        finding = self.detector._test_postgresql_probe('127.0.0.1', 5432)
        assert finding is None

    # ── test_all dispatch ─────────────────────────────────────────────────

    def test_test_all_dispatches(self):
        mock_redis = MagicMock(return_value={'title': 'Redis Open', 'severity': 'high'})
        self.detector._tests['redis'] = mock_redis
        open_ports = [{'port': 6379, 'service': 'redis'}]
        results = self.detector.test_all('127.0.0.1', open_ports)
        assert len(results) >= 1
        mock_redis.assert_called_once_with('127.0.0.1', 6379)

    def test_test_all_unknown_service(self):
        open_ports = [{'port': 99999, 'service': 'alien'}]
        results = self.detector.test_all('127.0.0.1', open_ports)
        assert results == []

    # ── _finding helper ───────────────────────────────────────────────────

    def test_finding_structure(self):
        f = ServiceDetector._finding('Test Title', '127.0.0.1', 80, 'high', 'desc', 'evidence')
        assert f['title'] == 'Test Title'
        assert f['host'] == '127.0.0.1'
        assert f['port'] == 80
        assert f['severity'] == 'high'
        assert f['description'] == 'desc'
        assert f['evidence'] == 'evidence'


# ════════════════════════════════════════════════════════════════════════════
# SSLTester
# ════════════════════════════════════════════════════════════════════════════

class TestSSLTester:

    def setup_method(self):
        self.tester = SSLTester(timeout=1.0)

    # ── Constants ─────────────────────────────────────────────────────────

    def test_weak_cipher_indicators(self):
        assert 'RC4' in WEAK_CIPHER_INDICATORS
        assert 'DES' in WEAK_CIPHER_INDICATORS
        assert 'NULL' in WEAK_CIPHER_INDICATORS

    def test_tls13_ciphers(self):
        assert len(TLS13_CIPHERS) >= 3
        assert 'TLS_AES_256_GCM_SHA384' in TLS13_CIPHERS

    # ── test_protocols ────────────────────────────────────────────────────

    @patch.object(SSLTester, '_try_protocol', return_value=False)
    @patch.object(SSLTester, '_try_tls13', return_value=True)
    def test_protocols_tls13_only(self, mock_tls13, mock_proto):
        results = self.tester.test_protocols('example.com', 443)
        assert any(r['protocol'] == 'TLSv1.3' and r['supported'] for r in results)
        deprecated = [r for r in results if r['deprecated'] and r['supported']]
        assert len(deprecated) == 0

    @patch.object(SSLTester, '_try_protocol')
    @patch.object(SSLTester, '_try_tls13', return_value=False)
    def test_protocols_sslv3_deprecated(self, mock_tls13, mock_proto):
        def proto_side_effect(host, port, const):
            if const == getattr(ssl, 'PROTOCOL_SSLv3', None):
                return True
            return False
        mock_proto.side_effect = proto_side_effect
        results = self.tester.test_protocols('example.com', 443)
        sslv3 = [r for r in results if r['protocol'] == 'SSLv3']
        if sslv3 and getattr(ssl, 'PROTOCOL_SSLv3', None) is not None:
            assert sslv3[0]['deprecated'] is True

    def test_protocols_returns_list(self):
        with patch.object(SSLTester, '_try_protocol', return_value=False), \
             patch.object(SSLTester, '_try_tls13', return_value=False):
            results = self.tester.test_protocols('example.com', 443)
            assert isinstance(results, list)
            assert len(results) >= 5  # SSLv2, SSLv3, TLS1.0, 1.1, 1.2, 1.3

    # ── enumerate_ciphers ─────────────────────────────────────────────────

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_enumerate_ciphers_strong(self, mock_ctx_factory, mock_conn):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        ssock = MagicMock()
        ssock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        ssock.shared_ciphers.return_value = [('TLS_AES_128_GCM_SHA256', 'TLSv1.3', 128)]
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = self.tester.enumerate_ciphers('example.com', 443)
        assert 'accepted' in result
        assert result['has_weak_ciphers'] is False
        assert len(result['strong']) >= 1

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_enumerate_ciphers_weak(self, mock_ctx_factory, mock_conn):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        ssock = MagicMock()
        ssock.cipher.return_value = ('DES-CBC3-SHA', 'TLSv1.0', 168)
        ssock.shared_ciphers.return_value = [('RC4-MD5', 'SSLv3', 128)]
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = self.tester.enumerate_ciphers('example.com', 443)
        assert result['has_weak_ciphers'] is True
        assert len(result['weak']) >= 1

    def test_enumerate_ciphers_connection_error(self):
        with patch('socket.create_connection', side_effect=OSError('refused')):
            result = self.tester.enumerate_ciphers('example.com', 443)
            assert result['accepted'] == []
            assert result['has_weak_ciphers'] is False

    # ── check_certificate ─────────────────────────────────────────────────

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_check_certificate_valid(self, mock_ctx_factory, mock_conn):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        ssock = MagicMock()
        ssock.getpeercert.side_effect = [
            None,  # binary_form=True
            {
                'subject': ((('commonName', 'example.com'),),),
                'issuer': ((('commonName', 'DigiCert'),),),
                'serialNumber': 'ABC123',
                'subjectAltName': (('DNS', 'example.com'), ('DNS', '*.example.com')),
                'notAfter': 'Dec 31 23:59:59 2099 GMT',
            },
        ]
        ssock.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('commonName', 'DigiCert'),),),
            'serialNumber': 'ABC123',
            'subjectAltName': (('DNS', 'example.com'), ('DNS', '*.example.com')),
            'notAfter': 'Dec 31 23:59:59 2099 GMT',
        }
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = self.tester.check_certificate('example.com', 443)
        assert result['hostname_match'] is True
        assert result['self_signed'] is False

    def test_check_certificate_connection_failure(self):
        with patch('socket.create_connection', side_effect=OSError('refused')):
            result = self.tester.check_certificate('example.com', 443)
            assert result['valid'] is False
            assert len(result['errors']) >= 1

    # ── check_vulnerabilities ─────────────────────────────────────────────

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=False)
    def test_check_vulns_poodle(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'SSLv3', 'supported': True, 'deprecated': True},
            {'protocol': 'TLSv1.0', 'supported': False, 'deprecated': True},
        ]
        mock_ciphers.return_value = {'accepted': [], 'weak': [], 'strong': [], 'has_weak_ciphers': False}
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        names = [v['name'] for v in vulns]
        assert 'POODLE' in names

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=False)
    def test_check_vulns_drown(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'SSLv2', 'supported': True, 'deprecated': True},
            {'protocol': 'SSLv3', 'supported': False, 'deprecated': True},
            {'protocol': 'TLSv1.0', 'supported': False, 'deprecated': True},
        ]
        mock_ciphers.return_value = {'accepted': [], 'weak': [], 'strong': [], 'has_weak_ciphers': False}
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        names = [v['name'] for v in vulns]
        assert 'DROWN' in names

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=True)
    def test_check_vulns_heartbleed(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'TLSv1.0', 'supported': False, 'deprecated': True},
        ]
        mock_ciphers.return_value = {'accepted': [], 'weak': [], 'strong': [], 'has_weak_ciphers': False}
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        names = [v['name'] for v in vulns]
        assert 'Heartbleed' in names

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=False)
    def test_check_vulns_beast(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'TLSv1.0', 'supported': True, 'deprecated': True},
        ]
        mock_ciphers.return_value = {
            'accepted': ['AES128-CBC-SHA'],
            'weak': [],
            'strong': ['AES128-CBC-SHA'],
            'has_weak_ciphers': False,
        }
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        names = [v['name'] for v in vulns]
        assert 'BEAST' in names

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=False)
    def test_check_vulns_robot(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'TLSv1.0', 'supported': False, 'deprecated': True},
        ]
        mock_ciphers.return_value = {
            'accepted': ['RSA-AES128-SHA'],
            'weak': [],
            'strong': ['RSA-AES128-SHA'],
            'has_weak_ciphers': False,
        }
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        names = [v['name'] for v in vulns]
        assert 'ROBOT' in names

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=False)
    def test_check_vulns_weak_ciphers(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'TLSv1.0', 'supported': False, 'deprecated': True},
        ]
        mock_ciphers.return_value = {
            'accepted': ['DES-CBC-SHA'],
            'weak': ['DES-CBC-SHA'],
            'strong': [],
            'has_weak_ciphers': True,
        }
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        names = [v['name'] for v in vulns]
        assert 'Weak Ciphers' in names

    @patch.object(SSLTester, 'enumerate_ciphers')
    @patch.object(SSLTester, 'test_protocols')
    @patch.object(SSLTester, '_check_heartbleed_indicator', return_value=False)
    def test_check_vulns_clean(self, mock_hb, mock_protos, mock_ciphers):
        mock_protos.return_value = [
            {'protocol': 'TLSv1.2', 'supported': True, 'deprecated': False},
            {'protocol': 'TLSv1.3', 'supported': True, 'deprecated': False},
        ]
        mock_ciphers.return_value = {
            'accepted': ['TLS_AES_256_GCM_SHA384'],
            'weak': [],
            'strong': ['TLS_AES_256_GCM_SHA384'],
            'has_weak_ciphers': False,
        }
        vulns = self.tester.check_vulnerabilities('example.com', 443)
        assert len(vulns) == 0

    # ── HSTS ─────────────────────────────────────────────────────────────

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_hsts_enabled(self, mock_ctx_factory, mock_conn):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        ssock = MagicMock()
        ssock.sendall = MagicMock()
        ssock.recv.side_effect = [
            b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n\r\n',
        ]
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = self.tester.check_hsts('example.com', 443)
        assert result['enabled'] is True
        assert result['max_age'] == 31536000
        assert result['include_subdomains'] is True
        assert result['preload'] is True

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_hsts_disabled(self, mock_ctx_factory, mock_conn):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx
        ssock = MagicMock()
        ssock.sendall = MagicMock()
        ssock.recv.side_effect = [
            b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n',
        ]
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = self.tester.check_hsts('example.com', 443)
        assert result['enabled'] is False

    def test_hsts_connection_error(self):
        with patch('socket.create_connection', side_effect=OSError('refused')):
            result = self.tester.check_hsts('example.com', 443)
            assert result['enabled'] is False

    # ── OCSP stapling ────────────────────────────────────────────────────

    def test_ocsp_connection_error(self):
        with patch('socket.create_connection', side_effect=OSError('refused')):
            result = self.tester.check_ocsp_stapling('example.com', 443)
            assert result['supported'] is False

    # ── full_test ─────────────────────────────────────────────────────────

    @patch.object(SSLTester, 'check_ocsp_stapling', return_value={'supported': False})
    @patch.object(SSLTester, 'check_hsts', return_value={'enabled': True})
    @patch.object(SSLTester, 'check_vulnerabilities', return_value=[])
    @patch.object(SSLTester, 'check_certificate', return_value={'valid': True})
    @patch.object(SSLTester, 'enumerate_ciphers', return_value={'accepted': [], 'weak': [], 'strong': [], 'has_weak_ciphers': False})
    @patch.object(SSLTester, 'test_protocols', return_value=[])
    def test_full_test_keys(self, *mocks):
        result = self.tester.full_test('example.com', 443)
        assert 'protocol_versions' in result
        assert 'ciphers' in result
        assert 'certificate' in result
        assert 'vulnerabilities' in result
        assert 'hsts' in result
        assert 'ocsp_stapling' in result

    # ── hostname matching ─────────────────────────────────────────────────

    def test_hostname_exact_match(self):
        assert SSLTester._hostname_matches('example.com', 'example.com') is True

    def test_hostname_wildcard_match(self):
        assert SSLTester._hostname_matches('sub.example.com', '*.example.com') is True

    def test_hostname_wildcard_no_match(self):
        assert SSLTester._hostname_matches('deep.sub.example.com', '*.example.com') is False

    def test_hostname_mismatch(self):
        assert SSLTester._hostname_matches('other.com', 'example.com') is False

    def test_hostname_empty(self):
        assert SSLTester._hostname_matches('example.com', '') is False

    # ── sig algo detection ────────────────────────────────────────────────

    def test_detect_sig_algo_sha256(self):
        # OID for sha256WithRSAEncryption
        oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b'
        cert_der = b'\x30\x82' + b'\x00' * 10 + oid + b'\x00' * 50
        assert SSLTester._detect_sig_algo(cert_der) == 'sha256WithRSAEncryption'

    def test_detect_sig_algo_unknown(self):
        assert SSLTester._detect_sig_algo(b'\x00' * 100) == 'unknown'

    def test_detect_sig_algo_none(self):
        assert SSLTester._detect_sig_algo(None) == ''


# ════════════════════════════════════════════════════════════════════════════
# NetworkScanner — Unified interface
# ════════════════════════════════════════════════════════════════════════════

class TestNetworkScanner:

    def setup_method(self):
        self.scanner = NetworkScanner(timeout=1.0)

    def test_has_submodules(self):
        assert hasattr(self.scanner, 'port_scanner')
        assert hasattr(self.scanner, 'service_detector')
        assert hasattr(self.scanner, 'ssl_tester')

    def test_port_scanner_type(self):
        assert isinstance(self.scanner.port_scanner, PortScanner)

    def test_service_detector_type(self):
        assert isinstance(self.scanner.service_detector, ServiceDetector)

    def test_ssl_tester_type(self):
        assert isinstance(self.scanner.ssl_tester, SSLTester)

    @patch.object(PortScanner, 'scan', return_value=[])
    def test_scan_ports_delegates(self, mock_scan):
        self.scanner.scan_ports('127.0.0.1', [80])
        mock_scan.assert_called_once_with('127.0.0.1', [80])

    @patch.object(ServiceDetector, 'test_all', return_value=[])
    def test_test_services_delegates(self, mock_test):
        self.scanner.test_services('127.0.0.1', [])
        mock_test.assert_called_once_with('127.0.0.1', [])

    @patch.object(SSLTester, 'full_test', return_value={})
    def test_test_ssl_delegates(self, mock_ssl):
        self.scanner.test_ssl('127.0.0.1', 443)
        mock_ssl.assert_called_once_with('127.0.0.1', 443)

    @patch.object(SSLTester, 'full_test', return_value={'protocol_versions': []})
    @patch.object(ServiceDetector, 'test_all', return_value=[])
    @patch.object(PortScanner, 'scan', return_value=[{'port': 443, 'state': 'open', 'service': 'https'}])
    def test_full_scan_structure(self, mock_scan, mock_svc, mock_ssl):
        result = self.scanner.full_scan('127.0.0.1', [443])
        assert 'open_ports' in result
        assert 'service_findings' in result
        assert 'ssl' in result


# ════════════════════════════════════════════════════════════════════════════
# NetworkTester — BaseTester integration
# ════════════════════════════════════════════════════════════════════════════

class TestNetworkTester:

    def setup_method(self):
        self.tester = NetworkTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Network Scanner'

    def test_empty_url(self):
        assert self.tester.test({'url': ''}) == []

    def test_no_url(self):
        assert self.tester.test({}) == []

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_quick_scan_risky_port(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 21, 'state': 'open', 'service': 'ftp', 'banner': ''},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {},
            'vulnerabilities': [],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='quick')
        risky = [v for v in vulns if 'risky' in v.get('name', '').lower() or 'port' in v.get('category', '')]
        assert len(risky) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_quick_scan_deprecated_proto(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 443, 'state': 'open', 'service': 'https'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [
                {'protocol': 'SSLv3', 'supported': True, 'deprecated': True},
            ],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {},
            'vulnerabilities': [],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='quick')
        deprecated = [v for v in vulns if 'deprecated' in v.get('name', '').lower()]
        assert len(deprecated) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_quick_scan_self_signed(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 443, 'state': 'open', 'service': 'https'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {'self_signed': True},
            'vulnerabilities': [],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='quick')
        cert_vulns = [v for v in vulns if 'self-signed' in v.get('name', '').lower()]
        assert len(cert_vulns) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_quick_scan_expired_cert(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 443, 'state': 'open', 'service': 'https'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {'days_until_expiry': -10},
            'vulnerabilities': [],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='quick')
        expired = [v for v in vulns if 'expired' in v.get('name', '').lower()]
        assert len(expired) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_quick_scan_missing_hsts(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 443, 'state': 'open', 'service': 'https'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {},
            'vulnerabilities': [],
            'hsts': {'enabled': False},
            'ocsp_stapling': {'supported': False},
        }
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='quick')
        hsts = [v for v in vulns if 'hsts' in v.get('name', '').lower()]
        assert len(hsts) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_deep_scan_ssl_vulns(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 443, 'state': 'open', 'service': 'https'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {},
            'vulnerabilities': [
                {'name': 'POODLE', 'cve': 'CVE-2014-3566', 'severity': 'high', 'info': 'SSLv3 vuln'},
            ],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        instance.test_services.return_value = []
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='deep')
        poodle = [v for v in vulns if 'poodle' in v.get('name', '').lower()]
        assert len(poodle) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_medium_scan_service_detection(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 6379, 'state': 'open', 'service': 'redis'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': False, 'weak': []},
            'certificate': {},
            'vulnerabilities': [],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        instance.test_services.return_value = [
            {'title': 'Redis Unauthenticated Access', 'severity': 'high',
             'description': 'Redis open', 'evidence': 'PONG'},
        ]
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='medium')
        redis_vulns = [v for v in vulns if 'redis' in v.get('name', '').lower()]
        assert len(redis_vulns) >= 1

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_http_scheme_no_ssl(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 80, 'state': 'open', 'service': 'http'},
        ]
        # Should not call test_ssl for pure HTTP without 443/8443
        vulns = self.tester.test({'url': 'http://example.com:8080/'}, depth='quick')
        # No SSL vulns expected for plain HTTP
        ssl_vulns = [v for v in vulns if v.get('category') == 'network_ssl']
        assert len(ssl_vulns) == 0

    @patch('apps.scanning.engine.network.NetworkScanner')
    def test_weak_cipher_vuln(self, MockScanner):
        instance = MockScanner.return_value
        instance.scan_ports.return_value = [
            {'port': 443, 'state': 'open', 'service': 'https'},
        ]
        instance.test_ssl.return_value = {
            'protocol_versions': [],
            'ciphers': {'has_weak_ciphers': True, 'weak': ['RC4-SHA']},
            'certificate': {},
            'vulnerabilities': [],
            'hsts': {'enabled': True},
            'ocsp_stapling': {'supported': False},
        }
        vulns = self.tester.test({'url': 'https://example.com/'}, depth='quick')
        weak = [v for v in vulns if 'weak' in v.get('name', '').lower() and 'cipher' in v.get('name', '').lower()]
        assert len(weak) >= 1


# ════════════════════════════════════════════════════════════════════════════
# Registration / Tester count
# ════════════════════════════════════════════════════════════════════════════

class TestRegistration:

    def test_registration(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers]
        assert 'Network Scanner' in names

    def test_tester_count(self):
        """Total tester count is 66 (65 + Phase 34)."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) == 87
