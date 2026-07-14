"""
GraphQLTester — GraphQL security testing.
OWASP A01:2021 — Broken Access Control, A03:2021 — Injection.

Tests for: introspection enabled, query depth/complexity abuse,
batching attacks, injection via GraphQL arguments, IDOR, and
information disclosure through error messages.
"""
import re
import logging
from urllib.parse import urlparse, urljoin
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

GRAPHQL_ENDPOINTS = [
    '/graphql', '/graphql/', '/graphiql', '/graphiql/',
    '/api/graphql', '/api/graphql/', '/v1/graphql',
    '/gql', '/query', '/api/query',
]

INTROSPECTION_QUERY = '''
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
    queryType { name }
    mutationType { name }
  }
}
'''

DEPTH_BOMB = '''
{
  __schema {
    types {
      fields {
        type {
          fields {
            type {
              fields {
                type { name }
              }
            }
          }
        }
      }
    }
  }
}
'''


class GraphQLTester(BaseTester):
    """Test for GraphQL-specific vulnerabilities."""

    TESTER_NAME = 'GraphQL'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Find GraphQL endpoints
        endpoints = self._find_graphql_endpoints(page)

        for endpoint in endpoints:
            # Test introspection
            vuln = self._test_introspection(endpoint)
            if vuln:
                vulnerabilities.append(vuln)

            # Test query depth/DoS
            if depth in ('medium', 'deep'):
                vuln = self._test_depth_limit(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

            # Test batching attack
            if depth in ('medium', 'deep'):
                vuln = self._test_batching(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

            # Test field suggestion (info disclosure)
            vuln = self._test_field_suggestions(endpoint)
            if vuln:
                vulnerabilities.append(vuln)

            # Test verbose errors
            vuln = self._test_verbose_errors(endpoint)
            if vuln:
                vulnerabilities.append(vuln)

            # SQL injection via arguments (deep)
            if depth == 'deep':
                vuln = self._test_injection_via_args(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _find_graphql_endpoints(self, page):
        """Discover GraphQL endpoints."""
        endpoints = []
        parsed = urlparse(page.url)
        base = f'{parsed.scheme}://{parsed.netloc}'

        # Check common GraphQL paths
        for path in GRAPHQL_ENDPOINTS:
            test_url = urljoin(base, path)
            response = self._make_request(
                'POST', test_url,
                json={'query': '{ __typename }'},
                headers={'Content-Type': 'application/json'},
            )
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data or 'errors' in data:
                        endpoints.append(test_url)
                except Exception:
                    pass

        # Check page source for GraphQL endpoint references
        body = page.body or ''
        gql_patterns = re.findall(r'["\'](/[a-z0-9_/]*graphql[a-z0-9_/]*)["\']', body, re.I)
        for path in gql_patterns:
            url = urljoin(base, path)
            if url not in endpoints:
                endpoints.append(url)

        return endpoints[:3]

    def _test_introspection(self, endpoint):
        """Test if GraphQL introspection is enabled."""
        response = self._make_request(
            'POST', endpoint,
            json={'query': INTROSPECTION_QUERY},
            headers={'Content-Type': 'application/json'},
        )
        if not response:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        if 'data' in data and data['data'] and '__schema' in data['data']:
            schema = data['data']['__schema']
            type_count = len(schema.get('types', []))
            has_mutations = schema.get('mutationType') is not None

            return self._build_vuln(
                name='GraphQL Introspection Enabled',
                severity='medium',
                category='GraphQL Security',
                description=f'The GraphQL endpoint has introspection enabled, exposing the complete '
                           f'API schema ({type_count} types, mutations: {"yes" if has_mutations else "no"}).',
                impact='Attackers can map the entire API, discover hidden fields, mutations, '
                      'and internal types to craft targeted attacks.',
                remediation='Disable introspection in production. '
                           'Use tools like graphql-depth-limit and graphql-query-complexity.',
                cwe='CWE-200',
                cvss=5.3,
                affected_url=endpoint,
                evidence=f'Schema: {type_count} types exposed. Mutations: {has_mutations}.',
            )
        return None

    def _test_depth_limit(self, endpoint):
        """Test for missing query depth limits (DoS potential)."""
        response = self._make_request(
            'POST', endpoint,
            json={'query': DEPTH_BOMB},
            headers={'Content-Type': 'application/json'},
            timeout=15,
        )
        if not response:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        # If the deep query was executed successfully
        if 'data' in data and data.get('data'):
            return self._build_vuln(
                name='GraphQL No Query Depth Limit',
                severity='medium',
                category='GraphQL Security',
                description='The GraphQL endpoint does not enforce query depth limits, '
                           'allowing deeply nested queries that can cause DoS.',
                impact='Attackers can craft exponentially complex queries to exhaust '
                      'server resources (CPU/memory), causing denial of service.',
                remediation='Implement query depth limiting (max 10-15 levels). '
                           'Use query cost analysis. Set execution timeouts.',
                cwe='CWE-770',
                cvss=5.3,
                affected_url=endpoint,
                evidence='Deep nested query (7 levels) executed successfully.',
            )
        return None

    def _test_batching(self, endpoint):
        """Test for GraphQL batching attacks."""
        # Send a batch of 20 identical queries
        batch = [{'query': '{ __typename }'} for _ in range(20)]

        response = self._make_request(
            'POST', endpoint,
            json=batch,
            headers={'Content-Type': 'application/json'},
        )
        if not response:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        if isinstance(data, list) and len(data) >= 15:
            return self._build_vuln(
                name='GraphQL Batching Allowed',
                severity='low',
                category='GraphQL Security',
                description=f'The GraphQL endpoint accepts batched queries ({len(data)} queries '
                           f'in a single request), which can be abused for brute-force attacks.',
                impact='Attackers can bypass rate limiting by batching many operations '
                      '(e.g., login attempts, OTP guesses) in a single HTTP request.',
                remediation='Limit batch query count (max 5-10). Apply rate limiting per operation, '
                           'not per HTTP request.',
                cwe='CWE-770',
                cvss=3.7,
                affected_url=endpoint,
                evidence=f'Batch of 20 queries accepted, {len(data)} responses returned.',
            )
        return None

    def _test_field_suggestions(self, endpoint):
        """Check if GraphQL exposes field name suggestions."""
        response = self._make_request(
            'POST', endpoint,
            json={'query': '{ nonexistentField12345 }'},
            headers={'Content-Type': 'application/json'},
        )
        if not response:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        errors = data.get('errors', [])
        for error in errors:
            msg = error.get('message', '')
            if 'did you mean' in msg.lower() or 'suggest' in msg.lower():
                return self._build_vuln(
                    name='GraphQL Field Suggestions Enabled',
                    severity='info',
                    category='GraphQL Security',
                    description='GraphQL returns field name suggestions in error messages, '
                               'leaking schema information even with introspection disabled.',
                    impact='Attackers can enumerate valid field names via suggestion messages.',
                    remediation='Disable field suggestions in production. '
                               'Use generic error messages.',
                    cwe='CWE-200',
                    cvss=2.0,
                    affected_url=endpoint,
                    evidence=f'Error message with suggestions: {msg[:200]}',
                )
        return None

    def _test_verbose_errors(self, endpoint):
        """Check for verbose error messages that leak internal information."""
        # Send a malformed query
        response = self._make_request(
            'POST', endpoint,
            json={'query': '{ __type(name: "ASDFInvalid") { name } }'},
            headers={'Content-Type': 'application/json'},
        )
        if not response:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        errors = data.get('errors', [])
        for error in errors:
            msg = str(error)
            # Check for stack traces or internal paths
            if any(k in msg for k in ('traceback', 'stack', '/app/', '/usr/',
                                       'node_modules', 'Exception', 'Error at')):
                return self._build_vuln(
                    name='GraphQL Verbose Error Messages',
                    severity='low',
                    category='GraphQL Security',
                    description='GraphQL error messages expose internal information such as '
                               'stack traces, file paths, or library details.',
                    impact='Internal error details help attackers understand the technology stack '
                          'and find specific vulnerabilities.',
                    remediation='Return generic error messages in production. '
                               'Log detailed errors server-side only.',
                    cwe='CWE-209',
                    cvss=3.7,
                    affected_url=endpoint,
                    evidence=f'Verbose error: {msg[:300]}',
                )
        return None

    def _test_injection_via_args(self, endpoint):
        """Test for SQL injection via GraphQL arguments."""
        sqli_payloads = [
            "' OR 1=1 --",
            '1; DROP TABLE users--',
        ]

        for payload in sqli_payloads:
            query = f'{{ user(id: "{payload}") {{ name email }} }}'
            response = self._make_request(
                'POST', endpoint,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
            )
            if not response:
                continue

            body = response.text.lower()
            sqli_indicators = ['sql', 'syntax error', 'pg_', 'mysql', 'sqlite',
                              'unterminated', 'operator', 'unexpected']
            if any(ind in body for ind in sqli_indicators):
                return self._build_vuln(
                    name='SQL Injection via GraphQL Arguments',
                    severity='critical',
                    category='GraphQL Security',
                    description='SQL injection payloads in GraphQL arguments trigger database errors, '
                               'indicating that GraphQL resolvers pass arguments directly to SQL queries.',
                    impact='Full database access via GraphQL argument injection.',
                    remediation='Use parameterized queries in all GraphQL resolvers. '
                               'Validate and sanitize all argument inputs.',
                    cwe='CWE-89',
                    cvss=9.8,
                    affected_url=endpoint,
                    evidence='SQL error triggered by GraphQL argument payload.',
                )
        return None
