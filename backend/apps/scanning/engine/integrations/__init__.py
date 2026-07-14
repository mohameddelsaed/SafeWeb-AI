"""
Integrations Engine — Issue tracker auto-creation for Jira, GitHub, GitLab.

Each integration implements IssueTrackerIntegration and can create issues
from vulnerability findings automatically.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Base protocol
# ────────────────────────────────────────────────────────────────────────────

class IssueTrackerIntegration:
    """Base class for issue tracker integrations."""
    name: str = 'base'

    def create_issue(self, finding: dict) -> dict | None:
        """Create a ticket from a vulnerability finding.

        Returns ``{id, url, key}`` on success, or None on failure.
        """
        raise NotImplementedError

    def test_connection(self) -> bool:
        raise NotImplementedError

    def format_title(self, finding: dict) -> str:
        sev = finding.get('severity', 'info').upper()
        name = finding.get('name', 'Unknown Vulnerability')
        return f"[{sev}] {name}"

    def format_body(self, finding: dict) -> str:
        parts = [
            f"**Vulnerability**: {finding.get('name', 'Unknown')}",
            f"**Severity**: {finding.get('severity', 'info').upper()}",
            f"**Category**: {finding.get('category', '')}",
            f"**CWE**: {finding.get('cwe', 'N/A')}",
            f"**CVSS**: {finding.get('cvss', 0)}",
            f"**Affected URL**: {finding.get('affected_url', '')}",
            '',
            '## Description',
            finding.get('description', ''),
            '',
            '## Impact',
            finding.get('impact', ''),
            '',
            '## Remediation',
            finding.get('remediation', ''),
            '',
            '## Evidence',
            f"```\n{finding.get('evidence', '')}\n```",
            '',
            '---',
            '*Created by SafeWeb AI Scanner*',
        ]
        return '\n'.join(parts)

    @staticmethod
    def severity_to_priority(severity: str) -> str:
        return {
            'critical': 'highest',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'lowest',
        }.get(severity.lower(), 'medium')


# ────────────────────────────────────────────────────────────────────────────
# Helper
# ────────────────────────────────────────────────────────────────────────────

def _api_request(url: str, method: str, headers: dict,
                 payload: dict | None = None,
                 timeout: float = 15.0) -> dict | None:
    """Make an API request and return parsed JSON response or None."""
    try:
        data = json.dumps(payload).encode('utf-8') if payload else None
        req = Request(url, data=data, headers=headers, method=method)
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read().decode('utf-8')
            return json.loads(body) if body else {}
    except Exception as exc:
        logger.debug('API request failed %s %s: %s', method, url, exc)
        return None


# ────────────────────────────────────────────────────────────────────────────
# Jira Integration
# ────────────────────────────────────────────────────────────────────────────

class JiraIntegration(IssueTrackerIntegration):
    """Create Jira issues from vulnerability findings."""
    name = 'jira'

    def __init__(self, base_url: str, email: str, api_token: str,
                 project_key: str, issue_type: str = 'Bug',
                 labels: list[str] | None = None):
        self.base_url = base_url.rstrip('/')
        self.project_key = project_key
        self.issue_type = issue_type
        self.labels = labels or ['security', 'safeweb-ai']
        import base64
        cred = base64.b64encode(f'{email}:{api_token}'.encode()).decode()
        self._headers = {
            'Authorization': f'Basic {cred}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def create_issue(self, finding: dict) -> dict | None:
        url = f'{self.base_url}/rest/api/3/issue'
        payload = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': self.format_title(finding),
                'description': {
                    'type': 'doc',
                    'version': 1,
                    'content': [{
                        'type': 'paragraph',
                        'content': [{'type': 'text', 'text': self.format_body(finding)}],
                    }],
                },
                'issuetype': {'name': self.issue_type},
                'labels': self.labels,
                'priority': {'name': self.severity_to_priority(
                    finding.get('severity', 'medium')).capitalize()},
            }
        }
        resp = _api_request(url, 'POST', self._headers, payload)
        if resp and 'key' in resp:
            return {
                'id': resp.get('id', ''),
                'key': resp['key'],
                'url': f"{self.base_url}/browse/{resp['key']}",
            }
        return None

    def test_connection(self) -> bool:
        url = f'{self.base_url}/rest/api/3/myself'
        resp = _api_request(url, 'GET', self._headers)
        return resp is not None and 'accountId' in (resp or {})

    def build_payload(self, finding: dict) -> dict:
        """Return the Jira payload that would be sent (for testing)."""
        return {
            'fields': {
                'project': {'key': self.project_key},
                'summary': self.format_title(finding),
                'issuetype': {'name': self.issue_type},
                'labels': self.labels,
            }
        }


# ────────────────────────────────────────────────────────────────────────────
# GitHub Issues Integration
# ────────────────────────────────────────────────────────────────────────────

class GitHubIntegration(IssueTrackerIntegration):
    """Create GitHub Issues from vulnerability findings."""
    name = 'github'

    def __init__(self, token: str, owner: str, repo: str,
                 labels: list[str] | None = None):
        self.owner = owner
        self.repo = repo
        self.labels = labels or ['security', 'safeweb-ai']
        self._headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2022-11-28',
        }

    def create_issue(self, finding: dict) -> dict | None:
        url = f'https://api.github.com/repos/{self.owner}/{self.repo}/issues'
        payload = {
            'title': self.format_title(finding),
            'body': self.format_body(finding),
            'labels': self.labels + [finding.get('severity', 'info')],
        }
        resp = _api_request(url, 'POST', self._headers, payload)
        if resp and 'number' in resp:
            return {
                'id': str(resp['number']),
                'key': f"#{resp['number']}",
                'url': resp.get('html_url', ''),
            }
        return None

    def test_connection(self) -> bool:
        url = f'https://api.github.com/repos/{self.owner}/{self.repo}'
        resp = _api_request(url, 'GET', self._headers)
        return resp is not None and 'id' in (resp or {})

    def build_payload(self, finding: dict) -> dict:
        return {
            'title': self.format_title(finding),
            'body': self.format_body(finding),
            'labels': self.labels + [finding.get('severity', 'info')],
        }


# ────────────────────────────────────────────────────────────────────────────
# GitLab Issues Integration
# ────────────────────────────────────────────────────────────────────────────

class GitLabIntegration(IssueTrackerIntegration):
    """Create GitLab Issues from vulnerability findings."""
    name = 'gitlab'

    def __init__(self, base_url: str, token: str, project_id: int | str,
                 labels: list[str] | None = None):
        self.base_url = base_url.rstrip('/')
        self.project_id = project_id
        self.labels = labels or ['security', 'safeweb-ai']
        self._headers = {
            'PRIVATE-TOKEN': token,
            'Content-Type': 'application/json',
        }

    def create_issue(self, finding: dict) -> dict | None:
        url = f'{self.base_url}/api/v4/projects/{self.project_id}/issues'
        payload = {
            'title': self.format_title(finding),
            'description': self.format_body(finding),
            'labels': ','.join(self.labels + [finding.get('severity', 'info')]),
        }
        resp = _api_request(url, 'POST', self._headers, payload)
        if resp and 'iid' in resp:
            return {
                'id': str(resp['iid']),
                'key': f"#{resp['iid']}",
                'url': resp.get('web_url', ''),
            }
        return None

    def test_connection(self) -> bool:
        url = f'{self.base_url}/api/v4/projects/{self.project_id}'
        resp = _api_request(url, 'GET', self._headers)
        return resp is not None and 'id' in (resp or {})

    def build_payload(self, finding: dict) -> dict:
        return {
            'title': self.format_title(finding),
            'description': self.format_body(finding),
            'labels': ','.join(self.labels + [finding.get('severity', 'info')]),
        }


# ────────────────────────────────────────────────────────────────────────────
# Integration Manager
# ────────────────────────────────────────────────────────────────────────────

class IntegrationManager:
    """Manage multiple issue tracker integrations.

    Auto-creates issues from findings based on severity threshold.
    """

    def __init__(self, min_severity: str = 'high'):
        self._integrations: list[IssueTrackerIntegration] = []
        self._min_severity = min_severity
        self._severity_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        self._created_issues: list[dict] = []

    def add_integration(self, integration: IssueTrackerIntegration) -> None:
        self._integrations.append(integration)

    def remove_integration(self, name: str) -> bool:
        before = len(self._integrations)
        self._integrations = [i for i in self._integrations if i.name != name]
        return len(self._integrations) < before

    def get_integrations(self) -> list[str]:
        return [i.name for i in self._integrations]

    def set_min_severity(self, severity: str) -> None:
        self._min_severity = severity

    def should_create_issue(self, finding: dict) -> bool:
        sev = finding.get('severity', 'info').lower()
        return self._severity_order.get(sev, 0) >= self._severity_order.get(self._min_severity, 0)

    def create_issues(self, finding: dict) -> list[dict]:
        """Create issues in all integrations for a finding (if above threshold)."""
        if not self.should_create_issue(finding):
            return []
        results = []
        for integration in self._integrations:
            try:
                result = integration.create_issue(finding)
                if result:
                    result['integration'] = integration.name
                    results.append(result)
                    self._created_issues.append(result)
            except Exception as exc:
                logger.debug('Issue creation failed for %s: %s', integration.name, exc)
        return results

    @property
    def created_issues(self) -> list[dict]:
        return list(self._created_issues)
