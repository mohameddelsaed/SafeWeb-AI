"""
Chat Notification Channels — Slack, Discord, Microsoft Teams, Telegram.

Each channel implements NotificationChannel and formats events into
platform-specific payloads sent via webhook or bot API.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from apps.scanning.engine.notifications import NotificationChannel, ScanEvent

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

_SEVERITY_EMOJI = {
    'critical': '\U0001F534',   # 🔴
    'high': '\U0001F7E0',       # 🟠
    'medium': '\U0001F7E1',     # 🟡
    'low': '\U0001F535',        # 🔵
    'info': '\u26AA',           # ⚪
}


def _severity_emoji(severity: str) -> str:
    return _SEVERITY_EMOJI.get(severity.lower(), '\u2753')


def _format_finding(data: dict) -> str:
    sev = data.get('severity', 'info')
    emoji = _severity_emoji(sev)
    name = data.get('name', 'Unknown')
    url = data.get('affected_url', '')
    return f"{emoji} [{sev.upper()}] {name}\n  URL: {url}"


def _format_progress(data: dict) -> str:
    phase = data.get('phase', '?')
    current = data.get('current', 0)
    total = data.get('total', 0)
    findings = data.get('findings_count', 0)
    return f"\u23F3 {phase}: {current}/{total} — {findings} findings so far"


def _format_event(event: ScanEvent) -> str:
    if event.event_type == 'finding':
        return _format_finding(event.data)
    if event.event_type == 'progress':
        return _format_progress(event.data)
    if event.event_type == 'scan_complete':
        total = event.data.get('total_findings', 0)
        critical = event.data.get('critical', 0)
        high = event.data.get('high', 0)
        return f"\u2705 Scan complete — {total} findings ({critical} critical, {high} high)"
    if event.event_type == 'error':
        return f"\u274C Error: {event.data.get('error', 'unknown')}"
    if event.event_type == 'phase_start':
        return f"\u25B6 Phase started: {event.data.get('phase', '')}"
    if event.event_type == 'phase_end':
        return f"\u23F9 Phase ended: {event.data.get('phase', '')} — {event.data.get('findings_count', 0)} findings"
    return f"[{event.event_type}] {json.dumps(event.data)}"


def _post_json(url: str, payload: dict, timeout: float = 10.0) -> bool:
    """POST JSON payload to a URL. Returns True on success."""
    try:
        data = json.dumps(payload).encode('utf-8')
        req = Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except Exception as exc:
        logger.debug('Webhook POST failed to %s: %s', url, exc)
        return False


# ────────────────────────────────────────────────────────────────────────────
# Slack
# ────────────────────────────────────────────────────────────────────────────

class SlackChannel(NotificationChannel):
    """Send notifications via Slack Incoming Webhook."""
    name = 'slack'

    def __init__(self, webhook_url: str, channel: str | None = None):
        self.webhook_url = webhook_url
        self.channel = channel

    def send(self, event: ScanEvent) -> bool:
        payload: dict[str, Any] = {'text': _format_event(event)}
        if self.channel:
            payload['channel'] = self.channel
        return _post_json(self.webhook_url, payload)

    def test_connection(self) -> bool:
        return _post_json(self.webhook_url, {'text': '\u2705 SafeWeb AI connected.'})

    def build_payload(self, event: ScanEvent) -> dict:
        """Return the payload that would be sent (for testing)."""
        payload: dict[str, Any] = {'text': _format_event(event)}
        if self.channel:
            payload['channel'] = self.channel
        return payload


# ────────────────────────────────────────────────────────────────────────────
# Discord
# ────────────────────────────────────────────────────────────────────────────

class DiscordChannel(NotificationChannel):
    """Send notifications via Discord Webhook."""
    name = 'discord'

    def __init__(self, webhook_url: str, username: str = 'SafeWeb AI'):
        self.webhook_url = webhook_url
        self.username = username

    def send(self, event: ScanEvent) -> bool:
        payload = {
            'username': self.username,
            'content': _format_event(event),
        }
        return _post_json(self.webhook_url, payload)

    def test_connection(self) -> bool:
        return _post_json(self.webhook_url, {
            'username': self.username,
            'content': '\u2705 SafeWeb AI connected.',
        })

    def build_payload(self, event: ScanEvent) -> dict:
        return {
            'username': self.username,
            'content': _format_event(event),
        }


# ────────────────────────────────────────────────────────────────────────────
# Microsoft Teams
# ────────────────────────────────────────────────────────────────────────────

class TeamsChannel(NotificationChannel):
    """Send notifications via Microsoft Teams Incoming Webhook."""
    name = 'teams'

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, event: ScanEvent) -> bool:
        payload = {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'summary': 'SafeWeb AI Notification',
            'themeColor': self._color(event),
            'title': f'SafeWeb AI — {event.event_type.replace("_", " ").title()}',
            'text': _format_event(event),
        }
        return _post_json(self.webhook_url, payload)

    def test_connection(self) -> bool:
        return _post_json(self.webhook_url, {
            '@type': 'MessageCard',
            'summary': 'Test',
            'text': '\u2705 SafeWeb AI connected.',
        })

    def build_payload(self, event: ScanEvent) -> dict:
        return {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'summary': 'SafeWeb AI Notification',
            'themeColor': self._color(event),
            'title': f'SafeWeb AI — {event.event_type.replace("_", " ").title()}',
            'text': _format_event(event),
        }

    @staticmethod
    def _color(event: ScanEvent) -> str:
        if event.event_type == 'finding':
            sev = event.data.get('severity', 'info')
            return {'critical': 'FF0000', 'high': 'FF8C00', 'medium': 'FFD700',
                    'low': '1E90FF', 'info': 'AAAAAA'}.get(sev, '808080')
        if event.event_type == 'error':
            return 'FF0000'
        return '00AA00'


# ────────────────────────────────────────────────────────────────────────────
# Telegram
# ────────────────────────────────────────────────────────────────────────────

class TelegramChannel(NotificationChannel):
    """Send notifications via Telegram Bot API."""
    name = 'telegram'
    _API_BASE = 'https://api.telegram.org'

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send(self, event: ScanEvent) -> bool:
        url = f'{self._API_BASE}/bot{self.bot_token}/sendMessage'
        payload = {
            'chat_id': self.chat_id,
            'text': _format_event(event),
            'parse_mode': 'HTML',
        }
        return _post_json(url, payload)

    def test_connection(self) -> bool:
        url = f'{self._API_BASE}/bot{self.bot_token}/sendMessage'
        return _post_json(url, {
            'chat_id': self.chat_id,
            'text': '\u2705 SafeWeb AI connected.',
        })

    def build_payload(self, event: ScanEvent) -> dict:
        return {
            'chat_id': self.chat_id,
            'text': _format_event(event),
            'parse_mode': 'HTML',
        }


# ────────────────────────────────────────────────────────────────────────────
# Custom Webhook
# ────────────────────────────────────────────────────────────────────────────

class CustomWebhookChannel(NotificationChannel):
    """Send notifications to any HTTP endpoint as JSON."""
    name = 'custom_webhook'

    def __init__(self, webhook_url: str, headers: dict | None = None,
                 name_override: str | None = None):
        self.webhook_url = webhook_url
        self.custom_headers = headers or {}
        if name_override:
            self.name = name_override

    def send(self, event: ScanEvent) -> bool:
        payload = {
            'source': 'safeweb-ai',
            'event': event.to_dict(),
        }
        try:
            data = json.dumps(payload).encode('utf-8')
            headers = {'Content-Type': 'application/json'}
            headers.update(self.custom_headers)
            req = Request(self.webhook_url, data=data, headers=headers)
            with urlopen(req, timeout=10.0) as resp:  # noqa: S310
                return 200 <= resp.status < 300
        except (URLError, OSError) as exc:
            logger.debug('Custom webhook failed: %s', exc)
            return False

    def test_connection(self) -> bool:
        return self.send(ScanEvent(event_type='test', data={'message': 'connection test'}))

    def build_payload(self, event: ScanEvent) -> dict:
        return {
            'source': 'safeweb-ai',
            'event': event.to_dict(),
        }
