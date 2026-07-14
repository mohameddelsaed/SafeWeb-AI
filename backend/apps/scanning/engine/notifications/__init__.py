"""
Notifications Engine — Real-time findings pipeline with severity-based
alerting and progress event streaming.

Provides:
  - NotificationManager: central hub that dispatches to registered channels
  - FindingsStream: real-time event buffer for WebSocket/SSE consumers
  - SeverityFilter: configurable alert thresholds
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Severity ordering
# ────────────────────────────────────────────────────────────────────────────

class Severity(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> 'Severity':
        mapping = {
            'info': cls.INFO,
            'low': cls.LOW,
            'medium': cls.MEDIUM,
            'high': cls.HIGH,
            'critical': cls.CRITICAL,
        }
        return mapping.get(value.lower(), cls.INFO)


# ────────────────────────────────────────────────────────────────────────────
# Event types
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanEvent:
    """A single event emitted during a scan."""
    event_type: str          # 'finding', 'progress', 'phase_start', 'phase_end', 'scan_complete', 'error'
    timestamp: float = field(default_factory=time.time)
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'event_type': self.event_type,
            'timestamp': self.timestamp,
            'data': self.data,
        }


# ────────────────────────────────────────────────────────────────────────────
# Severity filter
# ────────────────────────────────────────────────────────────────────────────

class SeverityFilter:
    """Filter findings by minimum severity threshold."""

    def __init__(self, min_severity: str = 'low'):
        self.min_severity = Severity.from_str(min_severity)

    def should_alert(self, finding: dict) -> bool:
        sev = Severity.from_str(finding.get('severity', 'info'))
        return sev.value >= self.min_severity.value

    def set_threshold(self, min_severity: str) -> None:
        self.min_severity = Severity.from_str(min_severity)


# ────────────────────────────────────────────────────────────────────────────
# Findings stream (event buffer)
# ────────────────────────────────────────────────────────────────────────────

class FindingsStream:
    """In-memory event buffer for real-time scan event consumers.

    Events are appended as they arrive. Consumers can poll for new events
    since a given index, or iterate over all accumulated events.
    """

    def __init__(self, max_events: int = 10_000):
        self._events: list[ScanEvent] = []
        self._max_events = max_events

    def push(self, event: ScanEvent) -> int:
        """Append an event and return its index."""
        if len(self._events) >= self._max_events:
            self._events.pop(0)
        self._events.append(event)
        return len(self._events) - 1

    def get_since(self, index: int) -> list[ScanEvent]:
        """Return all events after *index* (exclusive)."""
        if index < 0:
            return list(self._events)
        return list(self._events[index + 1:])

    def get_all(self) -> list[ScanEvent]:
        return list(self._events)

    def latest(self) -> ScanEvent | None:
        return self._events[-1] if self._events else None

    @property
    def count(self) -> int:
        return len(self._events)

    def clear(self) -> None:
        self._events.clear()


# ────────────────────────────────────────────────────────────────────────────
# Notification channel protocol
# ────────────────────────────────────────────────────────────────────────────

class NotificationChannel:
    """Base class for notification channels (Slack, Discord, etc.)."""
    name: str = 'base'

    def send(self, event: ScanEvent) -> bool:
        return False

    def test_connection(self) -> bool:
        return False


# ────────────────────────────────────────────────────────────────────────────
# Notification manager
# ────────────────────────────────────────────────────────────────────────────

class NotificationManager:
    """Central notification hub — dispatches events to registered channels.

    Features:
    - Severity-based filtering (only alert above threshold)
    - Multiple channels (Slack, Discord, Teams, Telegram, webhook)
    - Event callbacks for custom consumers
    - Built-in FindingsStream for SSE/WebSocket
    """

    def __init__(self, min_severity: str = 'medium'):
        self._channels: list[NotificationChannel] = []
        self._callbacks: list[Callable[[ScanEvent], None]] = []
        self._filter = SeverityFilter(min_severity)
        self._stream = FindingsStream()
        self._stats: dict[str, int] = {
            'total_events': 0,
            'findings': 0,
            'alerts_sent': 0,
            'errors': 0,
        }

    # ── Channel management ─────────────────────────────────────────────

    def add_channel(self, channel: NotificationChannel) -> None:
        self._channels.append(channel)

    def remove_channel(self, channel_name: str) -> bool:
        before = len(self._channels)
        self._channels = [c for c in self._channels if c.name != channel_name]
        return len(self._channels) < before

    def get_channels(self) -> list[str]:
        return [c.name for c in self._channels]

    # ── Callback management ────────────────────────────────────────────

    def add_callback(self, callback: Callable[[ScanEvent], None]) -> None:
        self._callbacks.append(callback)

    # ── Configuration ──────────────────────────────────────────────────

    def set_min_severity(self, severity: str) -> None:
        self._filter.set_threshold(severity)

    # ── Event emission ─────────────────────────────────────────────────

    def emit_finding(self, finding: dict) -> None:
        """Emit a vulnerability finding event."""
        event = ScanEvent(event_type='finding', data=finding)
        self._stream.push(event)
        self._stats['total_events'] += 1
        self._stats['findings'] += 1

        # Fire callbacks always
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as exc:
                logger.debug('Callback error: %s', exc)

        # Only alert channels if severity meets threshold
        if self._filter.should_alert(finding):
            self._dispatch(event)

    def emit_progress(self, phase: str, current: int, total: int,
                      findings_count: int = 0) -> None:
        """Emit a progress event."""
        event = ScanEvent(event_type='progress', data={
            'phase': phase,
            'current': current,
            'total': total,
            'findings_count': findings_count,
        })
        self._stream.push(event)
        self._stats['total_events'] += 1

        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as exc:
                logger.debug('Callback error: %s', exc)

    def emit_phase_start(self, phase: str, description: str = '') -> None:
        event = ScanEvent(event_type='phase_start', data={
            'phase': phase,
            'description': description,
        })
        self._stream.push(event)
        self._stats['total_events'] += 1

    def emit_phase_end(self, phase: str, findings_count: int = 0) -> None:
        event = ScanEvent(event_type='phase_end', data={
            'phase': phase,
            'findings_count': findings_count,
        })
        self._stream.push(event)
        self._stats['total_events'] += 1

    def emit_scan_complete(self, summary: dict) -> None:
        """Emit scan-complete and always dispatch to all channels."""
        event = ScanEvent(event_type='scan_complete', data=summary)
        self._stream.push(event)
        self._stats['total_events'] += 1
        self._dispatch(event)

    def emit_error(self, error: str, details: dict | None = None) -> None:
        event = ScanEvent(event_type='error', data={
            'error': error,
            **(details or {}),
        })
        self._stream.push(event)
        self._stats['total_events'] += 1
        self._stats['errors'] += 1

    # ── Accessors ──────────────────────────────────────────────────────

    @property
    def stream(self) -> FindingsStream:
        return self._stream

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    # ── Internal ───────────────────────────────────────────────────────

    def _dispatch(self, event: ScanEvent) -> None:
        """Send event to all registered channels."""
        for channel in self._channels:
            try:
                channel.send(event)
                self._stats['alerts_sent'] += 1
            except Exception as exc:
                logger.debug('Channel %s error: %s', channel.name, exc)
                self._stats['errors'] += 1
