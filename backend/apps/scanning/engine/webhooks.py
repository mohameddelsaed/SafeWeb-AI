"""
Webhook delivery utility — Phase 44 (API-First Architecture).

Fires HTTP POST requests to configured webhook endpoints with HMAC-SHA256
signatures. Records each delivery attempt in WebhookDelivery.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Maximum seconds to wait for the remote endpoint
_REQUEST_TIMEOUT = 10

# Back-off multiplier between retries (seconds)
_RETRY_DELAYS = [1, 5, 15]


def _sign_payload(secret: str, body: str) -> str:
    """Return an HMAC-SHA256 hex signature for *body* using *secret*."""
    return hmac.new(
        secret.encode('utf-8'),
        body.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def _build_headers(secret: str, body: str) -> dict:
    headers = {'Content-Type': 'application/json', 'User-Agent': 'SafeWeb-AI/1.0'}
    if secret:
        headers['X-SafeWeb-Signature'] = f'sha256={_sign_payload(secret, body)}'
    return headers


def fire_webhook(webhook, event_type: str, payload: dict) -> bool:
    """
    Deliver *payload* to *webhook* for the given *event_type*.

    Creates a WebhookDelivery record, attempts delivery up to
    webhook.max_retries times, and updates the record.

    Returns True if delivery succeeded, False otherwise.
    """
    try:
        import requests
    except ImportError:
        logger.error('requests library not available — webhook delivery skipped')
        return False

    from apps.scanning.models import WebhookDelivery

    body = json.dumps(payload)
    headers = _build_headers(webhook.secret, body)

    delivery = WebhookDelivery.objects.create(
        webhook=webhook,
        event_type=event_type,
        payload=payload,
        status='pending',
    )

    max_retries = max(1, webhook.max_retries)
    for attempt in range(max_retries):
        if attempt > 0:
            delay = _RETRY_DELAYS[min(attempt - 1, len(_RETRY_DELAYS) - 1)]
            time.sleep(delay)

        try:
            resp = requests.post(
                webhook.url,
                data=body,
                headers=headers,
                timeout=_REQUEST_TIMEOUT,
            )
            delivery.http_status = resp.status_code
            delivery.response_body = resp.text[:4096]
            delivery.attempt_count = attempt + 1
            delivery.last_attempted_at = datetime.now(tz=timezone.utc)

            if resp.ok:
                delivery.status = 'delivered'
                delivery.delivered_at = datetime.now(tz=timezone.utc)
                delivery.save()
                logger.info(
                    f'Webhook delivered: {event_type} → {webhook.url} '
                    f'(HTTP {resp.status_code})'
                )
                return True

        except Exception as exc:
            delivery.response_body = str(exc)[:4096]
            delivery.attempt_count = attempt + 1
            delivery.last_attempted_at = datetime.now(tz=timezone.utc)
            logger.warning(
                f'Webhook attempt {attempt + 1} failed for {webhook.url}: {exc}'
            )

    delivery.status = 'failed'
    delivery.save()
    logger.error(f'Webhook delivery failed after {max_retries} attempts: {webhook.url}')
    return False


def fire_event(user, event_type: str, payload: dict) -> int:
    """
    Notify all active webhooks of *user* that subscribe to *event_type*.

    Returns the number of webhooks that were triggered (not necessarily
    successfully delivered).
    """
    from apps.scanning.models import Webhook

    webhooks = Webhook.objects.filter(user=user, is_active=True)
    triggered = 0
    for webhook in webhooks:
        subscribed = webhook.events
        if not subscribed or event_type in subscribed:
            fire_webhook(webhook, event_type, payload)
            triggered += 1
    return triggered


def build_scan_payload(scan) -> dict:
    """Build the standard webhook payload for a scan event."""
    return {
        'scan_id': str(scan.id),
        'target': scan.target,
        'status': scan.status,
        'scan_type': scan.scan_type,
        'score': scan.score,
        'timestamp': datetime.now(tz=timezone.utc).isoformat(),
    }
