import logging
from celery import shared_task

logger = logging.getLogger(__name__)


# ── Phase 43: Scheduled & Continuous Scanning ─────────────────────────────────

@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def execute_scheduled_scan_task(self, scheduled_scan_id: str):
    """
    Execute a single ScheduledScan entry and update its last_run / next_run
    fields (Phase 43).
    """
    from django.utils import timezone as dj_tz
    from apps.scanning.models import ScheduledScan, Scan
    from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine

    logger.info(f'Starting scheduled scan task: {scheduled_scan_id}')
    try:
        scheduled = ScheduledScan.objects.get(id=scheduled_scan_id)
    except ScheduledScan.DoesNotExist:
        logger.error(f'ScheduledScan not found: {scheduled_scan_id}')
        return

    if not scheduled.is_active:
        logger.info(f'Scheduled scan {scheduled_scan_id} is inactive — skipping.')
        return

    now = dj_tz.now()
    config = scheduled.scan_config or {}

    try:
        # Build the child Scan record from the schedule config
        scan = Scan.objects.create(
            user=scheduled.user,
            scan_type=config.get('scan_type', 'website'),
            target=config.get('target', ''),
            depth=config.get('depth', 'medium'),
            include_subdomains=config.get('include_subdomains', False),
            control_external_tools=config.get('control_external_tools', True),
            status='pending',
        )

        # Kick off the actual scan
        execute_scan_task.delay(str(scan.id))

        # Update scheduling timestamps
        engine = ScheduledScanEngine()
        next_run = engine.compute_next_run(
            scheduled.cron_expr or scheduled.schedule_preset, from_dt=now,
        )
        scheduled.last_run = now
        scheduled.next_run = next_run
        scheduled.save(update_fields=['last_run', 'next_run'])

        logger.info(
            f'Scheduled scan {scheduled_scan_id} dispatched scan {scan.id}. '
            f'Next run: {next_run.isoformat()}'
        )
    except Exception as exc:
        logger.error(f'Scheduled scan {scheduled_scan_id} failed: {exc}')
        if self.request.retries >= self.max_retries:
            return
        raise self.retry(exc=exc)


@shared_task
def run_scheduled_scans():
    """
    Periodic (Celery Beat) task that finds all due ScheduledScan entries and
    dispatches each as an ``execute_scheduled_scan_task`` (Phase 43).
    """
    from django.utils import timezone as dj_tz
    from apps.scanning.models import ScheduledScan

    now = dj_tz.now()
    due = ScheduledScan.objects.filter(is_active=True, next_run__lte=now)
    count = 0
    for scheduled in due:
        execute_scheduled_scan_task.delay(str(scheduled.id))
        count += 1
    logger.info(f'run_scheduled_scans dispatched {count} scheduled scan(s).')
    return {'dispatched': count}


@shared_task
def compute_scan_diff_task(scan_id: str, baseline_scan_id: str) -> dict:
    """
    Compute a differential analysis between two scans and return a summary
    dict (Phase 43).
    """
    from apps.scanning.models import Vulnerability
    from apps.scanning.engine.scan_comparison import ScanComparison, compute_security_posture

    def _findings(sid):
        return list(
            Vulnerability.objects.filter(scan_id=sid).values(
                'name', 'severity', 'category', 'affected_url', 'cvss', 'cwe',
            )
        )

    baseline_findings = _findings(baseline_scan_id)
    current_findings = _findings(scan_id)

    comparison = ScanComparison(baseline_findings, current_findings).compare()
    posture = compute_security_posture(current_findings)

    result = comparison.to_dict()
    result['security_posture'] = posture
    result['scan_id'] = scan_id
    result['baseline_scan_id'] = baseline_scan_id

    logger.info(
        f'Scan diff computed: scan={scan_id} vs baseline={baseline_scan_id} — '
        f'new={result["new"]}, fixed={result["fixed"]}'
    )
    return result


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def execute_scan_task(self, scan_id):
    """Execute a scan asynchronously via Celery.

    The orchestrator internally uses asyncio.run() for async phases,
    so Celery workers don't need any async configuration.
    """
    from apps.scanning.engine.orchestrator import ScanOrchestrator
    from apps.scanning.models import Scan

    logger.info(f'Starting scan task: {scan_id}')
    try:
        orchestrator = ScanOrchestrator()
        orchestrator.execute_scan(scan_id)
        logger.info(f'Scan completed: {scan_id}')

        # Post-scan async population of AI explanations for new vulnerabilities
        populate_ai_explanations_task.delay(scan_id)

        # If this scan has a parent (child of wildcard/wide_scope), check aggregation
        scan = Scan.objects.get(id=scan_id)
        if scan.parent_scan_id:
            check_parent_scan_completion.delay(str(scan.parent_scan_id))

    except Scan.DoesNotExist:
        logger.error(f'Scan not found: {scan_id}')
        return  # Don't retry — permanent failure
    except Exception as exc:
        logger.error(f'Scan failed: {scan_id} — {exc}')
        try:
            scan = Scan.objects.get(id=scan_id)
            if self.request.retries >= self.max_retries:
                scan.status = 'failed'
                scan.error_message = str(exc)
                scan.save(update_fields=['status', 'error_message'])
                return  # Final failure — don't retry
            else:
                scan.error_message = f'Retry {self.request.retries + 1}: {exc}'
                scan.save(update_fields=['error_message'])
        except Scan.DoesNotExist:
            return
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=1)
def execute_agentic_scan_task(self, scan_id: str, target_url: str, allowlist: list = None):
    """Execute autonomous multi-agent pentesting scan via LangGraph."""
    from apps.scanning.engine.langgraph_engine import LangGraphOrchestrator
    logger.info(f"Dispatching agentic LangGraph scan for scan_id={scan_id}")
    orchestrator = LangGraphOrchestrator()
    initial_state = {
        "scan_id": str(scan_id),
        "target_url": target_url,
        "scope_allowlist": allowlist or [target_url],
        "flow_status": "initializing",
        "discovered_endpoints": [],
        "candidate_vulnerabilities": [],
        "verified_vulnerabilities": [],
        "current_cost": 0.0,
        "engagement_log": []
    }
    final_state = orchestrator.run_scan(initial_state)
    logger.info(f"Agentic scan completed. Final status: {final_state.get('flow_status')}")
    return final_state


@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def populate_ai_explanations_task(self, scan_id: str):
    """
    Post-scan task to populate AI explanations for all vulnerabilities found in a scan.
    """
    from apps.scanning.models import Vulnerability
    from apps.scanning.engine.ai.reasoning import LLMReasoningEngine

    logger.info(f'Populating AI explanations for scan: {scan_id}')
    try:
        engine = LLMReasoningEngine()
        if not engine.available:
            logger.info("LLM engine not available, skipping AI explanations.")
            return

        vulns = Vulnerability.objects.filter(scan_id=scan_id, ai_explanation='')
        for vuln in vulns:
            try:
                # Convert vuln model to dict for AI explanation
                finding_dict = {
                    'name': vuln.name,
                    'severity': vuln.severity,
                    'category': vuln.category,
                    'description': vuln.description,
                    'impact': vuln.impact,
                    'remediation': vuln.remediation,
                    'affected_url': vuln.affected_url,
                    'cvss': vuln.cvss,
                    'evidence': vuln.evidence,
                }
                
                # The method is synchronous since it uses the provider directly
                explanation_result = engine.explain_vulnerability(finding_dict)
                if explanation_result:
                    ai_explanation = explanation_result.get('ai_explanation', '')
                    ai_remediation = explanation_result.get('ai_remediation', '')
                    
                    vuln.ai_explanation = ai_explanation
                    vuln.ai_remediation = ai_remediation
                    vuln.save(update_fields=['ai_explanation', 'ai_remediation'])
            except Exception as item_exc:
                logger.warning(f"Failed to generate explanation for vuln {vuln.id}: {item_exc}")

        logger.info(f'Finished populating AI explanations for scan: {scan_id}')
    except Exception as exc:
        logger.error(f'populate_ai_explanations_task failed for {scan_id}: {exc}')
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def check_parent_scan_completion(self, parent_scan_id: str):
    """Check if all child scans of a parent (wildcard/wide_scope) are done.

    When every child has reached a terminal status (completed / failed),
    aggregate scores and vulnerability summaries into the parent scan.
    """
    from apps.scanning.models import Scan

    try:
        parent = Scan.objects.get(id=parent_scan_id)
    except Scan.DoesNotExist:
        logger.error(f'Parent scan not found: {parent_scan_id}')
        return

    children = Scan.objects.filter(parent_scan=parent)
    total = children.count()
    if total == 0:
        return

    terminal_states = {'completed', 'failed'}
    done = children.filter(status__in=terminal_states).count()

    # Update parent progress based on children completion ratio
    parent.progress = int((done / total) * 100)
    parent.save(update_fields=['progress'])

    if done < total:
        logger.info(
            f'Parent scan {parent_scan_id}: {done}/{total} children done — waiting.'
        )
        return

    # All children finished — aggregate results
    completed_children = children.filter(status='completed')
    scores = [c.score for c in completed_children if c.score is not None]

    parent.score = round(sum(scores) / len(scores), 1) if scores else 0
    parent.status = 'completed' if completed_children.exists() else 'failed'

    # Aggregate vulnerability summary across children
    agg_summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for child in completed_children:
        child_summary = child.vulnerability_summary or {}
        for sev in agg_summary:
            agg_summary[sev] += child_summary.get(sev, 0)
    parent.vulnerability_summary = agg_summary
    parent.save(update_fields=['score', 'status', 'vulnerability_summary', 'progress'])

    logger.info(
        f'Parent scan {parent_scan_id} aggregated: score={parent.score}, '
        f'status={parent.status}, vulns={agg_summary}'
    )


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def execute_scan_chunk_task(self, chunk_data: dict) -> dict:
    """
    Phase 15: Execute a single ScanChunk on a Celery worker.

    chunk_data keys: chunk_id, scan_id, chunk_type, payload
    Returns the result dict from ScanWorker.execute_chunk().
    """
    from apps.scanning.engine.distributed.scan_controller import ScanChunk
    from apps.scanning.engine.distributed.worker import ScanWorker

    chunk_id = chunk_data.get('chunk_id', 'unknown')
    logger.info(f'Starting chunk task: {chunk_id}')

    chunk = ScanChunk(
        chunk_id=chunk_data['chunk_id'],
        scan_id=chunk_data['scan_id'],
        chunk_type=chunk_data['chunk_type'],
        payload=chunk_data.get('payload', {}),
    )

    def progress_cb(state, meta):
        self.update_state(state=state, meta=meta)

    worker = ScanWorker(chunk, progress_cb=progress_cb)
    try:
        result = worker.execute_chunk()
        logger.info(f'Chunk task completed: {chunk_id}')
        return result
    except Exception as exc:
        logger.error(f'Chunk task failed: {chunk_id} — {exc}')
        if self.request.retries >= self.max_retries:
            return {'error': str(exc), 'chunk_id': chunk_id}
        raise self.retry(exc=exc)

