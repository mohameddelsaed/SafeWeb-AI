import logging
from celery import shared_task

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=2)
def process_user_feedback_task(self, vulnerability_id: str, action: str):
    """
    Celery feedback task triggered on user verification or false-positive marking.
    Indexes confirmed vulnerabilities into pgvector ExploitMemory for future RAG recall.
    """
    from apps.scanning.models import Vulnerability
    from apps.ml.rag import ExploitMemoryRAG
    
    logger.info(f"Processing user feedback for vulnerability [{vulnerability_id}] action: {action}")
    try:
        vuln = Vulnerability.objects.get(id=vulnerability_id)
        if action == "verify" or vuln.verified:
            # Index into memory
            tech = vuln.scan.target if vuln.scan else "general_web"
            ExploitMemoryRAG.index_exploit_memory(
                technology_stack=str(tech),
                vulnerability_class=vuln.category or vuln.name,
                attack_strategy_summary=f"Confirmed exploit on {vuln.affected_url or vuln.name}",
                successful_payload=str(vuln.exploit_data.get("payload", vuln.name))
            )
            logger.info(f"Indexed feedback for verified vuln: {vulnerability_id}")
        elif action == "false_positive" or vuln.is_false_positive:
            logger.info(f"Recorded false positive feedback for vuln: {vulnerability_id}")
    except Vulnerability.DoesNotExist:
        logger.warning(f"Vulnerability not found for feedback task: {vulnerability_id}")
    except Exception as e:
        logger.error(f"Error processing feedback task: {str(e)}")
        raise self.retry(exc=e)
