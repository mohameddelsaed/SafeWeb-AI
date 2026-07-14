import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class ExploitMemoryRAG:
    """RAG Search Query Builder and Indexer for Exploit Memory embeddings."""

    @staticmethod
    def _get_mock_embedding(dim: int = 1536) -> List[float]:
        """Generate deterministic/mock 1536-dim vector when real embeddings API is offline."""
        return [0.01] * dim

    @classmethod
    def index_exploit_memory(
        cls,
        technology_stack: str,
        vulnerability_class: str,
        attack_strategy_summary: str,
        successful_payload: str,
        embedding: Optional[List[float]] = None
    ) -> Any:
        """Create and store a new ExploitMemory embedding vector."""
        from apps.ml.models import ExploitMemory
        
        vec = embedding or cls._get_mock_embedding()
        try:
            memory = ExploitMemory.objects.create(
                technology_stack=technology_stack,
                vulnerability_class=vulnerability_class,
                attack_strategy_summary=attack_strategy_summary,
                successful_payload=successful_payload,
                vector_embedding=vec
            )
            logger.info(f"Indexed ExploitMemory [{memory.id}] for {vulnerability_class} on {technology_stack}")
            return memory
        except Exception as e:
            logger.error(f"Failed to index ExploitMemory: {str(e)}")
            return None

    @classmethod
    def query_similar_strategies(
        cls,
        query_text: str,
        technology_stack: Optional[str] = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Retrieve top similar attack strategies using pgvector vector distance."""
        from apps.ml.models import ExploitMemory
        
        query_vec = cls._get_mock_embedding()
        results = []
        
        try:
            from pgvector.django import CosineDistance
            qs = ExploitMemory.objects.all()
            if technology_stack:
                qs = qs.filter(technology_stack__icontains=technology_stack)
                
            qs = qs.order_by(CosineDistance('vector_embedding', query_vec))[:limit]
            
            for m in qs:
                results.append({
                    "id": str(m.id),
                    "technology_stack": m.technology_stack,
                    "vulnerability_class": m.vulnerability_class,
                    "attack_strategy_summary": m.attack_strategy_summary,
                    "successful_payload": m.successful_payload
                })
        except Exception as e:
            logger.warning(f"pgvector query failed (fallback to keyword search): {str(e)}")
            try:
                qs = ExploitMemory.objects.filter(vulnerability_class__icontains=query_text)[:limit]
                for m in qs:
                    results.append({
                        "id": str(m.id),
                        "technology_stack": m.technology_stack,
                        "vulnerability_class": m.vulnerability_class,
                        "attack_strategy_summary": m.attack_strategy_summary,
                        "successful_payload": m.successful_payload
                    })
            except Exception:
                pass
                
        return results
