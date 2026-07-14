import pytest
from unittest.mock import patch, MagicMock
from apps.ml.rag import ExploitMemoryRAG

@pytest.mark.unit
@patch('apps.ml.models.ExploitMemory.objects')
def test_exploit_memory_rag_query_fallback(mock_objects):
    """Test fallback querying when pgvector distance ordering fails or mocks."""
    mock_item = MagicMock()
    mock_item.id = "mock_uuid_123"
    mock_item.technology_stack = "Django / Python"
    mock_item.vulnerability_class = "SQLi"
    mock_item.attack_strategy_summary = "Time-based blind SQLi"
    mock_item.successful_payload = "' OR SLEEP(5)--"
    
    mock_objects.all.side_effect = Exception("pgvector not connected")
    mock_objects.filter.return_value.__getitem__.return_value = [mock_item]
    
    results = ExploitMemoryRAG.query_similar_strategies("SQLi", limit=1)
    assert len(results) == 1
    assert results[0]["vulnerability_class"] == "SQLi"
    assert results[0]["successful_payload"] == "' OR SLEEP(5)--"
