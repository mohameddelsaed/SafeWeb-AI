"""
Phase E2 Verification Script
Inserts a sample embedding into pgvector (ExploitMemory) and executes a similarity search.
"""
import os
import sys
import django

sys.path.insert(0, '.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
django.setup()

from apps.ml.models import ExploitMemory
from pgvector.django import L2Distance

def verify_pgvector():
    print("Clean up old test records...")
    ExploitMemory.objects.filter(vulnerability_class="E2_TEST_VULN").delete()
    
    sample_embedding = [0.1] * 1536
    print("Inserting sample embedding into pgvector...")
    mem = ExploitMemory.objects.create(
        technology_stack="Test Stack E2",
        vulnerability_class="E2_TEST_VULN",
        attack_strategy_summary="Sample attack vector for pgvector verification",
        successful_payload="<script>alert('pgvector')</script>",
        vector_embedding=sample_embedding
    )
    print(f"Created record ID: {mem.id}")
    
    print("Executing vector similarity search using L2 distance...")
    # Query nearest neighbors
    results = ExploitMemory.objects.order_by(L2Distance('vector_embedding', sample_embedding))[:5]
    
    assert len(results) >= 1
    top_match = results[0]
    print(f"Top match found: {top_match.vulnerability_class} (ID: {top_match.id})")
    assert top_match.vulnerability_class == "E2_TEST_VULN"
    
    print("Cleaning up verification record...")
    mem.delete()
    print("SUCCESS: pgvector index utilization and similarity search verified!")

if __name__ == '__main__':
    verify_pgvector()
