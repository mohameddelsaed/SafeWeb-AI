# Architectural Implementation Blueprint

## 1. Component Hierarchy & Container Boundaries

```
+-------------------------------------------------------------------------+
| HOST / CLOUD DOCKER BRIDGE NETWORK (safeweb-net)                        |
|                                                                         |
|  +--------------------+      +---------------------------------------+  |
|  | frontend (React)   |      | web (Django REST Control Plane)       |  |
|  | Container: Nginx   |----->| Container: Gunicorn :8000             |  |
|  +--------------------+      +-------------------+-------------------+  |
|                                                  |                      |
|                                      Celery Dispatch via Redis          |
|                                                  ▼                      |
|                              +---------------------------------------+  |
|                              | celery_worker (LangGraph Engine)      |  |
|                              | Container: Celery Worker concurrency=4|  |
|                              +---------+-------------------+---------+  |
|                                        |                   |            |
|                           SQL/pgvector |                   | SSH/RPC    |
|                                        ▼                   ▼            |
|                   +-----------------------+     +--------------------+  |
|                   | db (PostgreSQL 15)    |     | agent_sandbox      |  |
|                   | Container: pgvector   |     | Container: Kali/CLI|  |
|                   +-----------------------+     +--------------------+  |
+-------------------------------------------------------------------------+
```

## 2. Database Schema Changes (Exact Django Model Diffs)

### `backend/apps/scanning/models.py`
```diff
 class Scan(models.Model):
     # Existing fields...
+    flow_status = models.CharField(max_length=50, default='initializing')
+    task_graph = models.JSONField(default=dict, blank=True)
+    engagement_log = models.JSONField(default=list, blank=True)
+    cost_meter_usd = models.DecimalField(max_digits=8, decimal_places=4, default=0.0000)
+    scope_allowlist = models.JSONField(default=list, blank=True)

 class Vulnerability(models.Model):
+    VERIFICATION_STATUS_CHOICES = [
+        ('candidate', 'Candidate (Unverified)'),
+        ('verified', 'Verified (3/3 Confirmed)'),
+        ('unverified', 'Unverified (Replay Failed)'),
+    ]
     # Existing fields...
+    verification_status = models.CharField(max_length=20, choices=VERIFICATION_STATUS_CHOICES, default='candidate')
+    proof_capsule = models.JSONField(default=dict, blank=True, null=True)
+    action_id_reference = models.CharField(max_length=100, blank=True, null=True)
```

### `backend/apps/ml/models.py`
```diff
+from pgvector.django import VectorField
+
+class ExploitMemory(models.Model):
+    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
+    technology_stack = models.CharField(max_length=255)
+    vulnerability_class = models.CharField(max_length=100)
+    attack_strategy_summary = models.TextField()
+    successful_payload = models.TextField()
+    vector_embedding = VectorField(dimensions=1536)
+    created_at = models.DateTimeField(auto_now_add=True)
```

## 3. LangGraph State & Node Topology

```python
# State Definition
class PentestState(TypedDict):
    scan_id: str
    target_url: str
    scope_allowlist: list[str]
    intensity: str
    discovered_endpoints: list[dict]
    candidate_vulns: list[dict]
    verified_vulns: list[dict]
    current_cost: float
    messages: list[BaseMessage]

# Graph Topology
workflow = StateGraph(PentestState)
workflow.add_node("scope_gate", verify_scope_allowlist)
workflow.add_node("orchestrator", orchestrator_planner_node)
workflow.add_node("recon", recon_specialist_node)
workflow.add_node("vuln_scan", vuln_scanner_node)
workflow.add_node("exploit", web_api_exploit_node)
workflow.add_node("validator", poc_validator_node)
workflow.add_node("reporter", reporter_node)

workflow.set_entry_point("scope_gate")
workflow.add_edge("scope_gate", "orchestrator")
# Conditional edges driven by LLM routing decisions...
```
