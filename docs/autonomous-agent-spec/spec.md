# SafeWeb AI Platform Specification: Autonomous Multi-Agent Pentesting System

## 1. Executive Summary & Target Audience
SafeWeb AI is transitioning from a deterministic 7-phase vulnerability scanner into an autonomous, multi-agent offensive security platform. Built on Django REST Framework, Celery, LangGraph, and PostgreSQL, the platform orchestrates specialized LLM agents to conduct end-to-end web application penetration tests, multi-hop vulnerability chaining, and automated false-positive elimination.

**Target Audience**: Security Operations Centers (SOC), DevOps teams running continuous CI/CD security validation, and professional penetration testers requiring automated bug bounty verification.

## 2. Core Use Cases
* **UC-1: Autonomous Surface & API Exploration**: Given a target domain and authorized scope, the platform autonomously crawls SPAs, parses `robots.txt`/`sitemap.xml`, extracts API endpoints from JavaScript bundles, and constructs a live attack surface map.
* **UC-2: Multi-Hop Vulnerability Chaining**: An agent discovers an SSRF flaw on a secondary sub-service, chains it with an internal cloud metadata endpoint (`169.254.169.254`), retrieves IAM credentials, and escalates privileges to demonstrate business impact.
* **UC-3: Zero False-Positive Verification**: The system ingests 40 candidate noisy alerts from standard scanners, isolates each in a sandbox, executes non-destructive PoC replays, eliminates 37 false positives, and delivers 3 verified proof capsules.

## 3. System Architecture & Tiered Rosters
The platform implements a **Specialist Role Architecture (Pattern 3)** combined with an **MCP Tool Layer (Pattern 5)**:

```
[ Frontend UI ] <---(SSE Live Feed)---> [ Django Control Plane ]
                                                │
                                       (Celery Async Task)
                                                ▼
                                    [ LangGraph Orchestrator ]
                                     ├── Tier-1 Recon Agent (Read-Only)
                                     ├── Tier-1 Vuln Scanner Agent (Candidate Gen)
                                     ├── Tier-2 Web/API Exploit Agent (Sandbox Exec)
                                     ├── Tier-2 Exploit Chainer Agent (Graph Reasoning)
                                     ├── Tier-2 PoC Validator Agent (3/3 Oracle)
                                     └── Tier-1 Reporter Agent (Executive Summary)
```

## 4. Data Models & State Management
* **Engagement State**: Managed by LangGraph StateGraph, tracking `discovered_endpoints`, `candidate_vulns`, `verified_vulns`, and `cost_meter`.
* **Database Models**: Extended Django models stored in PostgreSQL. `Scan` records contain JSONB engagement state. `Vulnerability` rows enforce `verification_status` and store standalone JSON `proof_capsule` payloads.
* **Vector Memory**: `pgvector` table storing 1536-dimensional embeddings of historical exploit strategies and WAF bypass techniques.

## 5. Error Handling & Failure Modes
* **Soliloquizing Guard**: If an agent asserts a vulnerability without citing a valid stored `Action` ID from the tool log, the orchestrator rejects the finding and triggers a reflection nudge.
* **Loop Detection Mentor**: If an agent executes identical tool calls 3 times consecutively without state transition, the `Adviser` mentor block injects alternative methodology suggestions.
* **Cost Ceiling Enforcement**: If LLM API token spend exceeds the engagement threshold (e.g., $10.00), the loop gracefully checkpoints current findings, aborts pending subtasks, and outputs a partial verified report.
