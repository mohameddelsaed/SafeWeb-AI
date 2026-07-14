"""
AI / LLM Endpoint Reconnaissance Module.

Detects AI/ML frameworks, LLM gateway endpoints, chat interfaces,
model serving infrastructure, and AI safety layers.

References:
  - OWASP LLM Top 10 (LLM10: Model Theft)
  - NIST AI 100-2 (AI System Inventory)
"""
import logging
import re
import time
import requests
import urllib3

from urllib.parse import urlparse, urljoin

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Known AI/LLM API Endpoints ───────────────────────────────────────────────
AI_API_PATHS = [
    # OpenAI-compatible endpoints
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/embeddings',
    '/v1/models',
    '/v1/moderations',
    '/v1/images/generations',
    '/v1/audio/transcriptions',
    # Generic AI/chat endpoints
    '/api/chat',
    '/api/generate',
    '/api/completions',
    '/api/v1/chat',
    '/api/v1/generate',
    '/api/ai/chat',
    '/api/ai/complete',
    '/api/llm/chat',
    '/api/llm/generate',
    '/chat',
    '/chat/completions',
    '/generate',
    '/predict',
    '/inference',
    '/api/predict',
    '/api/inference',
    # Ollama
    '/api/generate',
    '/api/chat',
    '/api/tags',
    '/api/show',
    '/api/embeddings',
    # LiteLLM
    '/chat/completions',
    '/completions',
    '/embeddings',
    '/model/info',
    '/health',
    '/health/liveliness',
    # vLLM
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/models',
    '/health',
    # TensorFlow Serving
    '/v1/models',
    '/v1/models/model/metadata',
    '/v1/models/model:predict',
    '/v1/models/model:classify',
    # TorchServe
    '/predictions',
    '/api/inference',
    '/ping',
    '/models',
    # Triton Inference Server
    '/v2/health/ready',
    '/v2/health/live',
    '/v2/models',
    '/v2/repository/index',
    # Hugging Face
    '/api/inference',
    '/api/models',
    # Gradio
    '/api/',
    '/api/predict',
    '/config',
    '/info',
    '/queue/push',
    '/queue/status',
    # Streamlit
    '/_stcore/health',
    '/_stcore/stream',
    # Chainlit
    '/ws/socket.io/',
    '/project/settings',
    # LangServe
    '/invoke',
    '/batch',
    '/stream',
    '/input_schema',
    '/output_schema',
    # FastAPI ML
    '/docs',
    '/openapi.json',
    '/redoc',
    # MCP (Model Context Protocol) endpoints
    '/mcp',
    '/mcp/v1',
    '/sse',
    '/messages',
    '/.well-known/mcp.json',
    '/mcp/tools/list',
    '/mcp/resources/list',
    '/mcp/prompts/list',
    # Vector DB / Embedding stores
    '/api/v1/collections',          # Chroma
    '/api/v2/collections',          # Chroma v2
    '/v1/schema',                   # Weaviate
    '/v1/objects',                  # Weaviate
    '/v1/nodes',                    # Weaviate
    '/collections',                 # Qdrant
    '/points',                      # Qdrant
    '/collections/list',            # Qdrant via gRPC-web
    '/v1/describe_index_stats',     # Pinecone
    '/query',                       # generic / Pinecone
    '/upsert',                      # generic / Pinecone
    '/describe_index_stats',        # Pinecone
    '/v1/vector/search',            # Milvus REST
    '/v1/vector/insert',            # Milvus REST
    '/v1/vector/query',             # Milvus REST
    '/standalone/health',           # Milvus health
    '/v1/index',                    # Elasticsearch / OpenSearch
    '/v1/semantic/search',          # various
    # Agentic frameworks
    '/api/v1/chatflows',            # Flowise
    '/api/v1/prediction',           # Flowise
    '/api/v1/chatflows/apikey',     # Flowise key check
    '/apps',                        # Dify
    '/apps/list',                   # Dify
    '/v1/workflows/run',            # Dify
    '/v1/chat-messages',            # Dify
    '/v1/completion-messages',      # Dify
    '/api/v1/studio',               # AutoGen Studio
    '/api/v1/sessions',             # AutoGen Studio
    '/api/v1/agents',               # AutoGen / CrewAI
    '/api/v1/skills',               # AutoGen Studio
    '/api/v1/workflows',            # n8n / LangGraph
    '/api/workflows',               # n8n
    '/api/v1/runs',                 # LangGraph / Langflow
    '/api/v1/flows',                # Langflow
    '/api/v1/graphs',               # LangGraph
    '/studio',                      # LangGraph Studio
    '/rest/workflows',              # n8n REST API
    '/webhook',                     # n8n webhook endpoints
    # ── Phase 9 Expansion (250+ total) ───────────────────────────────────────
    # CrewAI
    '/api/v1/crews',                # CrewAI crew listing
    '/api/v1/crews/run',            # CrewAI run crew
    '/api/v1/tasks',                # CrewAI tasks
    '/api/v1/crew/kickoff',         # CrewAI kickoff
    '/api/crews',                   # CrewAI alt
    # AutoGPT
    '/api/v1/auto',                 # AutoGPT
    '/ap/v1/agent/tasks',           # AutoGPT task API
    '/ap/v1/agent/tasks/steps',     # AutoGPT steps
    '/api/agent',                   # AutoGPT agent
    '/api/agent/run',               # AutoGPT run
    # BabyAGI
    '/api/v1/objectives',           # BabyAGI
    '/api/v1/tasks/execute',        # BabyAGI execute
    '/api/objectives',              # BabyAGI alt
    # MetaGPT
    '/api/v1/metagpt',              # MetaGPT
    '/api/metagpt/run',             # MetaGPT run
    '/api/v1/software',             # MetaGPT software
    '/api/team/run',                # MetaGPT team
    # OpenDevin / All-Hands
    '/api/v1/conversation',         # OpenDevin
    '/api/v1/messages',             # OpenDevin messages
    '/api/v1/sandbox',              # OpenDevin sandbox
    '/api/v1/terminal',             # OpenDevin terminal
    '/api/devin',                   # OpenDevin alt
    # AgentGPT
    '/api/agent/create',            # AgentGPT
    '/api/agent/start',             # AgentGPT
    '/api/agent/execute',           # AgentGPT
    '/api/v1/agentgpt',             # AgentGPT alt
    # Flowise additional
    '/api/v1/credentials',          # Flowise credentials
    '/api/v1/nodes',                # Flowise nodes
    '/api/v1/documentstore',        # Flowise doc store
    '/api/v1/assistants',           # Flowise assistants
    # Dify additional
    '/v1/audio-to-text',            # Dify audio
    '/v1/text-to-audio',            # Dify TTS
    '/console/api/datasets',        # Dify datasets
    '/console/api/apps',            # Dify console
    '/v1/files/upload',             # Dify file upload
    # Langflow additional
    '/api/v1/components',           # Langflow components
    '/api/v1/store',                # Langflow store
    '/api/v1/monitor',              # Langflow monitor
    # LangGraph additional
    '/api/v1/threads',              # LangGraph threads
    '/api/v1/assistants',           # LangGraph assistants
    '/api/v1/crons',                # LangGraph crons
    '/api/v1/store',                # LangGraph store
    # RAG pipelines — Chroma admin
    '/api/v1/tenants',              # Chroma multi-tenant
    '/api/v1/databases',            # Chroma databases
    '/api/v1/heartbeat',            # Chroma heartbeat
    '/api/v1/pre-flight-checks',    # Chroma preflight
    # Weaviate additional
    '/v1/batch/objects',            # Weaviate batch
    '/v1/classifications',          # Weaviate classify
    '/v1/meta',                     # Weaviate meta
    '/v1/backups',                  # Weaviate backups
    '/v1/.well-known/openid-configuration',  # Weaviate OIDC
    # Qdrant additional
    '/collections/{name}/points',   # Qdrant points
    '/cluster',                     # Qdrant cluster
    '/telemetry',                   # Qdrant telemetry
    # Pinecone additional
    '/databases',                   # Pinecone serverless
    '/indexes',                     # Pinecone indexes
    '/vectors/upsert',              # Pinecone upsert
    '/vectors/query',               # Pinecone query
    # Milvus additional
    '/v1/vector/collections',       # Milvus collections
    '/v1/vector/delete',            # Milvus delete
    '/api/v1/health',               # Milvus health
    # MCP additional
    '/mcp/tools',                   # MCP tools namespace
    '/mcp/resources',               # MCP resources namespace
    '/mcp/prompts',                 # MCP prompts namespace
    '/mcp/sampling',                # MCP sampling
    '/mcp/completion',              # MCP completion
    '/.well-known/mcp',             # MCP discovery
    '/mcp/sse',                     # MCP SSE transport
    '/mcp/stdio',                   # MCP stdio transport
    # Multi-modal endpoints
    '/api/vision',                  # Vision API
    '/api/audio',                   # Audio API
    '/api/image-gen',               # Image generation
    '/api/tts',                     # Text-to-speech
    '/api/stt',                     # Speech-to-text
    '/api/v1/vision',               # Vision v1
    '/api/v1/audio',                # Audio v1
    '/api/v1/images/generations',   # Image gen v1
    '/api/v1/audio/speech',         # TTS v1
    '/api/v1/audio/transcriptions', # STT v1
    '/v1/audio/speech',             # OpenAI TTS
    '/v1/images/edits',             # OpenAI image edits
    '/v1/images/variations',        # OpenAI image variations
    # Anthropic Claude
    '/v1/messages',                 # Anthropic messages
    '/v1/complete',                 # Anthropic legacy
    # Google Gemini / Vertex AI
    '/v1/models:generateContent',   # Gemini generate
    '/v1/models:streamGenerateContent',
    '/v1/models:countTokens',       # Gemini count tokens
    '/v1beta/models:generateContent',
    # AWS Bedrock
    '/model/invoke',                # Bedrock invoke
    '/model/invoke-with-response-stream',
    # Cohere
    '/v1/chat',                     # Cohere chat
    '/v1/generate',                 # Cohere generate
    '/v1/rerank',                   # Cohere rerank
    '/v1/embed',                    # Cohere embed
    '/v1/classify',                 # Cohere classify
    # Replicate
    '/v1/predictions',              # Replicate predictions
    '/v1/deployments',              # Replicate deployments
    '/v1/models',                   # Replicate models
    # Together AI
    '/v1/inference',                # Together inference
    # Mistral
    '/v1/fim/completions',          # Mistral FIM
    '/v1/agents/completions',       # Mistral agents
    # Document/RAG ingestion
    '/api/documents',               # Generic doc upload
    '/api/upload',                  # Generic upload
    '/api/ingest',                  # Generic ingest
    '/api/v1/documents',            # Doc upload v1
    '/api/v1/ingest',               # Ingest v1
    '/api/v1/knowledge',            # Knowledge base
    '/api/v1/knowledge/upload',     # Knowledge upload
    # Fine-tuning
    '/v1/fine_tuning/jobs',         # OpenAI fine-tune
    '/v1/fine-tunes',               # OpenAI legacy fine-tune
    '/fine-tune',                   # Generic fine-tune
    '/finetune',                    # Alt fine-tune
    '/api/v1/fine-tune',            # Fine-tune v1
    '/train',                       # Generic train
    '/api/train',                   # Train API
    # LLM observability / tracing
    '/api/v1/traces',               # LangSmith / tracing
    '/api/v1/feedback',             # LangSmith feedback
    '/api/v1/runs',                 # LangSmith runs
    '/api/v1/datasets',             # LangSmith datasets
    '/api/v1/evaluations',          # Evaluation endpoints
    '/api/v1/experiments',          # Experiment tracking
]

# ── AI Framework Fingerprints (response headers / body patterns) ─────────────
AI_HEADER_FINGERPRINTS = {
    'openai': {
        'headers': {
            'x-request-id': r'req_[a-zA-Z0-9]+',
            'openai-organization': r'.+',
            'openai-processing-ms': r'\d+',
            'openai-version': r'\d{4}-\d{2}-\d{2}',
        },
        'name': 'OpenAI API',
    },
    'azure-openai': {
        'headers': {
            'x-ms-region': r'.+',
            'azureml-model-session': r'.+',
            'x-envoy-upstream-service-time': r'\d+',
        },
        'name': 'Azure OpenAI Service',
    },
    'ollama': {
        'headers': {
            'content-type': r'application/x-ndjson',
        },
        'body_patterns': [r'"model"\s*:', r'"created_at"\s*:', r'ollama'],
        'name': 'Ollama',
    },
    'vllm': {
        'body_patterns': [r'vllm', r'"model_version"', r'"max_model_len"'],
        'name': 'vLLM',
    },
    'litellm': {
        'body_patterns': [r'litellm', r'"litellm_params"'],
        'name': 'LiteLLM',
    },
    'tensorflow-serving': {
        'headers': {
            'content-type': r'application/json',
        },
        'body_patterns': [r'"model_spec"', r'"model_version_status"', r'tensorflow'],
        'name': 'TensorFlow Serving',
    },
    'torchserve': {
        'body_patterns': [r'"modelName"', r'"modelVersion"', r'torchserve', r'"status"\s*:\s*"Healthy"'],
        'name': 'TorchServe',
    },
    'triton': {
        'body_patterns': [r'"name"\s*:', r'"platform"\s*:', r'triton', r'"version"\s*:'],
        'name': 'NVIDIA Triton',
    },
    'huggingface': {
        'body_patterns': [r'huggingface', r'"pipeline_tag"', r'"model_id"'],
        'name': 'Hugging Face',
    },
    'gradio': {
        'body_patterns': [r'gradio', r'"is_queue"', r'"fn_index"', r'__gradio'],
        'name': 'Gradio',
    },
    'streamlit': {
        'body_patterns': [r'streamlit', r'_stcore', r'st\.'],
        'name': 'Streamlit',
    },
    'chainlit': {
        'body_patterns': [r'chainlit', r'"chainlit"'],
        'name': 'Chainlit',
    },
    'langserve': {
        'body_patterns': [r'langserve', r'"input_schema"', r'"output_schema"', r'langchain'],
        'name': 'LangServe',
    },
    # MCP (Model Context Protocol)
    'mcp-server': {
        'body_patterns': [
            r'"jsonrpc"\s*:\s*"2\.0"',
            r'"method"\s*:\s*"tools/list"',
            r'"method"\s*:\s*"resources/list"',
            r'"method"\s*:\s*"prompts/list"',
            r'"method"\s*:\s*"tools/call"',
            r'mcp_version',
            r'"serverInfo".*"capabilities"',
        ],
        'headers': {'x-mcp-version': r'.+'},
        'name': 'MCP Server',
    },
    # Vector Databases
    'chroma': {
        'body_patterns': [r'"collections"\s*:\s*\[', r'"chroma_version"', r'"heartbeat"'],
        'headers': {'x-chroma-version': r'.+'},
        'name': 'Chroma (Vector DB)',
    },
    'weaviate': {
        'body_patterns': [
            r'"hostname"\s*:\s*"http',
            r'"version"\s*:\s*"v\d+\.\d+',
            r'"schema"\s*:\s*\{',
            r'weaviate',
        ],
        'headers': {'x-weaviate-cluster-id': r'.+', 'server': r'weaviate'},
        'name': 'Weaviate (Vector DB)',
    },
    'qdrant': {
        'body_patterns': [
            r'"result"\s*:\s*\{"collections"',
            r'"vectors_count"',
            r'"points_count"',
            r'qdrant',
        ],
        'headers': {'server': r'qdrant'},
        'name': 'Qdrant (Vector DB)',
    },
    'pinecone': {
        'body_patterns': [r'pinecone', r'"namespaces"', r'"dimension"', r'"index_fullness"'],
        'headers': {'x-pinecone-api-version': r'.+'},
        'name': 'Pinecone (Vector DB)',
    },
    'milvus': {
        'body_patterns': [r'milvus', r'"collectionName"', r'"rowCount"', r'"indexBuildProgress"'],
        'headers': {'server': r'milvus'},
        'name': 'Milvus (Vector DB)',
    },
    # Agentic Frameworks
    'flowise': {
        'body_patterns': [r'flowise', r'"chatflows"', r'"chatflowId"', r'FlowiseAI'],
        'name': 'Flowise',
    },
    'dify': {
        'body_patterns': [r'"app_id"', r'"workflow_run_id"', r'dify', r'"conversation_id".*"answer"'],
        'headers': {'server': r'dify', 'x-dify-version': r'.+'},
        'name': 'Dify',
    },
    'langflow': {
        'body_patterns': [r'langflow', r'"flow_id"', r'"components".*"edges"'],
        'name': 'Langflow',
    },
    'autogen-studio': {
        'body_patterns': [r'autogen', r'"AutoAgent"', r'"skill_name"', r'"session_id".*"agent'],
        'name': 'AutoGen Studio',
    },
    'n8n': {
        'body_patterns': [r'"n8n-version"', r'"workflowId"', r'"node_types"', r'n8n\.io'],
        'headers': {'server': r'n8n', 'x-n8n-version': r'.+'},
        'name': 'n8n',
    },
    'langgraph': {
        'body_patterns': [r'langgraph', r'"graph_id"', r'"thread_id"', r'"checkpoint_id"'],
        'name': 'LangGraph',
    },
    # Cloud AI services
    'anthropic': {
        'headers': {
            'x-anthropic-version': r'.+',
            'anthropic-ratelimit-requests-limit': r'\d+',
        },
        'body_patterns': [r'"type"\s*:\s*"message"', r'"model"\s*:\s*"claude-'],
        'name': 'Anthropic Claude API',
    },
    'google-gemini': {
        'headers': {'x-goog-api-version': r'.+'},
        'body_patterns': [r'"model"\s*:\s*"gemini-', r'generativelanguage\.googleapis'],
        'name': 'Google Gemini API',
    },
    'aws-bedrock': {
        'headers': {
            'x-amzn-requestid': r'.+',
            'x-amzn-bedrock': r'.+',
        },
        'body_patterns': [r'bedrock', r'"modelId".*"amazon', r'"anthropic\.claude'],
        'name': 'AWS Bedrock',
    },
    'cohere': {
        'headers': {'x-cohere-request-id': r'.+'},
        'body_patterns': [r'"generations".*"text"', r'cohere\.com'],
        'name': 'Cohere API',
    },
}

# ── Chat Widget / Chatbot Indicators ─────────────────────────────────────────
CHAT_WIDGET_PATTERNS = [
    r'<div[^>]*(?:chat-widget|chatbot|chat-container|ai-chat)[^>]*>',
    r'(?:intercom|drift|crisp|tidio|tawk|zendesk|freshchat)\.',
    r'window\.__(?:CHAT|AI|BOT|ASSISTANT)_CONFIG',
    r'data-(?:chat-|bot-|ai-)',
    r'class=["\'][^"\']*(?:chat-bubble|chat-input|chat-message|ai-response)',
    r'id=["\'][^"\']*(?:chatbot|ai-assistant|chat-widget)',
    r'(?:WebSocket|ws://|wss://).*(?:chat|bot|ai)',
    r'fetch\(["\'][^"\']*(?:/api/chat|/chat/completions|/generate)',
]

# ── AI Safety Layer Indicators ───────────────────────────────────────────────
AI_SAFETY_SIGNATURES = {
    'azure-content-safety': {
        'patterns': [r'azure.*content.*safety', r'AzureContentSafety', r'contentsafety\.azure'],
        'name': 'Azure AI Content Safety',
    },
    'openai-moderation': {
        'patterns': [r'moderation', r'openai.*moderation', r'/v1/moderations'],
        'name': 'OpenAI Moderation API',
    },
    'guardrails': {
        'patterns': [r'guardrails', r'NeMo.*Guardrails', r'guardrails_ai'],
        'name': 'NeMo Guardrails',
    },
    'llm-guard': {
        'patterns': [r'llm.?guard', r'protectai'],
        'name': 'LLM Guard',
    },
    'rebuff': {
        'patterns': [r'rebuff', r'prompt.*injection.*detect'],
        'name': 'Rebuff (Prompt Injection Detection)',
    },
}


def run_ai_recon(target_url: str, depth: str = 'medium') -> dict:
    """
    Perform AI/LLM endpoint reconnaissance on a target.

    Returns dict with:
        - detected: bool — whether any AI/LLM features were found
        - endpoints: list of discovered AI API endpoints
        - frameworks: list of detected AI frameworks
        - chat_features: list of detected chat/bot UI elements
        - safety_layers: list of detected AI safety mechanisms
        - models: list of discovered model names/IDs
        - findings, metadata, errors, stats (standardised)
    """
    start = time.time()
    result = create_result('ai_recon', target_url, depth)

    parsed = urlparse(target_url)
    base_url = f'{parsed.scheme}://{parsed.netloc}'

    # Legacy keys
    result['detected'] = False
    result['endpoints'] = []
    result['frameworks'] = []
    result['chat_features'] = []
    result['safety_layers'] = []
    result['models'] = []

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'SafeWeb AI Scanner/1.0 (Security Assessment)',
    })
    session.verify = False

    # 1. Probe known AI API endpoints
    _probe_ai_endpoints(base_url, session, result)

    # 2. Analyze homepage for AI framework fingerprints
    _analyze_response_fingerprints(target_url, session, result)

    # 3. Detect chat widgets / chatbot UI
    _detect_chat_features(target_url, session, result)

    # 4. Detect AI safety layers
    _detect_safety_layers(target_url, session, result)

    # Set overall detection flag
    result['detected'] = bool(
        result['endpoints'] or result['frameworks'] or
        result['chat_features'] or result['models']
    )

    # Add structured findings
    for ep in result['endpoints']:
        add_finding(result, {
            'type': 'ai_endpoint',
            'url': ep.get('url'),
            'path': ep.get('path'),
            'status': ep.get('status'),
            'authenticated': ep.get('authenticated', False),
        })

    for fw in result['frameworks']:
        add_finding(result, {
            'type': 'ai_framework',
            'name': fw.get('name'),
            'key': fw.get('key'),
            'confidence': 'high' if fw.get('score', 0) >= 3 else 'medium',
        })

    for chat in result['chat_features']:
        add_finding(result, {
            'type': 'chat_feature',
            'pattern': chat.get('pattern'),
        })

    for safety in result['safety_layers']:
        add_finding(result, {
            'type': 'ai_safety_layer',
            'name': safety.get('name'),
        })

    for model in result['models']:
        add_finding(result, {
            'type': 'ai_model',
            'model_id': model,
        })

    return finalize_result(result, start)


def _probe_ai_endpoints(base_url: str, session: requests.Session, result: dict):
    """Probe known AI/LLM API endpoints for accessibility."""
    # Deduplicate paths
    unique_paths = list(dict.fromkeys(AI_API_PATHS))

    for path in unique_paths:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=5, allow_redirects=False)

            # Consider accessible if not 404/403/405/500
            if resp.status_code in (200, 201, 401, 422):
                endpoint_info = {
                    'url': url,
                    'path': path,
                    'status': resp.status_code,
                    'authenticated': resp.status_code == 401,
                    'content_type': resp.headers.get('content-type', ''),
                }

                # Try to extract model info from /v1/models or /models
                if '/models' in path and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and 'data' in data:
                            for model in data['data'][:10]:
                                model_id = model.get('id', '') if isinstance(model, dict) else str(model)
                                if model_id:
                                    result['models'].append(model_id)
                        elif isinstance(data, list):
                            for item in data[:10]:
                                name = item.get('name', '') if isinstance(item, dict) else str(item)
                                if name:
                                    result['models'].append(name)
                    except Exception:
                        pass

                result['endpoints'].append(endpoint_info)

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            continue
        except Exception:
            continue


def _analyze_response_fingerprints(target_url: str, session: requests.Session, result: dict):
    """Analyze response headers and body for AI framework fingerprints."""
    try:
        resp = session.get(target_url, timeout=10)
    except Exception:
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text or ''

    for framework_key, fingerprint in AI_HEADER_FINGERPRINTS.items():
        score = 0
        evidence = []

        # Check headers
        for header_name, pattern in fingerprint.get('headers', {}).items():
            header_val = headers.get(header_name.lower(), '')
            if header_val and re.search(pattern, header_val, re.IGNORECASE):
                score += 2
                evidence.append(f'Header: {header_name}={header_val[:60]}')

        # Check body patterns
        for pattern in fingerprint.get('body_patterns', []):
            if re.search(pattern, body, re.IGNORECASE):
                score += 1
                evidence.append(f'Body match: {pattern}')

        if score >= 2:
            result['frameworks'].append({
                'name': fingerprint['name'],
                'key': framework_key,
                'score': score,
                'evidence': evidence,
            })


def _detect_chat_features(target_url: str, session: requests.Session, result: dict):
    """Detect chat widgets, chatbots, and AI-powered UI features."""
    try:
        resp = session.get(target_url, timeout=10)
    except Exception:
        return

    body = resp.text or ''

    for pattern in CHAT_WIDGET_PATTERNS:
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            result['chat_features'].append({
                'pattern': pattern,
                'matches': [m[:100] if isinstance(m, str) else str(m)[:100] for m in matches[:3]],
            })


def _detect_safety_layers(target_url: str, session: requests.Session, result: dict):
    """Detect AI content safety and moderation layers."""
    try:
        resp = session.get(target_url, timeout=10)
    except Exception:
        return

    body = resp.text or ''
    headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())
    combined = body + ' ' + headers_str

    for layer_key, signature in AI_SAFETY_SIGNATURES.items():
        for pattern in signature['patterns']:
            if re.search(pattern, combined, re.IGNORECASE):
                result['safety_layers'].append({
                    'name': signature['name'],
                    'key': layer_key,
                    'evidence': f'Pattern match: {pattern}',
                })
                break  # One match per layer is enough
