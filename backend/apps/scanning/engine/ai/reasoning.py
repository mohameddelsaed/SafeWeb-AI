"""
LLM Reasoning Engine — Mimics a human penetration tester's critical
thinking by using local LLM (Ollama) for:

  1. Attack strategy planning based on recon data
  2. Payload generation for novel contexts
  3. Vulnerability assessment and verification
  4. Business logic flaw hypothesis generation
  5. WAF bypass reasoning
  6. Multi-step attack chain planning
  7. Finding deduplication and triage
"""
from __future__ import annotations

import json
import logging

from .provider import LLMProvider
import os

logger = logging.getLogger(__name__)

# Load prompts registry
_PROMPTS_FILE = os.path.join(os.path.dirname(__file__), 'prompts.json')
with open(_PROMPTS_FILE, 'r') as f:
    _PROMPTS = json.load(f)


class LLMReasoningEngine:
    """Human-like pentester reasoning powered by LLMProvider."""

    def __init__(self, provider: LLMProvider | None = None):
        self.provider = provider or LLMProvider()

    @property
    def available(self) -> bool:
        return self.provider.ollama.is_available() or bool(self.provider.openrouter_key)

    # ── 1. Attack Strategy ────────────────────────────────────────────────

    def plan_attack_strategy(self, recon_data: dict) -> dict | None:
        """Given recon data, produce an attack strategy like a real pentester.

        Args:
            recon_data: {
                'target': str,
                'tech_stack': list[str],
                'waf': str | None,
                'open_ports': list[int],
                'subdomains': list[str],
                'endpoints': list[dict],  # {url, method, params}
                'auth_type': str,
                'cms': str | None,
            }
        Returns:
            {
                'priority_targets': [...],
                'attack_phases': [...],
                'vuln_hypotheses': [...],
                'custom_payloads': [...],
                'estimated_risk_areas': [...],
            }
        """
        prompt = f"""Analyze this reconnaissance data and produce a penetration testing attack strategy.

RECON DATA:
{json.dumps(recon_data, indent=2, default=str)[:4000]}

Produce a JSON object with:
1. "priority_targets": top 10 most promising attack targets ranked by likelihood of vulnerability
2. "attack_phases": ordered list of attack phases with specific techniques for this target
3. "vuln_hypotheses": list of hypotheses about likely vulnerabilities based on the tech stack
4. "custom_payloads": list of {{vuln_type, payload, reasoning}} for this specific target
5. "estimated_risk_areas": areas of highest risk based on the attack surface"""

        return self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_PENTESTER"])

    # ── 2. Payload Generation ─────────────────────────────────────────────

    def generate_payloads(self, vuln_type: str, context: dict) -> list[str]:
        """Generate context-aware payloads using LLM reasoning.

        Args:
            vuln_type: e.g. 'sqli', 'xss', 'ssti', 'cmdi'
            context: {
                'tech': str,       # php, java, python, nodejs
                'waf': str,        # cloudflare, modsecurity, etc.
                'injection_point': str,  # url_param, header, cookie, body, json
                'encoding': str,   # none, url, base64, html
                'current_filter': str,  # what's being blocked
            }
        Returns:
            List of generated payload strings.
        """
        prompt = f"""Generate 20 {vuln_type.upper()} payloads for this specific context:

CONTEXT:
- Technology: {context.get('tech', 'unknown')}
- WAF: {context.get('waf', 'none')}
- Injection Point: {context.get('injection_point', 'url_param')}
- Current Encoding: {context.get('encoding', 'none')}
- Known Filter: {context.get('current_filter', 'none')}

Requirements:
- Payloads must be different from generic lists
- Use combination of encoding and obfuscation
- Include both detection and exploitation payloads
- Consider the specific technology's parser quirks

Return a JSON array of payload strings only."""

        result = self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_PAYLOAD_GEN"])
        if isinstance(result, list):
            return [str(p) for p in result if p]
        return []

    # ── 3. Vulnerability Assessment ───────────────────────────────────────

    def assess_finding(self, finding: dict) -> dict | None:
        """Use LLM to assess a potential vulnerability finding.

        Returns enriched finding with:
          - exploitability_score (0.0-1.0)
          - is_false_positive (bool)
          - fp_reasoning (str)
          - suggested_severity (str)
          - exploitation_steps (list)
          - business_impact (str)
        """
        prompt = f"""Assess this potential vulnerability finding:

FINDING:
{json.dumps(finding, indent=2, default=str)[:3000]}

Analyze:
1. Is this a real vulnerability or false positive? Explain your reasoning.
2. What's the exploitability score (0.0-1.0)?
3. What severity should it be (critical/high/medium/low/info)?
4. What are the specific exploitation steps?
5. What's the business impact if exploited?

Return JSON with: is_false_positive, fp_reasoning, exploitability_score,
suggested_severity, exploitation_steps, business_impact"""

        return self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_PENTESTER"])

    # ── 4. Business Logic Analysis ────────────────────────────────────────

    def analyze_business_logic(self, api_flows: list[dict]) -> dict | None:
        """Identify business logic vulnerabilities in API flows.

        Args:
            api_flows: List of {method, url, params, response_code, body_schema}
        """
        prompt = f"""Analyze these API flows for business logic vulnerabilities:

API FLOWS:
{json.dumps(api_flows[:20], indent=2, default=str)[:4000]}

Identify:
1. IDOR opportunities (parameter manipulation for unauthorized access)
2. Race conditions (concurrent request abuse)
3. State machine violations (skipping steps, replaying states)
4. Price/quantity manipulation
5. Privilege escalation paths
6. Missing authorization checks
7. Business rule bypass opportunities

For each finding, provide:
- vulnerability_type
- affected_endpoint
- attack_description
- test_steps (specific HTTP requests to verify)
- severity
- confidence (0.0-1.0)

Return JSON with "findings" array."""

        return self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_LOGIC_ANALYST"])

    # ── 5. WAF Bypass ─────────────────────────────────────────────────────

    def generate_waf_bypass(self, waf: str, blocked_payload: str,
                            vuln_type: str) -> list[str]:
        """Generate WAF bypass variants for a blocked payload."""
        prompt = f"""The following {vuln_type} payload was blocked by {waf}:

BLOCKED: {blocked_payload}

Generate 15 bypass variants using different techniques:
- Double/triple URL encoding
- Unicode/UTF-8 encoding
- HTML entity encoding
- SQL comment insertion (for SQLi)
- JavaScript alternatives (for XSS)
- Whitespace alternatives (tabs, newlines, null bytes)
- Case manipulation
- String concatenation/splitting
- Protocol-level tricks

Return a JSON array of bypass payload strings."""

        result = self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_WAF_BYPASS"])
        if isinstance(result, list):
            return [str(p) for p in result if p]
        return []

    # ── 6. Chain Planning ─────────────────────────────────────────────────

    def plan_attack_chain(self, findings: list[dict]) -> dict | None:
        """Given individual findings, identify multi-step attack chains.

        Returns chains where combining vulnerabilities increases impact.
        """
        prompt = f"""Analyze these individual vulnerability findings and identify
attack chains where combining vulnerabilities creates a higher-impact attack:

FINDINGS:
{json.dumps(findings[:30], indent=2, default=str)[:4000]}

For each chain, provide:
- chain_name: descriptive name
- steps: ordered list of {{finding_index, action, expected_result}}
- combined_severity: overall severity of the chain
- combined_impact: what the full chain achieves
- prerequisites: what conditions must be met
- probability_of_success: 0.0-1.0

Return JSON with "chains" array, ordered by severity."""

        return self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_PENTESTER"])

    # ── 7. Triage & Dedup ─────────────────────────────────────────────────

    def triage_findings(self, findings: list[dict]) -> dict | None:
        """Intelligent triage: dedup, merge, re-score findings."""
        prompt = f"""Triage these {len(findings)} vulnerability findings:

FINDINGS:
{json.dumps(findings[:50], indent=2, default=str)[:4000]}

Tasks:
1. Identify and group duplicate/near-duplicate findings
2. For each unique finding, assign:
   - final_severity (critical/high/medium/low/info)
   - confidence (0.0-1.0)
   - is_false_positive (bool)
   - group_id (string, same for related findings)
3. Identify any findings that can be chained together

Return JSON with:
- "triaged": array of {{original_index, group_id, final_severity, confidence, is_false_positive, reasoning}}
- "chains": array of {{name, finding_indices, combined_impact}}
- "summary": {{total, unique, false_positives, critical, high, medium, low, info}}"""

        return self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_TRIAGE"],
                                         temperature=0.1)

    def explain_vulnerability(self, finding: dict) -> dict | None:
        """Generate human-readable explanation and remediation for a finding.
        
        Returns JSON with:
          - ai_explanation (str)
          - ai_remediation (str)
        """
        prompt = f"""Explain this vulnerability finding and provide remediation steps:

FINDING:
{json.dumps(finding, indent=2, default=str)[:3000]}

Explain it as if you are a senior penetration tester explaining it to a developer.
Provide a clear, detailed explanation of how it works and what the impact is.
Then, provide specific, actionable remediation steps.

Return JSON with:
- "ai_explanation": string containing the explanation
- "ai_remediation": string containing the remediation steps
"""
        return self.provider.generate_json(prompt, system=_PROMPTS["SYSTEM_PENTESTER"])

    # ── Utility ───────────────────────────────────────────────────────────

    def ask(self, question: str, context: str = '') -> str:
        """General-purpose pentester question. Returns free-text answer."""
        prompt = question
        if context:
            prompt = f"Context:\n{context[:3000]}\n\nQuestion: {question}"
        return self.provider.generate(prompt, system=_PROMPTS["SYSTEM_PENTESTER"],
                                    temperature=0.4)

    async def aplan_attack_strategy(self, recon_data: dict) -> dict | list | None:
        """Async version of plan_attack_strategy."""
        prompt = f"""Analyze this reconnaissance data and produce a penetration testing attack strategy.

RECON DATA:
{json.dumps(recon_data, indent=2, default=str)[:4000]}

Produce a JSON object with priority_targets, attack_phases, vuln_hypotheses,
custom_payloads, estimated_risk_areas."""

        return await self.provider.agenerate_json(prompt, system=_PROMPTS["SYSTEM_PENTESTER"])
