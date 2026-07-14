"""
ML Enhancement Tester — BaseTester wrapper for Phase 38.

Integrates the four Phase 38 AI/ML engine modules:
  - NLP-Based Response Analysis     (engine/ml/nlp_detector.py)
  - Reinforcement Learning Fuzzing  (engine/ml/rl_fuzzer.py)
  - Smart False Positive Reduction  (engine/ml/false_positive_reducer.py)
  - Attack Path Optimization        (engine/ml/attack_path_optimizer.py)

Depth behaviour:
  quick  — Response interest scoring + FP confidence analysis
  medium — + RL fuzzer recommendations + stack trace detection
  deep   — + full NLP error classification + attack path chains
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class MLEnhancementTester(BaseTester):
    TESTER_NAME = 'ML Enhancement Engine'

    def test(
        self, page: dict, depth: str = 'quick',
        recon_data: dict | None = None,
    ) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        vulns: list[dict] = []

        # ── Always: response interest scoring ────────────────────────────
        vulns.extend(self._analyze_response_interest(url, page))

        # ── Always: attack path optimization ─────────────────────────────
        vulns.extend(self._analyze_attack_paths(url, page, recon_data or {}))

        if depth in ('medium', 'deep'):
            # ── Stack trace detection ─────────────────────────────────────
            vulns.extend(self._analyze_stack_traces(url, page))

            # ── RL fuzzer recommendations ─────────────────────────────────
            vulns.extend(self._get_fuzzer_recommendations(url, page))

        if depth == 'deep':
            # ── Full NLP error classification ─────────────────────────────
            vulns.extend(self._analyze_nlp_errors(url, page))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Response Interest Analysis
    # ─────────────────────────────────────────────────────────────────────
    def _analyze_response_interest(self, url: str, page: dict) -> list[dict]:
        """Flag highly interesting responses as potential investigation targets."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.ml.nlp_detector import score_response_interest
            response = {
                'status_code': page.get('status_code', 200),
                'text': page.get('content', '') or page.get('text', '') or '',
                'length': page.get('content_length', 0),
                'elapsed': page.get('response_time', 0.0),
            }
            score = score_response_interest(response)

            if score >= 0.80:
                vulns.append(self._build_vuln(
                    'Highly Interesting Response Detected',
                    'high', 'information-disclosure',
                    f'ML analysis scored this response {score:.2f}/1.00 — '
                    f'strong indicators of vulnerability presence '
                    f'(error messages, sensitive data, or anomalous behaviour).',
                    'Highly interesting responses often indicate exploitable conditions '
                    'such as verbose error messages, stack traces, or debug output.',
                    'Review the response for sensitive information leakage. '
                    'Disable debug mode and suppress verbose error messages in production.',
                    'CWE-200', 6.5, url,
                    f'Interest score: {score:.2f}',
                ))
            elif score >= 0.60:
                vulns.append(self._build_vuln(
                    'Suspicious Response Pattern',
                    'medium', 'information-disclosure',
                    f'ML analysis scored this response {score:.2f}/1.00 — '
                    f'moderate indicators of potential vulnerability.',
                    'Suspicious responses may contain partial information disclosure '
                    'or indirect vulnerability indicators.',
                    'Investigate response content for unintended information exposure.',
                    'CWE-200', 4.3, url,
                    f'Interest score: {score:.2f}',
                ))
        except Exception as exc:
            logger.debug('Response interest analysis failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Attack Path Analysis
    # ─────────────────────────────────────────────────────────────────────
    def _analyze_attack_paths(
        self, url: str, page: dict, recon_data: dict,
    ) -> list[dict]:
        """Suggest attack chains from accumulated findings in recon_data."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.ml.attack_path_optimizer import (
                suggest_exploit_chain, prioritize_by_risk,
            )

            existing_vulns = recon_data.get('vulnerabilities', [])
            if not existing_vulns:
                return []

            tech_stack = recon_data.get('tech_stack', 'unknown') or 'unknown'

            # Prioritize by risk
            prioritized = prioritize_by_risk(existing_vulns, tech_stack)
            high_risk = [v for v in prioritized if v.get('risk_score', 0) >= 7.0]

            if high_risk:
                names = ', '.join(v.get('name', v.get('category', '?')) for v in high_risk[:3])
                vulns.append(self._build_vuln(
                    'High-Risk Vulnerability Cluster',
                    'high', 'information-disclosure',
                    f'ML risk prioritization identified {len(high_risk)} high-risk '
                    f'finding(s) with risk scores ≥ 7.0: {names}.',
                    'High-risk findings should be addressed immediately as they '
                    'represent the most likely exploitation vectors.',
                    'Address findings in priority order beginning with the '
                    'highest risk-scored items.',
                    'CWE-693', 7.5, url,
                    f'Top risk scores: {[round(v["risk_score"],1) for v in high_risk[:3]]}',
                ))

            # Attack chain suggestion
            suggestion = suggest_exploit_chain(existing_vulns)
            if suggestion.get('found'):
                vulns.append(self._build_vuln(
                    'Multi-Stage Attack Chain Identified',
                    'critical', 'information-disclosure',
                    f'Attack path optimizer identified a {len(suggestion["chain"])}-step '
                    f'exploit chain leading to: {suggestion["impact"]}. '
                    f'{suggestion["narrative"]}',
                    'Multi-stage attack chains can lead to complete system compromise '
                    'even when individual vulnerabilities appear low-severity.',
                    'Remediate the initial vulnerability in the chain to break the '
                    'attack path. Review all linked findings together.',
                    'CWE-693', 9.0, url,
                    f'Chain: {" → ".join(suggestion["categories"])}',
                ))
        except Exception as exc:
            logger.debug('Attack path analysis failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Stack Trace Detection
    # ─────────────────────────────────────────────────────────────────────
    def _analyze_stack_traces(self, url: str, page: dict) -> list[dict]:
        """Detect and report stack traces in HTTP responses."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
            text = page.get('content', '') or page.get('text', '') or ''
            if not text:
                return []

            result = detect_stack_trace(text)
            if result['detected']:
                paths = result.get('sensitive_paths', [])
                frames = result.get('frames', [])
                lang = result.get('language', 'unknown')

                evidence_parts = [f'Language: {lang}']
                if paths:
                    evidence_parts.append(f'Internal paths: {paths[:3]}')
                if frames:
                    evidence_parts.append(f'Frames found: {len(frames)}')

                vulns.append(self._build_vuln(
                    f'Stack Trace Exposed in Response ({lang.title()})',
                    'high', 'information-disclosure',
                    f'A {lang} stack trace was detected in the HTTP response for {url}. '
                    f'Stack traces expose internal file paths, function names, '
                    f'and application structure to attackers.',
                    'Exposed stack traces reveal internal application architecture '
                    'and can guide targeted exploitation.',
                    'Configure the application to suppress stack traces in production. '
                    'Implement a generic error handler that returns sanitised error '
                    'messages without internal detail.',
                    'CWE-209', 5.3, url,
                    '; '.join(evidence_parts),
                ))
        except Exception as exc:
            logger.debug('Stack trace analysis failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # RL Fuzzer Recommendations
    # ─────────────────────────────────────────────────────────────────────
    def _get_fuzzer_recommendations(self, url: str, page: dict) -> list[dict]:
        """Surface RL fuzzer insights — debug-level info finding."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.ml.rl_fuzzer import (
                RLFuzzer, RLFuzzerState, classify_response_type,
            )

            response = {
                'status_code': page.get('status_code', 200),
                'text': page.get('content', '') or '',
                'elapsed': page.get('response_time', 0.0),
            }
            response_type = classify_response_type(response)

            if response_type in ('error', 'reflected', 'timeout'):
                fuzzer = RLFuzzer(epsilon=0.0)  # exploitation-only mode
                RLFuzzerState(
                    tech_stack=page.get('tech_stack', 'unknown') or 'unknown',
                    waf_detected=bool(page.get('waf_detected', False)),
                    last_response_type=response_type,
                )
                reward = fuzzer.compute_reward(response)

                if reward > 0.5:
                    vulns.append(self._build_vuln(
                        'RL Fuzzer: High-Value Response Signal',
                        'info', 'information-disclosure',
                        f'The RL fuzzer detected a high-value response signal '
                        f'(type={response_type}, reward={reward:.2f}). '
                        f'This endpoint warrants deeper fuzzing.',
                        'High-reward responses indicate vulnerability-relevant '
                        'server behaviour that may be exploitable with targeted payloads.',
                        'Apply targeted fuzzing to this endpoint using payloads '
                        'optimised for the detected technology stack.',
                        'CWE-20', 0.0, url,
                        f'Response type: {response_type}, RL reward: {reward:.2f}',
                    ))
        except Exception as exc:
            logger.debug('RL fuzzer recommendation failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # NLP Error Classification
    # ─────────────────────────────────────────────────────────────────────
    def _analyze_nlp_errors(self, url: str, page: dict) -> list[dict]:
        """Classify error messages found in the response."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.ml.nlp_detector import classify_error_message
            text = page.get('content', '') or page.get('text', '') or ''
            if not text:
                return []

            result = classify_error_message(text)
            category = result['category']
            confidence = result['confidence']
            severity_map = {
                'database':   ('high',   'CWE-209', 6.5),
                'code':       ('high',   'CWE-209', 5.3),
                'filesystem': ('high',   'CWE-209', 5.3),
                'auth':       ('medium', 'CWE-209', 4.3),
                'network':    ('low',    'CWE-209', 3.1),
            }

            if category in severity_map and confidence >= 0.60:
                sev, cwe, cvss = severity_map[category]
                indicators = result.get('indicators', [])
                vulns.append(self._build_vuln(
                    f'NLP: {category.title()} Error Message Detected',
                    sev, 'information-disclosure',
                    f'NLP classifier detected a {category} error message '
                    f'(confidence {confidence:.0%}) in the response for {url}. '
                    f'Indicators: {indicators[:3]}',
                    f'Verbose {category} error messages expose internal application '
                    'state and can assist attackers in crafting targeted payloads.',
                    'Implement a centralised error handler that logs full errors '
                    'server-side while returning only generic messages to clients.',
                    cwe, cvss, url,
                    f'Category: {category}, confidence: {confidence:.0%}, '
                    f'indicators: {indicators[:2]}',
                ))
        except Exception as exc:
            logger.debug('NLP error analysis failed: %s', exc)
        return vulns
