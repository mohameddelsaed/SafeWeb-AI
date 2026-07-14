"""
Smart False Positive Reducer — Multi-model ensemble combining the
VulnerabilityClassifier, AnomalyDetector, and contextual heuristics to
assign a calibrated confidence score to each potential vulnerability.

Scoring pipeline (weighted average):
    1. Classifier score  (40%) — RandomForest prediction confidence
    2. Anomaly score     (25%) — IsolationForest anomaly magnitude
    3. Heuristic score   (20%) — rule-based context signals
    4. Historical score  (15%) — category × tech-stack base rates

A finding is considered a real vulnerability when the ensemble
confidence exceeds `confidence_threshold` (default 0.55).
"""
from __future__ import annotations

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Default base-rate scores per vulnerability category (synthetic priors) ────

_BASE_RATES: dict[str, float] = {
    'sqli':             0.85,
    'xss':              0.72,
    'cmdi':             0.88,
    'ssti':             0.80,
    'xxe':              0.75,
    'ssrf':             0.68,
    'idor':             0.70,
    'lfi':              0.78,
    'rfi':              0.65,
    'csrf':             0.60,
    'deserialization':  0.80,
    'file upload':      0.74,
    'open redirect':    0.55,
    'cors':             0.50,
    'clickjacking':     0.45,
    'auth':             0.65,
    'jwt':              0.72,
    'misconfig':        0.62,
    'data exposure':    0.80,
    'path traversal':   0.78,
    'nosql':            0.68,
    'prototype pollution': 0.60,
    'mass assignment':  0.65,
    'race condition':   0.55,
    'crlf':             0.58,
    'host header':      0.62,
    'http smuggling':   0.70,
    'cache poisoning':  0.60,
    'subdomain takeover': 0.80,
    'supply chain':     0.72,
    'information-disclosure': 0.75,
}

# Evidence quality thresholds
_MIN_EVIDENCE_LEN_FOR_HIGH_CONF = 30   # below this, reduce confidence
_LONG_EVIDENCE_BONUS_LEN = 200         # above this, boost confidence

# Weights in the ensemble (5 components)
_WEIGHTS = {
    'classifier': 0.35,
    'anomaly':    0.20,
    'heuristic':  0.15,
    'historical': 0.10,
    'llm':        0.20,
}


class FalsePositiveReducer:
    """Multi-model ensemble for false positive reduction."""

    def __init__(self, confidence_threshold: float = 0.55):
        self.confidence_threshold = confidence_threshold

        # Lazy-initialise heavy models
        self._classifier = None
        self._anomaly_detector = None
        self._llm_engine = None  # LLM reasoning engine (optional)

        # Historical outcome tracking: category → {tech_stack → [bool, ...]}
        self._history: dict[str, dict[str, list[bool]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._total_analyzed = 0
        self._total_real = 0

    # ── Public API ────────────────────────────────────────────────────────

    def analyze(
        self,
        vuln: dict,
        response_data: dict | None = None,
        context: dict | None = None,
    ) -> dict:
        """Compute ensemble confidence for a potential vulnerability.

        Args:
            vuln:          vulnerability dict (name, severity, category, evidence, …)
            response_data: HTTP response characteristics dict
            context:       additional context (tech_stack, authenticated, etc.)

        Returns:
            {
                'is_real': bool,
                'confidence': float,
                'reasoning': list[str],
                'component_scores': {
                    'classifier': float,
                    'anomaly': float,
                    'heuristic': float,
                    'historical': float,
                }
            }
        """
        response_data = response_data or {}
        context = context or {}
        reasoning: list[str] = []

        # ── Component scores ──────────────────────────────────────────────
        clf_score = self._classifier_score(vuln, response_data, reasoning)
        anom_score = self._anomaly_score(response_data, reasoning)
        heur_score = self._heuristic_score(vuln, response_data, context, reasoning)
        hist_score = self._historical_score(
            vuln.get('category', ''),
            context.get('tech_stack', ''),
            reasoning,
        )
        llm_score = self._llm_score(vuln, context, reasoning)

        # ── Weighted ensemble ─────────────────────────────────────────────
        ensemble = (
            clf_score  * _WEIGHTS['classifier'] +
            anom_score * _WEIGHTS['anomaly'] +
            heur_score * _WEIGHTS['heuristic'] +
            hist_score * _WEIGHTS['historical'] +
            llm_score  * _WEIGHTS['llm']
        )
        confidence = round(min(max(ensemble, 0.0), 1.0), 3)
        is_real = confidence >= self.confidence_threshold

        self._total_analyzed += 1
        if is_real:
            self._total_real += 1

        return {
            'is_real': is_real,
            'confidence': confidence,
            'reasoning': reasoning,
            'component_scores': {
                'classifier': round(clf_score, 3),
                'anomaly':    round(anom_score, 3),
                'heuristic':  round(heur_score, 3),
                'historical': round(hist_score, 3),
                'llm':        round(llm_score, 3),
            },
        }

    def update_history(
        self,
        vuln: dict,
        is_real: bool,
        context: dict | None = None,
    ) -> None:
        """Record a confirmed outcome for future historical scoring."""
        category = (vuln.get('category', '') or '').lower().strip()
        tech = (context or {}).get('tech_stack', 'unknown') or 'unknown'
        if category:
            self._history[category][tech].append(is_real)

    def get_statistics(self) -> dict:
        """Return aggregate statistics."""
        confirmed_real = sum(
            sum(outcomes) for cat in self._history.values()
            for outcomes in cat.values()
        )
        confirmed_fp = sum(
            len(outcomes) - sum(outcomes)
            for cat in self._history.values()
            for outcomes in cat.values()
        )
        return {
            'total_analyzed': self._total_analyzed,
            'confirmed_real': confirmed_real,
            'confirmed_fp': confirmed_fp,
            'categories_tracked': len(self._history),
        }

    # ── Component scorers ─────────────────────────────────────────────────

    def _llm_score(
        self, vuln: dict, context: dict, reasoning: list[str],
    ) -> float:
        """Use LLM Reasoning Engine (Ollama) to assess the finding."""
        try:
            if self._llm_engine is None:
                from apps.scanning.engine.ai.reasoning import LLMReasoningEngine
                self._llm_engine = LLMReasoningEngine()
                if not self._llm_engine.available:
                    self._llm_engine = False  # Sentinel: don't retry
            if self._llm_engine is False:
                return 0.50  # Neutral if LLM unavailable

            assessment = self._llm_engine.assess_finding(vuln)
            fp_flag = assessment.get('is_false_positive', False)
            exploit_score = assessment.get('exploitability_score', 50) / 100.0
            llm_conf = (1.0 - exploit_score) if fp_flag else exploit_score
            reasoning.append(
                f'LLM: {"FP" if fp_flag else "real"} '
                f'(exploitability={exploit_score:.0%})'
            )
            return round(llm_conf, 3)
        except Exception as exc:
            logger.debug('LLM score failed: %s', exc)
            return 0.50

    def _classifier_score(
        self, vuln: dict, response_data: dict, reasoning: list[str],
    ) -> float:
        """Use VulnerabilityClassifier if sklearn is available."""
        try:
            if self._classifier is None:
                from apps.scanning.engine.ml.vulnerability_classifier import VulnerabilityClassifier
                self._classifier = VulnerabilityClassifier()

            features = self._classifier.extract_features(vuln, response_data)
            is_real, confidence = self._classifier.predict(features)
            reasoning.append(
                f'Classifier: {"real" if is_real else "false-positive"} '
                f'({confidence:.0%} confidence)'
            )
            return confidence if is_real else (1.0 - confidence)
        except Exception as exc:
            logger.debug('Classifier score failed: %s', exc)
            # Fallback: severity-based estimate
            sev_map = {'critical': 0.90, 'high': 0.80, 'medium': 0.65, 'low': 0.45, 'info': 0.30}
            return sev_map.get(vuln.get('severity', 'info'), 0.50)

    def _anomaly_score(
        self, response_data: dict, reasoning: list[str],
    ) -> float:
        """Use AnomalyDetector baseline score, or derive from response data."""
        if not response_data:
            return 0.50

        try:
            if self._anomaly_detector is None:
                from apps.scanning.engine.ml.anomaly_detector import AnomalyDetector
                self._anomaly_detector = AnomalyDetector()

            if self._anomaly_detector._baseline_stats is None:
                # No baseline — use raw signal heuristics
                pass
            else:
                score = self._anomaly_detector.score(response_data)
                reasoning.append(f'Anomaly detector: score={score:.2f}')
                return score
        except Exception as exc:
            logger.debug('Anomaly score failed: %s', exc)

        # Fallback: derive score from status+length
        status = response_data.get('status_code', 200)
        if status >= 500:
            reasoning.append('Anomaly: server error response')
            return 0.85
        if status == 200:
            delta = abs(response_data.get('length_delta', 0))
            if delta > 1000:
                reasoning.append(f'Anomaly: large response delta ({delta} bytes)')
                return 0.70
        return 0.40

    def _heuristic_score(
        self,
        vuln: dict,
        response_data: dict,
        context: dict,
        reasoning: list[str],
    ) -> float:
        """Rule-based contextual heuristics."""
        score = 0.50  # neutral baseline
        evidence = vuln.get('evidence', '') or ''

        # Short evidence → lower confidence
        if len(evidence) < _MIN_EVIDENCE_LEN_FOR_HIGH_CONF:
            score -= 0.15
            reasoning.append('Heuristic: short evidence string reduces confidence')
        elif len(evidence) > _LONG_EVIDENCE_BONUS_LEN:
            score += 0.10
            reasoning.append('Heuristic: detailed evidence boosts confidence')

        # Critical/high severity on admin endpoints
        sev = vuln.get('severity', 'info')
        url = vuln.get('affected_url', '') or context.get('url', '') or ''
        if sev in ('critical', 'high') and any(
            kw in url.lower() for kw in ('/admin', '/api/', '/dashboard', '/manage')
        ):
            score += 0.15
            reasoning.append('Heuristic: high-severity finding on sensitive endpoint')

        # Payload reflected in response
        if response_data.get('payload_reflected'):
            score += 0.20
            reasoning.append('Heuristic: payload reflected in response (+0.20)')

        # Time-based (blind) signal
        if response_data.get('time_diff', 0) > 4.5:
            score += 0.25
            reasoning.append('Heuristic: significant time delay (+0.25, possible blind injection)')

        # WAF blocking reduces confidence (we may have evaded it accidentally)
        if response_data.get('waf_detected'):
            score -= 0.05
            reasoning.append('Heuristic: WAF detected (-0.05)')

        # Multiple independent approaches → boost
        if context.get('confirmed_by_multiple_methods'):
            score += 0.25
            reasoning.append('Heuristic: confirmed by multiple methods (+0.25)')

        return round(min(max(score, 0.0), 1.0), 3)

    def _historical_score(
        self, category: str, tech_stack: str, reasoning: list[str],
    ) -> float:
        """Score based on historical true-positive rate for this category/tech."""
        cat = (category or '').lower().strip()
        tech = (tech_stack or 'unknown').lower().strip()

        # Check recorded history first
        if cat in self._history:
            tech_key = tech if tech in self._history[cat] else 'unknown'
            outcomes = self._history[cat].get(tech_key, [])
            if len(outcomes) >= 5:
                rate = sum(outcomes) / len(outcomes)
                reasoning.append(
                    f'Historical: {cat} on {tech_key} TP rate = {rate:.0%} '
                    f'(n={len(outcomes)})'
                )
                return rate

        # Fall back to synthetic priors
        prior = _BASE_RATES.get(cat, 0.60)
        reasoning.append(f'Historical: prior for "{cat}" = {prior:.0%}')
        return prior
