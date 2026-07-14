"""
Anomaly Detector — Detect anomalous HTTP responses that may indicate
vulnerabilities by establishing baseline behavior and flagging deviations.

Algorithm:
  1. Establish baseline response behavior (status, length, time)
  2. Flag responses that deviate significantly:
     - Status code change (200 → 500)
     - Response length > 3 std deviations from baseline
     - Response time > 5x baseline
     - Unique string not present in baseline (error, stack trace)

Model: scikit-learn IsolationForest (contamination=0.05).
Falls back to statistical thresholds if sklearn unavailable.
"""
import logging
import re
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Error patterns that suggest vulnerability when they appear anomalously
_ERROR_PATTERNS = re.compile(
    r'(stack\s*trace|traceback|exception|fatal\s*error|'
    r'syntax\s*error|undefined\s*variable|null\s*pointer|'
    r'segmentation\s*fault|internal\s*server\s*error|'
    r'ORA-\d{5}|mysql.*error|pg_query|sqlite3?\.|'
    r'SQLSTATE|Warning:.*mysql|'
    r'root:.*:0:0:|uid=\d+|/etc/passwd)',
    re.I,
)


class AnomalyDetector:
    """Detect anomalous HTTP responses indicative of vulnerabilities."""

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = None
        self._baseline_data: list[dict] = []
        self._baseline_stats: Optional[dict] = None

    # ── Public API ────────────────────────────────────────────────────────

    def fit_baseline(self, responses: list[dict]) -> None:
        """Establish baseline from normal responses.

        Each response dict should have: status_code, length, elapsed, text
        """
        self._baseline_data = responses
        if not responses:
            return

        statuses = [r.get('status_code', 200) for r in responses]
        lengths = [r.get('length', len(r.get('text', ''))) for r in responses]
        times = [r.get('elapsed', 0.0) for r in responses]

        self._baseline_stats = {
            'status_mode': max(set(statuses), key=statuses.count) if statuses else 200,
            'length_mean': float(np.mean(lengths)) if lengths else 0,
            'length_std': float(np.std(lengths)) if lengths else 0,
            'time_mean': float(np.mean(times)) if times else 0,
            'time_std': float(np.std(times)) if times else 0,
            'baseline_errors': set(),
        }

        # Collect error strings that are normal for the baseline
        for r in responses:
            text = r.get('text', '')
            matches = _ERROR_PATTERNS.findall(text)
            self._baseline_stats['baseline_errors'].update(m.lower() for m in matches)

        # Build IsolationForest if sklearn available
        if len(responses) >= 10:
            self._fit_sklearn(responses)

    def score(self, response: dict) -> float:
        """Returns anomaly score 0.0–1.0. Higher = more anomalous."""
        if not self._baseline_stats:
            return 0.5  # No baseline

        scores = []

        # Status anomaly
        status = response.get('status_code', 200)
        baseline_status = self._baseline_stats['status_mode']
        if status != baseline_status:
            if status >= 500:
                scores.append(0.9)
            elif status >= 400:
                scores.append(0.6)
            else:
                scores.append(0.3)
        else:
            scores.append(0.0)

        # Length anomaly (z-score)
        length = response.get('length', len(response.get('text', '')))
        mean_l = self._baseline_stats['length_mean']
        std_l = self._baseline_stats['length_std']
        if std_l > 0:
            z = abs(length - mean_l) / std_l
            scores.append(min(z / 5.0, 1.0))  # Normalize: 5 std devs = 1.0
        else:
            scores.append(0.0 if abs(length - mean_l) < 100 else 0.5)

        # Time anomaly
        elapsed = response.get('elapsed', 0.0)
        mean_t = self._baseline_stats['time_mean']
        if mean_t > 0 and elapsed > mean_t * 5:
            scores.append(min(elapsed / (mean_t * 10), 1.0))
        else:
            scores.append(0.0)

        # Error string anomaly
        text = response.get('text', '')
        new_errors = set()
        matches = _ERROR_PATTERNS.findall(text)
        for m in matches:
            if m.lower() not in self._baseline_stats['baseline_errors']:
                new_errors.add(m)
        if new_errors:
            scores.append(0.8)
        else:
            scores.append(0.0)

        # IsolationForest score if available
        if self.model is not None:
            try:
                X = self._response_to_features(response)
                iso_score = -self.model.score_samples(X)[0]
                # IsolationForest: higher score = more anomalous
                scores.append(min(max(iso_score, 0), 1.0))
            except Exception:
                pass

        return round(float(np.mean(scores)), 3) if scores else 0.5

    def is_anomalous(self, response: dict, threshold: float = 0.7) -> bool:
        """Return True if response anomaly score exceeds threshold."""
        return self.score(response) >= threshold

    def get_anomaly_details(self, response: dict) -> dict:
        """Return detailed anomaly breakdown."""
        if not self._baseline_stats:
            return {'anomalous': False, 'reason': 'No baseline established'}

        details = {
            'anomalous': self.is_anomalous(response),
            'score': self.score(response),
            'reasons': [],
        }

        status = response.get('status_code', 200)
        if status != self._baseline_stats['status_mode']:
            details['reasons'].append(
                f'Status changed: {self._baseline_stats["status_mode"]} → {status}'
            )

        length = response.get('length', len(response.get('text', '')))
        mean_l = self._baseline_stats['length_mean']
        std_l = self._baseline_stats['length_std']
        if std_l > 0 and abs(length - mean_l) > 3 * std_l:
            details['reasons'].append(
                f'Length deviation: {length} (baseline: {mean_l:.0f} ± {std_l:.0f})'
            )

        elapsed = response.get('elapsed', 0.0)
        mean_t = self._baseline_stats['time_mean']
        if mean_t > 0 and elapsed > mean_t * 5:
            details['reasons'].append(
                f'Slow response: {elapsed:.2f}s (baseline: {mean_t:.2f}s)'
            )

        text = response.get('text', '')
        matches = _ERROR_PATTERNS.findall(text)
        new_errors = [m for m in matches if m.lower() not in self._baseline_stats.get('baseline_errors', set())]
        if new_errors:
            details['reasons'].append(f'New error patterns: {", ".join(new_errors[:3])}')

        return details

    # ── sklearn Integration ───────────────────────────────────────────────

    def _fit_sklearn(self, responses: list[dict]):
        """Fit IsolationForest on baseline responses."""
        try:
            from sklearn.ensemble import IsolationForest
            X = np.array([self._response_to_features(r)[0] for r in responses])
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self.model.fit(X)
            logger.debug(f'IsolationForest fitted on {len(responses)} baseline responses')
        except ImportError:
            logger.debug('scikit-learn not available — statistical anomaly detection only')
        except Exception as exc:
            logger.debug(f'IsolationForest fit error: {exc}')

    def _response_to_features(self, response: dict) -> np.ndarray:
        """Convert response to feature array for IsolationForest."""
        return np.array([[
            response.get('status_code', 200),
            response.get('length', len(response.get('text', ''))),
            response.get('elapsed', 0.0),
            len(_ERROR_PATTERNS.findall(response.get('text', ''))),
        ]])
