"""
Attack Prioritizer — Predict which crawled pages/parameters are most
likely vulnerable and sort them by priority score.

Model: scikit-learn GradientBoostingClassifier.

Features per page (11):
  has_forms, has_file_upload, has_numeric_id_params, has_redirect_params,
  has_auth_params, is_admin_panel, is_api_endpoint, authentication_required,
  tech_stack_vuln_score, parameter_count, http_methods_count
"""
import logging
import re
from urllib.parse import urlparse, parse_qs

import numpy as np

logger = logging.getLogger(__name__)

_FEATURE_NAMES = [
    'has_forms', 'has_file_upload', 'has_numeric_id_params',
    'has_redirect_params', 'has_auth_params', 'is_admin_panel',
    'is_api_endpoint', 'authentication_required',
    'tech_stack_vuln_score', 'parameter_count', 'http_methods_count',
]

# URL patterns indicating admin panels
_ADMIN_PATTERNS = re.compile(
    r'(/admin|/dashboard|/manage|/panel|/cms|/backend|/control|/wp-admin)',
    re.I,
)

# URL patterns indicating API endpoints
_API_PATTERNS = re.compile(
    r'(/api/|/v\d+/|/graphql|/rest/|/json|/xml|\.json|\.xml)',
    re.I,
)

# Redirect parameter names
_REDIRECT_PARAMS = {'url', 'redirect', 'next', 'return', 'goto', 'continue', 'redir', 'dest', 'destination', 'returnurl', 'return_to'}

# Auth-related parameter names
_AUTH_PARAMS = {'user', 'username', 'password', 'passwd', 'email', 'token', 'auth', 'session', 'login', 'api_key', 'apikey'}


class AttackPrioritizer:
    """Prioritize crawled pages by vulnerability likelihood."""

    def __init__(self):
        self.model = None
        self._init_model()

    def prioritize(self, pages: list, recon_data: dict = None) -> list:
        """Returns pages sorted by descending vulnerability likelihood score.

        Each returned element is a dict: {'url': ..., 'priority_score': float, 'features': dict}
        """
        recon_data = recon_data or {}
        scored = []

        for page in pages:
            features = self._extract_features(page, recon_data)
            score = self._score(features)
            url = getattr(page, 'url', None) or (page.get('url', '') if isinstance(page, dict) else str(page))
            scored.append({
                'url': url,
                'priority_score': score,
                'features': features,
            })

        return sorted(scored, key=lambda x: x['priority_score'], reverse=True)

    # ── Feature Extraction ────────────────────────────────────────────────

    def _extract_features(self, page, recon_data: dict) -> dict:
        """Extract 11 features from a page dict, Page dataclass, or URL string."""
        url = getattr(page, 'url', None) or (page.get('url', '') if isinstance(page, dict) else str(page))
        body = getattr(page, 'body', None) or (page.get('body', '') if isinstance(page, dict) else '')
        methods = page.get('methods', ['GET']) if isinstance(page, dict) else ['GET']
        forms = getattr(page, 'forms', None) or (page.get('forms', []) if isinstance(page, dict) else [])

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        param_names = {k.lower() for k in params}

        return {
            'has_forms': int(bool(forms) or '<form' in body.lower()),
            'has_file_upload': int(
                'type="file"' in body.lower()
                or 'multipart/form-data' in body.lower()
                or any('file' in (f.get('enctype', '') or '') for f in forms)
            ),
            'has_numeric_id_params': int(
                any(re.search(r'id$|_id$|num$', k, re.I) for k in param_names)
            ),
            'has_redirect_params': int(bool(param_names & _REDIRECT_PARAMS)),
            'has_auth_params': int(bool(param_names & _AUTH_PARAMS)),
            'is_admin_panel': int(bool(_ADMIN_PATTERNS.search(url))),
            'is_api_endpoint': int(bool(_API_PATTERNS.search(url))),
            'authentication_required': int(
                getattr(page, 'authentication_required', False)
                if hasattr(page, 'authentication_required')
                else (page.get('auth_required', False) if isinstance(page, dict) else False)
            ),
            'tech_stack_vuln_score': self._tech_vuln_score(recon_data),
            'parameter_count': len(params),
            'http_methods_count': len(methods) if isinstance(methods, list) else 1,
        }

    def _tech_vuln_score(self, recon_data: dict) -> float:
        """Score based on known-vulnerable technologies in tech stack."""
        techs = recon_data.get('technologies', {}).get('technologies', [])
        if not techs:
            return 0.0

        # Technologies with known vulnerability history
        vuln_techs = {
            'wordpress': 3.0, 'drupal': 2.5, 'joomla': 2.5,
            'php': 1.5, 'apache': 1.0, 'nginx': 0.5,
            'jquery': 1.0, 'angular': 0.5, 'react': 0.3,
            'node.js': 1.0, 'express': 1.0, 'django': 0.5,
            'flask': 0.8, 'rails': 1.0, 'spring': 0.8,
            'tomcat': 1.5, 'iis': 1.0, 'struts': 3.0,
        }
        score = 0.0
        for tech in techs:
            name = (tech.get('name', '') if isinstance(tech, dict) else str(tech)).lower()
            for key, val in vuln_techs.items():
                if key in name:
                    score += val
                    break
        return round(score, 2)

    # ── Scoring ───────────────────────────────────────────────────────────

    def _score(self, features: dict) -> float:
        """Score a page using the ML model or heuristic fallback."""
        if self.model is not None:
            try:
                X = np.array([[features.get(name, 0) for name in _FEATURE_NAMES]])
                proba = self.model.predict_proba(X)[0]
                return round(float(proba[1]), 3)
            except Exception:
                pass

        # Heuristic fallback
        score = 0.0
        weights = {
            'has_forms': 0.15, 'has_file_upload': 0.2,
            'has_numeric_id_params': 0.15, 'has_redirect_params': 0.15,
            'has_auth_params': 0.1, 'is_admin_panel': 0.2,
            'is_api_endpoint': 0.15, 'authentication_required': 0.05,
        }
        for key, weight in weights.items():
            score += features.get(key, 0) * weight

        score += min(features.get('parameter_count', 0) * 0.03, 0.3)
        score += min(features.get('tech_stack_vuln_score', 0) * 0.02, 0.2)
        score += min(features.get('http_methods_count', 1) * 0.05, 0.15)

        return round(min(score, 1.0), 3)

    # ── Model Initialization ─────────────────────────────────────────────

    def _init_model(self):
        """Try to load or create a GradientBoosting model."""
        try:
            from sklearn.ensemble import GradientBoostingClassifier

            rng = np.random.RandomState(42)
            n = 500

            # Synthetic: vulnerable pages (label=1) tend to have forms, params, admin paths
            X_vuln = np.column_stack([
                rng.choice([0, 1], n // 2, p=[0.3, 0.7]),   # forms
                rng.choice([0, 1], n // 2, p=[0.6, 0.4]),   # file upload
                rng.choice([0, 1], n // 2, p=[0.4, 0.6]),   # numeric id
                rng.choice([0, 1], n // 2, p=[0.5, 0.5]),   # redirect params
                rng.choice([0, 1], n // 2, p=[0.5, 0.5]),   # auth params
                rng.choice([0, 1], n // 2, p=[0.6, 0.4]),   # admin panel
                rng.choice([0, 1], n // 2, p=[0.4, 0.6]),   # api endpoint
                rng.choice([0, 1], n // 2, p=[0.5, 0.5]),   # auth required
                rng.uniform(0, 5, n // 2),                    # tech vuln score
                rng.randint(1, 10, n // 2),                   # param count
                rng.randint(1, 5, n // 2),                    # http methods
            ])
            y_vuln = np.ones(n // 2)

            # Clean pages (label=0)
            X_clean = np.column_stack([
                rng.choice([0, 1], n // 2, p=[0.8, 0.2]),
                rng.choice([0, 1], n // 2, p=[0.95, 0.05]),
                rng.choice([0, 1], n // 2, p=[0.9, 0.1]),
                rng.choice([0, 1], n // 2, p=[0.95, 0.05]),
                rng.choice([0, 1], n // 2, p=[0.9, 0.1]),
                rng.choice([0, 1], n // 2, p=[0.95, 0.05]),
                rng.choice([0, 1], n // 2, p=[0.7, 0.3]),
                rng.choice([0, 1], n // 2, p=[0.8, 0.2]),
                rng.uniform(0, 2, n // 2),
                rng.randint(0, 3, n // 2),
                rng.choice([1, 1, 2], n // 2),
            ])
            y_clean = np.zeros(n // 2)

            X = np.vstack([X_vuln, X_clean])
            y = np.concatenate([y_vuln, y_clean])
            idx = rng.permutation(len(y))
            X, y = X[idx], y[idx]

            self.model = GradientBoostingClassifier(
                n_estimators=50, max_depth=5, random_state=42,
            )
            self.model.fit(X, y)
            logger.debug('Attack prioritizer model initialized')
        except ImportError:
            logger.warning('scikit-learn not available — using heuristic prioritizer')
            self.model = None
