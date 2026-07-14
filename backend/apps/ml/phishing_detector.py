"""
Phishing URL/page detector using scikit-learn.
Provides both a rule-based fallback and ML-based detection.
"""
import logging
import joblib
import numpy as np
from pathlib import Path
from .feature_extractors import extract_url_features, extract_html_features, features_to_vector
from .models import MLModel, MLPrediction

logger = logging.getLogger(__name__)

# Feature names used by the phishing model (must match training order)
URL_FEATURE_NAMES = [
    'url_length', 'hostname_length', 'path_length', 'query_length',
    'dot_count', 'hyphen_count', 'underscore_count', 'slash_count',
    'question_count', 'equal_count', 'at_count', 'ampersand_count',
    'digit_count', 'letter_count', 'special_char_count', 'digit_letter_ratio',
    'has_ip_address', 'has_https', 'has_port', 'has_at_symbol',
    'has_double_slash_redirect', 'has_subdomain',
    'hostname_entropy', 'path_entropy', 'url_entropy',
    'subdomain_count', 'path_depth',
    'has_login_keyword', 'has_secure_keyword', 'has_banking_keyword',
    'tld_is_suspicious',
]

MODELS_DIR = Path(__file__).parent / 'trained_models'


class PhishingDetector:
    """Detect phishing URLs and pages."""

    def __init__(self):
        self._model = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self):
        """Load the trained phishing detection model."""
        try:
            model_path = MODELS_DIR / 'phishing_model.pkl'
            if model_path.exists():
                self._model = joblib.load(model_path)
                self._model_loaded = True
                logger.info('Phishing detection model loaded successfully')
            else:
                logger.warning('No trained phishing model found — using rule-based detection')
        except Exception as e:
            logger.error(f'Failed to load phishing model: {e}')

    def predict(self, url: str, html_content: str = '', scan=None) -> dict:
        """
        Predict whether a URL is phishing.

        Returns:
            {
                'prediction': 'phishing' | 'legitimate',
                'confidence': float 0-1,
                'risk_score': float 0-100,
                'features': dict,
                'indicators': list[str],
            }
        """
        url_features = extract_url_features(url)
        html_features = extract_html_features(html_content, url) if html_content else {}

        if self._model_loaded:
            result = self._ml_predict(url, url_features, html_features)
        else:
            result = self._rule_based_predict(url, url_features, html_features)

        # Save prediction
        self._save_prediction(result, url_features, scan)

        return result

    def _ml_predict(self, url, url_features, html_features):
        """Use the trained ML model for prediction."""
        feature_vector = features_to_vector(url_features, URL_FEATURE_NAMES)
        X = np.array([feature_vector])

        try:
            prediction = self._model.predict(X)[0]
            probabilities = self._model.predict_proba(X)[0]
            confidence = float(max(probabilities))

            is_phishing = prediction == 1
            indicators = self._get_indicators(url_features, html_features)

            return {
                'prediction': 'phishing' if is_phishing else 'legitimate',
                'confidence': confidence,
                'risk_score': round(confidence * 100 if is_phishing else (1 - confidence) * 100),
                'features': {**url_features, **html_features},
                'indicators': indicators,
                'method': 'ml',
            }
        except Exception as e:
            logger.error(f'ML prediction failed: {e}')
            return self._rule_based_predict(url, url_features, html_features)

    def _rule_based_predict(self, url, url_features, html_features):
        """Rule-based phishing detection (fallback)."""
        risk_score = 0
        indicators = []

        # URL-based rules
        if url_features.get('has_ip_address'):
            risk_score += 25
            indicators.append('URL uses IP address instead of domain name')

        if not url_features.get('has_https'):
            risk_score += 10
            indicators.append('URL does not use HTTPS')

        if url_features.get('url_length', 0) > 75:
            risk_score += 10
            indicators.append(f'Unusually long URL ({url_features["url_length"]} characters)')

        if url_features.get('has_at_symbol'):
            risk_score += 20
            indicators.append('URL contains @ symbol (potential credential phishing)')

        if url_features.get('has_double_slash_redirect'):
            risk_score += 15
            indicators.append('URL contains double slash redirect')

        if url_features.get('subdomain_count', 0) > 3:
            risk_score += 15
            indicators.append(f'Excessive subdomains ({url_features["subdomain_count"]})')

        if url_features.get('hostname_entropy', 0) > 4.0:
            risk_score += 10
            indicators.append('High hostname entropy (possibly randomly generated)')

        if url_features.get('tld_is_suspicious'):
            risk_score += 15
            indicators.append('Uses suspicious/free TLD')

        if url_features.get('has_login_keyword') and url_features.get('has_banking_keyword'):
            risk_score += 15
            indicators.append('URL contains login and banking keywords')

        if url_features.get('digit_letter_ratio', 0) > 0.5:
            risk_score += 10
            indicators.append('High digit-to-letter ratio in URL')

        # HTML-based rules
        if html_features:
            if html_features.get('password_input_count', 0) > 0:
                risk_score += 10
                indicators.append('Page contains password input fields')

            if html_features.get('has_form_with_external_action'):
                risk_score += 20
                indicators.append('Form submits to external domain')

            if html_features.get('has_right_click_disabled'):
                risk_score += 10
                indicators.append('Right-click is disabled')

            if html_features.get('iframe_count', 0) > 2:
                risk_score += 10
                indicators.append(f'Multiple iframes detected ({html_features["iframe_count"]})')

        risk_score = min(risk_score, 100)
        is_phishing = risk_score >= 50
        confidence = risk_score / 100

        return {
            'prediction': 'phishing' if is_phishing else 'legitimate',
            'confidence': confidence,
            'risk_score': risk_score,
            'features': {**url_features, **html_features},
            'indicators': indicators,
            'method': 'rule-based',
        }

    def _get_indicators(self, url_features, html_features):
        """Get human-readable indicators for ML predictions."""
        indicators = []
        if url_features.get('has_ip_address'):
            indicators.append('URL uses IP address')
        if not url_features.get('has_https'):
            indicators.append('No HTTPS')
        if url_features.get('tld_is_suspicious'):
            indicators.append('Suspicious TLD')
        if url_features.get('has_at_symbol'):
            indicators.append('@ symbol in URL')
        if url_features.get('subdomain_count', 0) > 3:
            indicators.append('Excessive subdomains')
        if html_features.get('has_form_with_external_action'):
            indicators.append('External form action')
        return indicators

    def _save_prediction(self, result, features, scan=None):
        """Save prediction to database for audit."""
        try:
            active_model = MLModel.objects.filter(
                model_type='phishing', is_active=True
            ).first()

            MLPrediction.objects.create(
                model=active_model,
                scan=scan,
                input_data={'method': result.get('method')},
                prediction=result['prediction'],
                confidence=result['confidence'],
                features={k: v for k, v in features.items()
                         if isinstance(v, (int, float, str, bool))},
            )
        except Exception as e:
            logger.error(f'Failed to save prediction: {e}')
