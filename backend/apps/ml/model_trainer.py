"""
Model trainer — generates and trains scikit-learn models
for phishing and malware detection using synthetic data.
"""
import logging
import time
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent / 'trained_models'


def ensure_models_dir():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)


def train_phishing_model(n_samples=5000):
    """
    Train a phishing URL detection model using synthetic data.
    Returns model metadata dict.
    """
    from .phishing_detector import URL_FEATURE_NAMES

    logger.info(f'Training phishing model with {n_samples} samples...')
    ensure_models_dir()

    X, y = _generate_phishing_data(n_samples, len(URL_FEATURE_NAMES))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    start = time.time()
    model = GradientBoostingClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X_train, y_train)
    duration = time.time() - start

    y_pred = model.predict(X_test)
    metrics = {
        'accuracy': round(accuracy_score(y_test, y_pred), 4),
        'precision': round(precision_score(y_test, y_pred, zero_division=0), 4),
        'recall': round(recall_score(y_test, y_pred, zero_division=0), 4),
        'f1': round(f1_score(y_test, y_pred, zero_division=0), 4),
    }

    model_path = MODELS_DIR / 'phishing_model.pkl'
    joblib.dump(model, model_path)

    logger.info(f'Phishing model trained — Accuracy: {metrics["accuracy"]}, '
                f'F1: {metrics["f1"]}, Duration: {duration:.1f}s')

    return {
        'name': 'Phishing URL Detector',
        'model_type': 'phishing',
        'version': '1.0.0',
        'file_path': str(model_path),
        'training_samples': n_samples,
        'training_duration_seconds': round(duration, 2),
        **metrics,
    }


def train_malware_model(n_samples=3000):
    """
    Train a malware file detection model using synthetic data.
    Returns model metadata dict.
    """
    from .malware_detector import FILE_FEATURE_NAMES

    logger.info(f'Training malware model with {n_samples} samples...')
    ensure_models_dir()

    X, y = _generate_malware_data(n_samples, len(FILE_FEATURE_NAMES))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    start = time.time()
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    duration = time.time() - start

    y_pred = model.predict(X_test)
    metrics = {
        'accuracy': round(accuracy_score(y_test, y_pred), 4),
        'precision': round(precision_score(y_test, y_pred, zero_division=0), 4),
        'recall': round(recall_score(y_test, y_pred, zero_division=0), 4),
        'f1': round(f1_score(y_test, y_pred, zero_division=0), 4),
    }

    model_path = MODELS_DIR / 'malware_model.pkl'
    joblib.dump(model, model_path)

    logger.info(f'Malware model trained — Accuracy: {metrics["accuracy"]}, '
                f'F1: {metrics["f1"]}, Duration: {duration:.1f}s')

    return {
        'name': 'Malware File Detector',
        'model_type': 'malware',
        'version': '1.0.0',
        'file_path': str(model_path),
        'training_samples': n_samples,
        'training_duration_seconds': round(duration, 2),
        **metrics,
    }


# ---- Synthetic Data Generation ----

def _generate_phishing_data(n_samples, n_features):
    """
    Generate synthetic phishing URL feature data.
    Features simulate the distribution of real URL characteristics.
    """
    rng = np.random.RandomState(42)
    n_phishing = n_samples // 2
    n_legit = n_samples - n_phishing

    # Legitimate URL features (lower risk patterns)
    legit_features = np.column_stack([
        rng.randint(20, 60, n_legit),       # url_length: short
        rng.randint(5, 20, n_legit),        # hostname_length
        rng.randint(1, 30, n_legit),        # path_length
        rng.randint(0, 20, n_legit),        # query_length
        rng.randint(1, 4, n_legit),         # dot_count
        rng.randint(0, 2, n_legit),         # hyphen_count
        rng.randint(0, 1, n_legit),         # underscore_count
        rng.randint(2, 5, n_legit),         # slash_count
        rng.randint(0, 1, n_legit),         # question_count
        rng.randint(0, 3, n_legit),         # equal_count
        np.zeros(n_legit),                   # at_count
        rng.randint(0, 2, n_legit),         # ampersand_count
        rng.randint(0, 5, n_legit),         # digit_count
        rng.randint(15, 40, n_legit),       # letter_count
        rng.randint(3, 8, n_legit),         # special_char_count
        rng.uniform(0, 0.2, n_legit),       # digit_letter_ratio: low
        np.zeros(n_legit),                   # has_ip_address: no
        np.ones(n_legit),                    # has_https: yes
        np.zeros(n_legit),                   # has_port: no
        np.zeros(n_legit),                   # has_at_symbol: no
        np.zeros(n_legit),                   # has_double_slash_redirect
        rng.choice([0, 1], n_legit, p=[0.6, 0.4]),  # has_subdomain
        rng.uniform(2.0, 3.5, n_legit),    # hostname_entropy: low
        rng.uniform(2.0, 3.5, n_legit),    # path_entropy
        rng.uniform(3.0, 4.0, n_legit),    # url_entropy
        rng.randint(0, 2, n_legit),         # subdomain_count
        rng.randint(1, 3, n_legit),         # path_depth
        rng.choice([0, 1], n_legit, p=[0.9, 0.1]),  # has_login_keyword
        rng.choice([0, 1], n_legit, p=[0.9, 0.1]),  # has_secure_keyword
        rng.choice([0, 1], n_legit, p=[0.95, 0.05]),  # has_banking_keyword
        np.zeros(n_legit),                   # tld_is_suspicious
    ])

    # Phishing URL features (higher risk patterns)
    phish_features = np.column_stack([
        rng.randint(50, 200, n_phishing),   # url_length: long
        rng.randint(15, 60, n_phishing),    # hostname_length: long
        rng.randint(10, 80, n_phishing),    # path_length
        rng.randint(0, 50, n_phishing),     # query_length
        rng.randint(3, 10, n_phishing),     # dot_count: many
        rng.randint(1, 6, n_phishing),      # hyphen_count: many
        rng.randint(0, 4, n_phishing),      # underscore_count
        rng.randint(3, 10, n_phishing),     # slash_count
        rng.randint(0, 3, n_phishing),      # question_count
        rng.randint(0, 6, n_phishing),      # equal_count
        rng.choice([0, 1], n_phishing, p=[0.8, 0.2]),  # at_count
        rng.randint(0, 4, n_phishing),      # ampersand_count
        rng.randint(3, 20, n_phishing),     # digit_count: many
        rng.randint(20, 80, n_phishing),    # letter_count
        rng.randint(5, 20, n_phishing),     # special_char_count
        rng.uniform(0.2, 1.0, n_phishing),  # digit_letter_ratio: high
        rng.choice([0, 1], n_phishing, p=[0.7, 0.3]),  # has_ip_address
        rng.choice([0, 1], n_phishing, p=[0.4, 0.6]),  # has_https: often no
        rng.choice([0, 1], n_phishing, p=[0.85, 0.15]),  # has_port
        rng.choice([0, 1], n_phishing, p=[0.8, 0.2]),  # has_at_symbol
        rng.choice([0, 1], n_phishing, p=[0.7, 0.3]),  # has_double_slash_redirect
        rng.choice([0, 1], n_phishing, p=[0.3, 0.7]),  # has_subdomain: often yes
        rng.uniform(3.0, 5.0, n_phishing),  # hostname_entropy: high
        rng.uniform(3.0, 5.0, n_phishing),  # path_entropy
        rng.uniform(3.5, 5.0, n_phishing),  # url_entropy
        rng.randint(2, 6, n_phishing),      # subdomain_count: many
        rng.randint(2, 8, n_phishing),      # path_depth: deep
        rng.choice([0, 1], n_phishing, p=[0.4, 0.6]),  # has_login_keyword
        rng.choice([0, 1], n_phishing, p=[0.5, 0.5]),  # has_secure_keyword
        rng.choice([0, 1], n_phishing, p=[0.6, 0.4]),  # has_banking_keyword
        rng.choice([0, 1], n_phishing, p=[0.5, 0.5]),  # tld_is_suspicious
    ])

    X = np.vstack([legit_features, phish_features]).astype(float)
    y = np.concatenate([np.zeros(n_legit), np.ones(n_phishing)])

    # Shuffle
    indices = rng.permutation(len(y))
    return X[indices], y[indices]


def _generate_malware_data(n_samples, n_features):
    """Generate synthetic malware file feature data."""
    rng = np.random.RandomState(42)
    n_malware = n_samples // 2
    n_benign = n_samples - n_malware

    # Benign file features
    benign_features = np.column_stack([
        rng.randint(100, 500000, n_benign),     # file_size
        rng.uniform(3.0, 6.5, n_benign),        # file_entropy: moderate
        np.zeros(n_benign),                       # has_suspicious_extension
        np.zeros(n_benign),                       # has_double_extension
        rng.randint(0, 2, n_benign),             # script_pattern_count: few
        rng.randint(0, 1, n_benign),             # obfuscation_count: rare
        rng.randint(0, 2, n_benign),             # network_indicator_count
        rng.uniform(0.6, 1.0, n_benign),         # printable_ratio: high
        rng.uniform(0, 0.05, n_benign),          # null_byte_ratio: low
    ])

    # Malware file features
    malware_features = np.column_stack([
        rng.randint(1000, 2000000, n_malware),  # file_size
        rng.uniform(6.0, 8.0, n_malware),       # file_entropy: high
        rng.choice([0, 1], n_malware, p=[0.4, 0.6]),  # has_suspicious_extension
        rng.choice([0, 1], n_malware, p=[0.7, 0.3]),  # has_double_extension
        rng.randint(2, 8, n_malware),            # script_pattern_count: many
        rng.randint(1, 5, n_malware),            # obfuscation_count: high
        rng.randint(2, 7, n_malware),            # network_indicator_count: many
        rng.uniform(0.1, 0.6, n_malware),        # printable_ratio: low
        rng.uniform(0.02, 0.3, n_malware),       # null_byte_ratio: high
    ])

    X = np.vstack([benign_features, malware_features]).astype(float)
    y = np.concatenate([np.zeros(n_benign), np.ones(n_malware)])

    indices = rng.permutation(len(y))
    return X[indices], y[indices]
