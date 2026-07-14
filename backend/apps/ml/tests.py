from django.test import TestCase
from .feature_extractors import extract_url_features, extract_file_features
from .phishing_detector import PhishingDetector
from .malware_detector import MalwareDetector


class FeatureExtractionTest(TestCase):
    def test_url_features(self):
        features = extract_url_features('https://example.com/path?key=val')
        self.assertIn('url_length', features)
        self.assertEqual(features['has_https'], 1)
        self.assertEqual(features['has_ip_address'], 0)

    def test_phishing_url_features(self):
        features = extract_url_features('http://192.168.1.1/login/secure.html?user=admin@bank')
        self.assertEqual(features['has_ip_address'], 1)
        self.assertEqual(features['has_https'], 0)
        self.assertEqual(features['has_at_symbol'], 1)

    def test_file_features(self):
        content = b'Hello world, this is a test file.'
        features = extract_file_features(content, 'test.txt')
        self.assertIn('file_size', features)
        self.assertIn('file_entropy', features)
        self.assertEqual(features['has_suspicious_extension'], 0)

    def test_suspicious_file_features(self):
        content = b'MZ\x90\x00eval(system("cmd.exe")) subprocess os.system'
        features = extract_file_features(content, 'malware.exe.txt')
        self.assertEqual(features['has_double_extension'], 1)
        self.assertGreater(features['script_pattern_count'], 0)


class PhishingDetectorTest(TestCase):
    def test_rule_based_detection(self):
        detector = PhishingDetector()
        result = detector.predict('http://192.168.1.1/login/secure-banking')
        self.assertIn(result['prediction'], ('phishing', 'legitimate'))
        self.assertIn('confidence', result)
        self.assertIn('indicators', result)
        self.assertGreater(result['risk_score'], 0)

    def test_legitimate_url(self):
        detector = PhishingDetector()
        result = detector.predict('https://www.google.com')
        self.assertEqual(result['prediction'], 'legitimate')


class MalwareDetectorTest(TestCase):
    def test_benign_file(self):
        detector = MalwareDetector()
        result = detector.predict(b'Hello, this is a normal text file.', 'readme.txt')
        self.assertEqual(result['prediction'], 'benign')

    def test_suspicious_file(self):
        detector = MalwareDetector()
        content = b'MZ' + b'\x00' * 100 + b'eval(system("cmd")) subprocess os.system exec() base64 fromCharCode'
        result = detector.predict(content, 'payload.exe.txt')
        self.assertIn(result['prediction'], ('malicious', 'benign'))
        self.assertGreater(result['risk_score'], 0)
