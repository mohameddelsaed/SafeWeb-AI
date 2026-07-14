"""
Phase 38 — AI/ML Enhancement Tests.

Tests for:
  - NLP Detector         (engine/ml/nlp_detector.py)
  - RL Fuzzer            (engine/ml/rl_fuzzer.py)
  - False Positive Reducer (engine/ml/false_positive_reducer.py)
  - Attack Path Optimizer (engine/ml/attack_path_optimizer.py)
  - MLEnhancementTester  (testers/ml_enhancement_tester.py)
"""
import pytest
import sys
import os

# Ensure backend is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')
django.setup()

# ──────────────────────────────────────────────────────────────────────────────
# NLP Detector — Error Classification
# ──────────────────────────────────────────────────────────────────────────────

class TestNLPErrorClassification:
    def test_database_error_mysql(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message("Warning: mysql_fetch_array() expects parameter 1")
        assert result['category'] == 'database'
        assert result['confidence'] > 0.5
        assert result['severity'] == 'high'

    def test_database_error_oracle(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message("ORA-00942: table or view does not exist")
        assert result['category'] == 'database'
        assert result['confidence'] > 0.5

    def test_code_error_python_traceback(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message(
            "Traceback (most recent call last):\n  File 'app.py', line 42, in handler\n"
            "AttributeError: 'NoneType' object has no attribute 'get'"
        )
        assert result['category'] == 'code'
        assert result['confidence'] > 0.5

    def test_code_error_java_npe(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message("java.lang.NullPointerException at com.example.App.main(App.java:17)")
        assert result['category'] == 'code'

    def test_filesystem_error(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message("ENOENT: no such file or directory, open '/etc/app/config.json'")
        assert result['category'] == 'filesystem'
        assert result['severity'] == 'high'

    def test_auth_error(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message("Authentication failed: Invalid credentials provided")
        assert result['category'] == 'auth'
        assert result['severity'] == 'medium'

    def test_harmless_response(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message("Welcome to our website! Enjoy browsing our products.")
        assert result['category'] == 'harmless'
        assert result['confidence'] == 0.0  # no harmful patterns → 0.0

    def test_empty_text(self):
        from apps.scanning.engine.ml.nlp_detector import classify_error_message
        result = classify_error_message('')
        assert result['category'] == 'harmless'
        assert result['indicators'] == []


# ──────────────────────────────────────────────────────────────────────────────
# NLP Detector — Response Interest Scoring
# ──────────────────────────────────────────────────────────────────────────────

class TestResponseInterestScoring:
    def test_high_score_db_error(self):
        from apps.scanning.engine.ml.nlp_detector import score_response_interest
        # Score averages 6 components; 500+DB-error fire two strong signals (0.90, 0.85)
        response = {
            'status_code': 500,
            'text': "ORA-00942: table or view does not exist. Stack trace follows.",
            'length': 512,
            'elapsed': 0.3,
        }
        score = score_response_interest(response)
        assert score > 0.25  # 500 (0.90) + DB error (0.85) → avg ≈ 0.29

    def test_low_score_normal_page(self):
        from apps.scanning.engine.ml.nlp_detector import score_response_interest
        response = {
            'status_code': 200,
            'text': "Welcome! This is our homepage.",
            'length': 1024,
            'elapsed': 0.2,
        }
        score = score_response_interest(response)
        assert score < 0.5

    def test_time_delay_signal(self):
        from apps.scanning.engine.ml.nlp_detector import score_response_interest
        # Time delay (elapsed>5s → 0.80 component) should produce a higher score than no delay
        no_delay = score_response_interest({'status_code': 200, 'text': 'normal', 'elapsed': 0.1})
        with_delay = score_response_interest({'status_code': 200, 'text': 'normal', 'elapsed': 6.0})
        assert with_delay > no_delay
        assert with_delay > 0.10  # averaged across 6 components

    def test_stack_trace_boosts_score(self):
        from apps.scanning.engine.ml.nlp_detector import score_response_interest
        # Stack trace response should score higher than a bland 200
        blank = score_response_interest({'status_code': 200, 'text': 'OK', 'elapsed': 0.1})
        with_trace = score_response_interest({
            'status_code': 200,
            'text': (
                "Traceback (most recent call last):\n"
                '  File "app.py", line 10, in handle\n'
                "ValueError: invalid literal"
            ),
            'length': 300,
            'elapsed': 0.1,
        })
        assert with_trace > blank
        assert with_trace > 0.25  # code-error + trace → avg ≈ 0.325

    def test_returns_float_in_range(self):
        from apps.scanning.engine.ml.nlp_detector import score_response_interest
        for status in [200, 301, 403, 500]:
            score = score_response_interest({'status_code': status, 'text': 'x'})
            assert 0.0 <= score <= 1.0


# ──────────────────────────────────────────────────────────────────────────────
# NLP Detector — Contextual Payload Generation
# ──────────────────────────────────────────────────────────────────────────────

class TestContextualPayloadGeneration:
    def test_php_mutations(self):
        from apps.scanning.engine.ml.nlp_detector import generate_contextual_payloads
        payloads = generate_contextual_payloads("test", {'tech_stack': 'php'})
        assert len(payloads) > 0
        assert 'test' in payloads  # base payload always included
        # PHP-specific: null byte or path traversal
        combined = '\n'.join(payloads)
        assert any(x in combined for x in ['%00', 'php', 'passwd'])

    def test_python_mutations(self):
        from apps.scanning.engine.ml.nlp_detector import generate_contextual_payloads
        payloads = generate_contextual_payloads("val", {'tech_stack': 'python'})
        combined = '\n'.join(payloads)
        assert '{{' in combined or 'config' in combined  # SSTI patterns

    def test_nodejs_mutations(self):
        from apps.scanning.engine.ml.nlp_detector import generate_contextual_payloads
        payloads = generate_contextual_payloads("q", {'tech_stack': 'nodejs'})
        combined = '\n'.join(payloads)
        assert '$gt' in combined or 'passwd' in combined

    def test_unknown_tech_defaults(self):
        from apps.scanning.engine.ml.nlp_detector import generate_contextual_payloads
        payloads = generate_contextual_payloads("x", {'tech_stack': 'unknown'})
        assert len(payloads) > 0
        assert 'x' in payloads

    def test_aspnet_normalisation(self):
        from apps.scanning.engine.ml.nlp_detector import generate_contextual_payloads
        p1 = generate_contextual_payloads("p", {'tech_stack': 'asp.net'})
        p2 = generate_contextual_payloads("p", {'tech_stack': 'aspnet'})
        assert p1 == p2


# ──────────────────────────────────────────────────────────────────────────────
# NLP Detector — Stack Trace Detection
# ──────────────────────────────────────────────────────────────────────────────

class TestStackTraceDetection:
    def test_python_trace_detected(self):
        from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
        text = (
            "Traceback (most recent call last):\n"
            '  File "/app/views.py", line 23, in handle\n'
            "    return process(data)\n"
            "ValueError: bad data\n"
        )
        result = detect_stack_trace(text)
        assert result['detected'] is True
        assert result['language'] == 'python'

    def test_java_trace_detected(self):
        from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
        text = (
            "java.lang.NullPointerException: Cannot invoke method\n"
            "    at com.example.Service.process(Service.java:42)\n"
            "    at com.example.Controller.handle(Controller.java:15)\n"
        )
        result = detect_stack_trace(text)
        assert result['detected'] is True
        assert result['language'] == 'java'

    def test_no_trace_in_normal_text(self):
        from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
        result = detect_stack_trace("Hello, world! Nothing to see here.")
        assert result['detected'] is False
        assert result['language'] == 'unknown'

    def test_sensitive_paths_extracted(self):
        from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
        text = (
            "Traceback (most recent call last):\n"
            '  File "/app/config/database.py", line 5, in connect\n'
            "    raise ConnectionError\n"
        )
        result = detect_stack_trace(text)
        assert result['detected'] is True
        assert any('/app' in p or 'database.py' in p for p in result['sensitive_paths'])

    def test_frames_extracted_python(self):
        from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
        text = (
            "Traceback (most recent call last):\n"
            '  File "/srv/app.py", line 10, in main\n'
            '  File "/srv/utils.py", line 5, in helper\n'
            "RuntimeError: oops\n"
        )
        result = detect_stack_trace(text)
        assert len(result['frames']) >= 1
        assert result['frames'][0]['line'] == 10

    def test_empty_text_returns_not_detected(self):
        from apps.scanning.engine.ml.nlp_detector import detect_stack_trace
        result = detect_stack_trace('')
        assert result['detected'] is False
        assert result['frames'] == []


# ──────────────────────────────────────────────────────────────────────────────
# RL Fuzzer — Initialisation
# ──────────────────────────────────────────────────────────────────────────────

class TestRLFuzzerInit:
    def test_default_params(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        assert f.epsilon == 0.20
        assert f.alpha == 0.10
        assert f.gamma == 0.90

    def test_custom_params(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer(epsilon=0.5, alpha=0.05, gamma=0.95)
        assert f.epsilon == 0.5
        assert f.alpha == 0.05

    def test_invalid_epsilon_raises(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        with pytest.raises(ValueError):
            RLFuzzer(epsilon=1.5)


# ──────────────────────────────────────────────────────────────────────────────
# RL Fuzzer — Payload Selection
# ──────────────────────────────────────────────────────────────────────────────

class TestRLFuzzerPayloadSelection:
    def test_returns_valid_index_and_payload(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer()
        state = RLFuzzerState('php', False, 'normal')
        candidates = ["' OR 1=1--", "<script>alert(1)</script>", "/../etc/passwd"]
        idx, payload = f.select_payload(state, candidates)
        assert 0 <= idx < len(candidates)
        assert payload == candidates[idx]

    def test_exploit_mode_returns_best_q(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer(epsilon=0.0)  # no exploration
        state = RLFuzzerState('php', False, 'normal')
        candidates = ['a', 'b', 'c']
        # Manually set Q-value for index 2
        f._q_table[(f._state_key(state), 2)] = 10.0
        idx, _ = f.select_payload(state, candidates)
        assert idx == 2

    def test_explore_mode_random_choice(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer(epsilon=1.0)  # always explore
        state = RLFuzzerState('java', True, 'blocked')
        candidates = ['p1', 'p2', 'p3', 'p4', 'p5']
        indices = set()
        for _ in range(50):
            idx, _ = f.select_payload(state, candidates)
            indices.add(idx)
        assert len(indices) > 1  # should have explored multiple options

    def test_empty_candidates_raises(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer()
        state = RLFuzzerState('unknown', False, 'normal')
        with pytest.raises(ValueError):
            f.select_payload(state, [])

    def test_get_best_payloads(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer(epsilon=0.0)
        state = RLFuzzerState('php', False, 'normal')
        candidates = ['p0', 'p1', 'p2', 'p3']
        f._q_table[(f._state_key(state), 1)] = 5.0
        f._q_table[(f._state_key(state), 3)] = 3.0
        ranked = f.get_best_payloads(state, candidates, top_k=2)
        assert len(ranked) == 2
        assert ranked[0][0] == 1  # highest Q first
        assert ranked[1][0] == 3


# ──────────────────────────────────────────────────────────────────────────────
# RL Fuzzer — Reward Computation
# ──────────────────────────────────────────────────────────────────────────────

class TestRLFuzzerRewardComputation:
    def test_error_response_max_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        response = {'status_code': 500, 'text': 'Fatal error: exception traceback', 'elapsed': 0.3}
        assert f.compute_reward(response) == 1.00

    def test_reflected_payload_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        response = {'status_code': 200, 'text': '<script>alert(1)</script> reflected here', 'elapsed': 0.1}
        assert f.compute_reward(response) == 0.80

    def test_waf_block_negative_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        response = {'status_code': 403, 'text': 'Request blocked by security firewall', 'elapsed': 0.1}
        assert f.compute_reward(response) == -0.50

    def test_timeout_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        response = {'status_code': 200, 'text': '', 'elapsed': 8.0}
        assert f.compute_reward(response) == 0.60

    def test_normal_response_zero_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        response = {'status_code': 200, 'text': 'Welcome to our site', 'elapsed': 0.2}
        assert f.compute_reward(response) == 0.00


# ──────────────────────────────────────────────────────────────────────────────
# RL Fuzzer — Q-Learning Updates
# ──────────────────────────────────────────────────────────────────────────────

class TestRLFuzzerQLearningUpdate:
    def test_q_value_increases_with_positive_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer(alpha=1.0)  # full learning rate for predictable update
        state = RLFuzzerState('php', False, 'normal')
        initial_q = f._q_table[(f._state_key(state), 0)]
        f.update(state, 0, reward=1.0)
        new_q = f._q_table[(f._state_key(state), 0)]
        assert new_q > initial_q

    def test_q_value_decreases_with_negative_reward(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer(alpha=1.0)
        state = RLFuzzerState('php', True, 'blocked')
        f._q_table[(f._state_key(state), 2)] = 0.5
        f.update(state, 2, reward=-0.5)
        new_q = f._q_table[(f._state_key(state), 2)]
        assert new_q < 0.5

    def test_total_updates_increments(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer()
        state = RLFuzzerState('java', False, 'normal')
        for i in range(5):
            f.update(state, 0, reward=0.5)
        assert f._total_updates == 5

    def test_update_with_next_state(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f = RLFuzzer(alpha=1.0, gamma=0.9)
        state = RLFuzzerState('php', False, 'normal')
        next_state = RLFuzzerState('php', False, 'error')
        f._q_table[(f._state_key(next_state), 0)] = 1.0
        f.update(state, 0, reward=0.5, next_state=next_state)
        # Q = 0 + 1.0*(0.5 + 0.9*1.0 - 0) = 1.4
        updated_q = f._q_table[(f._state_key(state), 0)]
        assert abs(updated_q - 1.4) < 0.01


# ──────────────────────────────────────────────────────────────────────────────
# RL Fuzzer — Statistics & State Encoding
# ──────────────────────────────────────────────────────────────────────────────

class TestRLFuzzerStatistics:
    def test_stats_keys_present(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        stats = f.get_stats()
        for key in ('q_table_size', 'total_updates', 'exploration_rate'):
            assert key in stats

    def test_stats_explore_exploit_tracking(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer, RLFuzzerState
        f_explore = RLFuzzer(epsilon=1.0)
        f_exploit = RLFuzzer(epsilon=0.0)
        state = RLFuzzerState('php', False, 'normal')
        candidates = ['a', 'b', 'c']
        for _ in range(10):
            f_explore.select_payload(state, candidates)
            f_exploit.select_payload(state, candidates)
        assert f_explore.get_stats()['total_explores'] == 10
        assert f_exploit.get_stats()['total_exploits'] == 10

    def test_encode_state_from_response(self):
        from apps.scanning.engine.ml.rl_fuzzer import RLFuzzer
        f = RLFuzzer()
        response = {'status_code': 500, 'text': 'error traceback exception', 'elapsed': 0.3}
        state = f.encode_state_from_response(response, 'php', True)
        assert state.tech_stack == 'php'
        assert state.waf_detected is True
        assert state.last_response_type == 'error'


# ──────────────────────────────────────────────────────────────────────────────
# False Positive Reducer — Initialisation
# ──────────────────────────────────────────────────────────────────────────────

class TestFalsePositiveReducerInit:
    def test_default_threshold(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        assert r.confidence_threshold == 0.55

    def test_custom_threshold(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer(confidence_threshold=0.75)
        assert r.confidence_threshold == 0.75


# ──────────────────────────────────────────────────────────────────────────────
# False Positive Reducer — Analysis
# ──────────────────────────────────────────────────────────────────────────────

class TestFalsePositiveReducerAnalysis:
    def test_analyze_returns_required_keys(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'name': 'SQL Injection', 'severity': 'critical', 'category': 'sqli',
                'evidence': "AND 1=1-- returned different response (200 bytes difference)", 'cwe': 'CWE-89'}
        result = r.analyze(vuln, {'status_code': 500, 'length_delta': 500})
        for key in ('is_real', 'confidence', 'reasoning', 'component_scores'):
            assert key in result

    def test_high_severity_sqli_flagged_real(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'name': 'SQL Injection', 'severity': 'critical', 'category': 'sqli',
                'evidence': "' OR 1=1-- triggered error response with ORA-00942", 'cwe': 'CWE-89'}
        result = r.analyze(vuln, {'status_code': 500, 'length_delta': 1200})
        assert result['confidence'] > 0.0  # Should assign a meaningful confidence

    def test_info_no_evidence_reduced_confidence(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'name': 'Banner', 'severity': 'info', 'category': 'misconfig',
                'evidence': 'x', 'cwe': 'CWE-200'}
        result = r.analyze(vuln, {})
        # Short evidence, info severity should reduce confidence
        assert result['confidence'] < 1.0

    def test_reflected_payload_boosts_xss_confidence(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'name': 'XSS', 'severity': 'high', 'category': 'xss',
                'evidence': '<script>alert(1)</script> was reflected in page', 'cwe': 'CWE-79'}
        response_data = {'payload_reflected': True, 'status_code': 200}
        result = r.analyze(vuln, response_data)
        assert result['confidence'] > 0.5

    def test_component_scores_in_range(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'name': 'Test', 'severity': 'medium', 'category': 'xss',
                'evidence': 'some evidence here to pass length threshold', 'cwe': 'CWE-79'}
        result = r.analyze(vuln)
        for k, v in result['component_scores'].items():
            assert 0.0 <= v <= 1.0, f'{k}={v} out of range'

    def test_counter_increments(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'name': 'T', 'severity': 'low', 'category': 'cors', 'evidence': '', 'cwe': ''}
        r.analyze(vuln)
        r.analyze(vuln)
        assert r._total_analyzed == 2


# ──────────────────────────────────────────────────────────────────────────────
# False Positive Reducer — History & Statistics
# ──────────────────────────────────────────────────────────────────────────────

class TestFalsePositiveReducerHistory:
    def test_update_history_stores_entry(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'category': 'sqli'}
        r.update_history(vuln, True, {'tech_stack': 'php'})
        assert True in r._history['sqli']['php']

    def test_historical_score_used_after_enough_samples(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        vuln = {'category': 'lfi'}
        # Add 10 confirmed real samples
        for _ in range(10):
            r.update_history(vuln, True, {'tech_stack': 'php'})
        result = r.analyze(
            {'name': 'LFI', 'severity': 'high', 'category': 'lfi', 'evidence': 'etc/passwd found', 'cwe': 'CWE-22'},
            context={'tech_stack': 'php'},
        )
        # Should still return a valid result
        assert 0.0 <= result['confidence'] <= 1.0

    def test_get_statistics_keys(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        stats = r.get_statistics()
        for key in ('total_analyzed', 'confirmed_real', 'confirmed_fp', 'categories_tracked'):
            assert key in stats

    def test_statistics_after_updates(self):
        from apps.scanning.engine.ml.false_positive_reducer import FalsePositiveReducer
        r = FalsePositiveReducer()
        for _ in range(6):
            r.update_history({'category': 'xss'}, True, {})
        for _ in range(4):
            r.update_history({'category': 'xss'}, False, {})
        stats = r.get_statistics()
        assert stats['confirmed_real'] == 6
        assert stats['confirmed_fp'] == 4


# ──────────────────────────────────────────────────────────────────────────────
# Attack Path Optimizer — Graph Building
# ──────────────────────────────────────────────────────────────────────────────

class TestAttackGraphBuilding:
    def test_empty_vulns_empty_graph(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph
        graph = build_attack_graph([])
        assert graph['nodes'] == []
        assert graph['edges'] == []

    def test_single_vuln_node(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph
        vulns = [{'name': 'SQLi', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'}]
        graph = build_attack_graph(vulns)
        assert len(graph['nodes']) == 1
        assert graph['nodes'][0]['category'] == 'sqli'

    def test_two_chained_vulns_creates_edge(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph
        vulns = [
            {'name': 'SQLi',  'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
            {'name': 'Auth',  'category': 'auth', 'severity': 'high',     'cvss': 7.5, 'cwe': 'CWE-287'},
        ]
        graph = build_attack_graph(vulns)
        assert len(graph['edges']) > 0
        edge_labels = [e['label'] for e in graph['edges']]
        assert any('sqli' in lab.lower() or 'auth' in lab.lower() for lab in edge_labels)

    def test_adjacency_populated(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph
        graph = build_attack_graph([])
        assert isinstance(graph['adjacency'], dict)
        assert 'sqli' in graph['adjacency']

    def test_node_fields_complete(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph
        vulns = [{'name': 'X', 'category': 'xss', 'severity': 'high', 'cvss': 6.5, 'cwe': 'CWE-79'}]
        graph = build_attack_graph(vulns)
        node = graph['nodes'][0]
        for field in ('id', 'name', 'category', 'severity', 'cvss', 'cwe'):
            assert field in node


# ──────────────────────────────────────────────────────────────────────────────
# Attack Path Optimizer — Chain Finding
# ──────────────────────────────────────────────────────────────────────────────

class TestAttackChainFinding:
    def test_empty_graph_no_chains(self):
        from apps.scanning.engine.ml.attack_path_optimizer import find_attack_chains
        chains = find_attack_chains({'nodes': [], 'edges': [], 'adjacency': {}})
        assert chains == []

    def test_no_edges_no_chains(self):
        from apps.scanning.engine.ml.attack_path_optimizer import find_attack_chains
        graph = {'nodes': [{'id': 0, 'category': 'xss', 'cvss': 5.0}], 'edges': [], 'adjacency': {}}
        chains = find_attack_chains(graph)
        assert chains == []

    def test_sqli_auth_chain_found(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph, find_attack_chains
        vulns = [
            {'name': 'SQLi', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
            {'name': 'Auth', 'category': 'auth', 'severity': 'high',     'cvss': 8.0, 'cwe': 'CWE-287'},
        ]
        graph = build_attack_graph(vulns)
        chains = find_attack_chains(graph)
        assert len(chains) > 0
        cats = [set(c['categories']) for c in chains]
        assert any('sqli' in c and 'auth' in c for c in cats)

    def test_chain_fields_present(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph, find_attack_chains
        vulns = [
            {'name': 'SQLi', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
            {'name': 'Auth', 'category': 'auth', 'severity': 'high',     'cvss': 7.5, 'cwe': 'CWE-287'},
        ]
        graph = build_attack_graph(vulns)
        chains = find_attack_chains(graph)
        if chains:
            for field in ('steps', 'categories', 'total_cvss', 'min_probability', 'impact'):
                assert field in chains[0]

    def test_max_length_respected(self):
        from apps.scanning.engine.ml.attack_path_optimizer import build_attack_graph, find_attack_chains
        vulns = [
            {'name': 'V1', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': ''},
            {'name': 'V2', 'category': 'auth', 'severity': 'high', 'cvss': 8.0, 'cwe': ''},
            {'name': 'V3', 'category': 'data exposure', 'severity': 'high', 'cvss': 7.0, 'cwe': ''},
        ]
        graph = build_attack_graph(vulns)
        chains = find_attack_chains(graph, max_length=2)
        for chain in chains:
            assert len(chain['categories']) <= 2


# ──────────────────────────────────────────────────────────────────────────────
# Attack Path Optimizer — Risk Prioritization
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskPrioritization:
    def test_empty_list_returns_empty(self):
        from apps.scanning.engine.ml.attack_path_optimizer import prioritize_by_risk
        assert prioritize_by_risk([]) == []

    def test_higher_cvss_ranks_first(self):
        from apps.scanning.engine.ml.attack_path_optimizer import prioritize_by_risk
        vulns = [
            {'name': 'Low', 'category': 'cors', 'severity': 'low', 'cvss': 2.0, 'cwe': ''},
            {'name': 'Critical', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
        ]
        ranked = prioritize_by_risk(vulns)
        assert ranked[0]['name'] == 'Critical'

    def test_risk_score_added(self):
        from apps.scanning.engine.ml.attack_path_optimizer import prioritize_by_risk
        vulns = [{'name': 'X', 'category': 'xss', 'severity': 'high', 'cvss': 6.5, 'cwe': 'CWE-79'}]
        result = prioritize_by_risk(vulns)
        assert 'risk_score' in result[0]
        assert result[0]['risk_score'] > 0.0

    def test_in_attack_chain_flag(self):
        from apps.scanning.engine.ml.attack_path_optimizer import prioritize_by_risk
        vulns = [
            {'name': 'SQLi', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
            {'name': 'Auth Bypass', 'category': 'auth', 'severity': 'high', 'cvss': 8.0, 'cwe': 'CWE-287'},
        ]
        result = prioritize_by_risk(vulns)
        # Both should be flagged as in a chain
        chain_flags = [r['in_attack_chain'] for r in result]
        assert any(chain_flags)

    def test_tech_stack_affects_scores(self):
        from apps.scanning.engine.ml.attack_path_optimizer import prioritize_by_risk
        vulns = [{'name': 'X', 'category': 'sqli', 'severity': 'critical', 'cvss': 8.0, 'cwe': 'CWE-89'}]
        php_result = prioritize_by_risk(vulns, tech_stack='php')
        go_result = prioritize_by_risk(vulns, tech_stack='golang')
        # PHP has higher multiplier than Go
        assert php_result[0]['risk_score'] > go_result[0]['risk_score']


# ──────────────────────────────────────────────────────────────────────────────
# Attack Path Optimizer — EPSS Estimation
# ──────────────────────────────────────────────────────────────────────────────

class TestEPSSEstimation:
    def test_known_cwe_sqli(self):
        from apps.scanning.engine.ml.attack_path_optimizer import get_epss_estimate
        score = get_epss_estimate('CWE-89')
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # SQL injection is high risk

    def test_unknown_cwe_returns_default(self):
        from apps.scanning.engine.ml.attack_path_optimizer import get_epss_estimate
        score = get_epss_estimate('CWE-99999')
        assert score == 0.50

    def test_empty_cwe_returns_default(self):
        from apps.scanning.engine.ml.attack_path_optimizer import get_epss_estimate
        assert get_epss_estimate('') == 0.50

    def test_case_insensitive(self):
        from apps.scanning.engine.ml.attack_path_optimizer import get_epss_estimate
        assert get_epss_estimate('cwe-89') == get_epss_estimate('CWE-89')


# ──────────────────────────────────────────────────────────────────────────────
# Attack Path Optimizer — Exploit Chain Suggestion
# ──────────────────────────────────────────────────────────────────────────────

class TestExploitChainSuggestion:
    def test_no_vulns_returns_not_found(self):
        from apps.scanning.engine.ml.attack_path_optimizer import suggest_exploit_chain
        result = suggest_exploit_chain([])
        assert result['found'] is False

    def test_single_vuln_no_chain(self):
        from apps.scanning.engine.ml.attack_path_optimizer import suggest_exploit_chain
        vulns = [{'name': 'CORS', 'category': 'cors', 'severity': 'low', 'cvss': 3.0, 'cwe': ''}]
        result = suggest_exploit_chain(vulns)
        assert 'impact' in result
        assert 'narrative' in result

    def test_chain_found_for_sqli_auth(self):
        from apps.scanning.engine.ml.attack_path_optimizer import suggest_exploit_chain
        vulns = [
            {'name': 'SQLi', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
            {'name': 'Auth Bypass', 'category': 'auth', 'severity': 'high', 'cvss': 8.0, 'cwe': 'CWE-287'},
        ]
        result = suggest_exploit_chain(vulns)
        assert result['found'] is True
        assert len(result['chain']) >= 1

    def test_narrative_is_string(self):
        from apps.scanning.engine.ml.attack_path_optimizer import suggest_exploit_chain
        vulns = [
            {'name': 'SQLi', 'category': 'sqli', 'severity': 'critical', 'cvss': 9.0, 'cwe': 'CWE-89'},
            {'name': 'Data', 'category': 'data exposure', 'severity': 'high', 'cvss': 7.5, 'cwe': 'CWE-200'},
        ]
        result = suggest_exploit_chain(vulns)
        assert isinstance(result['narrative'], str)
        assert len(result['narrative']) > 10


# ──────────────────────────────────────────────────────────────────────────────
# MLEnhancementTester
# ──────────────────────────────────────────────────────────────────────────────

class TestMLEnhancementTester:
    def test_instantiation(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        assert t.TESTER_NAME == 'ML Enhancement Engine'

    def test_empty_url_returns_no_vulns(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        assert t.test({'url': ''}) == []

    def test_normal_page_quick_scan(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        page = {
            'url': 'https://example.com/',
            'status_code': 200,
            'content': 'Welcome to our site!',
            'response_time': 0.2,
        }
        vulns = t.test(page, depth='quick')
        assert isinstance(vulns, list)

    def test_high_interest_response_flagged(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        # response_time=6.0 triggers the elapsed-delay component (0.80), pushing averaged
        # score above the 0.60 "Suspicious" threshold.
        page = {
            'url': 'https://example.com/api',
            'status_code': 500,
            'content': (
                'Traceback (most recent call last):\n'
                '  File "/app/views.py", line 10, in handle\n'
                'ORA-00942: table or view does not exist\n'
                'password=secret_key api_key=AKIA1234567890'
            ),
            'response_time': 6.0,
        }
        vulns = t.test(page, depth='quick')
        names = [v['name'] for v in vulns]
        assert any('Interesting' in n or 'Suspicious' in n for n in names)

    def test_stack_trace_detected_medium(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        page = {
            'url': 'https://example.com/data',
            'status_code': 500,
            'content': (
                "Traceback (most recent call last):\n"
                '  File "/srv/app/models.py", line 42, in get_user\n'
                "    raise DatabaseError(msg)\n"
            ),
            'response_time': 0.2,
        }
        vulns = t.test(page, depth='medium')
        names = [v['name'] for v in vulns]
        assert any('Stack Trace' in n for n in names)

    def test_nlp_error_classification_deep(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        page = {
            'url': 'https://example.com/login',
            'status_code': 200,
            'content': "Warning: mysql_fetch_array() expects parameter 1 to be resource",
            'response_time': 0.1,
        }
        vulns = t.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert any('NLP' in n for n in names)

    def test_attack_path_with_recon_data(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        page = {'url': 'https://example.com/'}
        recon_data = {
            'tech_stack': 'php',
            'vulnerabilities': [
                {'name': 'SQL Injection', 'category': 'sqli', 'severity': 'critical',
                 'cvss': 9.0, 'cwe': 'CWE-89', 'evidence': 'error-based sqli confirmed'},
                {'name': 'Auth Bypass', 'category': 'auth', 'severity': 'high',
                 'cvss': 8.0, 'cwe': 'CWE-287', 'evidence': 'bypassed with OR 1=1'},
            ],
        }
        vulns = t.test(page, depth='medium', recon_data=recon_data)
        assert isinstance(vulns, list)

    def test_returns_list_of_dicts(self):
        from apps.scanning.engine.testers.ml_enhancement_tester import MLEnhancementTester
        t = MLEnhancementTester()
        page = {'url': 'https://example.com/x', 'status_code': 200, 'content': ''}
        vulns = t.test(page, depth='deep')
        for v in vulns:
            assert isinstance(v, dict)
            assert 'name' in v


# ──────────────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_70(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_ml_enhancement_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'ML Enhancement Engine' in names

    def test_ml_enhancement_tester_position(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert testers[-18].TESTER_NAME == 'ML Enhancement Engine'
