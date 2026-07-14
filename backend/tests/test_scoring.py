"""Tests for the CVSS calculator and security scoring utilities."""
import pytest
from apps.scanning.engine.scoring import (
    calculate_cvss_base,
    severity_from_cvss,
    calculate_security_score,
    categorize_score,
    SEVERITY_CVSS_MAP,
)


class TestSeverityFromCvss:
    def test_critical(self):
        assert severity_from_cvss(9.0) == 'critical'
        assert severity_from_cvss(10.0) == 'critical'
        assert severity_from_cvss(9.8) == 'critical'

    def test_high(self):
        assert severity_from_cvss(7.0) == 'high'
        assert severity_from_cvss(8.9) == 'high'

    def test_medium(self):
        assert severity_from_cvss(4.0) == 'medium'
        assert severity_from_cvss(6.9) == 'medium'

    def test_low(self):
        assert severity_from_cvss(0.1) == 'low'
        assert severity_from_cvss(3.9) == 'low'

    def test_info(self):
        assert severity_from_cvss(0.0) == 'info'


class TestCalculateCvssBase:
    def test_zero_impact_returns_zero(self):
        score = calculate_cvss_base(c='N', i='N', a='N')
        assert score == 0.0

    def test_critical_rce_vector(self):
        """Network / Low complexity / No privs / No interaction / High CIA."""
        score = calculate_cvss_base(av='N', ac='L', pr='N', ui='N', scope='U',
                                    c='H', i='H', a='H')
        assert 9.0 <= score <= 10.0

    def test_scope_changed_higher_score(self):
        """Scope changed should generally raise the score."""
        unchanged = calculate_cvss_base(av='N', ac='L', pr='N', ui='N', scope='U',
                                        c='L', i='L', a='N')
        changed = calculate_cvss_base(av='N', ac='L', pr='N', ui='N', scope='C',
                                      c='L', i='L', a='N')
        assert changed >= unchanged

    def test_physical_access_lower_score(self):
        score = calculate_cvss_base(av='P', ac='H', pr='H', ui='R', scope='U',
                                    c='L', i='N', a='N')
        assert score < 4.0

    def test_all_max_returns_ten(self):
        score = calculate_cvss_base(av='N', ac='L', pr='N', ui='N', scope='C',
                                    c='H', i='H', a='H')
        assert score == 10.0


class TestCalculateSecurityScore:
    def test_no_vulns_returns_100(self):
        assert calculate_security_score([]) == 100

    def test_single_critical(self):
        vulns = [{'severity': 'critical'}]
        score = calculate_security_score(vulns)
        assert score == 75  # 100 - 25

    def test_single_info_no_deduction(self):
        vulns = [{'severity': 'info'}]
        score = calculate_security_score(vulns)
        assert score == 100

    def test_diminishing_returns(self):
        """Multiple critical vulns should deduct less each time."""
        one = calculate_security_score([{'severity': 'critical'}])
        two = calculate_security_score([{'severity': 'critical'}] * 2)
        three = calculate_security_score([{'severity': 'critical'}] * 3)
        # Each additional critical deducts less
        assert (one - two) > (two - three)

    def test_mixed_severities(self):
        vulns = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'low'},
        ]
        score = calculate_security_score(vulns)
        assert 0 <= score <= 100
        assert score < 75  # Must be below single-critical-only score

    def test_floor_at_zero(self):
        """Score should never go below 0."""
        many = [{'severity': 'critical'}] * 50
        score = calculate_security_score(many)
        assert score >= 0


class TestCategorizeScore:
    @pytest.mark.parametrize('score,grade', [
        (100, 'A'), (90, 'A'),
        (89, 'B'), (80, 'B'),
        (79, 'C'), (70, 'C'),
        (69, 'D'), (50, 'D'),
        (49, 'F'), (0, 'F'),
    ])
    def test_grades(self, score, grade):
        assert categorize_score(score) == grade


class TestSeverityCvssMap:
    def test_all_severities_mapped(self):
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            assert sev in SEVERITY_CVSS_MAP
    
    def test_values_ordered(self):
        assert SEVERITY_CVSS_MAP['critical'] > SEVERITY_CVSS_MAP['high']
        assert SEVERITY_CVSS_MAP['high'] > SEVERITY_CVSS_MAP['medium']
        assert SEVERITY_CVSS_MAP['medium'] > SEVERITY_CVSS_MAP['low']
        assert SEVERITY_CVSS_MAP['low'] > SEVERITY_CVSS_MAP['info']
