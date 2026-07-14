"""
QA Scope Refusal Test Suite (Phase B2)
Verifies that the QA suite hardcodes the isolated target network as the ONLY allowed scope
and refuses to run against external or non-target URLs.
"""
import os
import pytest
from apps.scanning.engine.scope.scope_manager import ScopeManager


def test_qa_scope_refusal(monkeypatch):
    """Verify ScopeManager refuses targets outside the hardcoded QA network when ENFORCE_QA_SCOPE=true."""
    monkeypatch.setenv("ENFORCE_QA_SCOPE", "true")
    
    # Initialize ScopeManager with wildcards that would normally allow anything
    sm = ScopeManager(in_scope=["*"])
    
    # 1. Assert external internet targets are HARD REJECTED
    assert sm.is_in_scope("https://google.com") is False
    assert sm.is_in_scope("http://production-server.internal") is False
    assert sm.is_in_scope("https://example.com/login") is False
    
    # 2. Assert isolated QA targets are ALLOWED
    assert sm.is_in_scope("http://127.0.0.1:8081") is True
    assert sm.is_in_scope("http://localhost:3000") is True
    assert sm.is_in_scope("http://target-dvwa") is True
    assert sm.is_in_scope("http://target-juiceshop:3000") is True
    assert sm.is_in_scope("http://target-webgoat:8080/WebGoat/login") is True


def test_validate_targets_partitioning(monkeypatch):
    """Verify partition behavior blocks out of scope targets during batch check."""
    monkeypatch.setenv("ENFORCE_QA_SCOPE", "true")
    sm = ScopeManager(in_scope=["*"])
    
    targets = ["http://127.0.0.1:8081", "https://evil.com", "http://target-dvwa"]
    in_scope, out_scope = sm.validate_targets(targets)
    
    assert in_scope == ["http://127.0.0.1:8081", "http://target-dvwa"]
    assert out_scope == ["https://evil.com"]
