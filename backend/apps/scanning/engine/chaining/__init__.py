"""Vulnerability Chaining Engine — Detect and prove multi-step attack chains."""
from .chain_detector import ChainDetector
from .chain_models import AttackChain, ChainStep, ChainSeverity

__all__ = ['ChainDetector', 'AttackChain', 'ChainStep', 'ChainSeverity']
