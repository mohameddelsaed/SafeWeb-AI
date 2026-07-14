"""
Chain Models — Data models for vulnerability chain detection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ChainSeverity(str, Enum):
    """Severity of a complete attack chain (typically higher than individual vulns)."""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'

    @classmethod
    def from_combined_score(cls, score: float) -> 'ChainSeverity':
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class ChainStep:
    """One step in a multi-step attack chain."""
    order: int
    vuln_type: str         # e.g. 'ssrf', 'xss', 'idor'
    description: str
    url: str = ''
    payload: str = ''
    evidence: str = ''
    severity: str = 'medium'
    finding_id: str = ''   # Reference to original finding


@dataclass
class AttackChain:
    """A complete multi-step attack chain."""
    chain_id: str
    name: str               # e.g. "SSRF → Internal Service → RCE"
    steps: list[ChainStep] = field(default_factory=list)
    combined_severity: ChainSeverity = ChainSeverity.HIGH
    combined_cvss: float = 0.0
    impact: str = ''
    prerequisites: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def vuln_types(self) -> list[str]:
        return [s.vuln_type for s in self.steps]
