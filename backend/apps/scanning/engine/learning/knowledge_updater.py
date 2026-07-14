"""
Knowledge Updater — Update the scanner's knowledge base from external sources.

Sources:
  - CVE/NVD feeds (new vulnerability data)
  - CWE database updates
  - Previous scan outcomes (what worked / didn't)
  - LLM-generated insights from scan results

Feeds updates into:
  - VulnKB and RemediationKB
  - ML model retraining data
  - Payload selection preferences
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeEntry:
    """A single knowledge entry (CVE, technique, pattern)."""
    entry_id: str
    entry_type: str  # cve, technique, payload_pattern, waf_bypass
    title: str
    description: str = ''
    severity: str = 'medium'
    affected_tech: list[str] = field(default_factory=list)
    cwe: str = ''
    cvss: float = 0.0
    payloads: list[str] = field(default_factory=list)
    source: str = ''
    timestamp: float = 0.0


class KnowledgeUpdater:
    """Update and manage the scanner's knowledge base."""

    DEFAULT_PATH = Path(__file__).parent.parent / 'data' / 'knowledge_updates.json'

    def __init__(self, path: Path | str | None = None):
        self._path = Path(path) if path else self.DEFAULT_PATH
        self._entries: dict[str, KnowledgeEntry] = {}
        self._load()

    def add_entry(self, entry: KnowledgeEntry) -> None:
        """Add or update a knowledge entry."""
        if not entry.timestamp:
            entry.timestamp = time.time()
        self._entries[entry.entry_id] = entry
        self._save()

    def add_from_scan_findings(self, findings: list[dict],
                                tech_stack: list[str] | None = None) -> int:
        """Extract knowledge from confirmed scan findings.

        Returns number of entries added.
        """
        added = 0
        for f in findings:
            if not f.get('is_confirmed', True):
                continue

            entry_id = f'scan_{f.get("category", "unknown")}_{added}'
            cat = (f.get('category', '') or '').lower()
            entry = KnowledgeEntry(
                entry_id=entry_id,
                entry_type='technique',
                title=f.get('name', cat),
                description=f.get('description', ''),
                severity=f.get('severity', 'medium'),
                affected_tech=tech_stack or [],
                cwe=f.get('cwe', ''),
                payloads=[f.get('payload', '')] if f.get('payload') else [],
                source='scan_result',
                timestamp=time.time(),
            )
            self._entries[entry_id] = entry
            added += 1

        if added:
            self._save()
        return added

    def add_from_llm_analysis(self, analysis: dict) -> int:
        """Ingest knowledge from LLM reasoning output.

        Expects analysis dict with keys like 'new_techniques', 'patterns'.
        """
        added = 0
        for technique in analysis.get('new_techniques', []):
            entry_id = f'llm_{technique.get("name", "unknown")}_{int(time.time())}'
            entry = KnowledgeEntry(
                entry_id=entry_id,
                entry_type='technique',
                title=technique.get('name', ''),
                description=technique.get('description', ''),
                severity=technique.get('severity', 'medium'),
                payloads=technique.get('payloads', []),
                source='llm_analysis',
                timestamp=time.time(),
            )
            self._entries[entry_id] = entry
            added += 1

        if added:
            self._save()
        return added

    def get_entries(self, entry_type: str = '',
                    severity: str = '') -> list[KnowledgeEntry]:
        """Query knowledge entries by type and/or severity."""
        results = list(self._entries.values())
        if entry_type:
            results = [e for e in results if e.entry_type == entry_type]
        if severity:
            results = [e for e in results if e.severity == severity]
        return sorted(results, key=lambda e: e.timestamp, reverse=True)

    def get_payloads_for_tech(self, tech: str) -> list[str]:
        """Get all known payloads relevant to a technology."""
        payloads = []
        tech_lower = tech.lower()
        for entry in self._entries.values():
            if any(tech_lower in t.lower() for t in entry.affected_tech):
                payloads.extend(entry.payloads)
        return payloads

    def summary(self) -> dict:
        return {
            'total_entries': len(self._entries),
            'by_type': self._count_by('entry_type'),
            'by_source': self._count_by('source'),
        }

    def _count_by(self, attr: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self._entries.values():
            val = getattr(entry, attr, 'unknown')
            counts[val] = counts.get(val, 0) + 1
        return counts

    # ── Persistence ───────────────────────────────────────────────────────

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for eid, entry in self._entries.items():
                data[eid] = {
                    'entry_id': entry.entry_id,
                    'entry_type': entry.entry_type,
                    'title': entry.title,
                    'description': entry.description,
                    'severity': entry.severity,
                    'affected_tech': entry.affected_tech,
                    'cwe': entry.cwe,
                    'cvss': entry.cvss,
                    'payloads': entry.payloads[:10],
                    'source': entry.source,
                    'timestamp': entry.timestamp,
                }
            self._path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        except Exception as e:
            logger.debug('KnowledgeUpdater save error: %s', e)

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding='utf-8'))
            for eid, d in data.items():
                self._entries[eid] = KnowledgeEntry(
                    entry_id=d.get('entry_id', eid),
                    entry_type=d.get('entry_type', ''),
                    title=d.get('title', ''),
                    description=d.get('description', ''),
                    severity=d.get('severity', 'medium'),
                    affected_tech=d.get('affected_tech', []),
                    cwe=d.get('cwe', ''),
                    cvss=d.get('cvss', 0),
                    payloads=d.get('payloads', []),
                    source=d.get('source', ''),
                    timestamp=d.get('timestamp', 0),
                )
            logger.debug('KnowledgeUpdater loaded: %d entries', len(self._entries))
        except Exception as e:
            logger.debug('KnowledgeUpdater load error: %s', e)
