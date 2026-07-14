"""
Scan Controller — Phase 15 Distributed Scanning.

Splits a large scan into independent chunks and merges results when each
chunk completes.  Designed to work with Celery so each chunk can run on
a different worker process.
"""
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────────

@dataclass
class ScanChunk:
    """A unit of work that can be dispatched to a Celery worker."""
    chunk_id: str
    scan_id: int
    chunk_type: str          # 'recon' | 'crawl' | 'testing' | 'verification'
    payload: dict            # Chunk-specific inputs (urls, modules, etc.)
    status: str = 'pending'  # pending | running | done | failed
    result: dict = field(default_factory=dict)
    error: str = ''
    worker_id: str = ''
    progress: float = 0.0    # 0.0–1.0


# ──────────────────────────────────────────────────
# Scan Controller
# ──────────────────────────────────────────────────

class ScanController:
    """
    Coordinates distributed execution of a single scan across multiple workers.

    Lifecycle:
        1. split_recon()    → list[ScanChunk]  (subdomain/port recon tasks)
        2. split_testing()  → list[ScanChunk]  (one chunk per URL bucket)
        3. register_result() is called by workers as they finish
        4. merge_results()  → unified vulnerability list
        5. get_progress()   → float 0.0-1.0
    """

    # How many URLs to put into each testing chunk
    URLS_PER_CHUNK = 20

    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self._chunks: dict[str, ScanChunk] = {}

    # ── Splitting ──────────────────────────────────

    def split_recon(self, target: str, recon_modules: list[str]) -> list[ScanChunk]:
        """Create one chunk per recon module so they run in parallel."""
        chunks = []
        for module in recon_modules:
            chunk = ScanChunk(
                chunk_id=str(uuid.uuid4()),
                scan_id=self.scan_id,
                chunk_type='recon',
                payload={'target': target, 'module': module},
            )
            self._chunks[chunk.chunk_id] = chunk
            chunks.append(chunk)
        logger.info(f'[scan={self.scan_id}] Created {len(chunks)} recon chunks')
        return chunks

    def split_testing(self, urls: list[str], tester_names: list[str]) -> list[ScanChunk]:
        """
        Bucket URLs into groups of URLS_PER_CHUNK.
        Each chunk carries the full tester list so workers can run all
        relevant testers against its URL slice independently.
        """
        chunks = []
        for i in range(0, max(len(urls), 1), self.URLS_PER_CHUNK):
            bucket = urls[i: i + self.URLS_PER_CHUNK]
            chunk = ScanChunk(
                chunk_id=str(uuid.uuid4()),
                scan_id=self.scan_id,
                chunk_type='testing',
                payload={'urls': bucket, 'testers': tester_names},
            )
            self._chunks[chunk.chunk_id] = chunk
            chunks.append(chunk)
        logger.info(f'[scan={self.scan_id}] Created {len(chunks)} testing chunks '
                    f'for {len(urls)} URLs')
        return chunks

    # ── Result collection ──────────────────────────

    def register_result(self, chunk_id: str, result: dict,
                         worker_id: str = '') -> None:
        """Record the outcome of a completed chunk."""
        if chunk_id not in self._chunks:
            logger.warning(f'register_result: unknown chunk_id {chunk_id}')
            return
        chunk = self._chunks[chunk_id]
        chunk.status = 'done'
        chunk.result = result
        chunk.worker_id = worker_id
        chunk.progress = 1.0
        logger.debug(f'Chunk {chunk_id} registered (worker={worker_id})')

    def register_failure(self, chunk_id: str, error: str) -> None:
        """Mark a chunk as failed."""
        if chunk_id not in self._chunks:
            return
        chunk = self._chunks[chunk_id]
        chunk.status = 'failed'
        chunk.error = error
        logger.warning(f'Chunk {chunk_id} failed: {error}')

    def update_progress(self, chunk_id: str, progress: float) -> None:
        """Update the progress of a running chunk (0.0–1.0)."""
        if chunk_id in self._chunks:
            self._chunks[chunk_id].progress = max(0.0, min(1.0, progress))

    # ── Merging ────────────────────────────────────

    def merge_results(self) -> dict[str, Any]:
        """
        Combine results from all completed chunks into a single dict:
        {
            'recon': {...merged recon data...},
            'vulnerabilities': [...all vulns...],
            'failed_chunks': [...chunk_ids...],
        }
        """
        merged: dict[str, Any] = {
            'recon': {},
            'vulnerabilities': [],
            'failed_chunks': [],
        }

        for chunk in self._chunks.values():
            if chunk.status == 'failed':
                merged['failed_chunks'].append({
                    'chunk_id': chunk.chunk_id,
                    'type': chunk.chunk_type,
                    'error': chunk.error,
                })
                continue

            if chunk.chunk_type == 'recon':
                # Merge recon dicts — module key → data
                module = chunk.payload.get('module', 'unknown')
                merged['recon'][module] = chunk.result

            elif chunk.chunk_type == 'testing':
                vulns = chunk.result.get('vulnerabilities', [])
                merged['vulnerabilities'].extend(vulns)

        # Deduplicate vulnerabilities by (url, name, parameter)
        seen = set()
        deduped = []
        for v in merged['vulnerabilities']:
            key = (v.get('url', ''), v.get('name', ''), v.get('parameter', ''))
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        merged['vulnerabilities'] = deduped

        logger.info(f'[scan={self.scan_id}] Merge complete: '
                    f'{len(merged["vulnerabilities"])} vulns, '
                    f'{len(merged["failed_chunks"])} failed chunks')
        return merged

    # ── Progress ───────────────────────────────────

    def get_progress(self) -> float:
        """Return overall scan progress as a float 0.0–1.0."""
        if not self._chunks:
            return 0.0
        total = sum(c.progress for c in self._chunks.values())
        return total / len(self._chunks)

    def get_chunk_summary(self) -> list[dict]:
        """Return a summary of all chunks for status reporting."""
        return [
            {
                'chunk_id': c.chunk_id,
                'type': c.chunk_type,
                'status': c.status,
                'progress': c.progress,
                'worker_id': c.worker_id,
                'error': c.error,
            }
            for c in self._chunks.values()
        ]
