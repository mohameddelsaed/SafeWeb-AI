from __future__ import annotations

from typing import Iterable


PLACEHOLDER_MARKERS = [
    'Write a concise business and engineering impact statement.',
    'Explain the attack chain step by step with realistic examples.',
    'Include vulnerable patterns in pseudocode or framework-specific snippets.',
    'Include secure coding examples and explicit rationale.',
    'Primary standard reference URL',
]


def detect_placeholders(content: str) -> list[str]:
    """Return placeholder markers still present in article content."""
    if not content:
        return []
    return [marker for marker in PLACEHOLDER_MARKERS if marker in content]


def _normalize_count(items: Iterable | None) -> int:
    if items is None:
        return 0
    if isinstance(items, str):
        return 1 if items.strip() else 0
    try:
        return len(list(items))
    except TypeError:
        return 0


def compute_quality_score(
    *,
    content: str,
    references: Iterable | None,
    cwe_ids: Iterable | None,
    owasp_refs: Iterable | None,
    tags: Iterable | None,
    source_count: int | None,
    read_time: int | None,
) -> tuple[int, dict[str, int]]:
    """Compute a coarse quality score for editorial publish gates.

    Score range is 0-100.
    """
    text = content or ''
    ref_count = _normalize_count(references)
    cwe_count = _normalize_count(cwe_ids)
    owasp_count = _normalize_count(owasp_refs)
    tag_count = _normalize_count(tags)
    src_count = max(0, int(source_count or 0))
    rt = max(0, int(read_time or 0))

    points_content = min(30, int((len(text) / 3500) * 30))
    points_refs = min(20, ref_count * 5)
    points_cwe = min(10, cwe_count * 5)
    points_owasp = min(10, owasp_count * 5)
    points_tags = min(10, tag_count * 2)
    points_sources = min(10, src_count * 2)

    # Reward practical depth range rather than short notes.
    if rt >= 10:
        points_read_time = min(10, int((rt / 20) * 10))
    else:
        points_read_time = int((rt / 10) * 4)

    penalties = 0
    if detect_placeholders(text):
        penalties += 20

    score = max(
        0,
        min(
            100,
            points_content
            + points_refs
            + points_cwe
            + points_owasp
            + points_tags
            + points_sources
            + points_read_time
            - penalties,
        ),
    )

    breakdown = {
        'content': points_content,
        'references': points_refs,
        'cwe': points_cwe,
        'owasp': points_owasp,
        'tags': points_tags,
        'sources': points_sources,
        'read_time': points_read_time,
        'penalties': penalties,
    }
    return score, breakdown
