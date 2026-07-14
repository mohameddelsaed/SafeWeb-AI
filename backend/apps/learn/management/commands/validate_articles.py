import json
from pathlib import Path
from urllib.parse import urlparse

from django.core.management.base import BaseCommand, CommandError
from django.db.utils import OperationalError, ProgrammingError

from apps.learn.models import Article, Category
from apps.learn.quality import compute_quality_score, detect_placeholders


class Command(BaseCommand):
    help = 'Validate Learning Center article batch files before bulk loading.'

    def add_arguments(self, parser):
        parser.add_argument('--source', required=True, help='Path to JSON file containing article objects.')
        parser.add_argument(
            '--strict',
            action='store_true',
            help='Treat warnings as errors (for CI quality gates).',
        )
        parser.add_argument(
            '--min-score',
            type=int,
            default=0,
            help='Optional minimum quality score threshold (0-100).',
        )

    def handle(self, *args, **options):
        source_path = Path(options['source']).resolve()
        strict = options['strict']
        min_score = max(0, min(100, int(options.get('min_score', 0))))

        payload = self._read_payload(source_path)
        normalized = [self._normalize(item) for item in payload]

        errors = []
        warnings = []
        scores = []

        seen_slugs = set()
        existing_slugs = self._safe_existing_slugs(normalized)
        valid_legacy_categories = {choice[0] for choice in Article.CATEGORY_CHOICES}
        valid_category_slugs = self._safe_existing_category_slugs()
        valid_difficulties = {choice[0] for choice in Article.DIFFICULTY_CHOICES}
        valid_statuses = {choice[0] for choice in Article.STATUS_CHOICES}

        for idx, item in enumerate(normalized, start=1):
            prefix = f'item {idx}'
            required_fields = ['title', 'slug', 'excerpt', 'content', 'category']
            for field in required_fields:
                if not item.get(field):
                    errors.append(f'{prefix}: missing required field "{field}"')

            slug = (item.get('slug') or '').strip()
            if slug:
                if slug in seen_slugs:
                    errors.append(f'{prefix}: duplicate slug in source file ({slug})')
                seen_slugs.add(slug)
                if slug in existing_slugs:
                    warnings.append(f'{prefix}: slug already exists in DB ({slug})')

            category = (item.get('category') or '').strip()
            if category and category not in valid_legacy_categories and category not in valid_category_slugs:
                errors.append(
                    f'{prefix}: unknown category "{category}" (not in legacy choices or seeded category slugs)'
                )

            difficulty = item.get('difficulty_level', 'practitioner')
            if difficulty not in valid_difficulties:
                errors.append(f'{prefix}: invalid difficulty_level "{difficulty}"')

            status = item.get('status', 'published')
            if status not in valid_statuses:
                errors.append(f'{prefix}: invalid status "{status}"')

            content = item.get('content') or ''
            if len(content) < 800:
                warnings.append(f'{prefix}: content is short ({len(content)} chars); target specialist depth may be unmet')

            if detect_placeholders(content):
                warnings.append(f'{prefix}: content still contains template placeholder text')

            references = item.get('references') or []
            if not isinstance(references, list):
                errors.append(f'{prefix}: references must be a JSON array')
            elif len(references) < 2:
                warnings.append(f'{prefix}: references count is {len(references)}; expected >= 2')
            else:
                invalid_urls = self._invalid_urls(references)
                if invalid_urls:
                    errors.append(f'{prefix}: invalid reference URLs: {", ".join(invalid_urls[:3])}')

            categories = item.get('categories') or []
            if categories and not isinstance(categories, list):
                errors.append(f'{prefix}: categories must be a JSON array when provided')

            cwe_ids = item.get('cwe_ids') or []
            if cwe_ids and not isinstance(cwe_ids, list):
                errors.append(f'{prefix}: cwe_ids must be a JSON array when provided')

            owasp_refs = item.get('owasp_refs') or []
            if owasp_refs and not isinstance(owasp_refs, list):
                errors.append(f'{prefix}: owasp_refs must be a JSON array when provided')

            score, _ = compute_quality_score(
                content=content,
                references=references if isinstance(references, list) else [],
                cwe_ids=cwe_ids if isinstance(cwe_ids, list) else [],
                owasp_refs=owasp_refs if isinstance(owasp_refs, list) else [],
                tags=item.get('tags') if isinstance(item.get('tags'), list) else [],
                source_count=item.get('source_count'),
                read_time=item.get('read_time'),
            )
            scores.append(score)

            if score < 55:
                warnings.append(f'{prefix}: quality score is low ({score}/100)')
            if min_score and score < min_score:
                errors.append(f'{prefix}: quality score {score} below required min-score {min_score}')

        if errors or (strict and warnings):
            for err in errors:
                self.stderr.write(self.style.ERROR(err))
            if strict:
                for warn in warnings:
                    self.stderr.write(self.style.ERROR(f'[strict-warning] {warn}'))
            raise CommandError(
                f'Validation failed with {len(errors)} errors and {len(warnings)} warnings.'
            )

        for warn in warnings:
            self.stdout.write(self.style.WARNING(warn))

        self.stdout.write(self.style.SUCCESS('Validation successful.'))
        self.stdout.write(f'Articles checked: {len(normalized)}')
        self.stdout.write(f'Warnings: {len(warnings)}')
        if scores:
            avg_score = round(sum(scores) / len(scores), 2)
            self.stdout.write(
                f'Quality scores: avg={avg_score} min={min(scores)} max={max(scores)}'
            )

    @staticmethod
    def _read_payload(path: Path):
        if not path.exists():
            raise CommandError(f'Source file does not exist: {path}')
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise CommandError(f'Invalid JSON in {path}: {exc}') from exc

        if not isinstance(payload, list):
            raise CommandError('Source JSON must be an array of article objects.')
        return payload

    @staticmethod
    def _normalize(item):
        if isinstance(item, dict) and 'model' in item and 'fields' in item:
            return dict(item['fields'])
        if isinstance(item, dict):
            return dict(item)
        return {}

    @staticmethod
    def _safe_existing_slugs(normalized_items):
        try:
            slugs = [x.get('slug') for x in normalized_items]
            return set(Article.objects.filter(slug__in=slugs).values_list('slug', flat=True))
        except (OperationalError, ProgrammingError):
            return set()

    @staticmethod
    def _safe_existing_category_slugs():
        try:
            return set(Category.objects.values_list('slug', flat=True))
        except (OperationalError, ProgrammingError):
            return set()

    @staticmethod
    def _invalid_urls(urls):
        invalid = []
        for value in urls:
            if not isinstance(value, str):
                invalid.append(str(value))
                continue
            parsed = urlparse(value)
            if parsed.scheme not in ('http', 'https') or not parsed.netloc:
                invalid.append(value)
        return invalid
