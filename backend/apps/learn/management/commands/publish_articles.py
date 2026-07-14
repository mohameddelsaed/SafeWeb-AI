import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db.utils import OperationalError, ProgrammingError
from django.db import transaction
from django.utils import timezone

from apps.learn.models import Article
from apps.learn.quality import compute_quality_score


class Command(BaseCommand):
    help = 'Update article workflow status for a list of slugs or IDs.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--source',
            help='Optional JSON source file containing article objects or slug/id strings.',
        )
        parser.add_argument(
            '--slug',
            action='append',
            default=[],
            help='Article slug to update. Repeat to add multiple values.',
        )
        parser.add_argument(
            '--id',
            action='append',
            default=[],
            help='Article UUID to update. Repeat to add multiple values.',
        )
        parser.add_argument(
            '--status',
            choices=['draft', 'review', 'published'],
            default='published',
            help='Target status for selected articles.',
        )
        parser.add_argument(
            '--touch-reviewed-at',
            action='store_true',
            help='Update last_reviewed_at to now when status is changed.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without writing to DB.',
        )
        parser.add_argument(
            '--allow-missing',
            action='store_true',
            help='Do not fail when no matching articles are found.',
        )
        parser.add_argument(
            '--min-quality-score',
            type=int,
            default=0,
            help='Optional minimum quality score (0-100) required when publishing.',
        )
        parser.add_argument(
            '--allow-low-quality',
            action='store_true',
            help='Allow publishing below the min-quality-score threshold.',
        )

    def handle(self, *args, **options):
        source = options.get('source')
        requested_status = options['status']
        dry_run = options['dry_run']
        touch_reviewed_at = options['touch_reviewed_at']
        allow_missing = options['allow_missing']
        min_quality_score = max(0, min(100, int(options.get('min_quality_score', 0))))
        allow_low_quality = options['allow_low_quality']

        slugs = {slug.strip() for slug in options['slug'] if slug and slug.strip()}
        ids = {item.strip() for item in options['id'] if item and item.strip()}

        if source:
            source_slugs, source_ids = self._extract_targets_from_source(Path(source).resolve())
            slugs.update(source_slugs)
            ids.update(source_ids)

        if not slugs and not ids:
            raise CommandError('No targets provided. Use --slug, --id, or --source.')

        try:
            queryset = Article.objects.all()
            if slugs and ids:
                queryset = queryset.filter(slug__in=slugs) | Article.objects.filter(id__in=ids)
            elif slugs:
                queryset = queryset.filter(slug__in=slugs)
            else:
                queryset = queryset.filter(id__in=ids)

            articles = list(queryset.distinct())
        except (OperationalError, ProgrammingError) as exc:
            raise CommandError(
                'Learning Center tables are not available. Run migrations before publishing articles.'
            ) from exc
        if not articles:
            message = 'No matching articles were found for the provided targets.'
            if allow_missing or dry_run:
                self.stdout.write(self.style.WARNING(message))
                self.stdout.write(self.style.SUCCESS('No-op completed.'))
                return
            raise CommandError(message)

        publish_flag = requested_status == 'published'
        now = timezone.now() if touch_reviewed_at else None

        self.stdout.write(
            f'Preparing to update {len(articles)} article(s) to status={requested_status} is_published={publish_flag}.'
        )

        for article in articles:
            self.stdout.write(f' - {article.slug} ({article.id})')

        if publish_flag and min_quality_score > 0:
            low_quality = self._find_low_quality_articles(articles, min_quality_score)
            if low_quality and not allow_low_quality:
                for slug, score in low_quality:
                    self.stderr.write(self.style.ERROR(f' - {slug}: quality={score}'))
                raise CommandError(
                    f'{len(low_quality)} article(s) below minimum quality score {min_quality_score}. '
                    'Use --allow-low-quality to bypass.'
                )

        if dry_run:
            self.stdout.write(self.style.SUCCESS('Dry run complete. No changes were written.'))
            return

        with transaction.atomic():
            for article in articles:
                article.status = requested_status
                article.is_published = publish_flag
                update_fields = ['status', 'is_published', 'updated_at']
                if now:
                    article.last_reviewed_at = now
                    update_fields.append('last_reviewed_at')
                article.save(update_fields=update_fields)

        self.stdout.write(self.style.SUCCESS(f'Updated {len(articles)} article(s).'))

    @staticmethod
    def _extract_targets_from_source(path: Path):
        if not path.exists():
            raise CommandError(f'Source file does not exist: {path}')

        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise CommandError(f'Invalid JSON in source file: {exc}') from exc

        if not isinstance(payload, list):
            raise CommandError('Source JSON must be an array.')

        slugs = set()
        ids = set()
        for item in payload:
            # Support fixture style {model, fields, pk}
            if isinstance(item, dict) and 'fields' in item:
                fields = item.get('fields', {})
                if isinstance(fields, dict):
                    slug = fields.get('slug')
                    if slug:
                        slugs.add(str(slug).strip())
                if item.get('pk'):
                    ids.add(str(item['pk']).strip())
                continue

            # Support plain object style
            if isinstance(item, dict):
                slug = item.get('slug')
                if slug:
                    slugs.add(str(slug).strip())
                item_id = item.get('id')
                if item_id:
                    ids.add(str(item_id).strip())
                continue

            # Support raw string style slug
            if isinstance(item, str):
                value = item.strip()
                if value:
                    slugs.add(value)

        return slugs, ids

    @staticmethod
    def _find_low_quality_articles(articles, minimum):
        low_quality = []
        for article in articles:
            score, _ = compute_quality_score(
                content=article.content,
                references=article.references,
                cwe_ids=article.cwe_ids,
                owasp_refs=article.owasp_refs,
                tags=list(article.tags.values_list('slug', flat=True)),
                source_count=article.source_count,
                read_time=article.read_time,
            )
            if score < minimum:
                low_quality.append((article.slug, score))
        return low_quality
