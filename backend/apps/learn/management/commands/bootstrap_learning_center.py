from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand

from apps.learn.models import Article


class Command(BaseCommand):
    help = (
        'Bootstrap Learning Center content by syncing taxonomy, loading article JSON '
        'batches, and publishing imported articles.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--source',
            action='append',
            default=[],
            help='Additional JSON source path(s) to import. Can be repeated.',
        )
        parser.add_argument(
            '--skip-taxonomy',
            action='store_true',
            help='Skip taxonomy sync step.',
        )
        parser.add_argument(
            '--skip-fixture',
            action='store_true',
            help='Skip default fixtures/articles.json import.',
        )
        parser.add_argument(
            '--skip-generated',
            action='store_true',
            help='Skip generated_* article batch imports.',
        )
        parser.add_argument(
            '--skip-curated',
            action='store_true',
            help='Skip curated_* article batch imports.',
        )
        parser.add_argument(
            '--skip-publish',
            action='store_true',
            help='Do not force imported articles to public published state.',
        )
        parser.add_argument('--batch-size', type=int, default=100, help='Batch size for inserts.')
        parser.add_argument('--dry-run', action='store_true', help='Validate without writing to DB.')

    def handle(self, *args, **options):
        skip_taxonomy = options['skip_taxonomy']
        skip_fixture = options['skip_fixture']
        skip_generated = options['skip_generated']
        skip_curated = options['skip_curated']
        skip_publish = options['skip_publish']
        dry_run = options['dry_run']
        batch_size = max(1, int(options['batch_size']))

        sources = self._resolve_sources(
            custom_sources=options['source'],
            skip_fixture=skip_fixture,
            skip_generated=skip_generated,
            skip_curated=skip_curated,
        )

        if not sources:
            self.stdout.write(self.style.WARNING('No article source files resolved. Nothing to import.'))
            return

        if not skip_taxonomy:
            self.stdout.write('Syncing Learning Center taxonomy...')
            call_command('seed_learning_taxonomy', dry_run=dry_run)

        initial_total = Article.objects.count()
        initial_published = Article.objects.filter(is_published=True, status='published').count()

        self.stdout.write(
            f'Importing {len(sources)} source file(s). '
            f'Current articles={initial_total}, published={initial_published}'
        )

        for source in sources:
            self.stdout.write(f'Loading source: {source}')
            call_command(
                'bulk_load_articles',
                source=str(source),
                batch_size=batch_size,
                skip_duplicates=True,
                dry_run=dry_run,
            )

            if not dry_run and not skip_publish:
                call_command(
                    'publish_articles',
                    source=str(source),
                    status='published',
                    allow_missing=True,
                )

        if dry_run:
            self.stdout.write(self.style.SUCCESS('Dry run complete. No database writes performed.'))
            return

        final_total = Article.objects.count()
        final_published = Article.objects.filter(is_published=True, status='published').count()

        self.stdout.write(
            self.style.SUCCESS(
                'Learning Center bootstrap complete. '
                f'articles: {initial_total} -> {final_total}, '
                f'published: {initial_published} -> {final_published}'
            )
        )

    def _resolve_sources(self, custom_sources, skip_fixture, skip_generated, skip_curated):
        learn_root = settings.BASE_DIR / 'apps' / 'learn'
        batch_dir = learn_root / 'data' / 'article_batches'
        resolved = []

        if not skip_fixture:
            fixture_path = learn_root / 'fixtures' / 'articles.json'
            if fixture_path.exists():
                resolved.append(fixture_path)

        if not skip_generated and batch_dir.exists():
            resolved.extend(sorted(batch_dir.glob('generated_*.json')))

        if not skip_curated and batch_dir.exists():
            resolved.extend(sorted(batch_dir.glob('curated_*.json')))

        for raw in custom_sources:
            path = Path(raw).expanduser()
            if not path.is_absolute():
                path = (settings.BASE_DIR / path).resolve()
            else:
                path = path.resolve()
            if path.exists():
                resolved.append(path)
            else:
                self.stdout.write(self.style.WARNING(f'Skipping missing source: {path}'))

        # Deduplicate while preserving order.
        unique = []
        seen = set()
        for path in resolved:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)

        return unique
