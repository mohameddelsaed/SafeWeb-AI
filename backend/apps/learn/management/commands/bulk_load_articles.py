import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.learn.models import Article, Category, Tag


class Command(BaseCommand):
    help = 'Bulk load Learning Center articles from a JSON source file.'

    def add_arguments(self, parser):
        parser.add_argument('--source', required=True, help='Path to JSON source file.')
        parser.add_argument('--batch-size', type=int, default=100, help='Batch size for inserts.')
        parser.add_argument(
            '--skip-duplicates',
            action='store_true',
            help='Skip existing slugs instead of failing on duplicates.',
        )
        parser.add_argument('--dry-run', action='store_true', help='Validate without writing to the database.')

    def handle(self, *args, **options):
        source_path = Path(options['source']).resolve()
        batch_size = max(1, options['batch_size'])
        skip_duplicates = options['skip_duplicates']
        dry_run = options['dry_run']

        if not source_path.exists():
            raise CommandError(f'Source file not found: {source_path}')

        self.stdout.write(f'Loading articles from {source_path}')
        payload = self._read_payload(source_path)
        normalized_items = [self._normalize_item(item) for item in payload]

        missing = [idx + 1 for idx, item in enumerate(normalized_items) if not self._is_valid(item)]
        if missing:
            raise CommandError(f'Invalid articles found at item indexes: {missing[:20]}')

        slugs = [item['slug'] for item in normalized_items]
        duplicates_in_file = self._get_duplicates(slugs)
        if duplicates_in_file:
            raise CommandError(
                f'Duplicate slugs inside source file: {", ".join(sorted(duplicates_in_file)[:20])}'
            )

        existing_slugs = set(Article.objects.filter(slug__in=slugs).values_list('slug', flat=True))
        if existing_slugs and not skip_duplicates:
            raise CommandError(
                f'Source contains {len(existing_slugs)} existing slugs. Use --skip-duplicates to continue.'
            )

        queued = [item for item in normalized_items if item['slug'] not in existing_slugs]
        self.stdout.write(f'Validated {len(normalized_items)} articles. New articles queued: {len(queued)}')

        if dry_run:
            self.stdout.write(self.style.SUCCESS('Dry run complete. No data was written.'))
            return

        with transaction.atomic():
            category_cache = self._build_category_cache()
            tag_cache = self._build_tag_cache()
            created_count = 0

            for start in range(0, len(queued), batch_size):
                chunk = queued[start:start + batch_size]
                article_objects = [self._to_article_model(item) for item in chunk]
                Article.objects.bulk_create(article_objects, batch_size=batch_size)
                created_count += len(article_objects)

                created_articles = Article.objects.filter(slug__in=[item['slug'] for item in chunk])
                article_map = {article.slug: article for article in created_articles}

                for item in chunk:
                    article = article_map.get(item['slug'])
                    if not article:
                        continue
                    self._attach_taxonomy(article, item, category_cache, tag_cache)

                self.stdout.write(f'Inserted {created_count}/{len(queued)} articles...')

        self.stdout.write(self.style.SUCCESS(f'Successfully created {created_count} articles.'))

    @staticmethod
    def _read_payload(source_path: Path):
        data = json.loads(source_path.read_text(encoding='utf-8'))
        if not isinstance(data, list):
            raise CommandError('Source JSON must be a list of objects.')
        return data

    @staticmethod
    def _normalize_item(item):
        if 'model' in item and 'fields' in item:
            fields = item.get('fields', {})
            normalized = dict(fields)
            if item.get('pk'):
                normalized['id'] = item['pk']
            return normalized
        return dict(item)

    @staticmethod
    def _is_valid(item):
        required = ['title', 'slug', 'excerpt', 'content', 'category']
        return all(bool(item.get(field)) for field in required)

    @staticmethod
    def _get_duplicates(values):
        seen = set()
        duplicates = set()
        for value in values:
            if value in seen:
                duplicates.add(value)
            seen.add(value)
        return duplicates

    @staticmethod
    def _build_category_cache():
        return {category.slug: category for category in Category.objects.all()}

    @staticmethod
    def _build_tag_cache():
        return {tag.slug: tag for tag in Tag.objects.all()}

    @staticmethod
    def _to_article_model(item):
        references = item.get('references') or []
        status = item.get('status')
        is_published = item.get('is_published', True)
        if not status:
            status = 'published' if is_published else 'draft'

        return Article(
            title=item['title'],
            slug=item['slug'],
            canonical_slug=item.get('canonical_slug') or item['slug'],
            excerpt=item['excerpt'],
            content=item['content'],
            category=item.get('category', 'best_practices'),
            author=item.get('author', 'Security Team'),
            read_time=item.get('read_time', 5),
            image=item.get('image'),
            is_published=is_published,
            difficulty_level=item.get('difficulty_level', 'practitioner'),
            status=status,
            source_count=item.get('source_count', len(references)),
            references=references,
            cwe_ids=item.get('cwe_ids') or [],
            owasp_refs=item.get('owasp_refs') or [],
            related_article_ids=item.get('related_article_ids') or [],
            version=item.get('version', '1.0'),
            last_reviewed_at=item.get('last_reviewed_at'),
        )

    def _attach_taxonomy(self, article, item, category_cache, tag_cache):
        categories = item.get('categories') or [item.get('category')]
        tags = item.get('tags') or []

        category_instances = []
        for category in categories:
            slug, label = self._normalize_taxonomy_entry(category)
            if not slug:
                continue
            instance = category_cache.get(slug)
            if not instance:
                instance = Category.objects.create(slug=slug, label=label or slug.replace('_', ' ').title())
                category_cache[slug] = instance
            category_instances.append(instance)

        if category_instances:
            article.categories.set(category_instances)

        tag_instances = []
        for tag in tags:
            slug, label = self._normalize_taxonomy_entry(tag)
            if not slug:
                continue
            instance = tag_cache.get(slug)
            if not instance:
                instance = Tag.objects.create(slug=slug, label=label or slug.replace('-', ' ').title())
                tag_cache[slug] = instance
            tag_instances.append(instance)

        if tag_instances:
            article.tags.set(tag_instances)

    @staticmethod
    def _normalize_taxonomy_entry(entry):
        if isinstance(entry, dict):
            return entry.get('slug'), entry.get('label')
        if isinstance(entry, str):
            return entry.strip(), entry.replace('_', ' ').replace('-', ' ').title()
        return None, None
