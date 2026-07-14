import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.learn.models import Category, Tag


class Command(BaseCommand):
    help = 'Seed or update Learning Center taxonomy (categories and tags) from JSON files.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--categories',
            default=str(settings.BASE_DIR / 'apps' / 'learn' / 'data' / 'taxonomy' / 'categories.json'),
            help='Path to categories JSON file.',
        )
        parser.add_argument(
            '--tags',
            default=str(settings.BASE_DIR / 'apps' / 'learn' / 'data' / 'taxonomy' / 'tags.json'),
            help='Path to tags JSON file.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Validate and print changes without writing to the database.',
        )

    def handle(self, *args, **options):
        categories_path = Path(options['categories']).resolve()
        tags_path = Path(options['tags']).resolve()
        dry_run = options['dry_run']

        categories = self._read_json(categories_path, 'categories')
        tags = self._read_json(tags_path, 'tags')

        self._validate_categories(categories)
        self._validate_tags(tags)

        if dry_run:
            self.stdout.write(self.style.SUCCESS('Dry run successful. Taxonomy files are valid.'))
            self.stdout.write(f'Categories: {len(categories)}')
            self.stdout.write(f'Tags: {len(tags)}')
            return

        with transaction.atomic():
            category_stats = self._sync_categories(categories)
            tag_stats = self._sync_tags(tags)

        self.stdout.write(self.style.SUCCESS('Learning taxonomy synced successfully.'))
        self.stdout.write(
            f"Categories created={category_stats['created']} updated={category_stats['updated']}"
        )
        self.stdout.write(
            f"Tags created={tag_stats['created']} updated={tag_stats['updated']}"
        )

    @staticmethod
    def _read_json(path: Path, label: str):
        if not path.exists():
            raise CommandError(f'{label} file does not exist: {path}')
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise CommandError(f'Invalid JSON in {path}: {exc}') from exc

        if not isinstance(payload, list):
            raise CommandError(f'{label} file must contain a JSON array.')
        return payload

    @staticmethod
    def _validate_categories(categories):
        seen = set()
        for index, category in enumerate(categories, start=1):
            if not isinstance(category, dict):
                raise CommandError(f'Category item {index} must be an object.')
            slug = (category.get('slug') or '').strip()
            label = (category.get('label') or '').strip()
            if not slug or not label:
                raise CommandError(f'Category item {index} must include non-empty slug and label.')
            if slug in seen:
                raise CommandError(f'Duplicate category slug in input: {slug}')
            seen.add(slug)

    @staticmethod
    def _validate_tags(tags):
        seen = set()
        valid_types = {choice[0] for choice in Tag.TYPE_CHOICES}
        for index, tag in enumerate(tags, start=1):
            if not isinstance(tag, dict):
                raise CommandError(f'Tag item {index} must be an object.')
            slug = (tag.get('slug') or '').strip()
            label = (tag.get('label') or '').strip()
            tag_type = (tag.get('type') or '').strip()
            if not slug or not label or not tag_type:
                raise CommandError(f'Tag item {index} must include slug, label, and type.')
            if tag_type not in valid_types:
                raise CommandError(f'Tag item {index} has invalid type: {tag_type}')
            if slug in seen:
                raise CommandError(f'Duplicate tag slug in input: {slug}')
            seen.add(slug)

    def _sync_categories(self, categories):
        created = 0
        updated = 0
        cache = {c.slug: c for c in Category.objects.all()}

        # First pass: create/update non-parent fields.
        for item in categories:
            slug = item['slug'].strip()
            defaults = {
                'label': item['label'].strip(),
                'description': (item.get('description') or '').strip(),
                'depth': int(item.get('depth', 0)),
                'sort_order': int(item.get('sort_order', 0)),
                'is_active': bool(item.get('is_active', True)),
            }
            obj, was_created = Category.objects.update_or_create(slug=slug, defaults=defaults)
            cache[slug] = obj
            if was_created:
                created += 1
            else:
                updated += 1

        # Second pass: link parent categories.
        for item in categories:
            slug = item['slug'].strip()
            parent_slug = item.get('parent')
            category = cache[slug]
            parent = cache.get(parent_slug) if parent_slug else None
            if category.parent_id != (parent.id if parent else None):
                category.parent = parent
                category.save(update_fields=['parent', 'updated_at'])

        return {'created': created, 'updated': updated}

    @staticmethod
    def _sync_tags(tags):
        created = 0
        updated = 0

        for item in tags:
            defaults = {
                'label': item['label'].strip(),
                'tag_type': item['type'].strip(),
                'is_active': bool(item.get('is_active', True)),
            }
            _, was_created = Tag.objects.update_or_create(slug=item['slug'].strip(), defaults=defaults)
            if was_created:
                created += 1
            else:
                updated += 1

        return {'created': created, 'updated': updated}
