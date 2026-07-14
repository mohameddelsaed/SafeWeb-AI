import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Generate draft article JSON payloads from outline files.'

    def add_arguments(self, parser):
        parser.add_argument('--outlines', required=True, help='Path to outlines JSON file.')
        parser.add_argument('--output', required=True, help='Output path for generated draft JSON file.')
        parser.add_argument(
            '--template',
            default=str(settings.BASE_DIR / 'apps' / 'learn' / 'data' / 'article_blueprints' / 'security_article_template.md'),
            help='Markdown template path used to generate article content.',
        )
        parser.add_argument(
            '--author',
            default='Security Team',
            help='Default author value for generated drafts.',
        )

    def handle(self, *args, **options):
        outlines_path = Path(options['outlines']).resolve()
        output_path = Path(options['output']).resolve()
        template_path = Path(options['template']).resolve()
        author = options['author']

        outlines = self._read_json_array(outlines_path, 'outlines')
        template = self._read_text(template_path)

        generated = []
        for outline in outlines:
            generated.append(self._build_article(outline, template, author))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(generated, indent=2, ensure_ascii=True), encoding='utf-8')

        self.stdout.write(self.style.SUCCESS(f'Generated {len(generated)} draft articles.'))
        self.stdout.write(f'Output file: {output_path}')

    @staticmethod
    def _read_json_array(path: Path, label: str):
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
    def _read_text(path: Path):
        if not path.exists():
            raise CommandError(f'Template file does not exist: {path}')
        return path.read_text(encoding='utf-8')

    @staticmethod
    def _fill_template(template, title, difficulty_level, read_time):
        replaced = template
        replaced = replaced.replace('{{title}}', title)
        replaced = replaced.replace('{{audience}}', 'Security specialists and developers')
        replaced = replaced.replace('{{difficulty_level}}', difficulty_level)
        replaced = replaced.replace('{{read_time}}', str(read_time))
        replaced = replaced.replace('{{owasp_refs}}', 'OWASP Top 10')
        replaced = replaced.replace('{{cwe_ids}}', 'CWE mappings required')
        replaced = replaced.replace('{{wstg_refs}}', 'WSTG references required')
        replaced = replaced.replace('{{asvs_refs}}', 'ASVS references required')
        replaced = replaced.replace('{{reference_1}}', 'Primary standard reference URL')
        replaced = replaced.replace('{{reference_2}}', 'Secondary testing/research URL')
        replaced = replaced.replace('{{reference_3}}', 'Implementation guidance URL')
        return replaced

    def _build_article(self, outline, template, author):
        title = (outline.get('title') or '').strip()
        slug = (outline.get('slug') or '').strip()
        category = (outline.get('category') or 'best_practices').strip()

        if not title or not slug:
            raise CommandError('Each outline item must include title and slug.')

        difficulty_level = (outline.get('difficulty_level') or 'practitioner').strip()
        read_time = int(outline.get('read_time') or 10)
        tags = outline.get('tags') or []

        return {
            'title': title,
            'slug': slug,
            'canonical_slug': slug,
            'excerpt': f'{title} - practical guidance, exploit understanding, and secure remediation patterns.',
            'content': self._fill_template(template, title, difficulty_level, read_time),
            'category': category,
            'categories': [category],
            'tags': tags,
            'author': author,
            'read_time': read_time,
            'difficulty_level': difficulty_level,
            'status': 'draft',
            'is_published': False,
            'source_count': 0,
            'references': [],
            'cwe_ids': [],
            'owasp_refs': [],
            'related_article_ids': [],
            'version': '1.0',
        }
