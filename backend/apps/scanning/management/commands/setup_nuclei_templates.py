"""Management command: clone or update the nuclei-templates repository."""
import os
import shutil

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Clone or update the projectdiscovery/nuclei-templates repository.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Remove the existing repository and re-clone from scratch.',
        )

    def handle(self, *args, **options):
        from apps.scanning.engine.nuclei.template_manager import TemplateManager

        mgr = TemplateManager()

        if options['force'] and os.path.isdir(mgr.templates_dir):
            self.stdout.write(f'Removing existing templates at {mgr.templates_dir} …')
            shutil.rmtree(mgr.templates_dir)

        self.stdout.write('Setting up nuclei-templates (this may take a while) …')
        ready = mgr.setup(clone=True)

        if ready:
            stats = mgr.get_stats()
            self.stdout.write(self.style.SUCCESS(
                f'✓ {stats["total"]} templates indexed in '
                f'{stats.get("index_time_seconds", 0):.1f}s'
            ))
            self.stdout.write('  By severity: ' + ', '.join(
                f'{k}={v}' for k, v in sorted(stats.get('by_severity', {}).items())
            ))
            self.stdout.write('  By type:     ' + ', '.join(
                f'{k}={v}' for k, v in sorted(stats.get('by_type', {}).items())
            ))
            self.stdout.write(f'  Templates dir: {stats["templates_dir"]}')
        else:
            self.stderr.write(self.style.ERROR(
                '✗ Failed to set up nuclei-templates. Check the logs for details.'
            ))
