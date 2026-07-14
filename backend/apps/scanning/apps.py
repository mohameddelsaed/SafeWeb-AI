from django.apps import AppConfig


class ScanningConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scanning'

    def ready(self):
        import logging
        from pathlib import Path
        logger = logging.getLogger(__name__)
        templates_dir = Path(__file__).parent / 'engine' / 'nuclei' / 'templates_repo'
        if not templates_dir.is_dir():
            logger.warning(
                'Nuclei community templates not found at %s. '
                'Run: python manage.py setup_nuclei_templates',
                templates_dir,
            )
    verbose_name = 'Scanning'
