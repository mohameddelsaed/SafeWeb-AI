"""
Management command to train ML models.
Usage: python manage.py train_models [--type phishing|malware|all] [--samples N]
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.ml.model_trainer import train_phishing_model, train_malware_model
from apps.ml.models import MLModel


class Command(BaseCommand):
    help = 'Train ML models for phishing and malware detection'

    def add_arguments(self, parser):
        parser.add_argument(
            '--type',
            type=str,
            default='all',
            choices=['phishing', 'malware', 'all'],
            help='Type of model to train (default: all)',
        )
        parser.add_argument(
            '--samples',
            type=int,
            default=5000,
            help='Number of training samples (default: 5000)',
        )

    def handle(self, *args, **options):
        model_type = options['type']
        samples = options['samples']

        if model_type in ('phishing', 'all'):
            self.stdout.write('Training phishing detection model...')
            result = train_phishing_model(n_samples=samples)
            self._save_model(result)
            self.stdout.write(self.style.SUCCESS(
                f'  Phishing model trained — '
                f'Accuracy: {result["accuracy"]}, F1: {result["f1"]}, '
                f'Duration: {result["training_duration_seconds"]}s'
            ))

        if model_type in ('malware', 'all'):
            self.stdout.write('Training malware detection model...')
            result = train_malware_model(n_samples=samples)
            self._save_model(result)
            self.stdout.write(self.style.SUCCESS(
                f'  Malware model trained — '
                f'Accuracy: {result["accuracy"]}, F1: {result["f1"]}, '
                f'Duration: {result["training_duration_seconds"]}s'
            ))

        self.stdout.write(self.style.SUCCESS('All models trained successfully!'))

    def _save_model(self, result):
        """Save model metadata to database."""
        # Deactivate previous models of same type
        MLModel.objects.filter(
            model_type=result['model_type'], is_active=True
        ).update(is_active=False)

        MLModel.objects.create(
            name=result['name'],
            model_type=result['model_type'],
            version=result['version'],
            accuracy=result['accuracy'],
            precision_score=result['precision'],
            recall=result['recall'],
            f1_score=result['f1'],
            file_path=result['file_path'],
            is_active=True,
            training_samples=result['training_samples'],
            training_duration_seconds=result['training_duration_seconds'],
            trained_at=timezone.now(),
        )
