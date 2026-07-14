"""
Phase 44 — API-First Architecture
Creates: webhooks, webhook_deliveries, nuclei_templates tables.
"""
from django.conf import settings
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanning', '0005_phase43_scheduled_scanning'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── Webhook ──────────────────────────────────────────────────────────
        migrations.CreateModel(
            name='Webhook',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('url', models.URLField(max_length=2048)),
                ('secret', models.CharField(blank=True, default='', max_length=255)),
                ('events', models.JSONField(default=list)),
                ('is_active', models.BooleanField(default=True)),
                ('max_retries', models.IntegerField(default=3)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='webhooks',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'db_table': 'webhooks', 'ordering': ['-created_at']},
        ),
        # ── WebhookDelivery ──────────────────────────────────────────────────
        migrations.CreateModel(
            name='WebhookDelivery',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('event_type', models.CharField(max_length=50)),
                ('payload', models.JSONField()),
                ('status', models.CharField(
                    choices=[('pending', 'Pending'), ('delivered', 'Delivered'), ('failed', 'Failed')],
                    default='pending', max_length=20,
                )),
                ('http_status', models.IntegerField(blank=True, null=True)),
                ('response_body', models.TextField(blank=True, default='')),
                ('attempt_count', models.IntegerField(default=0)),
                ('last_attempted_at', models.DateTimeField(blank=True, null=True)),
                ('delivered_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('webhook', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='deliveries',
                    to='scanning.webhook',
                )),
            ],
            options={'db_table': 'webhook_deliveries', 'ordering': ['-created_at']},
        ),
        # ── NucleiTemplate ───────────────────────────────────────────────────
        migrations.CreateModel(
            name='NucleiTemplate',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, default='')),
                ('category', models.CharField(blank=True, default='custom', max_length=100)),
                ('severity', models.CharField(
                    choices=[
                        ('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'),
                        ('high', 'High'), ('critical', 'Critical'),
                    ],
                    default='medium', max_length=20,
                )),
                ('content', models.TextField()),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('uploaded_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='nuclei_templates',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'db_table': 'nuclei_templates', 'ordering': ['-created_at']},
        ),
    ]
