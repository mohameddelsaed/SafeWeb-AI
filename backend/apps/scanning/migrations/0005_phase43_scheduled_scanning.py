"""
Phase 43 — Scheduled & Continuous Scanning
Adds ScheduledScan and AssetMonitorRecord models.
"""
import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanning', '0004_scan_mode_scan_next_scan_at_scan_parent_scan'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── ScheduledScan ──────────────────────────────────────────────────
        migrations.CreateModel(
            name='ScheduledScan',
            fields=[
                ('id', models.UUIDField(
                    default=uuid.uuid4, editable=False, primary_key=True,
                    serialize=False,
                )),
                ('name', models.CharField(max_length=200)),
                ('scan_config', models.JSONField(default=dict)),
                ('schedule_preset', models.CharField(
                    choices=[
                        ('hourly', 'Hourly'),
                        ('daily', 'Daily'),
                        ('weekly', 'Weekly'),
                        ('monthly', 'Monthly'),
                        ('custom', 'Custom Cron'),
                    ],
                    default='weekly',
                    max_length=20,
                )),
                ('cron_expr', models.CharField(default='0 2 * * 1', max_length=100)),
                ('last_run', models.DateTimeField(blank=True, null=True)),
                ('next_run', models.DateTimeField()),
                ('is_active', models.BooleanField(default=True)),
                ('notify_on_new_findings', models.BooleanField(default=True)),
                ('notify_on_ssl_expiry', models.BooleanField(default=True)),
                ('notify_on_asset_changes', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='scheduled_scans',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'db_table': 'scheduled_scans', 'ordering': ['next_run']},
        ),
        # ── AssetMonitorRecord ─────────────────────────────────────────────
        migrations.CreateModel(
            name='AssetMonitorRecord',
            fields=[
                ('id', models.UUIDField(
                    default=uuid.uuid4, editable=False, primary_key=True,
                    serialize=False,
                )),
                ('target', models.CharField(max_length=2048)),
                ('change_type', models.CharField(
                    choices=[
                        ('new_subdomain', 'New Subdomain'),
                        ('removed_subdomain', 'Subdomain Removed'),
                        ('ssl_expiring', 'SSL Certificate Expiring'),
                        ('ssl_expired', 'SSL Certificate Expired'),
                        ('new_port', 'New Open Port'),
                        ('closed_port', 'Port Closed'),
                        ('tech_added', 'Technology Added'),
                        ('tech_removed', 'Technology Removed'),
                        ('new_finding', 'New Vulnerability Finding'),
                        ('fixed_finding', 'Fixed Vulnerability'),
                        ('regressed_finding', 'Regressed Vulnerability'),
                    ],
                    max_length=50,
                )),
                ('detail', models.TextField()),
                ('severity', models.CharField(default='info', max_length=20)),
                ('acknowledged', models.BooleanField(default=False)),
                ('detected_at', models.DateTimeField(auto_now_add=True)),
                ('scheduled_scan', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='monitor_records',
                    to='scanning.scheduledscan',
                )),
            ],
            options={
                'db_table': 'asset_monitor_records',
                'ordering': ['-detected_at'],
            },
        ),
    ]
