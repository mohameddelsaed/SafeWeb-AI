"""
Phase 45 — Multi-Target & Scope Management
Creates: scope_definitions, multi_target_scans (with M2M to scanning_scan),
         discovered_assets
"""
from django.conf import settings
import django.db.models.deletion
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('scanning', '0007_phase44_oob_callback'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # 1. ScopeDefinition
        migrations.CreateModel(
            name='ScopeDefinition',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True, default='')),
                ('organization', models.CharField(blank=True, default='', max_length=200)),
                ('in_scope', models.JSONField(default=list)),
                ('out_of_scope', models.JSONField(default=list)),
                ('import_format', models.CharField(
                    choices=[
                        ('manual', 'Manual'),
                        ('hackerone', 'HackerOne'),
                        ('bugcrowd', 'Bugcrowd'),
                        ('file', 'File Import'),
                    ],
                    default='manual',
                    max_length=20,
                )),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='scope_definitions',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'db_table': 'scope_definitions', 'ordering': ['-created_at']},
        ),

        # 2. MultiTargetScan
        migrations.CreateModel(
            name='MultiTargetScan',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('targets', models.JSONField(default=list)),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                        ('partial', 'Partially Completed'),
                    ],
                    default='pending',
                    max_length=20,
                )),
                ('scan_depth', models.CharField(default='medium', max_length=20)),
                ('parallel_limit', models.IntegerField(default=3)),
                ('total_targets', models.IntegerField(default=0)),
                ('completed_targets', models.IntegerField(default=0)),
                ('failed_targets', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='multi_target_scans',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('scope', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='multi_scans',
                    to='scanning.scopedefinition',
                )),
                ('sub_scans', models.ManyToManyField(
                    blank=True,
                    related_name='multi_target_parent',
                    to='scanning.scan',
                )),
            ],
            options={'db_table': 'multi_target_scans', 'ordering': ['-created_at']},
        ),

        # 3. DiscoveredAsset
        migrations.CreateModel(
            name='DiscoveredAsset',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ('organization', models.CharField(blank=True, default='', max_length=200)),
                ('url', models.TextField()),
                ('asset_type', models.CharField(
                    choices=[
                        ('web_app', 'Web Application'),
                        ('api', 'REST/GraphQL API'),
                        ('mobile_api', 'Mobile API'),
                        ('cdn', 'CDN / Static Asset'),
                        ('subdomain', 'Subdomain'),
                        ('ip', 'IP Address / Network'),
                        ('other', 'Other'),
                    ],
                    default='web_app',
                    max_length=20,
                )),
                ('tech_stack', models.JSONField(default=list)),
                ('is_active', models.BooleanField(default=True)),
                ('is_new', models.BooleanField(default=True)),
                ('notes', models.TextField(blank=True, default='')),
                ('first_seen', models.DateTimeField(auto_now_add=True)),
                ('last_seen', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='discovered_assets',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('last_scan', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='discovered_assets',
                    to='scanning.scan',
                )),
            ],
            options={
                'db_table': 'discovered_assets',
                'ordering': ['-last_seen'],
                'unique_together': {('user', 'url')},
            },
        ),
    ]
