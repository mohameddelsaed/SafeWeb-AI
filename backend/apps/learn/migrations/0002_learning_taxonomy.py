# Generated manually for Learning Center taxonomy and metadata expansion.

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('learn', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('slug', models.SlugField(max_length=120, unique=True)),
                ('label', models.CharField(max_length=120)),
                ('description', models.TextField(blank=True)),
                ('depth', models.PositiveSmallIntegerField(default=0)),
                ('sort_order', models.IntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=models.CASCADE, related_name='children', to='learn.category')),
            ],
            options={
                'ordering': ['sort_order', 'label'],
                'indexes': [
                    models.Index(fields=['slug'], name='learn_categ_slug_8894bb_idx'),
                    models.Index(fields=['is_active'], name='learn_categ_is_acti_10b6f9_idx'),
                    models.Index(fields=['parent', 'is_active'], name='learn_categ_parent__d05499_idx'),
                ],
            },
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('slug', models.SlugField(max_length=120, unique=True)),
                ('label', models.CharField(max_length=120)),
                ('tag_type', models.CharField(choices=[('vuln', 'Vulnerability'), ('defense', 'Defense'), ('framework', 'Framework'), ('protocol', 'Protocol'), ('standard', 'Standard'), ('industry', 'Industry')], default='vuln', max_length=20)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['label'],
                'indexes': [
                    models.Index(fields=['slug'], name='learn_tag_slug_7d91ea_idx'),
                    models.Index(fields=['tag_type', 'is_active'], name='learn_tag_tag_typ_98f9ad_idx'),
                ],
            },
        ),
        migrations.AddField(
            model_name='article',
            name='canonical_slug',
            field=models.SlugField(blank=True, max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='article',
            name='cwe_ids',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='article',
            name='difficulty_level',
            field=models.CharField(choices=[('foundation', 'Foundation'), ('practitioner', 'Practitioner'), ('specialist', 'Specialist')], default='practitioner', max_length=20),
        ),
        migrations.AddField(
            model_name='article',
            name='last_reviewed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='article',
            name='owasp_refs',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='article',
            name='references',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='article',
            name='related_article_ids',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='article',
            name='source_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='article',
            name='status',
            field=models.CharField(choices=[('draft', 'Draft'), ('review', 'Review'), ('published', 'Published')], default='published', max_length=20),
        ),
        migrations.AddField(
            model_name='article',
            name='version',
            field=models.CharField(default='1.0', max_length=20),
        ),
        migrations.AddField(
            model_name='article',
            name='categories',
            field=models.ManyToManyField(blank=True, related_name='articles', to='learn.category'),
        ),
        migrations.AddField(
            model_name='article',
            name='tags',
            field=models.ManyToManyField(blank=True, related_name='articles', to='learn.tag'),
        ),
        migrations.AddIndex(
            model_name='article',
            index=models.Index(fields=['slug'], name='learn_artic_slug_65cace_idx'),
        ),
        migrations.AddIndex(
            model_name='article',
            index=models.Index(fields=['is_published', 'created_at'], name='learn_artic_is_publ_ef6ea9_idx'),
        ),
        migrations.AddIndex(
            model_name='article',
            index=models.Index(fields=['status', 'created_at'], name='learn_artic_status_67860c_idx'),
        ),
        migrations.AddIndex(
            model_name='article',
            index=models.Index(fields=['difficulty_level', 'created_at'], name='learn_artic_difficu_adba1a_idx'),
        ),
    ]
