from django.contrib import admin
from .models import Article, Category, Tag


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['label', 'slug', 'parent', 'depth', 'sort_order', 'is_active']
    list_filter = ['is_active', 'depth']
    search_fields = ['label', 'slug']
    list_editable = ['sort_order', 'is_active']


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ['label', 'slug', 'tag_type', 'is_active']
    list_filter = ['tag_type', 'is_active']
    search_fields = ['label', 'slug']
    list_editable = ['is_active']


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'category', 'difficulty_level', 'status', 'author',
        'read_time', 'is_published', 'created_at',
    ]
    list_filter = ['category', 'difficulty_level', 'status', 'is_published']
    search_fields = ['title', 'slug', 'excerpt']
    readonly_fields = ['created_at', 'updated_at']
    filter_horizontal = ['categories', 'tags']
    list_per_page = 25
    date_hierarchy = 'created_at'
    prepopulated_fields = {'slug': ('title',)}
