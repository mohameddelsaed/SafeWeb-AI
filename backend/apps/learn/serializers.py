from rest_framework import serializers
from .models import Article, Category, Tag


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'slug', 'label', 'depth', 'parent']


class TagSerializer(serializers.ModelSerializer):
    type = serializers.CharField(source='tag_type')

    class Meta:
        model = Tag
        fields = ['id', 'slug', 'label', 'type']


class ArticleListSerializer(serializers.ModelSerializer):
    """Matches the Learn.tsx article card data shape."""
    category = serializers.SerializerMethodField()
    category_value = serializers.CharField(source='category')
    primary_category = serializers.SerializerMethodField()
    categories = CategorySerializer(many=True, read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    date = serializers.DateTimeField(source='created_at', format='%Y-%m-%dT%H:%M:%S.%fZ')
    read_time = serializers.IntegerField()

    class Meta:
        model = Article
        fields = [
            'id', 'title', 'excerpt', 'category', 'category_value', 'primary_category',
            'categories', 'tags', 'difficulty_level', 'author', 'date', 'read_time',
            'image', 'slug', 'status',
        ]

    def get_category(self, obj):
        return obj.get_category_display()

    def get_primary_category(self, obj):
        category = obj.categories.first()
        if not category:
            return None
        return {
            'slug': category.slug,
            'label': category.label,
        }


class ArticleDetailSerializer(serializers.ModelSerializer):
    category = serializers.SerializerMethodField()
    category_value = serializers.CharField(source='category')
    primary_category = serializers.SerializerMethodField()
    categories = CategorySerializer(many=True, read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    date = serializers.DateTimeField(source='created_at', format='%Y-%m-%dT%H:%M:%S.%fZ')

    class Meta:
        model = Article
        fields = [
            'id', 'title', 'slug', 'canonical_slug', 'excerpt', 'content', 'category',
            'category_value', 'primary_category', 'categories', 'tags', 'difficulty_level',
            'status', 'author', 'date', 'read_time', 'image', 'source_count',
            'references', 'cwe_ids', 'owasp_refs', 'related_article_ids', 'version',
            'last_reviewed_at',
        ]

    def get_category(self, obj):
        return obj.get_category_display()

    def get_primary_category(self, obj):
        category = obj.categories.first()
        if not category:
            return None
        return {
            'slug': category.slug,
            'label': category.label,
        }
