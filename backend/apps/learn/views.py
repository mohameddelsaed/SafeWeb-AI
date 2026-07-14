from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import connection
from django.db.models import Q
from .models import Article, Category, Tag
from .serializers import (
    ArticleListSerializer,
    ArticleDetailSerializer,
    CategorySerializer,
    TagSerializer,
)


LEGACY_CATEGORY_LABEL_TO_VALUE = {
    label.lower(): value for value, label in Article.CATEGORY_CHOICES
}


def _parse_positive_int(value, default, minimum=1, maximum=100):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _normalize_legacy_category(raw_category):
    if not raw_category:
        return raw_category
    lowered = raw_category.lower().strip()
    if lowered in LEGACY_CATEGORY_LABEL_TO_VALUE:
        return LEGACY_CATEGORY_LABEL_TO_VALUE[lowered]
    return raw_category


def _get_categories_payload():
    active_categories = Category.objects.filter(is_active=True).order_by('sort_order', 'label')
    if active_categories.exists():
        return [{'value': 'all', 'label': 'All Articles'}] + [
            {'value': category.slug, 'label': category.label}
            for category in active_categories
        ]

    payload = [{'value': 'all', 'label': 'All Articles'}]
    for value, label in Article.CATEGORY_CHOICES:
        payload.append({'value': value, 'label': label})
    return payload


def _apply_search(queryset, search):
    if not search:
        return queryset

    if connection.vendor == 'postgresql':
        from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector

        search_query = SearchQuery(search)
        search_vector = (
            SearchVector('title', weight='A')
            + SearchVector('excerpt', weight='B')
            + SearchVector('content', weight='C')
        )
        return queryset.annotate(
            search_rank=SearchRank(search_vector, search_query)
        ).filter(
            search_rank__gte=0.01
        ).order_by('-search_rank', '-created_at')

    return queryset.filter(
        Q(title__icontains=search)
        | Q(excerpt__icontains=search)
        | Q(content__icontains=search)
    )


class ArticleListView(APIView):
    """List published articles with search and category filtering."""
    permission_classes = [AllowAny]

    def get(self, request):
        queryset = Article.objects.filter(is_published=True, status='published').prefetch_related('categories', 'tags')

        # Search
        search = request.query_params.get('search', '')
        queryset = _apply_search(queryset, search)

        # Category filter
        category = request.query_params.get('category', '')
        if category and category != 'all':
            normalized_category = _normalize_legacy_category(category)
            queryset = queryset.filter(
                Q(category=normalized_category)
                | Q(categories__slug=normalized_category)
                | Q(categories__label__iexact=category)
            ).distinct()

        # Tag filter
        tag = request.query_params.get('tag', '')
        if tag:
            queryset = queryset.filter(tags__slug=tag).distinct()

        # Difficulty filter
        difficulty = request.query_params.get('difficulty', '')
        if difficulty:
            queryset = queryset.filter(difficulty_level=difficulty)

        # Sorting
        order_by = request.query_params.get('order_by', 'newest')
        order_map = {
            'newest': '-created_at',
            'oldest': 'created_at',
            'title': 'title',
            'read_time': '-read_time',
        }
        if order_by in order_map and not search:
            queryset = queryset.order_by(order_map[order_by])

        total = queryset.count()
        page = _parse_positive_int(request.query_params.get('page', '1'), default=1, minimum=1, maximum=100000)
        raw_page_size = request.query_params.get('page_size') or request.query_params.get('pageSize') or '20'
        page_size = _parse_positive_int(raw_page_size, default=20, minimum=1, maximum=100)
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)

        serializer = ArticleListSerializer(page_obj.object_list, many=True)

        categories = _get_categories_payload()
        tags = Tag.objects.filter(is_active=True).order_by('label')
        serialized_tags = TagSerializer(tags, many=True).data

        return Response({
            'articles': serializer.data,
            'results': serializer.data,
            'categories': categories,
            'tags': serialized_tags,
            'total': total,
            'page': page_obj.number,
            'page_size': page_size,
            'total_pages': paginator.num_pages,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
        })


class ArticleDetailView(APIView):
    """Get a single article by slug or ID."""
    permission_classes = [AllowAny]

    def get(self, request, slug):
        queryset = Article.objects.filter(is_published=True, status='published').prefetch_related('categories', 'tags')

        try:
            article = queryset.get(slug=slug)
        except Article.DoesNotExist:
            # Try by ID
            try:
                article = queryset.get(id=slug)
            except (Article.DoesNotExist, ValueError, ValidationError):
                return Response(
                    {'detail': 'Article not found'},
                    status=status.HTTP_404_NOT_FOUND,
                )

        serializer = ArticleDetailSerializer(article)
        return Response(serializer.data)


class ArticleCategoryListView(APIView):
    """List active learning center categories."""

    permission_classes = [AllowAny]

    def get(self, request):
        queryset = Category.objects.filter(is_active=True).order_by('sort_order', 'label')
        serializer = CategorySerializer(queryset, many=True)
        return Response({'categories': serializer.data, 'total': queryset.count()})


class ArticleTagListView(APIView):
    """List active learning center tags."""

    permission_classes = [AllowAny]

    def get(self, request):
        queryset = Tag.objects.filter(is_active=True).order_by('label')
        serializer = TagSerializer(queryset, many=True)
        return Response({'tags': serializer.data, 'total': queryset.count()})
