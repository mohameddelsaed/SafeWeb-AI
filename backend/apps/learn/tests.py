from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from apps.learn.models import Article, Category, Tag


class ArticleModelTest(TestCase):
    """Tests for the Article model."""

    def setUp(self):
        self.article = Article.objects.create(
            title="Test Article",
            slug="test-article",
            excerpt="Test excerpt",
            content="# Test Content\n\nThis is a test article.",
            category="injection",
            author="Test Author",
            read_time=5,
            is_published=True,
        )

    def test_article_creation(self):
        self.assertEqual(self.article.title, "Test Article")
        self.assertEqual(self.article.slug, "test-article")
        self.assertEqual(self.article.category, "injection")
        self.assertTrue(self.article.is_published)

    def test_str_representation(self):
        self.assertEqual(str(self.article), "Test Article")

    def test_category_display(self):
        self.assertEqual(
            self.article.get_category_display(), "Injection Attacks"
        )

    def test_unpublished_article(self):
        article = Article.objects.create(
            title="Draft Article",
            slug="draft-article",
            excerpt="Draft",
            content="Draft content",
            category="xss",
            author="Author",
            read_time=3,
            is_published=False,
        )
        self.assertFalse(article.is_published)


class ArticleAPITest(APITestCase):
    """Tests for Article API endpoints."""

    def setUp(self):
        self.client = APIClient()

        self.article1 = Article.objects.create(
            title="SQL Injection Guide",
            slug="sql-injection-guide",
            excerpt="Learn about SQL injection",
            content="Full content about SQL injection...",
            category="injection",
            author="Security Team",
            read_time=8,
            is_published=True,
        )
        self.category_injection = Category.objects.create(slug='injection', label='Injection Attacks')
        self.tag_sqli = Tag.objects.create(slug='sqli', label='SQL Injection', tag_type='vuln')
        self.article1.categories.add(self.category_injection)
        self.article1.tags.add(self.tag_sqli)

        self.article2 = Article.objects.create(
            title="XSS Patterns",
            slug="xss-patterns",
            excerpt="Learn about XSS",
            content="Full content about XSS...",
            category="xss",
            author="Security Team",
            read_time=10,
            difficulty_level='foundation',
            is_published=True,
        )
        self.category_xss = Category.objects.create(slug='xss-and-client-side', label='XSS and Client-Side Attacks')
        self.tag_xss = Tag.objects.create(slug='xss', label='Cross-Site Scripting', tag_type='vuln')
        self.article2.categories.add(self.category_xss)
        self.article2.tags.add(self.tag_xss)

        self.review_article = Article.objects.create(
            title="Review Pending Article",
            slug="review-pending-article",
            excerpt="Review workflow test",
            content="Content under review",
            category="best_practices",
            author="Security Team",
            read_time=6,
            status='review',
            is_published=True,
        )

        self.draft_article = Article.objects.create(
            title="Draft Article",
            slug="draft-article",
            excerpt="This is a draft",
            content="Draft content...",
            category="best_practices",
            author="Security Team",
            read_time=5,
            is_published=False,
        )

        self.specialist_article = Article.objects.create(
            title="Specialist Security Design",
            slug="specialist-security-design",
            excerpt="Advanced content",
            content="Specialist depth content...",
            category="best_practices",
            author="Security Team",
            read_time=14,
            difficulty_level='specialist',
            is_published=True,
        )

    def test_list_articles_unauthenticated(self):
        """Articles should be accessible without authentication."""
        response = self.client.get(reverse("article-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_articles_returns_published_only(self):
        """Only published articles should be returned."""
        response = self.client.get(reverse("article-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        slugs = [a["slug"] for a in articles]
        self.assertIn("sql-injection-guide", slugs)
        self.assertIn("xss-patterns", slugs)
        self.assertNotIn("draft-article", slugs)

    def test_list_articles_search(self):
        """Search should filter articles by title and content."""
        response = self.client.get(
            reverse("article-list"), {"search": "SQL"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["slug"], "sql-injection-guide")

    def test_list_articles_filter_by_category(self):
        """Should filter articles by category."""
        response = self.client.get(
            reverse("article-list"), {"category": "xss"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["slug"], "xss-patterns")

    def test_list_articles_filter_by_legacy_category_label(self):
        """Legacy category label should resolve to the legacy category value."""
        response = self.client.get(
            reverse("article-list"), {"category": "Injection Attacks"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["slug"], "sql-injection-guide")

    def test_list_articles_filter_by_taxonomy_category_slug(self):
        """Taxonomy category slug should filter via many-to-many relation."""
        response = self.client.get(
            reverse("article-list"), {"category": "xss-and-client-side"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["slug"], "xss-patterns")

    def test_list_articles_filter_by_tag_slug(self):
        """Tag slug should filter via many-to-many relation."""
        response = self.client.get(reverse("article-list"), {"tag": "sqli"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["slug"], "sql-injection-guide")

    def test_list_articles_filter_by_difficulty(self):
        """Difficulty filter should return matching difficulty levels only."""
        response = self.client.get(reverse("article-list"), {"difficulty": "specialist"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["slug"], "specialist-security-design")

    def test_list_articles_excludes_non_published_status(self):
        """Only status=published should be returned in list endpoint."""
        response = self.client.get(reverse("article-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        articles = data.get("articles", data.get("results", []))
        slugs = [a["slug"] for a in articles]
        self.assertNotIn("review-pending-article", slugs)

    def test_list_articles_returns_categories(self):
        """Article list should include available categories."""
        response = self.client.get(reverse("article-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertIn("categories", data)

    def test_list_articles_includes_pagination_metadata(self):
        """List endpoint should include pagination metadata for large datasets."""
        response = self.client.get(reverse("article-list"), {"page": 1, "page_size": 1})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("page", response.data)
        self.assertIn("page_size", response.data)
        self.assertIn("total_pages", response.data)
        self.assertIn("has_next", response.data)

    def test_article_detail_by_slug(self):
        """Should retrieve article by slug."""
        response = self.client.get(
            reverse("article-detail", kwargs={"slug": "sql-injection-guide"})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "SQL Injection Guide")
        self.assertIn("content", response.data)
        self.assertIn("categories", response.data)
        self.assertIn("tags", response.data)

    def test_article_detail_not_found(self):
        """Should return 404 for non-existent article."""
        response = self.client.get(
            reverse("article-detail", kwargs={"slug": "nonexistent"})
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_draft_article_not_accessible(self):
        """Draft articles should not be accessible via detail view."""
        response = self.client.get(
            reverse("article-detail", kwargs={"slug": "draft-article"})
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_category_list_endpoint(self):
        """Category endpoint should return active categories."""
        response = self.client.get(reverse("article-categories"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("categories", response.data)

    def test_tag_list_endpoint(self):
        """Tag endpoint should return active tags."""
        response = self.client.get(reverse("article-tags"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("tags", response.data)
