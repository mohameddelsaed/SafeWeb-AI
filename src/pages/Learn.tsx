import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Input from '@components/ui/Input';
import ScrollReveal from '@components/ui/ScrollReveal';
import { formatDate } from '@utils/date';
import { learnAPI } from '@/services/api';
import { useLanguage } from '@/contexts/LanguageContext';

type CategoryFilter = {
    value: string;
    label: string;
};

type LearnArticle = {
    id: string;
    title: string;
    slug: string;
    excerpt: string;
    category: string;
    categoryDisplay: string;
    categoryValue: string;
    author: string;
    date: Date;
    readTime: number;
    image: string | null;
};

export default function Learn() {
    const { t } = useLanguage();
    const [searchParams] = useSearchParams();
    const [searchInput, setSearchInput] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedCategory, setSelectedCategory] = useState(searchParams.get('category') || '');
    const [isLoading, setIsLoading] = useState(true);
    const [articles, setArticles] = useState<LearnArticle[]>([]);
    const [categories, setCategories] = useState<CategoryFilter[]>([
        { value: 'all', label: 'All Articles' },
    ]);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);

    useEffect(() => {
        const timeout = window.setTimeout(() => {
            setSearchQuery(searchInput.trim());
            setPage(1);
        }, 350);

        return () => window.clearTimeout(timeout);
    }, [searchInput]);

    useEffect(() => {
        setPage(1);
    }, [selectedCategory]);

    useEffect(() => {
        setIsLoading(true);
        const params: Record<string, string> = {};
        if (searchQuery) params.search = searchQuery;
        if (selectedCategory) params.category = selectedCategory;
        params.page = String(page);
        params.pageSize = '20';

        learnAPI.getArticles(params)
            .then(({ data }) => {
                const items = data.articles || data.results || data || [];
                setArticles(items.map((a: Record<string, unknown>) => ({
                    id: String(a.id),
                    title: String(a.title || ''),
                    slug: String(a.slug || ''),
                    excerpt: String(a.excerpt || ''),
                    category: String(a.category || ''),
                    categoryDisplay: String(
                        (a.primaryCategory as { label?: string } | undefined)?.label
                        || a.categoryDisplay
                        || a.category
                        || ''
                    ),
                    categoryValue: String(
                        (a.primaryCategory as { slug?: string } | undefined)?.slug
                        || a.categoryValue
                        || ''
                    ),
                    author: String(a.author || 'Security Team'),
                    date: new Date(String(a.createdAt || a.date || new Date().toISOString())),
                    readTime: Number(a.readTime || 5),
                    image: (a.image as string) || null,
                })));
                setTotal(Number(data.total || 0));
                setTotalPages(Number(data.totalPages || data.total_pages || 1));
                if (data.categories) {
                    const normalized = (data.categories as Array<{ value?: string; label?: string } | string>)
                        .map((c) => {
                            if (typeof c === 'string') {
                                const normalizedValue = c === 'All Articles' ? 'all' : c;
                                return { value: normalizedValue, label: c };
                            }
                            return {
                                value: c.value || c.label || 'all',
                                label: c.label || c.value || 'All Articles',
                            };
                        });
                    setCategories(normalized);
                }
            })
            .catch(() => {})
            .finally(() => setIsLoading(false));
    }, [searchQuery, selectedCategory, page]);

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <ScrollReveal>
                    <div className="text-center mb-12">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            {t.learn.title}
                        </h1>
                        <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                            {t.learn.subtitle}
                        </p>
                    </div>
                    </ScrollReveal>

                    {/* Search */}
                    <div className="max-w-2xl mx-auto mb-12">
                        <Input
                            type="text"
                            placeholder={t.learn.searchPlaceholder}
                            value={searchInput}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchInput(e.target.value)}
                            leftIcon={
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                </svg>
                            }
                        />
                    </div>

                    {/* Categories */}
                    <div className="flex flex-wrap items-center justify-center gap-3 mb-12">
                        {categories.map((category) => (
                            <button
                                key={category.value}
                                onClick={() => setSelectedCategory(category.value === 'all' ? '' : category.value)}
                                className={`px-4 py-2 rounded-lg border text-sm transition-all duration-200 ${
                                    (category.value === 'all' && !selectedCategory) || category.value === selectedCategory
                                        ? 'bg-accent-green/10 border-accent-green text-accent-green'
                                        : 'bg-bg-card border-border-primary text-text-secondary hover:text-accent-green hover:border-accent-green'
                                }`}
                            >
                                {category.value === 'all' ? t.learn.allArticles : category.label}
                            </button>
                        ))}
                    </div>

                    {/* Articles Grid */}
                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">{t.learn.loading}</span>
                        </div>
                    ) : articles.length === 0 ? (
                        <Card className="p-12 text-center">
                            <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                            </svg>
                            <h3 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                {searchQuery ? t.learn.noArticlesTitle : 'No articles available yet'}
                            </h3>
                            <p className="text-text-secondary">
                                {searchQuery ? t.learn.noArticlesDesc : 'Check back soon for new security articles and tutorials.'}
                            </p>
                        </Card>
                    ) : (
                    <>
                    {/* Featured Article */}
                    {articles.length > 0 && (
                    <Card className="p-8 mb-12 hover:shadow-card-hover transition-all duration-300">
                        <div className="flex items-start gap-3 mb-3">
                            <Badge variant="info" size="sm">Featured</Badge>
                            <Badge variant="default" size="sm">{articles[0].categoryDisplay}</Badge>
                        </div>
                        <Link to={`/learn/${articles[0].slug || articles[0].id}`}>
                            <h2 className="text-3xl font-heading font-bold text-text-primary mb-4 hover:text-accent-green transition-colors">
                                {articles[0].title}
                            </h2>
                        </Link>
                        <p className="text-lg text-text-secondary mb-6 leading-relaxed">
                            {articles[0].excerpt}
                        </p>
                        <div className="flex items-center gap-4 text-sm text-text-tertiary">
                            <span>{articles[0].author}</span>
                            <span>•</span>
                            <span>{formatDate(articles[0].date)}</span>
                            <span>•</span>
                            <span>{articles[0].readTime} min read</span>
                        </div>
                    </Card>
                    )}

                    {/* Articles Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {(articles.length > 1 ? articles.slice(1) : []).map((article) => (
                            <Card key={article.id} hover className="p-6 flex flex-col">
                                <div className="mb-3">
                                    <Badge variant="default" size="sm">{article.categoryDisplay}</Badge>
                                </div>
                                <Link to={`/learn/${article.slug || article.id}`}>
                                    <h3 className="text-xl font-heading font-semibold text-text-primary mb-3 hover:text-accent-green transition-colors">
                                        {article.title}
                                    </h3>
                                </Link>
                                <p className="text-sm text-text-secondary mb-4 leading-relaxed flex-1">
                                    {article.excerpt}
                                </p>
                                <div className="flex items-center justify-between text-xs text-text-tertiary pt-4 border-t border-border-primary">
                                    <span>{formatDate(article.date)}</span>
                                    <span>{article.readTime} min read</span>
                                </div>
                            </Card>
                        ))}
                    </div>
                    </>
                    )}

                    {/* Pagination */}
                    {!isLoading && totalPages > 1 && (
                        <div className="mt-8 flex flex-col md:flex-row items-center justify-between gap-4">
                            <p className="text-sm text-text-secondary">
                                Showing page {page} of {totalPages} ({total} total articles)
                            </p>
                            <div className="flex items-center gap-2">
                                <button
                                    type="button"
                                    disabled={page <= 1}
                                    onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                                    className="px-4 py-2 rounded-lg border border-border-primary text-sm text-text-secondary disabled:opacity-50 disabled:cursor-not-allowed hover:text-accent-green hover:border-accent-green transition-colors"
                                >
                                    Previous
                                </button>
                                <button
                                    type="button"
                                    disabled={page >= totalPages}
                                    onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
                                    className="px-4 py-2 rounded-lg border border-border-primary text-sm text-text-secondary disabled:opacity-50 disabled:cursor-not-allowed hover:text-accent-green hover:border-accent-green transition-colors"
                                >
                                    Next
                                </button>
                            </div>
                        </div>
                    )}

                    {/* CTA */}
                    <Card className="mt-12 p-8 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20 text-center">
                        <h3 className="text-2xl font-heading font-bold text-text-primary mb-3">
                            Want to Contribute?
                        </h3>
                        <p className="text-text-secondary mb-6 max-w-2xl mx-auto">
                            Share your security knowledge with the community. We&apos;re always looking for quality content.
                        </p>
                        <Link to="/contact">
                            <button className="px-6 py-3 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors">
                                Submit an Article
                            </button>
                        </Link>
                    </Card>
                </Container>
            </div>
        </Layout>
    );
}
