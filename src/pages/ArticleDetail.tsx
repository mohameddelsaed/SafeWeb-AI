import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import { formatDate } from '@utils/date';
import { learnAPI } from '@/services/api';

interface Article {
    id: string;
    title: string;
    slug: string;
    content: string;
    excerpt: string;
    category: string;
    categoryDisplay: string;
    author: string;
    date: Date;
    readTime: number;
    image: string | null;
}

export default function ArticleDetail() {
    const { slug } = useParams();
    const [article, setArticle] = useState<Article | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        if (!slug) return;
        setIsLoading(true);
        learnAPI.getArticle(slug)
            .then(({ data }) => {
                setArticle({
                    id: data.id,
                    title: data.title,
                    slug: data.slug,
                    content: data.content || '',
                    excerpt: data.excerpt || '',
                    category: data.category || '',
                    categoryDisplay: data.categoryDisplay || data.category || '',
                    author: data.author || 'SafeWeb AI Team',
                    date: new Date(data.createdAt || data.date),
                    readTime: data.readTime || 5,
                    image: data.image || null,
                });
            })
            .catch(() => setError('Article not found'))
            .finally(() => setIsLoading(false));
    }, [slug]);

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="max-w-4xl mx-auto">
                        {/* Back Link */}
                        <Link
                            to="/learn"
                            className="text-sm text-accent-green hover:text-accent-green-hover mb-6 inline-flex items-center gap-1"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                            </svg>
                            Back to Learning Center
                        </Link>

                        {isLoading ? (
                            <div className="flex items-center justify-center py-20">
                                <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                                <span className="ml-3 text-text-secondary">Loading article...</span>
                            </div>
                        ) : error || !article ? (
                            <Card className="p-12 text-center">
                                <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M12 2a10 10 0 100 20 10 10 0 000-20z" />
                                </svg>
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                    Article Not Found
                                </h2>
                                <p className="text-text-secondary mb-4">
                                    The article you&apos;re looking for doesn&apos;t exist or has been removed.
                                </p>
                                <Link to="/learn">
                                    <button className="px-6 py-2 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors">
                                        Browse Articles
                                    </button>
                                </Link>
                            </Card>
                        ) : (
                            <>
                                {/* Article Header */}
                                <div className="mb-8">
                                    <div className="flex items-center gap-3 mb-4">
                                        <Badge variant="default" size="sm">{article.categoryDisplay}</Badge>
                                        <span className="text-sm text-text-tertiary">{article.readTime} min read</span>
                                    </div>
                                    <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                                        {article.title}
                                    </h1>
                                    {article.excerpt && (
                                        <p className="text-lg text-text-secondary leading-relaxed mb-6">
                                            {article.excerpt}
                                        </p>
                                    )}
                                    <div className="flex items-center gap-4 text-sm text-text-tertiary pb-6 border-b border-border-primary">
                                        <div className="flex items-center gap-2">
                                            <div className="w-8 h-8 rounded-full bg-accent-green/20 flex items-center justify-center text-accent-green font-semibold text-sm">
                                                {article.author.charAt(0).toUpperCase()}
                                            </div>
                                            <span>{article.author}</span>
                                        </div>
                                        <span>&bull;</span>
                                        <span>{formatDate(article.date)}</span>
                                    </div>
                                </div>

                                {/* Article Content */}
                                <Card className="p-8">
                                    <div
                                        className="prose prose-invert max-w-none 
                                            prose-headings:font-heading prose-headings:text-text-primary
                                            prose-p:text-text-secondary prose-p:leading-relaxed
                                            prose-a:text-accent-green prose-a:no-underline hover:prose-a:underline
                                            prose-strong:text-text-primary
                                            prose-code:text-accent-green prose-code:bg-bg-secondary prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded
                                            prose-pre:bg-bg-secondary prose-pre:border prose-pre:border-border-primary
                                            prose-li:text-text-secondary
                                            prose-blockquote:border-accent-green prose-blockquote:text-text-secondary"
                                    >
                                        <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]}>
                                            {article.content}
                                        </ReactMarkdown>
                                    </div>
                                </Card>

                                {/* Navigation */}
                                <div className="mt-8 flex justify-center">
                                    <Link to="/learn">
                                        <button className="px-6 py-3 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors">
                                            More Articles
                                        </button>
                                    </Link>
                                </div>
                            </>
                        )}
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
