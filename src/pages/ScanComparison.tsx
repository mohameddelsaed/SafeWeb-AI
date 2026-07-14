import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import { formatDateTime } from '@utils/date';
import { scanAPI } from '@/services/api';
import type { Vulnerability } from '@/types';

interface ComparisonData {
    scan1: { id: string; target: string; createdAt: string; score: number; totalFindings: number };
    scan2: { id: string; target: string; createdAt: string; score: number; totalFindings: number };
    new: Vulnerability[];
    fixed: Vulnerability[];
    persisted: Vulnerability[];
    scoreDiff: number;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function SeverityBadge({ severity }: { severity: string }) {
    const variantMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
        critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
    };
    return <Badge variant={variantMap[severity] ?? 'info'} size="sm">{severity}</Badge>;
}

function FindingRow({ vuln }: { vuln: Vulnerability }) {
    return (
        <tr className="border-b border-border-primary/50 hover:bg-bg-secondary/50 transition-colors">
            <td className="px-4 py-3">
                <p className="text-sm font-medium text-text-primary">{vuln.name}</p>
                {vuln.affectedUrl && <p className="text-xs text-text-tertiary font-mono truncate max-w-xs mt-0.5">{vuln.affectedUrl}</p>}
            </td>
            <td className="px-4 py-3"><SeverityBadge severity={vuln.severity} /></td>
            <td className="px-4 py-3 text-xs text-text-tertiary">{vuln.category}</td>
        </tr>
    );
}

function FindingsTable({ vulns, emptyMsg, scanId }: { vulns: Vulnerability[]; emptyMsg: string; scanId?: string }) {
    const sorted = [...vulns].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
    if (sorted.length === 0) {
        return <p className="text-sm text-text-tertiary py-4 px-4">{emptyMsg}</p>;
    }
    return (
        <div>
            <table className="w-full text-sm">
                <thead>
                    <tr className="text-xs text-text-tertiary border-b border-border-primary">
                        <th className="text-left px-4 py-2">Finding</th>
                        <th className="text-left px-4 py-2">Severity</th>
                        <th className="text-left px-4 py-2">Category</th>
                    </tr>
                </thead>
                <tbody>
                    {sorted.map((v) => <FindingRow key={v.id} vuln={v} />)}
                </tbody>
            </table>
            {sorted.length > 0 && (
                <div className="px-4 py-3 border-t border-border-primary">
                    <button
                        onClick={() => {
                            const summary = sorted.slice(0, 5).map(v => `${v.severity}: ${v.name}`).join(', ');
                            const msg = `Explain these findings and suggest fixes: ${summary}${sorted.length > 5 ? ` (and ${sorted.length - 5} more)` : ''}`;
                            window.dispatchEvent(new CustomEvent('safeweb-chatbot-ask', { detail: { message: msg, scanId } }));
                        }}
                        className="text-xs px-3 py-1.5 rounded-lg bg-accent-green/10 text-accent-green hover:bg-accent-green/20 transition-colors border border-accent-green/30 flex items-center gap-1.5"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                        </svg>
                        Ask AI about these findings
                    </button>
                </div>
            )}
        </div>
    );
}

export default function ScanComparison() {
    const { id1, id2 } = useParams<{ id1: string; id2: string }>();
    const [data, setData] = useState<ComparisonData | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!id1 || !id2) return;
        scanAPI.compareScan(id1, id2)
            .then(({ data: d }) => setData(d as ComparisonData))
            .catch(() => setError('Failed to load comparison data.'))
            .finally(() => setIsLoading(false));
    }, [id1, id2]);

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="mb-8">
                        <Link to="/history" className="text-sm text-text-tertiary hover:text-accent-green transition-colors inline-flex items-center gap-1 mb-3">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                            </svg>
                            Back to History
                        </Link>
                        <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Scan Comparison</h1>
                        <p className="text-text-secondary">Side-by-side diff of two scan results.</p>
                    </div>

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading comparison…</span>
                        </div>
                    ) : error ? (
                        <Card className="p-12 text-center">
                            <p className="text-status-critical text-lg font-semibold mb-2">Error</p>
                            <p className="text-text-secondary">{error}</p>
                            <Link to="/history" className="mt-4 inline-block text-accent-green hover:underline text-sm">Go back to history</Link>
                        </Card>
                    ) : data ? (
                        <>
                            {/* Score banner */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                                {/* Scan 1 */}
                                <Card className="p-5">
                                    <p className="text-xs text-text-tertiary mb-1">Scan A</p>
                                    <Link to={`/scan/results/${data.scan1.id}`} className="truncate text-sm font-mono text-text-primary hover:text-accent-green transition-colors block mb-2">{data.scan1.target}</Link>
                                    <div className="flex items-end justify-between">
                                        <span className="text-3xl font-bold text-accent-green">{data.scan1.score}</span>
                                        <span className="text-sm text-text-tertiary">{data.scan1.totalFindings} findings</span>
                                    </div>
                                    <p className="text-xs text-text-tertiary mt-1">{formatDateTime(new Date(data.scan1.createdAt))}</p>
                                </Card>

                                {/* Diff card */}
                                <Card className={`p-5 flex flex-col items-center justify-center ${data.scoreDiff > 0 ? 'border-status-low/30' : data.scoreDiff < 0 ? 'border-status-high/30' : ''}`}>
                                    <p className="text-xs text-text-tertiary mb-2">Score Change</p>
                                    <span className={`text-4xl font-bold ${data.scoreDiff > 0 ? 'text-status-low' : data.scoreDiff < 0 ? 'text-status-high' : 'text-text-tertiary'}`}>
                                        {data.scoreDiff > 0 ? '+' : ''}{data.scoreDiff}
                                    </span>
                                    <div className="flex gap-3 text-xs mt-3">
                                        <span className="text-status-high">+{data.new.length} new</span>
                                        <span className="text-status-low">-{data.fixed.length} fixed</span>
                                        <span className="text-text-tertiary">{data.persisted.length} persisted</span>
                                    </div>
                                </Card>

                                {/* Scan 2 */}
                                <Card className="p-5">
                                    <p className="text-xs text-text-tertiary mb-1">Scan B</p>
                                    <Link to={`/scan/results/${data.scan2.id}`} className="truncate text-sm font-mono text-text-primary hover:text-accent-green transition-colors block mb-2">{data.scan2.target}</Link>
                                    <div className="flex items-end justify-between">
                                        <span className="text-3xl font-bold text-accent-green">{data.scan2.score}</span>
                                        <span className="text-sm text-text-tertiary">{data.scan2.totalFindings} findings</span>
                                    </div>
                                    <p className="text-xs text-text-tertiary mt-1">{formatDateTime(new Date(data.scan2.createdAt))}</p>
                                </Card>
                            </div>

                            {/* New findings */}
                            <Card className="mb-5 overflow-hidden">
                                <div className="px-5 py-4 border-b border-border-primary flex items-center gap-3">
                                    <svg className="w-4 h-4 text-status-high" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                    </svg>
                                    <h3 className="font-semibold text-text-primary">New Findings in Scan B</h3>
                                    <span className="ml-auto text-sm text-status-high font-medium">{data.new.length}</span>
                                </div>
                                <FindingsTable vulns={data.new} emptyMsg="No new findings — no regressions!" scanId={id2} />
                            </Card>

                            {/* Fixed findings */}
                            <Card className="mb-5 overflow-hidden">
                                <div className="px-5 py-4 border-b border-border-primary flex items-center gap-3">
                                    <svg className="w-4 h-4 text-status-low" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    <h3 className="font-semibold text-text-primary">Fixed / Resolved</h3>
                                    <span className="ml-auto text-sm text-status-low font-medium">{data.fixed.length}</span>
                                </div>
                                <FindingsTable vulns={data.fixed} emptyMsg="No fixed findings between these scans." scanId={id1} />
                            </Card>

                            {/* Persisted findings */}
                            <Card className="overflow-hidden">
                                <div className="px-5 py-4 border-b border-border-primary flex items-center gap-3">
                                    <svg className="w-4 h-4 text-text-tertiary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    <h3 className="font-semibold text-text-primary">Persisted (Both Scans)</h3>
                                    <span className="ml-auto text-sm text-text-tertiary font-medium">{data.persisted.length}</span>
                                </div>
                                <FindingsTable vulns={data.persisted} emptyMsg="No persisted findings." scanId={id2} />
                            </Card>
                        </>
                    ) : null}
                </Container>
            </div>
        </Layout>
    );
}
