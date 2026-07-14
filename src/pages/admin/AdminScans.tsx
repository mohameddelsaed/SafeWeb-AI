import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';
import { adminAPI, scanAPI } from '@services/api';

interface ScanRow {
    id: string;
    url: string;
    user: string;
    status: string;
    vulnerabilities: number;
    severity: string;
    started: string;
    duration: string;
}

interface TesterEntry {
    name: string;
    findings: number;
    duration: number;
    status: string;
}

export default function AdminScans() {
    const navigate = useNavigate();
    const [searchQuery, setSearchQuery] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');
    const [scans, setScans] = useState<ScanRow[]>([]);
    const [totalScans, setTotalScans] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [stats, setStats] = useState([
        { label: 'Total Scans Today', value: '—', change: '' },
        { label: 'Currently Running', value: '—', change: '' },
        { label: 'Failed Today', value: '—', change: '' },
        { label: 'Avg Duration', value: '—', change: '' },
    ]);
    const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
    const [testerCache, setTesterCache] = useState<Record<string, TesterEntry[]>>({});
    const [loadingTesters, setLoadingTesters] = useState<string | null>(null);

    const fetchScans = () => {
        setIsLoading(true);
        const params: Record<string, string> = { page: String(page) };
        if (searchQuery) params.search = searchQuery;
        if (filterStatus !== 'all') params.status = filterStatus;
        adminAPI.getScans(params)
            .then((res) => {
                const d = res.data;
                setScans(d.results ?? d.scans ?? d);
                setTotalScans(d.count ?? d.total ?? 0);
                if (d.stats) setStats(d.stats);
            })
            .catch(() => setScans([]))
            .finally(() => setIsLoading(false));
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { fetchScans(); }, [page, filterStatus]);
    useEffect(() => { setPage(1); }, [filterStatus]);
    useEffect(() => {
        const t = setTimeout(fetchScans, 400);
        return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [searchQuery]);

    const handleToggleTesters = async (id: string) => {
        if (expandedScanId === id) { setExpandedScanId(null); return; }
        setExpandedScanId(id);
        if (testerCache[id]) return;
        setLoadingTesters(id);
        try {
            const { data } = await scanAPI.getResults(id);
            const results: TesterEntry[] = Array.isArray(data.tester_results)
                ? data.tester_results.map((t: Record<string, unknown>) => ({
                    name: String(t.testerName ?? t.name ?? t.tester ?? ''),
                    findings: Number(t.findingsCount ?? t.findings ?? t.finding_count ?? 0),
                    duration: typeof t.durationMs === 'number' ? t.durationMs / 1000 : Number(t.duration ?? 0),
                    status: String(t.status ?? 'completed'),
                }))
                : [];
            setTesterCache((p) => ({ ...p, [id]: results }));
        } catch { setTesterCache((p) => ({ ...p, [id]: [] })); }
        finally { setLoadingTesters(null); }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this scan?')) return;
        try {
            await adminAPI.deleteScan(id);
            fetchScans();
        } catch (err) {
            console.error('Delete scan failed:', err);
            alert('Failed to delete scan. Please try again.');
        }
    };

    const statusOptions = [
        { value: 'all', label: 'All Status' },
        { value: 'running', label: 'Running' },
        { value: 'completed', label: 'Completed' },
        { value: 'failed', label: 'Failed' },
        { value: 'queued', label: 'Queued' },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Scan Monitoring
                            </h1>
                            <p className="text-text-secondary">Monitor all security scans across the platform</p>
                        </div>
                        <div className="flex items-center gap-3">
                            <Button variant="outline" size="sm" onClick={() => {
                                const csv = ['ID,URL,User,Status,Vulnerabilities,Severity,Started,Duration'];
                                scans.forEach((s) => csv.push(`${s.id},${s.url},${s.user},${s.status},${s.vulnerabilities},${s.severity},${s.started},${s.duration}`));
                                const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
                                const a = document.createElement('a');
                                a.href = URL.createObjectURL(blob);
                                a.download = 'scans_report.csv';
                                a.click();
                            }}>
                                Export Report
                            </Button>
                            <Button variant="primary" size="sm" onClick={fetchScans}>
                                Refresh
                            </Button>
                        </div>
                    </div>

                    {/* Stats */}
                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                        </div>
                    ) : (
                    <>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        {stats.map((stat, index) => (
                            <Card key={index} className="p-6">
                                <div className="text-sm text-text-tertiary mb-2">{stat.label}</div>
                                <div className="flex items-end justify-between">
                                    <div className="text-3xl font-bold text-text-primary">{stat.value}</div>
                                    <span className="text-sm text-accent-green">{stat.change}</span>
                                </div>
                            </Card>
                        ))}
                    </div>

                    {/* Filters */}
                    <Card className="p-6 mb-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input
                                type="text"
                                placeholder="Search by URL or user email..."
                                value={searchQuery}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                                leftIcon={
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                    </svg>
                                }
                            />
                            <Select
                                options={statusOptions}
                                value={filterStatus}
                                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilterStatus(e.target.value)}
                            />
                        </div>
                    </Card>

                    {/* Scans Table */}
                    <Card className="overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="bg-bg-secondary">
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">ID</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Target URL</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">User</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Vulnerabilities</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Severity</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Started</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Duration</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {scans.map((scan) => (
                                        <React.Fragment key={scan.id}>
                                        <tr className="border-t border-border-primary hover:bg-bg-secondary/50">
                                            <td className="py-4 px-6 text-text-secondary">#{scan.id}</td>
                                            <td className="py-4 px-6">
                                                <div className="font-medium text-text-primary">{scan.url}</div>
                                            </td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{scan.user}</td>
                                            <td className="py-4 px-6">
                                                <Badge
                                                    variant={
                                                        scan.status === 'completed'
                                                            ? 'success'
                                                            : scan.status === 'running'
                                                                ? 'info'
                                                                : scan.status === 'failed'
                                                                    ? 'critical'
                                                                    : 'default'
                                                    }
                                                >
                                                    {scan.status}
                                                </Badge>
                                            </td>
                                            <td className="py-4 px-6 text-text-primary font-semibold">
                                                {scan.vulnerabilities > 0 ? scan.vulnerabilities : '-'}
                                            </td>
                                            <td className="py-4 px-6">
                                                {scan.severity !== '-' ? (
                                                    <Badge
                                                        variant={
                                                            scan.severity === 'critical'
                                                                ? 'critical'
                                                                : scan.severity === 'high'
                                                                    ? 'high'
                                                                    : scan.severity === 'medium'
                                                                        ? 'medium'
                                                                        : 'low'
                                                        }
                                                    >
                                                        {scan.severity}
                                                    </Badge>
                                                ) : (
                                                    <span className="text-text-tertiary">-</span>
                                                )}
                                            </td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{scan.started}</td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{scan.duration}</td>
                                            <td className="py-4 px-6">
                                                <div className="flex items-center gap-2">
                                                    <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-accent-green transition-colors" title="View scan results" onClick={() => navigate(`/scan/results/${scan.id}`)}>
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                        </svg>
                                                    </button>
                                                    {scan.status === 'running' && (
                                                        <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-status-high transition-colors" title="Stop scan" onClick={() => handleDelete(scan.id)}>
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                                            </svg>
                                                        </button>
                                                    )}
                                                    <button
                                                        className={`p-2 rounded-lg hover:bg-bg-hover transition-colors ${expandedScanId === scan.id ? 'text-accent-green' : 'text-text-secondary hover:text-accent-green'}`}
                                                        onClick={() => handleToggleTesters(scan.id)}
                                                        title="View tester breakdown"
                                                    >
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                                        </svg>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                        {expandedScanId === scan.id && (
                                            <tr className="bg-bg-secondary/30">
                                                <td colSpan={9} className="px-6 py-4">
                                                    {loadingTesters === scan.id ? (
                                                        <div className="flex items-center gap-2 text-sm text-text-secondary">
                                                            <div className="w-4 h-4 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                                                            Loading tester results…
                                                        </div>
                                                    ) : (testerCache[scan.id] ?? []).length === 0 ? (
                                                        <p className="text-sm text-text-tertiary">No tester results available.</p>
                                                    ) : (
                                                        <table className="w-full text-xs">
                                                            <thead>
                                                                <tr className="text-text-tertiary">
                                                                    <th className="text-left py-1 pr-6">Tester</th>
                                                                    <th className="text-left py-1 pr-6">Findings</th>
                                                                    <th className="text-left py-1 pr-6">Duration (s)</th>
                                                                    <th className="text-left py-1">Status</th>
                                                                </tr>
                                                            </thead>
                                                            <tbody>
                                                                {testerCache[scan.id].map((t, i) => (
                                                                    <tr key={i} className="border-t border-border-primary/30">
                                                                        <td className="py-1.5 pr-6 font-mono">{t.name}</td>
                                                                        <td className="py-1.5 pr-6">
                                                                            {t.findings > 0
                                                                                ? <span className="text-status-high font-medium">{t.findings}</span>
                                                                                : '0'}
                                                                        </td>
                                                                        <td className="py-1.5 pr-6 text-text-tertiary">{t.duration.toFixed(1)}</td>
                                                                        <td className="py-1.5">
                                                                            <Badge
                                                                                variant={t.status === 'completed' ? 'success' : t.status === 'failed' ? 'critical' : 'info'}
                                                                                size="sm"
                                                                            >
                                                                                {t.status}
                                                                            </Badge>
                                                                        </td>
                                                                    </tr>
                                                                ))}
                                                            </tbody>
                                                        </table>
                                                    )}
                                                </td>
                                            </tr>
                                        )}
                                        </React.Fragment>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Pagination */}
                        <div className="flex items-center justify-between px-6 py-4 border-t border-border-primary">
                            <div className="text-sm text-text-secondary">
                                Showing {scans.length > 0 ? (page - 1) * 10 + 1 : 0} to {Math.min(page * 10, totalScans)} of {totalScans.toLocaleString()} scans
                            </div>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
                                <span className="text-sm text-text-secondary px-2">Page {page}</span>
                                <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={scans.length < 10}>Next</Button>
                            </div>
                        </div>
                    </Card>
                    </>
                    )}
                </Container>
            </div>
        </Layout>
    );
}
