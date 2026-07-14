import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';
import { formatDateTime, getRelativeTime } from '@utils/date';
import { scanAPI } from '@/services/api';

export default function ScanHistory() {
    const [searchQuery, setSearchQuery] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');
    const [filterType, setFilterType] = useState('all');
    const [isLoading, setIsLoading] = useState(true);

    const [scans, setScans] = useState<{
        id: string; target: string; type: string; status: string; scopeType: string;
        date: Date; duration: number; score: number;
        vulnerabilities: { critical: number; high: number; medium: number; low: number };
    }[]>([]);

    useEffect(() => {
        const timer = setTimeout(() => {
            const params: Record<string, string> = {};
            if (searchQuery) params.search = searchQuery;
            if (filterStatus !== 'all') params.status = filterStatus;
            if (filterType !== 'all') params.scope_type = filterType;

            scanAPI.getList(params)
                .then(({ data }) => {
                    const results = data.results || data.scans || data || [];
                    setScans(results.map((s: Record<string, unknown>) => ({
                        id: s.id,
                        target: s.target,
                        type: s.scanType || s.type || 'Website',
                        scopeType: (s.scopeType || s.scope_type || 'single_domain') as string,
                        status: s.status,
                        date: new Date(s.createdAt as string || s.date as string),
                        duration: s.duration || 0,
                        score: s.score || 0,
                        vulnerabilities: s.vulnerabilitySummary || s.vulnerabilities || { critical: 0, high: 0, medium: 0, low: 0 },
                    })));
                })
                .catch(() => {})
                .finally(() => setIsLoading(false));
        }, 400);
        return () => clearTimeout(timer);
    }, [searchQuery, filterStatus, filterType]);

    const handleDelete = async (scanId: string) => {
        if (!confirm('Are you sure you want to delete this scan?')) return;
        try {
            await scanAPI.deleteScan(scanId);
            setScans((prev) => prev.filter((s) => s.id !== scanId));
        } catch (err) {
            console.error('Delete failed:', err);
            alert('Failed to delete scan. Please try again.');
        }
    };

    const filteredScans = scans;

    const completedScans = scans.filter((s) => s.status === 'completed');
    const stats = {
        total: scans.length,
        completed: completedScans.length,
        failed: scans.filter((s) => s.status === 'failed').length,
        avgScore: completedScans.length > 0
            ? Math.round(completedScans.reduce((acc, s) => acc + s.score, 0) / completedScans.length)
            : 0,
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading scan history...</span>
                        </div>
                    ) : (
                    <>
                    {/* Header */}
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Scan History
                            </h1>
                            <p className="text-text-secondary">
                                View and manage all your security scans
                            </p>
                        </div>
                        <Link to="/scan">
                            <Button variant="primary" className="mt-4 md:mt-0">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                                </svg>
                                New Scan
                            </Button>
                        </Link>
                    </div>

                    {/* Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                        <Card className="p-6">
                            <div className="text-3xl font-bold text-text-primary mb-1">{stats.total}</div>
                            <div className="text-sm text-text-tertiary">Total Scans</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-3xl font-bold text-status-low mb-1">{stats.completed}</div>
                            <div className="text-sm text-text-tertiary">Completed</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-3xl font-bold text-status-critical mb-1">{stats.failed}</div>
                            <div className="text-sm text-text-tertiary">Failed</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-3xl font-bold text-accent-green mb-1">{stats.avgScore}</div>
                            <div className="text-sm text-text-tertiary">Avg Score</div>
                        </Card>
                    </div>

                    {/* Filters */}
                    <Card className="p-6 mb-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <Input
                                type="text"
                                placeholder="Search by target domain..."
                                value={searchQuery}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                                leftIcon={
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                    </svg>
                                }
                            />
                            <Select
                                options={[
                                    { value: 'all', label: 'All Status' },
                                    { value: 'completed', label: 'Completed' },
                                    { value: 'failed', label: 'Failed' },
                                ]}
                                value={filterStatus}
                                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilterStatus(e.target.value)}
                            />
                            <Select
                                options={[
                                    { value: 'all', label: 'All Scope Types' },
                                    { value: 'single_domain', label: 'Single Domain' },
                                    { value: 'wildcard', label: 'Wildcard' },
                                    { value: 'wide_scope', label: 'Wide Scope' },
                                ]}
                                value={filterType}
                                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilterType(e.target.value)}
                            />
                        </div>
                    </Card>

                    {/* Scans Table */}
                    <Card className="overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead className="bg-bg-secondary border-b border-border-primary">
                                    <tr>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Target</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Type</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Status</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Date</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Score</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Issues</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-text-primary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border-primary">
                                    {filteredScans.map((scan) => (
                                        <tr key={scan.id} className="hover:bg-bg-hover transition-colors">
                                            <td className="px-6 py-4">
                                                <div className="font-mono text-sm text-text-primary">{scan.target}</div>
                                                <div className="text-xs text-text-tertiary mt-1">
                                                    Duration: {scan.duration}min
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <Badge variant="default" size="sm">
                                                    {{
                                                        single_domain: 'Single Domain',
                                                        wildcard: 'Wildcard',
                                                        wide_scope: 'Wide Scope',
                                                    }[scan.scopeType] || scan.type}
                                                </Badge>
                                            </td>
                                            <td className="px-6 py-4">
                                                {scan.status === 'completed' ? (
                                                    <Badge variant="low" size="sm">Completed</Badge>
                                                ) : (
                                                    <Badge variant="critical" size="sm">Failed</Badge>
                                                )}
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-sm text-text-primary">{getRelativeTime(scan.date)}</div>
                                                <div className="text-xs text-text-tertiary mt-1">
                                                    {formatDateTime(scan.date)}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                {scan.status === 'completed' ? (
                                                    <div className="text-xl font-bold text-accent-green">{scan.score}</div>
                                                ) : (
                                                    <span className="text-sm text-text-tertiary">N/A</span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4">
                                                {scan.status === 'completed' ? (
                                                    <div className="flex flex-col gap-1 text-xs">
                                                        {scan.vulnerabilities.critical > 0 && (
                                                            <span className="text-status-critical">
                                                                {scan.vulnerabilities.critical} Critical
                                                            </span>
                                                        )}
                                                        {scan.vulnerabilities.high > 0 && (
                                                            <span className="text-status-high">
                                                                {scan.vulnerabilities.high} High
                                                            </span>
                                                        )}
                                                        {scan.vulnerabilities.medium > 0 && (
                                                            <span className="text-status-medium">
                                                                {scan.vulnerabilities.medium} Medium
                                                            </span>
                                                        )}
                                                    </div>
                                                ) : (
                                                    <span className="text-sm text-text-tertiary">-</span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-2">
                                                    {scan.status === 'completed' && (
                                                        <Link to={`/scan/results/${scan.id}`}>
                                                            <Button variant="outline" size="sm">
                                                                View Report
                                                            </Button>
                                                        </Link>
                                                    )}
                                                    <button
                                                        onClick={() => handleDelete(scan.id)}
                                                        className="p-2 text-text-tertiary hover:text-status-critical transition-colors"
                                                    >
                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                        </svg>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {filteredScans.length === 0 && (
                            <div className="text-center py-12">
                                <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                                <p className="text-text-tertiary">No scans found matching your filters</p>
                            </div>
                        )}
                    </Card>
                    </>
                    )}
                </Container>
            </div>
        </Layout>
    );
}
