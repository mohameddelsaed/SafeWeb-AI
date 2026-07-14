import { useState } from 'react';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import type { TesterResult } from '@/types';

interface TesterBreakdownTabProps {
    testerResults?: TesterResult[];
    totalTesters?: number;
}

export default function TesterBreakdownTab({ testerResults, totalTesters }: TesterBreakdownTabProps) {
    const [sortKey, setSortKey] = useState<'findings' | 'duration' | 'name'>('findings');
    const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

    if (!testerResults || testerResults.length === 0) {
        return (
            <Card className="p-12 text-center">
                <p className="text-text-secondary">No tester breakdown data available for this scan.</p>
                <p className="text-xs text-text-tertiary mt-2">
                    Tester metrics are recorded for scans run after Phase 48.
                </p>
            </Card>
        );
    }

    const sorted = [...testerResults].sort((a, b) => {
        let cmp = 0;
        if (sortKey === 'findings') cmp = a.findingsCount - b.findingsCount;
        else if (sortKey === 'duration') cmp = a.durationMs - b.durationMs;
        else cmp = a.testerName.localeCompare(b.testerName);
        return sortDir === 'desc' ? -cmp : cmp;
    });

    const total = testerResults.length;
    const totalFindings = testerResults.reduce((s, t) => s + t.findingsCount, 0);
    const passed = testerResults.filter((t) => t.status === 'passed').length;
    const failed = testerResults.filter((t) => t.status === 'failed').length;
    const skipped = testerResults.filter((t) => t.status === 'skipped').length;
    const coverage = totalTesters ? Math.round((total / totalTesters) * 100) : null;

    const toggleSort = (key: typeof sortKey) => {
        if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        else { setSortKey(key); setSortDir('desc'); }
    };

    return (
        <div className="space-y-6">
            {/* Summary bar */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <Card className="p-4 text-center">
                    <div className="text-2xl font-bold text-text-primary">{total}</div>
                    <div className="text-xs text-text-tertiary mt-1">Testers Run</div>
                </Card>
                <Card className="p-4 text-center">
                    <div className="text-2xl font-bold text-accent-green">{passed}</div>
                    <div className="text-xs text-text-tertiary mt-1">Passed</div>
                </Card>
                <Card className="p-4 text-center">
                    <div className="text-2xl font-bold text-status-critical">{failed}</div>
                    <div className="text-xs text-text-tertiary mt-1">Failed</div>
                </Card>
                <Card className="p-4 text-center">
                    <div className="text-2xl font-bold text-status-medium">{skipped}</div>
                    <div className="text-xs text-text-tertiary mt-1">Skipped</div>
                </Card>
                <Card className="p-4 text-center">
                    <div className="text-2xl font-bold text-text-primary">{totalFindings}</div>
                    <div className="text-xs text-text-tertiary mt-1">Total Findings</div>
                </Card>
            </div>

            {/* Coverage bar */}
            {coverage !== null && (
                <Card className="p-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-text-secondary">Tester Coverage ({total}/{totalTesters})</span>
                        <span className="text-sm font-semibold text-accent-green">{coverage}%</span>
                    </div>
                    <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                        <div
                            className="h-full bg-accent-green rounded-full transition-all duration-500"
                            style={{ width: `${coverage}%` }}
                        />
                    </div>
                </Card>
            )}

            {/* Table */}
            <Card className="overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead className="bg-bg-secondary border-b border-border-primary">
                            <tr>
                                <th
                                    className="text-left px-4 py-3 text-text-tertiary font-medium cursor-pointer hover:text-text-primary select-none"
                                    onClick={() => toggleSort('name')}
                                >
                                    Tester {sortKey === 'name' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                                </th>
                                <th
                                    className="text-center px-4 py-3 text-text-tertiary font-medium cursor-pointer hover:text-text-primary select-none"
                                    onClick={() => toggleSort('findings')}
                                >
                                    Findings {sortKey === 'findings' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                                </th>
                                <th
                                    className="text-center px-4 py-3 text-text-tertiary font-medium cursor-pointer hover:text-text-primary select-none"
                                    onClick={() => toggleSort('duration')}
                                >
                                    Time {sortKey === 'duration' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                                </th>
                                <th className="text-center px-4 py-3 text-text-tertiary font-medium">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map((t, i) => (
                                <tr key={i} className="border-b border-border-primary/30 hover:bg-bg-hover transition-colors">
                                    <td className="px-4 py-3 text-text-primary font-medium">{t.testerName}</td>
                                    <td className="px-4 py-3 text-center">
                                        {t.findingsCount > 0 ? (
                                            <span className="text-status-high font-semibold">{t.findingsCount}</span>
                                        ) : (
                                            <span className="text-text-tertiary">0</span>
                                        )}
                                    </td>
                                    <td className="px-4 py-3 text-center font-mono text-text-secondary">
                                        {t.durationMs >= 1000
                                            ? `${(t.durationMs / 1000).toFixed(1)}s`
                                            : `${t.durationMs}ms`}
                                    </td>
                                    <td className="px-4 py-3 text-center">
                                        <Badge
                                            variant={
                                                t.status === 'passed' ? 'low' :
                                                t.status === 'failed' ? 'critical' : 'info'
                                            }
                                            size="sm"
                                        >
                                            {t.status}
                                        </Badge>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
}
