import { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { formatDateTime } from '@utils/date';
import { scheduledScanAPI } from '@/services/api';
import type { ScheduledScan } from '@/types';

export default function ScheduledScans() {
    const [scans, setScans] = useState<ScheduledScan[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState({ name: '', target: '', cronExpr: '0 2 * * *', scanDepth: 'medium' });
    const [isSubmitting, setIsSubmitting] = useState(false);

    const fetchScans = () => {
        scheduledScanAPI.getAll().then(({ data }) => {
            setScans(Array.isArray(data) ? data : data.results ?? []);
        }).finally(() => setIsLoading(false));
    };

    useEffect(() => { fetchScans(); }, []);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await scheduledScanAPI.create({
                name: formData.name || formData.target,
                target: formData.target,
                cronExpr: formData.cronExpr,
                scanConfig: { depth: formData.scanDepth },
            });
            setShowForm(false);
            setFormData({ name: '', target: '', cronExpr: '0 2 * * *', scanDepth: 'medium' });
            fetchScans();
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleToggle = async (scan: ScheduledScan) => {
        await scheduledScanAPI.toggle(scan.id, !scan.isActive);
        fetchScans();
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this scheduled scan?')) return;
        await scheduledScanAPI.delete(id);
        fetchScans();
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Scheduled Scans</h1>
                            <p className="text-text-secondary">Automate recurring security scans with cron schedules.</p>
                        </div>
                        <Button variant="primary" onClick={() => setShowForm(true)}>
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                            </svg>
                            New Schedule
                        </Button>
                    </div>

                    {/* Create form */}
                    {showForm && (
                        <Card className="p-6 mb-6 border-accent-green/30">
                            <h3 className="text-lg font-semibold text-text-primary mb-4">New Scheduled Scan</h3>
                            <form onSubmit={handleCreate} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-1">Schedule Name</label>
                                    <input
                                        type="text"
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                        placeholder="Daily production scan"
                                        value={formData.name}
                                        onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                                    />
                                </div>
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-1">Target URL</label>
                                    <input
                                        type="url" required
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                        placeholder="https://example.com"
                                        value={formData.target}
                                        onChange={(e) => setFormData((p) => ({ ...p, target: e.target.value }))}
                                    />
                                </div>
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-1">Cron Expression</label>
                                    <input
                                        type="text" required
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary font-mono focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                        placeholder="0 2 * * *"
                                        value={formData.cronExpr}
                                        onChange={(e) => setFormData((p) => ({ ...p, cronExpr: e.target.value }))}
                                    />
                                    <p className="text-xs text-text-tertiary mt-1">Standard cron syntax (min hr dom mon dow)</p>
                                </div>
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-1">Scan Depth</label>
                                    <select
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                        value={formData.scanDepth}
                                        onChange={(e) => setFormData((p) => ({ ...p, scanDepth: e.target.value }))}
                                    >
                                        <option value="shallow">Shallow</option>
                                        <option value="medium">Medium</option>
                                        <option value="deep">Deep</option>
                                    </select>
                                </div>
                                <div className="md:col-span-3 flex gap-3 justify-end">
                                    <Button variant="outline" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                                    <Button variant="primary" type="submit" isLoading={isSubmitting}>Create Schedule</Button>
                                </div>
                            </form>
                        </Card>
                    )}

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading schedules…</span>
                        </div>
                    ) : scans.length === 0 ? (
                        <Card className="p-12 text-center">
                            <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <h3 className="text-xl font-semibold text-text-primary mb-2">No Scheduled Scans</h3>
                            <p className="text-text-secondary mb-4">Automate your security testing by creating a scheduled scan.</p>
                            <Button variant="primary" onClick={() => setShowForm(true)}>Create First Schedule</Button>
                        </Card>
                    ) : (
                        <div className="space-y-4">
                            {scans.map((scan) => (
                                <Card key={scan.id} className="p-6">
                                    <div className="flex items-start justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <h3 className="text-base font-semibold text-text-primary font-mono">{scan.target}</h3>
                                                <Badge variant={scan.isActive ? 'low' : 'info'} size="sm">{scan.isActive ? 'Active' : 'Paused'}</Badge>
                                            </div>
                                            <div className="flex items-center gap-6 text-xs text-text-tertiary">
                                                <span>Cron: <code className="text-accent-green">{scan.cronExpr}</code></span>
                                                {scan.nextRun && <span>Next run: {formatDateTime(new Date(scan.nextRun))}</span>}
                                                {scan.lastRun && <span>Last run: {formatDateTime(new Date(scan.lastRun))}</span>}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2 ml-4">
                                            <button onClick={() => handleToggle(scan)}
                                                className="text-xs px-3 py-1.5 rounded bg-bg-secondary text-text-secondary hover:bg-bg-hover transition-colors">
                                                {scan.isActive ? 'Pause' : 'Resume'}
                                            </button>
                                            <button onClick={() => handleDelete(scan.id)}
                                                className="text-xs px-3 py-1.5 rounded bg-status-critical/10 text-status-critical hover:bg-status-critical/20 transition-colors">
                                                Delete
                                            </button>
                                        </div>
                                    </div>
                                </Card>
                            ))}
                        </div>
                    )}
                </Container>
            </div>
        </Layout>
    );
}
