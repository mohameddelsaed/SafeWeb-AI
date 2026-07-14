import { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { formatDateTime } from '@utils/date';
import { webhookAPI } from '@/services/api';
import type { Webhook } from '@/types';

const EVENT_OPTIONS = [
    { value: 'scan.completed', label: 'Scan Completed' },
    { value: 'scan.failed', label: 'Scan Failed' },
    { value: 'vulnerability.found', label: 'Vulnerability Found' },
    { value: 'asset.changed', label: 'Asset Changed' },
    { value: 'scheduled.run', label: 'Scheduled Scan Run' },
];

export default function WebhookSettings() {
    const [webhooks, setWebhooks] = useState<Webhook[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState({ url: '', secret: '', events: ['scan.completed'] });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [testing, setTesting] = useState<string | null>(null);
    const [testResult, setTestResult] = useState<Record<string, string>>({});
    const [expandedDeliveries, setExpandedDeliveries] = useState<string | null>(null);
    const [deliveries, setDeliveries] = useState<Record<string, unknown[]>>({});

    const fetchWebhooks = () => {
        webhookAPI.getAll().then(({ data }) => {
            setWebhooks(Array.isArray(data) ? data : data.results ?? []);
        }).finally(() => setIsLoading(false));
    };

    useEffect(() => { fetchWebhooks(); }, []);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await webhookAPI.create({ url: formData.url, secret: formData.secret, events: formData.events });
            setShowForm(false);
            setFormData({ url: '', secret: '', events: ['scan.completed'] });
            fetchWebhooks();
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this webhook?')) return;
        await webhookAPI.delete(id);
        fetchWebhooks();
    };

    const handleTest = async (id: string) => {
        setTesting(id);
        setTestResult((p) => ({ ...p, [id]: '' }));
        try {
            await webhookAPI.test(id);
            setTestResult((p) => ({ ...p, [id]: 'success' }));
        } catch {
            setTestResult((p) => ({ ...p, [id]: 'failed' }));
        } finally {
            setTesting(null);
        }
    };

    const handleToggleDeliveries = async (id: string) => {
        if (expandedDeliveries === id) {
            setExpandedDeliveries(null);
            return;
        }
        setExpandedDeliveries(id);
        if (!deliveries[id]) {
            const { data } = await webhookAPI.getDeliveries(id);
            setDeliveries((p) => ({ ...p, [id]: Array.isArray(data) ? data : data.results ?? [] }));
        }
    };

    const toggleEvent = (event: string) => {
        setFormData((p) => ({
            ...p,
            events: p.events.includes(event) ? p.events.filter((e) => e !== event) : [...p.events, event],
        }));
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Webhook Settings</h1>
                            <p className="text-text-secondary">Get notified of scan events via HTTP callbacks.</p>
                        </div>
                        <Button variant="primary" onClick={() => setShowForm(true)}>
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                            </svg>
                            Add Webhook
                        </Button>
                    </div>

                    {showForm && (
                        <Card className="p-6 mb-6 border-accent-green/30">
                            <h3 className="text-lg font-semibold text-text-primary mb-4">New Webhook</h3>
                            <form onSubmit={handleCreate} className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label className="text-sm font-medium text-text-secondary block mb-1">Payload URL</label>
                                        <input type="url" required
                                            className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                            placeholder="https://hooks.example.com/safeweb"
                                            value={formData.url}
                                            onChange={(e) => setFormData((p) => ({ ...p, url: e.target.value }))}
                                        />
                                    </div>
                                    <div>
                                        <label className="text-sm font-medium text-text-secondary block mb-1">Secret (optional)</label>
                                        <input type="text"
                                            className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary font-mono focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                            placeholder="Used for HMAC signature verification"
                                            value={formData.secret}
                                            onChange={(e) => setFormData((p) => ({ ...p, secret: e.target.value }))}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-2">Events</label>
                                    <div className="flex flex-wrap gap-2">
                                        {EVENT_OPTIONS.map((opt) => (
                                            <button key={opt.value} type="button"
                                                onClick={() => toggleEvent(opt.value)}
                                                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${formData.events.includes(opt.value) ? 'bg-accent-green/20 border-accent-green text-accent-green' : 'bg-bg-secondary border-border-primary text-text-secondary hover:border-accent-green/50'}`}>
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                                <div className="flex gap-3 justify-end">
                                    <Button variant="outline" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                                    <Button variant="primary" type="submit" isLoading={isSubmitting} disabled={formData.events.length === 0}>Add Webhook</Button>
                                </div>
                            </form>
                        </Card>
                    )}

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading webhooks…</span>
                        </div>
                    ) : webhooks.length === 0 ? (
                        <Card className="p-12 text-center">
                            <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                            <h3 className="text-xl font-semibold text-text-primary mb-2">No Webhooks</h3>
                            <p className="text-text-secondary mb-4">Receive real-time notifications when scans complete or vulnerabilities are found.</p>
                            <Button variant="primary" onClick={() => setShowForm(true)}>Add First Webhook</Button>
                        </Card>
                    ) : (
                        <div className="space-y-4">
                            {webhooks.map((wh) => (
                                <Card key={wh.id} className="overflow-hidden">
                                    <div className="p-5 flex items-start justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <code className="text-sm text-accent-green">{wh.url}</code>
                                                <Badge variant={wh.isActive ? 'low' : 'info'} size="sm">{wh.isActive ? 'Active' : 'Inactive'}</Badge>
                                            </div>
                                            <div className="flex flex-wrap gap-1.5">
                                                {(wh.events ?? []).map((ev) => (
                                                    <span key={ev} className="px-2 py-0.5 bg-bg-secondary rounded text-xs text-text-secondary">{ev}</span>
                                                ))}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2 ml-4">
                                            <button onClick={() => handleTest(wh.id)}
                                                disabled={testing === wh.id}
                                                className="text-xs px-3 py-1.5 rounded bg-bg-secondary text-text-secondary hover:bg-bg-hover transition-colors disabled:opacity-50">
                                                {testing === wh.id ? 'Sending…' : 'Test'}
                                            </button>
                                            {testResult[wh.id] && (
                                                <span className={`text-xs ${testResult[wh.id] === 'success' ? 'text-status-low' : 'text-status-critical'}`}>
                                                    {testResult[wh.id] === 'success' ? '✓ Delivered' : '✗ Failed'}
                                                </span>
                                            )}
                                            <button onClick={() => handleToggleDeliveries(wh.id)}
                                                className="text-xs px-3 py-1.5 rounded bg-bg-secondary text-text-secondary hover:bg-bg-hover transition-colors">
                                                History
                                            </button>
                                            <button onClick={() => handleDelete(wh.id)}
                                                className="text-xs px-3 py-1.5 rounded bg-status-critical/10 text-status-critical hover:bg-status-critical/20 transition-colors">
                                                Delete
                                            </button>
                                        </div>
                                    </div>

                                    {expandedDeliveries === wh.id && (
                                        <div className="border-t border-border-primary bg-bg-secondary/50">
                                            <h4 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider px-5 py-3">Delivery History</h4>
                                            {(deliveries[wh.id] ?? []).length === 0 ? (
                                                <p className="text-sm text-text-tertiary px-5 pb-4">No deliveries yet.</p>
                                            ) : (
                                                <table className="w-full text-xs">
                                                    <thead>
                                                        <tr className="text-text-tertiary border-b border-border-primary">
                                                            <th className="text-left px-5 py-2">Event</th>
                                                            <th className="text-left px-5 py-2">Status</th>
                                                            <th className="text-left px-5 py-2">Response</th>
                                                            <th className="text-left px-5 py-2">Delivered At</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {(deliveries[wh.id] as Record<string, unknown>[]).map((d, i) => (
                                                            <tr key={i} className="border-b border-border-primary/50">
                                                                <td className="px-5 py-2 font-mono text-text-secondary">{String(d.event)}</td>
                                                                <td className="px-5 py-2">
                                                                    <span className={`font-medium ${(d.success) ? 'text-status-low' : 'text-status-critical'}`}>
                                                                        {(d.success) ? '✓ OK' : '✗ Failed'}
                                                                    </span>
                                                                </td>
                                                                <td className="px-5 py-2 text-text-tertiary">{String(d.responseCode ?? '—')}</td>
                                                                <td className="px-5 py-2 text-text-tertiary">
                                                                    {d.deliveredAt ? formatDateTime(new Date(String(d.deliveredAt))) : '—'}
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>
                                    )}
                                </Card>
                            ))}
                        </div>
                    )}
                </Container>
            </div>
        </Layout>
    );
}
