import { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { targetAPI } from '@/services/api';

interface Target {
    id: string;
    domain: string;
    display_name: string;
    tags: string[];
    is_dns_verified: boolean;
    current_score: number;
    last_scanned_at: string | null;
}

export default function Targets() {
    const [targets, setTargets] = useState<Target[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState({ domain: '', display_name: '', tags: '' });
    const [isSubmitting, setIsSubmitting] = useState(false);

    const fetchTargets = () => {
        targetAPI.getTargets().then(({ data }) => {
            setTargets(Array.isArray(data) ? data : data.results ?? []);
        }).finally(() => setIsLoading(false));
    };

    useEffect(() => { fetchTargets(); }, []);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await targetAPI.createTarget({
                domain: formData.domain,
                display_name: formData.display_name,
                tags: formData.tags.split(',').map(t => t.trim()).filter(Boolean),
            });
            setShowForm(false);
            setFormData({ domain: '', display_name: '', tags: '' });
            fetchTargets();
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this target?')) return;
        await targetAPI.deleteTarget(id);
        fetchTargets();
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Target Management</h1>
                            <p className="text-text-secondary">Manage web targets for your organization.</p>
                        </div>
                        <Button variant="primary" onClick={() => setShowForm(true)}>
                            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                            </svg>
                            New Target
                        </Button>
                    </div>

                    {showForm && (
                        <Card className="p-6 mb-6 border-accent-green/30">
                            <h3 className="text-lg font-semibold text-text-primary mb-4">Add Target</h3>
                            <form onSubmit={handleCreate} className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label className="text-sm font-medium text-text-secondary block mb-1">Domain</label>
                                        <input type="text" required
                                            className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                            placeholder="example.com"
                                            value={formData.domain}
                                            onChange={(e) => setFormData((p) => ({ ...p, domain: e.target.value }))}
                                        />
                                    </div>
                                    <div>
                                        <label className="text-sm font-medium text-text-secondary block mb-1">Display Name</label>
                                        <input type="text" required
                                            className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                            placeholder="Production API"
                                            value={formData.display_name}
                                            onChange={(e) => setFormData((p) => ({ ...p, display_name: e.target.value }))}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-1">Tags (comma separated)</label>
                                    <input type="text"
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                        placeholder="prod, api, critical"
                                        value={formData.tags}
                                        onChange={(e) => setFormData((p) => ({ ...p, tags: e.target.value }))}
                                    />
                                </div>
                                <div className="flex gap-3 justify-end">
                                    <Button variant="outline" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                                    <Button variant="primary" type="submit" isLoading={isSubmitting}>Add Target</Button>
                                </div>
                            </form>
                        </Card>
                    )}

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading targets…</span>
                        </div>
                    ) : targets.length === 0 ? (
                        <Card className="p-12 text-center">
                            <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <h3 className="text-xl font-semibold text-text-primary mb-2">No Targets Added</h3>
                            <p className="text-text-secondary mb-4">Add targets to start scanning your infrastructure.</p>
                            <Button variant="primary" onClick={() => setShowForm(true)}>Add First Target</Button>
                        </Card>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {targets.map((target) => (
                                <Card key={target.id} className="p-6">
                                    <div className="flex justify-between items-start mb-4">
                                        <div>
                                            <h3 className="text-lg font-semibold text-text-primary">{target.display_name}</h3>
                                            <p className="text-sm font-mono text-text-secondary mt-1">{target.domain}</p>
                                        </div>
                                        {target.is_dns_verified ? (
                                            <Badge variant="success" size="sm">Verified</Badge>
                                        ) : (
                                            <Badge variant="medium" size="sm">Unverified</Badge>
                                        )}
                                    </div>
                                    <div className="flex flex-wrap gap-2 mb-4">
                                        {target.tags?.map((tag, i) => (
                                            <span key={i} className="px-2 py-0.5 bg-bg-secondary text-text-secondary rounded text-xs">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                    <div className="pt-4 border-t border-border-primary flex items-center justify-between">
                                        <div>
                                            <p className="text-xs text-text-tertiary">Last Scanned</p>
                                            <p className="text-sm text-text-secondary">
                                                {target.last_scanned_at ? new Date(target.last_scanned_at).toLocaleDateString() : 'Never'}
                                            </p>
                                        </div>
                                        <button onClick={() => handleDelete(target.id)}
                                            className="text-xs px-3 py-1.5 rounded bg-status-critical/10 text-status-critical hover:bg-status-critical/20 transition-colors">
                                            Delete
                                        </button>
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
