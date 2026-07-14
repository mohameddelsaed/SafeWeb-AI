import { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { scopeAPI } from '@/services/api';
import type { ScopeDefinition } from '@/types';

export default function ScopeManagement() {
    const [scopes, setScopes] = useState<ScopeDefinition[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState({ name: '', allowedDomains: '', excludedPaths: '' });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [importError, setImportError] = useState<string | null>(null);

    const fetchScopes = () => {
        scopeAPI.getAll().then(({ data }) => {
            setScopes(Array.isArray(data) ? data : data.results ?? []);
        }).finally(() => setIsLoading(false));
    };

    useEffect(() => { fetchScopes(); }, []);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await scopeAPI.create({
                name: formData.name,
                inScope: formData.allowedDomains.split('\n').map((s) => s.trim()).filter(Boolean),
                outOfScope: formData.excludedPaths.split('\n').map((s) => s.trim()).filter(Boolean),
            });
            setShowForm(false);
            setFormData({ name: '', allowedDomains: '', excludedPaths: '' });
            fetchScopes();
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this scope?')) return;
        await scopeAPI.delete(id);
        fetchScopes();
    };

    const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            try {
                const parsed = JSON.parse(ev.target?.result as string);
                setFormData({
                    name: parsed.name ?? '',
                    allowedDomains: (parsed.allowed_domains ?? []).join('\n'),
                    excludedPaths: (parsed.excluded_paths ?? []).join('\n'),
                });
                setShowForm(true);
                setImportError(null);
            } catch {
                setImportError('Invalid scope JSON file.');
            }
        };
        reader.readAsText(file);
        e.target.value = '';
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Scope Management</h1>
                            <p className="text-text-secondary">Define allowed domains and excluded paths for your scans.</p>
                        </div>
                        <div className="flex gap-3">
                            <label className="cursor-pointer">
                                <span className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border-primary text-text-secondary text-sm hover:bg-bg-hover transition-colors">
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
                                    </svg>
                                    Import JSON
                                </span>
                                <input type="file" accept=".json" className="hidden" onChange={handleImportFile} />
                            </label>
                            <Button variant="primary" onClick={() => setShowForm(true)}>
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                </svg>
                                New Scope
                            </Button>
                        </div>
                    </div>

                    {importError && <p className="text-sm text-status-critical mb-4">{importError}</p>}

                    {showForm && (
                        <Card className="p-6 mb-6 border-accent-green/30">
                            <h3 className="text-lg font-semibold text-text-primary mb-4">Create Scope</h3>
                            <form onSubmit={handleCreate} className="space-y-4">
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-1">Scope Name</label>
                                    <input type="text" required
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                        placeholder="e.g. Production App"
                                        value={formData.name}
                                        onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                                    />
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label className="text-sm font-medium text-text-secondary block mb-1">Allowed Domains / IPs</label>
                                        <textarea rows={5}
                                            className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary font-mono resize-none focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                            placeholder={"example.com\napi.example.com\n192.168.1.0/24"}
                                            value={formData.allowedDomains}
                                            onChange={(e) => setFormData((p) => ({ ...p, allowedDomains: e.target.value }))}
                                        />
                                        <p className="text-xs text-text-tertiary mt-1">One entry per line</p>
                                    </div>
                                    <div>
                                        <label className="text-sm font-medium text-text-secondary block mb-1">Excluded Paths</label>
                                        <textarea rows={5}
                                            className="w-full bg-bg-secondary border border-border-primary rounded-lg px-3 py-2 text-sm text-text-primary font-mono resize-none focus:outline-none focus:ring-2 focus:ring-accent-green/50"
                                            placeholder={"/logout\n/admin/\n/api/internal/*"}
                                            value={formData.excludedPaths}
                                            onChange={(e) => setFormData((p) => ({ ...p, excludedPaths: e.target.value }))}
                                        />
                                        <p className="text-xs text-text-tertiary mt-1">Supports wildcard *</p>
                                    </div>
                                </div>
                                <div className="flex gap-3 justify-end">
                                    <Button variant="outline" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                                    <Button variant="primary" type="submit" isLoading={isSubmitting}>Create Scope</Button>
                                </div>
                            </form>
                        </Card>
                    )}

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading scopes…</span>
                        </div>
                    ) : scopes.length === 0 ? (
                        <Card className="p-12 text-center">
                            <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            <h3 className="text-xl font-semibold text-text-primary mb-2">No Scopes Defined</h3>
                            <p className="text-text-secondary mb-4">Create a scope to limit scan boundaries and improve accuracy.</p>
                            <Button variant="primary" onClick={() => setShowForm(true)}>Create First Scope</Button>
                        </Card>
                    ) : (
                        <div className="space-y-4">
                            {scopes.map((scope) => (
                                <Card key={scope.id} className="p-6">
                                    <div className="flex items-start justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-3">
                                                <h3 className="text-base font-semibold text-text-primary">{scope.name}</h3>
                                                <Badge variant="info" size="sm">
                                                    {(scope.inScope ?? []).length} domains
                                                </Badge>
                                                <Badge variant="medium" size="sm">
                                                    {(scope.outOfScope ?? []).length} exclusions
                                                </Badge>
                                            </div>
                                            {(scope.inScope ?? []).length > 0 && (
                                                <div className="mb-2">
                                                    <p className="text-xs font-medium text-text-tertiary mb-1">Allowed Domains:</p>
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {scope.inScope!.slice(0, 6).map((d, i) => (
                                                            <span key={i} className="px-2 py-0.5 bg-status-low/10 text-status-low rounded text-xs font-mono">{d}</span>
                                                        ))}
                                                        {scope.inScope!.length > 6 && (
                                                            <span className="px-2 py-0.5 bg-bg-secondary text-text-tertiary rounded text-xs">+{scope.inScope!.length - 6} more</span>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                            {(scope.outOfScope ?? []).length > 0 && (
                                                <div>
                                                    <p className="text-xs font-medium text-text-tertiary mb-1">Excluded Paths:</p>
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {scope.outOfScope!.slice(0, 4).map((p, i) => (
                                                            <span key={i} className="px-2 py-0.5 bg-bg-secondary text-text-secondary rounded text-xs font-mono">{p}</span>
                                                        ))}
                                                        {scope.outOfScope!.length > 4 && (
                                                            <span className="px-2 py-0.5 bg-bg-secondary text-text-tertiary rounded text-xs">+{scope.outOfScope!.length - 4} more</span>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                        <button onClick={() => handleDelete(scope.id)}
                                            className="ml-4 text-xs px-3 py-1.5 rounded bg-status-critical/10 text-status-critical hover:bg-status-critical/20 transition-colors">
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
