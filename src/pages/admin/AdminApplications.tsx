import React, { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import { adminAPI } from '@services/api';

interface JobApplication {
    id: string;
    position: string;
    name: string;
    email: string;
    phone: string;
    cover_letter: string;
    resume_url: string;
    portfolio_url: string;
    status: 'pending' | 'reviewed' | 'shortlisted' | 'rejected';
    admin_notes: string;
    created_at: string;
}

const STATUS_VARIANTS: Record<string, 'default' | 'info' | 'success' | 'high' | 'critical'> = {
    pending: 'default',
    reviewed: 'info',
    shortlisted: 'success',
    rejected: 'critical',
};

export default function AdminApplications() {
    const [applications, setApplications] = useState<JobApplication[]>([]);
    const [total, setTotal] = useState(0);
    const [pending, setPending] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');
    const [selectedApp, setSelectedApp] = useState<JobApplication | null>(null);
    const [notes, setNotes] = useState('');
    const [isSaving, setIsSaving] = useState(false);

    const fetchApplications = () => {
        setIsLoading(true);
        const params: Record<string, string> = {};
        if (searchQuery) params.search = searchQuery;
        if (filterStatus !== 'all') params.status = filterStatus;

        adminAPI.getApplications(params)
            .then((res) => {
                const data = res.data;
                setApplications(data.applications ?? data.results ?? []);
                setTotal(data.total ?? 0);
                setPending(data.pending ?? 0);
            })
            .catch(() => setApplications([]))
            .finally(() => setIsLoading(false));
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { fetchApplications(); }, [filterStatus]);

    const handleSearch = () => fetchApplications();

    const openApplication = (app: JobApplication) => {
        setSelectedApp(app);
        setNotes(app.admin_notes || '');
    };

    const updateStatus = async (newStatus: string) => {
        if (!selectedApp) return;
        setIsSaving(true);
        try {
            await adminAPI.updateApplication(selectedApp.id, { status: newStatus, admin_notes: notes });
            setApplications((prev) =>
                prev.map((a) =>
                    a.id === selectedApp.id
                        ? { ...a, status: newStatus as JobApplication['status'], admin_notes: notes }
                        : a
                )
            );
            setSelectedApp((prev) =>
                prev ? { ...prev, status: newStatus as JobApplication['status'], admin_notes: notes } : prev
            );
            alert(`Application status updated to "${newStatus}".`);
        } catch {
            alert('Failed to update application.');
        } finally {
            setIsSaving(false);
        }
    };

    const saveNotes = async () => {
        if (!selectedApp) return;
        setIsSaving(true);
        try {
            await adminAPI.updateApplication(selectedApp.id, { admin_notes: notes });
            setApplications((prev) =>
                prev.map((a) => (a.id === selectedApp.id ? { ...a, admin_notes: notes } : a))
            );
            setSelectedApp((prev) => (prev ? { ...prev, admin_notes: notes } : prev));
            alert('Notes saved.');
        } catch {
            alert('Failed to save notes.');
        } finally {
            setIsSaving(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this application permanently?')) return;
        try {
            await adminAPI.deleteApplication(id);
            setApplications((prev) => prev.filter((a) => a.id !== id));
            setTotal((t) => t - 1);
            if (selectedApp?.id === id) setSelectedApp(null);
        } catch {
            alert('Failed to delete application.');
        }
    };

    const formatDate = (dateStr: string) => {
        try {
            return new Date(dateStr).toLocaleDateString('en-US', {
                year: 'numeric', month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit',
            });
        } catch { return dateStr; }
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Job Applications
                            </h1>
                            <p className="text-text-secondary">
                                {total} total applications · {pending} pending review
                            </p>
                        </div>
                        <Button variant="outline" size="sm" onClick={() => window.history.back()}>
                            ← Back to Admin
                        </Button>
                    </div>

                    {/* Filters */}
                    <Card className="p-4 mb-6">
                        <div className="flex flex-wrap gap-4 items-end">
                            <div className="flex-1 min-w-[200px]">
                                <Input
                                    type="text"
                                    placeholder="Search by name, email, or position..."
                                    value={searchQuery}
                                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                                    onKeyDown={(e: React.KeyboardEvent) => e.key === 'Enter' && handleSearch()}
                                />
                            </div>
                            <select
                                value={filterStatus}
                                onChange={(e) => setFilterStatus(e.target.value)}
                                className="px-4 py-2 rounded-lg bg-bg-secondary border border-border-primary text-text-primary"
                            >
                                <option value="all">All Statuses</option>
                                <option value="pending">Pending</option>
                                <option value="reviewed">Reviewed</option>
                                <option value="shortlisted">Shortlisted</option>
                                <option value="rejected">Rejected</option>
                            </select>
                            <Button variant="primary" size="sm" onClick={handleSearch}>
                                Search
                            </Button>
                        </div>
                    </Card>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Application List */}
                        <div className="lg:col-span-1 space-y-3 max-h-[calc(100vh-300px)] overflow-y-auto">
                            {isLoading ? (
                                <Card className="p-8 text-center">
                                    <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin mx-auto" />
                                </Card>
                            ) : applications.length === 0 ? (
                                <Card className="p-8 text-center">
                                    <p className="text-text-tertiary">No applications found.</p>
                                </Card>
                            ) : (
                                applications.map((app) => (
                                    <Card
                                        key={app.id}
                                        className={`p-4 cursor-pointer hover:border-accent-green/50 transition-colors ${
                                            selectedApp?.id === app.id ? 'border-accent-green' : ''
                                        }`}
                                        onClick={() => openApplication(app)}
                                    >
                                        <div className="flex items-start justify-between mb-2">
                                            <div className="font-medium text-text-primary text-sm truncate flex-1">
                                                {app.name}
                                            </div>
                                            <Badge variant={STATUS_VARIANTS[app.status] || 'default'}>
                                                {app.status}
                                            </Badge>
                                        </div>
                                        <div className="text-xs text-text-tertiary mb-1">{app.email}</div>
                                        <div className="text-xs font-medium text-accent-green mb-1">
                                            {app.position}
                                        </div>
                                        <div className="text-xs text-text-tertiary mt-1">{formatDate(app.created_at)}</div>
                                    </Card>
                                ))
                            )}
                        </div>

                        {/* Application Detail */}
                        <div className="lg:col-span-2">
                            {selectedApp ? (
                                <Card className="p-6">
                                    <div className="flex items-start justify-between mb-6">
                                        <div>
                                            <h2 className="text-xl font-semibold text-text-primary mb-1">
                                                {selectedApp.name}
                                            </h2>
                                            <div className="text-sm text-text-secondary mb-1">
                                                {selectedApp.email}
                                                {selectedApp.phone && (
                                                    <span className="ml-3"> · {selectedApp.phone}</span>
                                                )}
                                            </div>
                                            <div className="flex items-center gap-2 mt-2">
                                                <Badge variant="info">{selectedApp.position}</Badge>
                                                <Badge variant={STATUS_VARIANTS[selectedApp.status] || 'default'}>
                                                    {selectedApp.status}
                                                </Badge>
                                            </div>
                                            <div className="text-xs text-text-tertiary mt-2">
                                                Applied: {formatDate(selectedApp.created_at)}
                                            </div>
                                        </div>
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={() => handleDelete(selectedApp.id)}
                                            className="text-status-critical hover:bg-status-critical/10"
                                        >
                                            Delete
                                        </Button>
                                    </div>

                                    {/* Links */}
                                    {(selectedApp.resume_url || selectedApp.portfolio_url) && (
                                        <div className="flex flex-wrap gap-3 mb-6">
                                            {selectedApp.resume_url && (
                                                <a
                                                    href={selectedApp.resume_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-accent-green hover:bg-bg-hover transition-colors"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                                                    Resume
                                                </a>
                                            )}
                                            {selectedApp.portfolio_url && (
                                                <a
                                                    href={selectedApp.portfolio_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-accent-green hover:bg-bg-hover transition-colors"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                                                    Portfolio
                                                </a>
                                            )}
                                        </div>
                                    )}

                                    {/* Cover Letter */}
                                    {selectedApp.cover_letter && (
                                        <div className="mb-6">
                                            <h3 className="text-sm font-semibold text-text-primary mb-2">Cover Letter</h3>
                                            <div className="p-4 rounded-lg bg-bg-secondary">
                                                <div className="text-sm text-text-secondary whitespace-pre-wrap">
                                                    {selectedApp.cover_letter}
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Status Actions */}
                                    <div className="mb-6">
                                        <h3 className="text-sm font-semibold text-text-primary mb-3">Update Status</h3>
                                        <div className="flex flex-wrap gap-2">
                                            {(['pending', 'reviewed', 'shortlisted', 'rejected'] as const).map((s) => (
                                                <button
                                                    key={s}
                                                    onClick={() => updateStatus(s)}
                                                    disabled={isSaving || selectedApp.status === s}
                                                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                                                        selectedApp.status === s
                                                            ? 'bg-accent-green text-bg-primary'
                                                            : 'bg-bg-secondary border border-border-primary text-text-secondary hover:bg-bg-hover hover:text-text-primary'
                                                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                                                >
                                                    {s.charAt(0).toUpperCase() + s.slice(1)}
                                                </button>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Admin Notes */}
                                    <div>
                                        <h3 className="text-sm font-semibold text-text-primary mb-2">Admin Notes</h3>
                                        <textarea
                                            value={notes}
                                            onChange={(e) => setNotes(e.target.value)}
                                            rows={4}
                                            className="w-full px-4 py-3 rounded-lg bg-bg-secondary border border-border-primary text-text-primary placeholder-text-tertiary focus:outline-none focus:border-accent-green resize-y"
                                            placeholder="Internal notes about this application..."
                                        />
                                        <div className="flex justify-end mt-3">
                                            <Button
                                                variant="primary"
                                                onClick={saveNotes}
                                                disabled={isSaving}
                                            >
                                                {isSaving ? 'Saving...' : 'Save Notes'}
                                            </Button>
                                        </div>
                                    </div>
                                </Card>
                            ) : (
                                <Card className="p-12 text-center">
                                    <div className="text-text-tertiary">
                                        <svg className="w-16 h-16 mx-auto mb-4 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 13.255A23.193 23.193 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                        </svg>
                                        <p className="text-lg font-medium mb-1">Select an application</p>
                                        <p className="text-sm">Choose an application from the list to review details.</p>
                                    </div>
                                </Card>
                            )}
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
