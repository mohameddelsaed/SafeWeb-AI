import React, { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';
import { adminAPI } from '@services/api';

interface UserRow {
    id: string;
    name: string;
    email: string;
    plan: string;
    status: string;
    scans: number;
    joined: string;
    lastActive: string;
}

export default function AdminUsers() {
    const [searchQuery, setSearchQuery] = useState('');
    const [filterPlan, setFilterPlan] = useState('all');
    const [filterStatus, setFilterStatus] = useState('all');
    const [users, setUsers] = useState<UserRow[]>([]);
    const [totalUsers, setTotalUsers] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [editingUser, setEditingUser] = useState<UserRow | null>(null);
    const [showAddUser, setShowAddUser] = useState(false);

    const fetchUsers = () => {
        setIsLoading(true);
        const params: Record<string, string> = { page: String(page) };
        if (searchQuery) params.search = searchQuery;
        if (filterPlan !== 'all') params.plan = filterPlan;
        if (filterStatus !== 'all') params.status = filterStatus;
        adminAPI.getUsers(params)
            .then((res) => {
                setUsers(res.data.results ?? res.data.users ?? []);
                setTotalUsers(res.data.count ?? res.data.total ?? 0);
            })
            .catch(() => setUsers([]))
            .finally(() => setIsLoading(false));
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { fetchUsers(); }, [page, filterPlan, filterStatus]);
    useEffect(() => { setPage(1); }, [filterPlan, filterStatus]);
    useEffect(() => {
        const t = setTimeout(fetchUsers, 400);
        return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [searchQuery]);

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this user?')) return;
        try {
            await adminAPI.deleteUser(id);
            fetchUsers();
        } catch (err) {
            console.error('Delete user failed:', err);
            alert('Failed to delete user. Please try again.');
        }
    };

    const planOptions = [
        { value: 'all', label: 'All Plans' },
        { value: 'free', label: 'Free' },
        { value: 'pro', label: 'Pro' },
        { value: 'enterprise', label: 'Enterprise' },
    ];

    const statusOptions = [
        { value: 'all', label: 'All Status' },
        { value: 'active', label: 'Active' },
        { value: 'suspended', label: 'Suspended' },
        { value: 'inactive', label: 'Inactive' },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                User Management
                            </h1>
                            <p className="text-text-secondary">Manage all platform users</p>
                        </div>
                        <Button variant="primary" onClick={() => setShowAddUser(true)}>
                            Add New User
                        </Button>
                    </div>

                    {/* Stats Cards */}
                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                        </div>
                    ) : (
                    <>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Total Users</div>
                            <div className="text-3xl font-bold text-text-primary">{totalUsers.toLocaleString()}</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Active Users</div>
                            <div className="text-3xl font-bold text-accent-green">{users.filter(u => u.status === 'active').length}</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Pro Users</div>
                            <div className="text-3xl font-bold text-accent-blue">{users.filter(u => u.plan === 'Pro' || u.plan === 'pro').length}</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Enterprise</div>
                            <div className="text-3xl font-bold text-text-primary">{users.filter(u => u.plan === 'Enterprise' || u.plan === 'enterprise').length}</div>
                        </Card>
                    </div>

                    {/* Filters */}
                    <Card className="p-6 mb-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <Input
                                type="text"
                                placeholder="Search by name or email..."
                                value={searchQuery}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                                leftIcon={
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                    </svg>
                                }
                            />
                            <Select
                                options={planOptions}
                                value={filterPlan}
                                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilterPlan(e.target.value)}
                            />
                            <Select
                                options={statusOptions}
                                value={filterStatus}
                                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilterStatus(e.target.value)}
                            />
                        </div>
                    </Card>

                    {/* Users Table */}
                    <Card className="overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="bg-bg-secondary">
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">User</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Plan</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Scans</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Joined</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Last Active</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {users.map((user) => (
                                        <tr key={user.id} className="border-t border-border-primary hover:bg-bg-secondary/50">
                                            <td className="py-4 px-6">
                                                <div>
                                                    <div className="font-medium text-text-primary">{user.name}</div>
                                                    <div className="text-sm text-text-tertiary">{user.email}</div>
                                                </div>
                                            </td>
                                            <td className="py-4 px-6">
                                                <Badge variant={user.plan === 'Enterprise' ? 'info' : user.plan === 'Pro' ? 'success' : 'default'}>
                                                    {user.plan}
                                                </Badge>
                                            </td>
                                            <td className="py-4 px-6">
                                                <Badge variant={user.status === 'active' ? 'success' : user.status === 'suspended' ? 'high' : 'default'}>
                                                    {user.status}
                                                </Badge>
                                            </td>
                                            <td className="py-4 px-6 text-text-secondary">{user.scans}</td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{user.joined}</td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{user.lastActive}</td>
                                            <td className="py-4 px-6">
                                                <div className="flex items-center gap-2">
                                                    <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-accent-green transition-colors" onClick={() => setEditingUser(user)}>
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                                        </svg>
                                                    </button>
                                                    <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-status-high transition-colors" onClick={() => handleDelete(user.id)}>
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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

                        {/* Pagination */}
                        <div className="flex items-center justify-between px-6 py-4 border-t border-border-primary">
                            <div className="text-sm text-text-secondary">
                                Showing {users.length > 0 ? (page - 1) * 10 + 1 : 0} to {Math.min(page * 10, totalUsers)} of {totalUsers.toLocaleString()} users
                            </div>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
                                <span className="text-sm text-text-secondary px-2">Page {page}</span>
                                <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={users.length < 10}>Next</Button>
                            </div>
                        </div>
                    </Card>
                    </>
                    )}
                </Container>
            </div>

            {/* Edit User Modal */}
            {editingUser && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" onClick={(e) => { if (e.target === e.currentTarget) setEditingUser(null); }}>
                    <div className="bg-bg-primary border border-border-primary rounded-xl shadow-xl w-full max-w-md p-6">
                        <h2 className="text-xl font-heading font-semibold text-text-primary mb-4">Edit User</h2>
                        <EditUserForm
                            user={editingUser}
                            onSave={async (data) => {
                                try {
                                    await adminAPI.updateUser(editingUser.id, data);
                                    setEditingUser(null);
                                    fetchUsers();
                                } catch { alert('Failed to update user'); }
                            }}
                            onCancel={() => setEditingUser(null)}
                        />
                    </div>
                </div>
            )}

            {/* Add User Modal */}
            {showAddUser && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" onClick={(e) => { if (e.target === e.currentTarget) setShowAddUser(false); }}>
                    <div className="bg-bg-primary border border-border-primary rounded-xl shadow-xl w-full max-w-md p-6">
                        <h2 className="text-xl font-heading font-semibold text-text-primary mb-4">Add New User</h2>
                        <AddUserForm
                            onSave={() => { setShowAddUser(false); fetchUsers(); }}
                            onCancel={() => setShowAddUser(false)}
                        />
                    </div>
                </div>
            )}
        </Layout>
    );
}

function EditUserForm({ user, onSave, onCancel }: { user: UserRow; onSave: (data: Record<string, unknown>) => Promise<void>; onCancel: () => void }) {
    const [form, setForm] = useState({ name: user.name, email: user.email, plan: user.plan.toLowerCase(), status: user.status });
    const [saving, setSaving] = useState(false);
    return (
        <div className="space-y-4">
            <Input type="text" label="Name" value={form.name} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, name: e.target.value })} />
            <Input type="email" label="Email" value={form.email} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, email: e.target.value })} />
            <Select label="Plan" options={[{ value: 'free', label: 'Free' }, { value: 'pro', label: 'Pro' }, { value: 'enterprise', label: 'Enterprise' }]} value={form.plan} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setForm({ ...form, plan: e.target.value })} />
            <Select label="Status" options={[{ value: 'active', label: 'Active' }, { value: 'suspended', label: 'Suspended' }, { value: 'inactive', label: 'Inactive' }]} value={form.status} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setForm({ ...form, status: e.target.value })} />
            <div className="flex justify-end gap-3 pt-2">
                <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
                <Button variant="primary" size="sm" isLoading={saving} onClick={async () => { setSaving(true); await onSave(form); setSaving(false); }}>Save</Button>
            </div>
        </div>
    );
}

function AddUserForm({ onSave, onCancel }: { onSave: () => void; onCancel: () => void }) {
    const [form, setForm] = useState({ name: '', email: '', password: '', plan: 'free', role: 'user' });
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState('');
    return (
        <div className="space-y-4">
            <Input type="text" label="Name" value={form.name} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, name: e.target.value })} />
            <Input type="email" label="Email" value={form.email} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, email: e.target.value })} />
            <Input type="password" label="Password" value={form.password} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, password: e.target.value })} />
            <Select label="Plan" options={[{ value: 'free', label: 'Free' }, { value: 'pro', label: 'Pro' }, { value: 'enterprise', label: 'Enterprise' }]} value={form.plan} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setForm({ ...form, plan: e.target.value })} />
            <Select label="Role" options={[{ value: 'user', label: 'User' }, { value: 'admin', label: 'Admin' }]} value={form.role} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setForm({ ...form, role: e.target.value })} />
            {error && <p className="text-sm text-accent-red">{error}</p>}
            <div className="flex justify-end gap-3 pt-2">
                <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
                <Button variant="primary" size="sm" isLoading={saving} onClick={async () => {
                    if (!form.name || !form.email || !form.password) { setError('All fields are required'); return; }
                    setSaving(true);
                    try {
                        await adminAPI.createUser(form);
                        onSave();
                    } catch { setError('Failed to create user'); }
                    setSaving(false);
                }}>Create User</Button>
            </div>
        </div>
    );
}
