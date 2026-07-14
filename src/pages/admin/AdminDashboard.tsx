import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { adminAPI, nucleiAPI, scheduledScanAPI, chatAPI } from '@services/api';

interface DashboardData {
    stats: { label: string; value: string; change: string; trend: string }[];
    recentUsers: { id: string; name: string; email: string; plan: string; status: string; joined: string }[];
    systemAlerts: { id: number; type: string; message: string; time: string }[];
    scanStats: { status: string; count: number; percentage: number }[];
}

const statIcons = [
    <svg key={0} className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" /></svg>,
    <svg key={1} className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>,
    <svg key={2} className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>,
    <svg key={3} className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" /></svg>,
];

export default function AdminDashboard() {
    const navigate = useNavigate();
    const [timeRange, setTimeRange] = useState('7d');
    const [data, setData] = useState<DashboardData | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [nucleiCount, setNucleiCount] = useState(0);
    const [scheduledCount, setScheduledCount] = useState(0);
    const [chatStats, setChatStats] = useState<{
        totalSessions: number; totalMessages: number; uniqueUsers: number;
        feedback: { positive: number; negative: number; total: number; satisfactionRate: number };
        tokens: { total: number; llmMessages: number; avgPerMessage: number };
        topTopics: { topic: string; count: number }[];
    } | null>(null);

    useEffect(() => {
        setIsLoading(true);
        adminAPI.getDashboard({ timeRange })
            .then((res) => setData(res.data))
            .catch(() => setData(null))
            .finally(() => setIsLoading(false));

        nucleiAPI.getAll().then(({ data: d }) => {
            const arr = Array.isArray(d) ? d : d.results ?? [];
            setNucleiCount(arr.length);
        }).catch(() => {});

        scheduledScanAPI.getAll().then(({ data: d }) => {
            const arr = Array.isArray(d) ? d : d.results ?? [];
            setScheduledCount(arr.filter((s: { isActive: boolean }) => s.isActive).length);
        }).catch(() => {});

        chatAPI.getAnalytics(timeRange).then(({ data: d }) => {
            setChatStats(d);
        }).catch(() => {});
    }, [timeRange]);

    const stats = (data?.stats ?? [
        { label: 'Total Users', value: '—', change: '', trend: 'up' },
        { label: 'Active Scans', value: '—', change: '', trend: 'up' },
        { label: 'Vulnerabilities Found', value: '—', change: '', trend: 'down' },
        { label: 'System Uptime', value: '—', change: '', trend: 'up' },
    ]).map((s, i) => ({ ...s, icon: statIcons[i] }));

    const recentUsers = data?.recentUsers ?? [];
    const systemAlerts = data?.systemAlerts ?? [];
    const scanStats = data?.scanStats ?? [];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Admin Dashboard
                            </h1>
                            <p className="text-text-secondary">System overview and management</p>
                        </div>
                        <div className="flex items-center gap-3">
                            <select
                                value={timeRange}
                                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setTimeRange(e.target.value)}
                                className="px-4 py-2 rounded-lg bg-bg-secondary border border-border-primary text-text-primary"
                            >
                                <option value="24h">Last 24 Hours</option>
                                <option value="7d">Last 7 Days</option>
                                <option value="30d">Last 30 Days</option>
                                <option value="90d">Last 90 Days</option>
                            </select>
                            <Button variant="primary" size="sm" onClick={() => navigate('/admin/scans')}>
                                Export Report
                            </Button>
                        </div>
                    </div>

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                        </div>
                    ) : (
                    <>
                    {/* Stats Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        {stats.map((stat, index) => (
                            <Card key={index} className="p-6">
                                <div className="flex items-center justify-between mb-4">
                                    <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green">
                                        {stat.icon}
                                    </div>
                                    <span
                                        className={`text-sm font-medium ${stat.trend === 'up' ? 'text-accent-green' : 'text-status-high'
                                            }`}
                                    >
                                        {stat.change}
                                    </span>
                                </div>
                                <div className="text-3xl font-bold text-text-primary mb-1">{stat.value}</div>
                                <div className="text-sm text-text-tertiary">{stat.label}</div>
                            </Card>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                        {/* Scan Statistics */}
                        <Card className="lg:col-span-2 p-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                Scan Statistics
                            </h2>
                            <div className="space-y-4">
                                {scanStats.map((stat, index) => (
                                    <div key={index}>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-secondary">{stat.status}</span>
                                            <span className="text-sm font-semibold text-text-primary">
                                                {stat.count.toLocaleString()} ({stat.percentage}%)
                                            </span>
                                        </div>
                                        <div className="w-full h-2 bg-bg-secondary rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-accent-green rounded-full transition-all"
                                                style={{ width: `${stat.percentage}%` }}
                                            />
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </Card>

                        {/* System Alerts */}
                        <Card className="p-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                System Alerts
                            </h2>
                            <div className="space-y-4">
                                {systemAlerts.map((alert) => (
                                    <div
                                        key={alert.id}
                                        className="p-3 rounded-lg bg-bg-secondary border border-border-primary"
                                    >
                                        <div className="flex items-start gap-3">
                                            <Badge variant={alert.type === 'critical' ? 'critical' : alert.type === 'warning' ? 'high' : 'info'}>
                                                {alert.type}
                                            </Badge>
                                            <div className="flex-1">
                                                <div className="text-sm text-text-primary mb-1">{alert.message}</div>
                                                <div className="text-xs text-text-tertiary">{alert.time}</div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                            <Button variant="outline" size="sm" className="w-full mt-4" onClick={() => navigate('/admin/settings')}>
                                View All Alerts
                            </Button>
                        </Card>
                    </div>

                    {/* Quick Admin Links */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                        {[
                            { label: 'Manage Users', path: '/admin/users', icon: '👥' },
                            { label: 'Scan Management', path: '/admin/scans', icon: '🔍' },
                            { label: 'Contact Messages', path: '/admin/contacts', icon: '✉️' },
                            { label: 'Job Applications', path: '/admin/applications', icon: '📋' },
                            { label: 'ML Models', path: '/admin/ml', icon: '🤖' },
                            { label: 'Scheduled Scans', path: '/scheduled-scans', icon: '🕐' },
                            { label: 'Asset Inventory', path: '/assets', icon: '🗄️' },
                            { label: 'Webhook Settings', path: '/settings/webhooks', icon: '🔗' },
                        ].map((link) => (
                            <Card
                                key={link.path}
                                className="p-4 cursor-pointer hover:border-accent-green/50 transition-colors"
                                onClick={() => navigate(link.path)}
                            >
                                <div className="flex items-center gap-3">
                                    <span className="text-2xl">{link.icon}</span>
                                    <span className="font-medium text-text-primary text-sm">{link.label}</span>
                                </div>
                            </Card>
                        ))}
                    </div>

                    {/* Scanner Engine Status */}
                    <Card className="p-6 mb-8">
                        <h2 className="text-lg font-heading font-semibold text-text-primary mb-4">Scanner Engine Status</h2>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                            <div className="text-center">
                                <p className="text-3xl font-bold text-accent-green">87</p>
                                <p className="text-sm text-text-tertiary mt-1">Active Testers</p>
                            </div>
                            <div className="text-center">
                                <p className="text-3xl font-bold text-text-primary">{nucleiCount}</p>
                                <p className="text-sm text-text-tertiary mt-1">Nuclei Templates</p>
                            </div>
                            <div className="text-center">
                                <p className="text-3xl font-bold text-text-primary">{scheduledCount}</p>
                                <p className="text-sm text-text-tertiary mt-1">Active Schedules</p>
                            </div>
                            <div className="text-center">
                                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-status-low/15 text-status-low text-sm font-medium">
                                    <span className="w-2 h-2 rounded-full bg-status-low animate-pulse" />
                                    Operational
                                </div>
                                <p className="text-sm text-text-tertiary mt-2">Engine Status</p>
                            </div>
                        </div>
                    </Card>

                    {/* Chat Analytics */}
                    {chatStats && (
                    <Card className="p-6 mb-8">
                        <h2 className="text-lg font-heading font-semibold text-text-primary mb-4">AI Chat Analytics</h2>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-6">
                            <div className="text-center">
                                <p className="text-3xl font-bold text-accent-green">{chatStats.totalSessions}</p>
                                <p className="text-sm text-text-tertiary mt-1">Chat Sessions</p>
                            </div>
                            <div className="text-center">
                                <p className="text-3xl font-bold text-text-primary">{chatStats.totalMessages}</p>
                                <p className="text-sm text-text-tertiary mt-1">Total Messages</p>
                            </div>
                            <div className="text-center">
                                <p className="text-3xl font-bold text-text-primary">{chatStats.uniqueUsers}</p>
                                <p className="text-sm text-text-tertiary mt-1">Unique Users</p>
                            </div>
                            <div className="text-center">
                                <p className="text-3xl font-bold text-accent-blue">{chatStats.tokens.total.toLocaleString()}</p>
                                <p className="text-sm text-text-tertiary mt-1">Tokens Used</p>
                            </div>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            {/* Feedback stats */}
                            <div className="p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                <h3 className="text-sm font-semibold text-text-primary mb-3">User Feedback</h3>
                                {chatStats.feedback.total > 0 ? (
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-text-secondary">Satisfaction Rate</span>
                                            <span className="text-lg font-bold text-accent-green">{chatStats.feedback.satisfactionRate}%</span>
                                        </div>
                                        <div className="w-full h-2 bg-bg-primary rounded-full overflow-hidden">
                                            <div className="h-full bg-accent-green rounded-full transition-all" style={{ width: `${chatStats.feedback.satisfactionRate}%` }} />
                                        </div>
                                        <div className="flex items-center justify-between text-xs text-text-tertiary">
                                            <span>👍 {chatStats.feedback.positive}</span>
                                            <span>👎 {chatStats.feedback.negative}</span>
                                            <span>{chatStats.feedback.total} total</span>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-sm text-text-tertiary">No feedback collected yet.</p>
                                )}
                            </div>
                            {/* Top topics */}
                            <div className="p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                <h3 className="text-sm font-semibold text-text-primary mb-3">Top Topics</h3>
                                {chatStats.topTopics.length > 0 ? (
                                    <div className="space-y-2">
                                        {chatStats.topTopics.slice(0, 5).map((t, i) => (
                                            <div key={i} className="flex items-center justify-between">
                                                <span className="text-sm text-text-secondary truncate flex-1">{t.topic}</span>
                                                <span className="text-xs font-mono text-text-tertiary ml-2">{t.count}</span>
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <p className="text-sm text-text-tertiary">No conversations yet.</p>
                                )}
                            </div>
                        </div>
                    </Card>
                    )}

                    {/* Recent Users */}
                    <Card className="p-6">
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary">
                                Recent Users
                            </h2>
                            <Button variant="outline" size="sm" onClick={() => navigate('/admin/users')}>
                                View All Users
                            </Button>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-border-primary">
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Name</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Email</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Plan</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Joined</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {recentUsers.map((user) => (
                                        <tr key={user.id} className="border-b border-border-primary/50 hover:bg-bg-secondary/50">
                                            <td className="py-3 px-4">
                                                <div className="font-medium text-text-primary">{user.name}</div>
                                            </td>
                                            <td className="py-3 px-4 text-sm text-text-secondary">{user.email}</td>
                                            <td className="py-3 px-4">
                                                <Badge variant={user.plan === 'Enterprise' ? 'info' : user.plan === 'Pro' ? 'success' : 'default'}>
                                                    {user.plan}
                                                </Badge>
                                            </td>
                                            <td className="py-3 px-4">
                                                <Badge variant={user.status === 'active' ? 'success' : 'high'}>
                                                    {user.status}
                                                </Badge>
                                            </td>
                                            <td className="py-3 px-4 text-sm text-text-secondary">{user.joined}</td>
                                            <td className="py-3 px-4">
                                                <Button variant="ghost" size="sm" onClick={() => navigate('/admin/users')}>
                                                    Manage
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </Card>
                    </>
                    )}
                </Container>
            </div>
        </Layout>
    );
}
