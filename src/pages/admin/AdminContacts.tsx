import React, { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import { adminAPI } from '@services/api';

interface ContactMessage {
    id: string;
    name: string;
    email: string;
    subject: string;
    subject_display?: string;
    message: string;
    is_read: boolean;
    reply: string | null;
    replied_at: string | null;
    replied_by_name: string | null;
    created_at: string;
}

export default function AdminContacts() {
    const [messages, setMessages] = useState<ContactMessage[]>([]);
    const [total, setTotal] = useState(0);
    const [unread, setUnread] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterRead, setFilterRead] = useState('all');
    const [selectedMessage, setSelectedMessage] = useState<ContactMessage | null>(null);
    const [replyText, setReplyText] = useState('');
    const [isSending, setIsSending] = useState(false);

    const fetchMessages = () => {
        setIsLoading(true);
        const params: Record<string, string> = {};
        if (searchQuery) params.search = searchQuery;
        if (filterRead === 'unread') params.is_read = 'false';
        if (filterRead === 'read') params.is_read = 'true';

        adminAPI.getContacts(params)
            .then((res) => {
                const data = res.data;
                setMessages(data.messages ?? data.results ?? []);
                setTotal(data.total ?? 0);
                setUnread(data.unread ?? 0);
            })
            .catch(() => setMessages([]))
            .finally(() => setIsLoading(false));
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { fetchMessages(); }, [filterRead]);

    const handleSearch = () => fetchMessages();

    const openMessage = (msg: ContactMessage) => {
        setSelectedMessage(msg);
        setReplyText(msg.reply || '');
        // Mark as read
        if (!msg.is_read) {
            adminAPI.replyContact(msg.id, { is_read: true }).then(() => {
                setMessages((prev) =>
                    prev.map((m) => (m.id === msg.id ? { ...m, is_read: true } : m))
                );
                setUnread((u) => Math.max(0, u - 1));
            });
        }
    };

    const handleReply = async () => {
        if (!selectedMessage || !replyText.trim()) return;
        setIsSending(true);
        try {
            await adminAPI.replyContact(selectedMessage.id, { reply: replyText.trim() });
            setMessages((prev) =>
                prev.map((m) =>
                    m.id === selectedMessage.id
                        ? { ...m, reply: replyText, replied_at: new Date().toISOString(), is_read: true }
                        : m
                )
            );
            setSelectedMessage((prev) =>
                prev ? { ...prev, reply: replyText, replied_at: new Date().toISOString() } : prev
            );
            alert('Reply sent successfully!');
        } catch {
            alert('Failed to send reply.');
        } finally {
            setIsSending(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this message permanently?')) return;
        try {
            await adminAPI.deleteContact(id);
            setMessages((prev) => prev.filter((m) => m.id !== id));
            setTotal((t) => t - 1);
            if (selectedMessage?.id === id) setSelectedMessage(null);
        } catch {
            alert('Failed to delete message.');
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

    const subjectLabel = (subject: string) => {
        const labels: Record<string, string> = {
            general: 'General Inquiry',
            support: 'Technical Support',
            sales: 'Sales',
            partnership: 'Partnership',
            bug: 'Bug Report',
            feature: 'Feature Request',
            security: 'Security Report',
        };
        return labels[subject] || subject;
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Contact Messages
                            </h1>
                            <p className="text-text-secondary">
                                {total} total messages · {unread} unread
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
                                    placeholder="Search by name, email, or message..."
                                    value={searchQuery}
                                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                                    onKeyDown={(e: React.KeyboardEvent) => e.key === 'Enter' && handleSearch()}
                                />
                            </div>
                            <select
                                value={filterRead}
                                onChange={(e) => setFilterRead(e.target.value)}
                                className="px-4 py-2 rounded-lg bg-bg-secondary border border-border-primary text-text-primary"
                            >
                                <option value="all">All Messages</option>
                                <option value="unread">Unread Only</option>
                                <option value="read">Read Only</option>
                            </select>
                            <Button variant="primary" size="sm" onClick={handleSearch}>
                                Search
                            </Button>
                        </div>
                    </Card>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Message List */}
                        <div className="lg:col-span-1 space-y-3">
                            {isLoading ? (
                                <Card className="p-8 text-center">
                                    <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin mx-auto" />
                                </Card>
                            ) : messages.length === 0 ? (
                                <Card className="p-8 text-center">
                                    <p className="text-text-tertiary">No messages found.</p>
                                </Card>
                            ) : (
                                messages.map((msg) => (
                                    <Card
                                        key={msg.id}
                                        className={`p-4 cursor-pointer hover:border-accent-green/50 transition-colors ${
                                            selectedMessage?.id === msg.id ? 'border-accent-green' : ''
                                        } ${!msg.is_read ? 'border-l-4 border-l-accent-blue' : ''}`}
                                        onClick={() => openMessage(msg)}
                                    >
                                        <div className="flex items-start justify-between mb-2">
                                            <div className="font-medium text-text-primary text-sm truncate flex-1">
                                                {msg.name}
                                            </div>
                                            <div className="flex items-center gap-2 ml-2 shrink-0">
                                                {!msg.is_read && (
                                                    <span className="w-2 h-2 rounded-full bg-accent-blue" />
                                                )}
                                                {msg.reply && (
                                                    <Badge variant="success">Replied</Badge>
                                                )}
                                            </div>
                                        </div>
                                        <div className="text-xs text-text-tertiary mb-1">{msg.email}</div>
                                        <div className="text-xs font-medium text-accent-green mb-1">
                                            {msg.subject_display || subjectLabel(msg.subject)}
                                        </div>
                                        <div className="text-xs text-text-secondary line-clamp-2">{msg.message}</div>
                                        <div className="text-xs text-text-tertiary mt-2">{formatDate(msg.created_at)}</div>
                                    </Card>
                                ))
                            )}
                        </div>

                        {/* Message Detail */}
                        <div className="lg:col-span-2">
                            {selectedMessage ? (
                                <Card className="p-6">
                                    <div className="flex items-start justify-between mb-6">
                                        <div>
                                            <h2 className="text-xl font-semibold text-text-primary mb-1">
                                                {selectedMessage.subject_display || subjectLabel(selectedMessage.subject)}
                                            </h2>
                                            <div className="text-sm text-text-secondary">
                                                From <strong>{selectedMessage.name}</strong> ({selectedMessage.email})
                                            </div>
                                            <div className="text-xs text-text-tertiary mt-1">
                                                {formatDate(selectedMessage.created_at)}
                                            </div>
                                        </div>
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={() => handleDelete(selectedMessage.id)}
                                            className="text-status-critical hover:bg-status-critical/10"
                                        >
                                            Delete
                                        </Button>
                                    </div>

                                    {/* Original Message */}
                                    <div className="p-4 rounded-lg bg-bg-secondary mb-6">
                                        <div className="text-sm text-text-primary whitespace-pre-wrap">
                                            {selectedMessage.message}
                                        </div>
                                    </div>

                                    {/* Previous Reply */}
                                    {selectedMessage.reply && (
                                        <div className="mb-6">
                                            <h3 className="text-sm font-semibold text-text-primary mb-2">
                                                Your Reply
                                                {selectedMessage.replied_at && (
                                                    <span className="font-normal text-text-tertiary ml-2">
                                                        — {formatDate(selectedMessage.replied_at)}
                                                    </span>
                                                )}
                                            </h3>
                                            <div className="p-4 rounded-lg bg-accent-green/5 border border-accent-green/20">
                                                <div className="text-sm text-text-secondary whitespace-pre-wrap">
                                                    {selectedMessage.reply}
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Reply Form */}
                                    <div>
                                        <h3 className="text-sm font-semibold text-text-primary mb-2">
                                            {selectedMessage.reply ? 'Update Reply' : 'Send Reply'}
                                        </h3>
                                        <textarea
                                            value={replyText}
                                            onChange={(e) => setReplyText(e.target.value)}
                                            rows={5}
                                            className="w-full px-4 py-3 rounded-lg bg-bg-secondary border border-border-primary text-text-primary placeholder-text-tertiary focus:outline-none focus:border-accent-green resize-y"
                                            placeholder="Type your reply here..."
                                        />
                                        <div className="flex justify-end mt-3">
                                            <Button
                                                variant="primary"
                                                onClick={handleReply}
                                                disabled={!replyText.trim() || isSending}
                                            >
                                                {isSending ? 'Sending...' : selectedMessage.reply ? 'Update Reply' : 'Send Reply'}
                                            </Button>
                                        </div>
                                    </div>
                                </Card>
                            ) : (
                                <Card className="p-12 text-center">
                                    <div className="text-text-tertiary">
                                        <svg className="w-16 h-16 mx-auto mb-4 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                        </svg>
                                        <p className="text-lg font-medium mb-1">Select a message</p>
                                        <p className="text-sm">Choose a message from the list to view details and reply.</p>
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
