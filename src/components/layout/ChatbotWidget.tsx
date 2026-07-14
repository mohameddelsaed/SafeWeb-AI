import React, { useState, useRef, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import { chatAPI } from '@/services/api';
import { useNavigate, useLocation } from 'react-router-dom';
import { useLanguage } from '@/contexts/LanguageContext';

interface ChatAction {
    type: 'navigate' | 'download';
    path?: string;
    url?: string;
}

interface ChatMsg {
    id: number;
    messageId?: string;       // backend UUID for feedback
    text: string;
    sender: 'user' | 'bot';
    time: string;
    suggestions?: string[];
    actions?: ChatAction[];
    feedback?: 'positive' | 'negative' | null;
    source?: string;
    tokensUsed?: number;
}

interface SessionItem {
    id: string;
    title: string;
    messageCount: number;
    updatedAt: string;
}

const WELCOME_MSG: ChatMsg = {
    id: 1,
    text: "Hello! I'm **SafeWeb AI Assistant** — your cybersecurity expert.\n\nI can help you with:\n- 🔍 Starting and managing security scans\n- 🛡️ Understanding vulnerabilities and remediation\n- 📊 Analyzing your scan results\n- ⚙️ Navigating SafeWeb AI features\n\nWhat would you like to know?",
    sender: 'bot',
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    suggestions: ['How do I start a scan?', 'What is OWASP Top 10?', 'Check my subscription'],
};

const WELCOME_MSG_AR: ChatMsg = {
    id: 1,
    text: "مرحباً! أنا **مساعد SafeWeb AI الذكي** — خبير الأمن السيبراني الخاص بك.\n\nيمكنني مساعدتك في:\n- 🔍 بدء وإدارة فحوصات الأمان\n- 🛡️ فهم ومعالجة الثغرات الأمنية\n- 📊 تحليل نتائج فحوصاتك\n- ⚙️ التنقل في مزايا المنصة\n\nكيف يمكنني مساعدتك اليوم؟",
    sender: 'bot',
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    suggestions: ['كيف أبدأ فحصاً جديداً؟', 'ما هو تصنيف OWASP Top 10؟', 'عرض باقة اشتراكي'],
};

const QUICK_ACTIONS = [
    { label: '🔍 Start a scan', text: 'How do I start a new scan?' },
    { label: '📊 My scans', text: 'Show my recent scans' },
    { label: '🛡️ OWASP Top 10', text: 'What is OWASP Top 10?' },
    { label: '💳 Subscription', text: 'What is my subscription plan?' },
    { label: '📤 Export report', text: 'How do I export scan results?' },
    { label: '⚙️ Security score', text: 'How is my security score calculated?' },
    { label: '🔐 Enable 2FA', text: 'How do I enable 2FA?' },
    { label: '❓ Help', text: 'What can you help me with?' },
];

const QUICK_ACTIONS_AR = [
    { label: '🔍 بدء فحص', text: 'كيف أبدأ فحصاً جديداً؟' },
    { label: '📊 فحوصاتي', text: 'اعرض أحدث فحوصاتي' },
    { label: '🛡️ OWASP Top 10', text: 'ما هو تصنيف OWASP Top 10؟' },
    { label: '💳 باقة الاشتراك', text: 'ما هي باقة اشتراكي الحالية؟' },
    { label: '📤 تصدير تقرير', text: 'كيف أصدر تقرير الفحص؟' },
    { label: '⚙️ درجة الأمان', text: 'كيف يتم حساب تقييم الأمان؟' },
    { label: '🔐 تفعيل 2FA', text: 'كيف أفعل المصادقة الثنائية؟' },
    { label: '❓ مساعدة', text: 'كيف يمكنك مساعدتي؟' },
];

export default function ChatbotWidget() {
    const { language } = useLanguage();
    const activeWelcome = language === 'ar' ? WELCOME_MSG_AR : WELCOME_MSG;
    const activeQuickActions = language === 'ar' ? QUICK_ACTIONS_AR : QUICK_ACTIONS;

    const [isOpen, setIsOpen] = useState(false);
    const [message, setMessage] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [sessionId, setSessionId] = useState<string | undefined>();
    const [messages, setMessages] = useState<ChatMsg[]>([activeWelcome]);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const navigate = useNavigate();
    const location = useLocation();

    // Auto-detect scanId from current URL (e.g. /scan/results/:id)
    const detectedScanId = React.useMemo(() => {
        const match = location.pathname.match(/\/scan\/results\/([a-f0-9-]+)/i);
        return match ? match[1] : undefined;
    }, [location.pathname]);

    // Session management state
    const [showSessions, setShowSessions] = useState(false);
    const [sessions, setSessions] = useState<SessionItem[]>([]);
    const [sessionsLoading, setSessionsLoading] = useState(false);

    // Auto-scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Fetch sessions list
    const fetchSessions = useCallback(async () => {
        setSessionsLoading(true);
        try {
            const { data } = await chatAPI.getSessions();
            const list = Array.isArray(data) ? data : data.results ?? [];
            setSessions(list.map((s: Record<string, unknown>) => ({
                id: String(s.id),
                title: String(s.title || 'New Chat'),
                messageCount: Number(s.messageCount ?? s.message_count ?? 0),
                updatedAt: String(s.updatedAt ?? s.updated_at ?? ''),
            })));
        } catch {
            setSessions([]);
        } finally {
            setSessionsLoading(false);
        }
    }, []);

    // Listen for external "ask about finding" events
    useEffect(() => {
        const handler = (e: Event) => {
            const detail = (e as CustomEvent<{ message: string; scanId?: string }>).detail;
            if (!detail?.message) return;
            setIsOpen(true);
            setTimeout(() => sendMessage(detail.message, detail.scanId), 150);
        };
        window.addEventListener('safeweb-chatbot-ask', handler);
        return () => window.removeEventListener('safeweb-chatbot-ask', handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [sessionId]);

    // Load session messages
    const loadSession = async (id: string) => {
        try {
            const { data } = await chatAPI.getSession(id);
            const msgs: ChatMsg[] = (data.messages ?? []).map(
                (m: Record<string, unknown>, i: number) => ({
                    id: i + 1,
                    messageId: String(m.id || ''),
                    text: String(m.content),
                    sender: m.role === 'user' ? 'user' as const : 'bot' as const,
                    time: m.createdAt
                        ? new Date(String(m.createdAt)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                        : m.created_at
                            ? new Date(String(m.created_at)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                            : '',
                    feedback: (m.feedback as string) || null,
                })
            );
            setSessionId(id);
            setMessages(msgs.length > 0 ? msgs : [activeWelcome]);
            setShowSessions(false);
        } catch {
            // silently fail
        }
    };

    // Delete a session
    const deleteSession = async (id: string) => {
        if (!confirm('Delete this chat session?')) return;
        try {
            await chatAPI.deleteSession(id);
            setSessions((prev) => prev.filter((s) => s.id !== id));
            if (sessionId === id) {
                setSessionId(undefined);
                setMessages([activeWelcome]);
            }
        } catch {
            // silently fail
        }
    };

    // Start a brand-new chat
    const startNewChat = () => {
        setSessionId(undefined);
        setMessages([activeWelcome]);
        setShowSessions(false);
    };

    // Execute chatbot action
    const executeAction = (action: ChatAction) => {
        if (action.type === 'navigate' && action.path) {
            navigate(action.path);
            setIsOpen(false);
        } else if (action.type === 'download' && action.url) {
            window.open(action.url, '_blank');
        }
    };

    // Send feedback
    const sendFeedback = async (msgIndex: number, feedback: 'positive' | 'negative') => {
        const msg = messages[msgIndex];
        if (!msg?.messageId) return;
        try {
            await chatAPI.sendFeedback(msg.messageId, feedback);
            setMessages((prev) =>
                prev.map((m, i) => i === msgIndex ? { ...m, feedback } : m)
            );
        } catch {
            // silently fail
        }
    };

    // Copy message text
    const copyText = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const sendMessage = async (text: string, scanId?: string) => {
        const effectiveScanId = scanId || detectedScanId;
        const userMsg: ChatMsg = {
            id: messages.length + 1,
            text,
            sender: 'user',
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };
        setMessages((prev) => [...prev, userMsg]);
        setIsTyping(true);

        try {
            const { data } = await chatAPI.send({
                message: text,
                sessionId,
                scanId: effectiveScanId,
            });

            if (data.sessionId) setSessionId(data.sessionId);

            // Execute any actions automatically
            const actions: ChatAction[] = data.actions || [];
            actions.forEach((a: ChatAction) => {
                if (a.type === 'navigate') {
                    // Don't auto-navigate, let user click
                }
            });

            setMessages((prev) => [
                ...prev,
                {
                    id: prev.length + 1,
                    messageId: data.message_id || data.messageId,
                    text: data.response || data.message || 'I apologize, I could not process that.',
                    sender: 'bot' as const,
                    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                    suggestions: data.suggestions || [],
                    actions: actions.length > 0 ? actions : undefined,
                    source: data.source,
                    tokensUsed: data.tokens_used,
                },
            ]);
        } catch {
            setMessages((prev) => [
                ...prev,
                {
                    id: prev.length + 1,
                    text: "I'm having trouble connecting. Please try again later.",
                    sender: 'bot' as const,
                    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                },
            ]);
        } finally {
            setIsTyping(false);
        }
    };

    const handleSend = () => {
        if (!message.trim()) return;
        const text = message;
        setMessage('');
        sendMessage(text);
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    // Relative timestamp
    const relativeTime = (time: string) => time;

    return (
        <>
            {/* Chat Window */}
            {isOpen && (
                <div className="fixed bottom-24 right-6 w-96 z-50 animate-float">
                    <Card className="overflow-hidden shadow-2xl">
                        {/* Header */}
                        <div className="px-6 py-4 bg-gradient-to-r from-accent-green to-accent-blue">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-full bg-bg-primary flex items-center justify-center">
                                        <svg
                                            className="w-6 h-6 text-accent-green"
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={2}
                                                d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                                            />
                                        </svg>
                                    </div>
                                    <div>
                                        <div className="font-semibold text-bg-primary">SafeWeb AI Assistant</div>
                                        <div className="text-xs text-bg-primary/80 flex items-center gap-1">
                                            <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse"></span>
                                            Online
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-1">
                                    <button
                                        onClick={startNewChat}
                                        className="p-1.5 text-bg-primary hover:text-bg-secondary transition-colors rounded"
                                        title="New Chat"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                        </svg>
                                    </button>
                                    <button
                                        onClick={() => { setShowSessions(!showSessions); if (!showSessions) fetchSessions(); }}
                                        className="p-1.5 text-bg-primary hover:text-bg-secondary transition-colors rounded"
                                        title="Chat History"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </button>
                                    <button
                                        onClick={() => setIsOpen(false)}
                                        className="p-1.5 text-bg-primary hover:text-bg-secondary transition-colors rounded"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Session History Panel */}
                        {showSessions && (
                            <div className="h-96 overflow-y-auto bg-bg-secondary border-b border-border-primary">
                                <div className="px-4 py-3 border-b border-border-primary flex items-center justify-between">
                                    <span className="text-sm font-medium text-text-primary">Chat History</span>
                                    <button
                                        onClick={() => setShowSessions(false)}
                                        className="text-xs text-accent-green hover:underline"
                                    >
                                        Back to chat
                                    </button>
                                </div>
                                {sessionsLoading ? (
                                    <div className="flex items-center justify-center py-12">
                                        <div className="w-6 h-6 border-2 border-accent-green border-t-transparent rounded-full animate-spin"></div>
                                    </div>
                                ) : sessions.length === 0 ? (
                                    <div className="text-center py-12 text-text-tertiary text-sm">
                                        No past sessions found.
                                    </div>
                                ) : (
                                    <div className="divide-y divide-border-primary">
                                        {sessions.map((s) => (
                                            <div
                                                key={s.id}
                                                className={`px-4 py-3 hover:bg-bg-hover transition-colors cursor-pointer flex items-center gap-3 ${s.id === sessionId ? 'bg-accent-green/10 border-l-2 border-accent-green' : ''}`}
                                            >
                                                <div className="flex-1 min-w-0" onClick={() => loadSession(s.id)}>
                                                    <div className="text-sm font-medium text-text-primary truncate">{s.title}</div>
                                                    <div className="text-xs text-text-tertiary mt-0.5">
                                                        {s.messageCount} messages
                                                        {s.updatedAt && ` · ${new Date(s.updatedAt).toLocaleDateString()}`}
                                                    </div>
                                                </div>
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); deleteSession(s.id); }}
                                                    className="p-1 text-text-tertiary hover:text-red-400 transition-colors shrink-0"
                                                    title="Delete session"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                    </svg>
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Messages */}
                        {!showSessions && (
                        <>
                        <div className="h-96 overflow-y-auto p-4 space-y-4 bg-bg-secondary">
                            {messages.map((msg, idx) => (
                                <div key={msg.id}>
                                    <div className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                                        <div
                                            className={`max-w-[85%] rounded-lg px-4 py-2 ${msg.sender === 'user'
                                                    ? 'bg-accent-green text-bg-primary'
                                                    : 'bg-bg-primary border border-border-primary text-text-primary'
                                                }`}
                                        >
                                            {msg.sender === 'bot' ? (
                                                <div className="text-sm prose prose-invert prose-sm max-w-none
                                                    prose-headings:text-text-primary prose-headings:mt-3 prose-headings:mb-1 prose-headings:text-sm
                                                    prose-p:my-1 prose-li:my-0.5
                                                    prose-strong:text-accent-green
                                                    prose-code:text-accent-blue prose-code:bg-bg-secondary prose-code:px-1 prose-code:rounded prose-code:text-xs
                                                    prose-pre:bg-bg-secondary prose-pre:border prose-pre:border-border-primary prose-pre:rounded-lg prose-pre:my-2
                                                    prose-a:text-accent-blue prose-a:no-underline hover:prose-a:underline
                                                    prose-table:text-xs prose-th:px-2 prose-th:py-1 prose-td:px-2 prose-td:py-1
                                                    prose-th:border prose-th:border-border-primary prose-td:border prose-td:border-border-primary">
                                                    <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]}>
                                                        {msg.text}
                                                    </ReactMarkdown>
                                                </div>
                                            ) : (
                                                <div className="text-sm">{msg.text}</div>
                                            )}
                                            <div className={`text-xs mt-1 flex items-center gap-2 ${msg.sender === 'user' ? 'text-bg-primary/70' : 'text-text-tertiary'}`}>
                                                <span>{relativeTime(msg.time)}</span>
                                                {msg.source === 'llm' && msg.tokensUsed ? (
                                                    <span className="bg-accent-blue/20 text-accent-blue px-1.5 py-0.5 rounded text-[10px]">
                                                        AI · {msg.tokensUsed} tokens
                                                    </span>
                                                ) : null}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Bot message toolbar: feedback + copy */}
                                    {msg.sender === 'bot' && msg.messageId && (
                                        <div className="flex items-center gap-1 mt-1 ml-1">
                                            <button
                                                onClick={() => sendFeedback(idx, 'positive')}
                                                className={`p-1 rounded transition-colors ${msg.feedback === 'positive' ? 'text-accent-green' : 'text-text-tertiary hover:text-accent-green'}`}
                                                title="Helpful"
                                            >
                                                <svg className="w-3.5 h-3.5" fill={msg.feedback === 'positive' ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3H14z M4 15h-2v7h2v-7z" />
                                                </svg>
                                            </button>
                                            <button
                                                onClick={() => sendFeedback(idx, 'negative')}
                                                className={`p-1 rounded transition-colors ${msg.feedback === 'negative' ? 'text-red-400' : 'text-text-tertiary hover:text-red-400'}`}
                                                title="Not helpful"
                                            >
                                                <svg className="w-3.5 h-3.5" fill={msg.feedback === 'negative' ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 15v4a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3H10z M20 2h2v7h-2V2z" />
                                                </svg>
                                            </button>
                                            <button
                                                onClick={() => copyText(msg.text)}
                                                className="p-1 text-text-tertiary hover:text-text-primary rounded transition-colors"
                                                title="Copy"
                                            >
                                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                                                </svg>
                                            </button>
                                        </div>
                                    )}

                                    {/* Action buttons */}
                                    {msg.actions && msg.actions.length > 0 && (
                                        <div className="flex flex-wrap gap-2 mt-2 ml-1">
                                            {msg.actions.map((action, aIdx) => (
                                                <button
                                                    key={aIdx}
                                                    onClick={() => executeAction(action)}
                                                    className="px-3 py-1.5 rounded-lg text-xs bg-accent-green/20 text-accent-green border border-accent-green/30 hover:bg-accent-green/30 transition-all flex items-center gap-1"
                                                >
                                                    {action.type === 'navigate' ? (
                                                        <>
                                                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                                            </svg>
                                                            Go to {action.path}
                                                        </>
                                                    ) : (
                                                        <>
                                                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                                            </svg>
                                                            Download
                                                        </>
                                                    )}
                                                </button>
                                            ))}
                                        </div>
                                    )}

                                    {/* Suggested follow-up questions */}
                                    {msg.suggestions && msg.suggestions.length > 0 && idx === messages.length - 1 && (
                                        <div className="flex flex-wrap gap-1.5 mt-2 ml-1">
                                            {msg.suggestions.map((s, sIdx) => (
                                                <button
                                                    key={sIdx}
                                                    onClick={() => sendMessage(s)}
                                                    className="px-2.5 py-1 rounded-full text-xs bg-bg-primary border border-border-primary text-text-secondary hover:border-accent-green/50 hover:text-accent-green transition-all"
                                                >
                                                    {s}
                                                </button>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            ))}
                            {isTyping && (
                                <div className="flex justify-start">
                                    <div className="bg-bg-primary border border-border-primary rounded-lg px-4 py-2">
                                        <div className="flex gap-1">
                                            <span className="w-2 h-2 bg-text-tertiary rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
                                            <span className="w-2 h-2 bg-text-tertiary rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
                                            <span className="w-2 h-2 bg-text-tertiary rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* Quick Actions — shown only on welcome */}
                        {messages.length === 1 && (
                            <div className="px-4 py-3 bg-bg-secondary border-t border-border-primary">
                                <div className="text-xs text-text-tertiary mb-2">
                                    {language === 'ar' ? 'إجراءات سريعة:' : 'Quick actions:'}
                                </div>
                                <div className="flex flex-wrap gap-1.5">
                                    {activeQuickActions.map((qa, index) => (
                                        <button
                                            key={index}
                                            onClick={() => sendMessage(qa.text)}
                                            className="px-2.5 py-1.5 rounded-lg text-xs bg-bg-primary border border-border-primary text-text-secondary hover:bg-bg-hover hover:border-accent-green/30 transition-all"
                                        >
                                            {qa.label}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Input */}
                        <div className="p-4 bg-bg-primary border-t border-border-primary">
                            <div className="flex items-center gap-2">
                                <Input
                                    type="text"
                                    placeholder={language === 'ar' ? 'اسأل عن الأمان، الفحوصات، المزايا...' : 'Ask about security, scans, features...'}
                                    value={message}
                                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setMessage(e.target.value)}
                                    onKeyDown={handleKeyDown}
                                    className="flex-1"
                                />
                                <Button
                                    onClick={handleSend}
                                    variant="primary"
                                    size="sm"
                                    className="px-4"
                                    disabled={!message.trim() || isTyping}
                                >
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                                        />
                                    </svg>
                                </Button>
                            </div>
                            <div className="text-xs text-text-tertiary mt-2 text-center">
                                Powered by SafeWeb AI
                            </div>
                        </div>
                        </>
                        )}
                    </Card>
                </div>
            )}

            {/* Floating Button */}
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="fixed bottom-6 right-6 w-14 h-14 rounded-full bg-gradient-to-r from-accent-green to-accent-blue text-bg-primary shadow-glow-green hover:scale-110 transition-transform z-50 flex items-center justify-center"
            >
                {isOpen ? (
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M6 18L18 6M6 6l12 12"
                        />
                    </svg>
                ) : (
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                        />
                    </svg>
                )}
            </button>
        </>
    );
}
