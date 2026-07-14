import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Button from '@components/ui/Button';
import Badge from '@components/ui/Badge';
import PasswordStrengthMeter from '@components/ui/PasswordStrengthMeter';
import { useAuth } from '@/contexts/AuthContext';
import { userAPI } from '@/services/api';
import { validatePassword } from '@/utils/validation';

export default function Profile() {
    const { user, updateUser } = useAuth();
    const navigate = useNavigate();
    const [isEditing, setIsEditing] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const [showEnable2FA, setShowEnable2FA] = useState(false);
    const [showSessions, setShowSessions] = useState(false);
    const [userData, setUserData] = useState({
        name: user?.name || '',
        email: user?.email || '',
        company: user?.company || '',
        role: user?.jobTitle || '',
    });

    const [apiKeys, setApiKeys] = useState<{
        id: string; name: string; created: string; lastUsed: string; scans: number;
    }[]>([]);

    const [usageStats, setUsageStats] = useState({
        totalScans: 0,
        vulnerabilitiesFound: 0,
        issuesFixed: 0,
    });

    const [subscription, setSubscription] = useState({
        plan: user?.plan || 'Free',
        status: 'active',
        scansUsed: 0,
        scansLimit: 'Unlimited',
        billingCycle: 'Monthly',
        nextBilling: '',
        amount: '$0.00',
    });

    useEffect(() => {
        // Fetch profile data
        userAPI.getProfile().then(({ data }) => {
            setUserData({
                name: data.name || '',
                email: data.email || '',
                company: data.company || '',
                role: data.jobTitle || '',
            });
            if (data.subscription) {
                setSubscription({
                    plan: data.subscription.plan || data.plan || 'Free',
                    status: data.subscription.status || 'active',
                    scansUsed: data.stats?.totalScans || 0,
                    scansLimit: data.subscription.scansLimit || 'Unlimited',
                    billingCycle: data.subscription.billingCycle || 'Monthly',
                    nextBilling: data.subscription.nextBilling || '',
                    amount: data.subscription.amount || '$0.00',
                });
            }
            if (data.stats) {
                setUsageStats({
                    totalScans: data.stats.totalScans || 0,
                    vulnerabilitiesFound: data.stats.vulnerabilitiesFound || 0,
                    issuesFixed: data.stats.issuesFixed || 0,
                });
            }
        }).catch(() => {});

        // Fetch API keys
        userAPI.getAPIKeys().then(({ data }) => {
            const keys = data.results || data || [];
            setApiKeys(keys.map((k: Record<string, unknown>) => ({
                id: k.key || k.id || '',
                name: k.name || '',
                created: k.createdAt || k.created || '',
                lastUsed: k.lastUsed || 'Never',
                scans: k.scans || 0,
            })));
        }).catch(() => {});
    }, []);

    const handleSave = async () => {
        try {
            await userAPI.updateProfile({
                name: userData.name,
                company: userData.company,
                jobTitle: userData.role,
            });
            updateUser({ name: userData.name, company: userData.company, jobTitle: userData.role });
            setIsEditing(false);
        } catch {
            alert('Failed to update profile');
        }
    };

    const handleGenerateKey = async () => {
        const name = prompt('Enter a name for the API key:');
        if (!name) return;
        try {
            const { data } = await userAPI.createAPIKey(name);
            setApiKeys((prev) => [...prev, {
                id: data.key || data.id,
                name: data.name,
                created: data.createdAt || new Date().toISOString(),
                lastUsed: 'Never',
                scans: 0,
            }]);
            alert(`API Key created: ${data.key}`);
        } catch {
            alert('Failed to create API key');
        }
    };

    const handleRevokeKey = async (keyId: string) => {
        if (!confirm('Are you sure you want to revoke this API key?')) return;
        try {
            await userAPI.deleteAPIKey(keyId);
            setApiKeys((prev) => prev.filter((k) => k.id !== keyId));
        } catch {
            alert('Failed to revoke API key');
        }
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="mb-8">
                        <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                            Account Settings
                        </h1>
                        <p className="text-text-secondary">Manage your profile, subscription, and API keys</p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Main Content */}
                        <div className="lg:col-span-2 space-y-8">
                            {/* Profile Information */}
                            <Card className="p-6">
                                <div className="flex items-center justify-between mb-6">
                                    <h2 className="text-xl font-heading font-semibold text-text-primary">
                                        Profile Information
                                    </h2>
                                    {!isEditing ? (
                                        <Button variant="outline" size="sm" onClick={() => setIsEditing(true)}>
                                            Edit Profile
                                        </Button>
                                    ) : (
                                        <div className="flex items-center gap-2">
                                            <Button variant="outline" size="sm" onClick={() => setIsEditing(false)}>
                                                Cancel
                                            </Button>
                                            <Button variant="primary" size="sm" onClick={handleSave}>
                                                Save Changes
                                            </Button>
                                        </div>
                                    )}
                                </div>

                                <div className="space-y-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <Input
                                            type="text"
                                            label="Full Name"
                                            value={userData.name}
                                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserData({ ...userData, name: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                        <Input
                                            type="email"
                                            label="Email Address"
                                            value={userData.email}
                                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserData({ ...userData, email: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                    </div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <Input
                                            type="text"
                                            label="Company"
                                            value={userData.company}
                                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserData({ ...userData, company: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                        <Input
                                            type="text"
                                            label="Role"
                                            value={userData.role}
                                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserData({ ...userData, role: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                    </div>
                                </div>
                            </Card>

                            {/* API Keys */}
                            <Card className="p-6">
                                <div className="flex items-center justify-between mb-6">
                                    <div>
                                        <h2 className="text-xl font-heading font-semibold text-text-primary mb-1">
                                            API Keys
                                        </h2>
                                        <p className="text-sm text-text-tertiary">
                                            Manage your API keys for integration
                                        </p>
                                    </div>
                                    <Button variant="primary" size="sm" onClick={handleGenerateKey}>
                                        Generate New Key
                                    </Button>
                                </div>

                                <div className="space-y-4">
                                    {apiKeys.length === 0 && (
                                        <div className="text-center py-8">
                                            <svg className="w-12 h-12 mx-auto text-text-tertiary mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                            </svg>
                                            <p className="text-sm text-text-tertiary">No API keys generated yet. Create one to start integrating.</p>
                                        </div>
                                    )}
                                    {apiKeys.map((key) => (
                                        <div
                                            key={key.id}
                                            className="p-4 rounded-lg bg-bg-secondary border border-border-primary"
                                        >
                                            <div className="flex items-start justify-between mb-3">
                                                <div>
                                                    <div className="font-medium text-text-primary mb-1">{key.name}</div>
                                                    <div className="text-sm text-text-tertiary font-mono">{key.id}</div>
                                                </div>
                                                <Button variant="ghost" size="sm" onClick={() => handleRevokeKey(key.id)}>
                                                    Revoke
                                                </Button>
                                            </div>
                                            <div className="grid grid-cols-3 gap-4 text-sm">
                                                <div>
                                                    <div className="text-text-tertiary mb-1">Created</div>
                                                    <div className="text-text-secondary">{key.created}</div>
                                                </div>
                                                <div>
                                                    <div className="text-text-tertiary mb-1">Last Used</div>
                                                    <div className="text-text-secondary">{key.lastUsed}</div>
                                                </div>
                                                <div>
                                                    <div className="text-text-tertiary mb-1">Total Scans</div>
                                                    <div className="text-text-secondary">{key.scans.toLocaleString()}</div>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                <div className="mt-4 p-4 rounded-lg bg-accent-blue/10 border border-accent-blue/20">
                                    <div className="flex items-start gap-3">
                                        <svg
                                            className="w-5 h-5 text-accent-blue flex-shrink-0 mt-0.5"
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={2}
                                                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                            />
                                        </svg>
                                        <div className="text-sm">
                                            <div className="text-text-primary font-medium mb-1">Keep your keys secure</div>
                                            <div className="text-text-tertiary">
                                                Never share your API keys publicly or commit them to version control.
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            {/* Security */}
                            <Card className="p-6">
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                    Security Settings
                                </h2>
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">Password</div>
                                            <div className="text-sm text-text-tertiary">Update your password regularly for security</div>
                                        </div>
                                        <Button variant="outline" size="sm" onClick={() => setShowChangePassword(true)}>
                                            Change Password
                                        </Button>
                                    </div>
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">
                                                Two-Factor Authentication
                                            </div>
                                            <div className="text-sm text-text-tertiary">Add an extra layer of security</div>
                                        </div>
                                        <Button variant="outline" size="sm" onClick={() => setShowEnable2FA(true)}>
                                            Enable 2FA
                                        </Button>
                                    </div>
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">Active Sessions</div>
                                            <div className="text-sm text-text-tertiary">Manage your active sessions</div>
                                        </div>
                                        <Button variant="outline" size="sm" onClick={() => setShowSessions(true)}>
                                            View Sessions
                                        </Button>
                                    </div>
                                </div>
                            </Card>
                        </div>

                        {/* Sidebar */}
                        <div className="space-y-6">
                            {/* Subscription */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Subscription
                                </h3>
                                <div className="space-y-4">
                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Current Plan</span>
                                            <Badge variant="success">{subscription.plan}</Badge>
                                        </div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Status</span>
                                            <span className="text-sm text-accent-green capitalize">
                                                {subscription.status}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Billing Cycle</span>
                                            <span className="text-sm text-text-secondary">{subscription.billingCycle}</span>
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-text-tertiary">Amount</span>
                                            <span className="text-sm font-semibold text-text-primary">
                                                {subscription.amount}
                                            </span>
                                        </div>
                                    </div>

                                    <div className="pt-4 border-t border-border-primary">
                                        <div className="text-sm text-text-tertiary mb-2">Scans This Month</div>
                                        <div className="text-2xl font-bold text-accent-green mb-1">
                                            {subscription.scansUsed.toLocaleString()}
                                        </div>
                                        <div className="text-sm text-text-tertiary">{subscription.scansLimit} available</div>
                                    </div>

                                    <div className="space-y-2 pt-4 border-t border-border-primary">
                                        <Button variant="outline" size="sm" className="w-full" onClick={() => navigate('/services#pricing')}>
                                            Upgrade Plan
                                        </Button>
                                        <Button variant="ghost" size="sm" className="w-full" onClick={() => {
                                            if (confirm('Are you sure you want to cancel your subscription? You will lose access to premium features at the end of your current billing period.')) {
                                                alert('Subscription cancellation request submitted. You will retain access until the end of your billing period.');
                                            }
                                        }}>
                                            Cancel Subscription
                                        </Button>
                                    </div>
                                </div>
                            </Card>

                            {/* Usage Stats */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Usage Statistics
                                </h3>
                                <div className="space-y-4">
                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Total Scans</span>
                                            <span className="text-sm font-semibold text-text-primary">{usageStats.totalScans.toLocaleString()}</span>
                                        </div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Vulnerabilities Found</span>
                                            <span className="text-sm font-semibold text-text-primary">{usageStats.vulnerabilitiesFound.toLocaleString()}</span>
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-text-tertiary">Issues Fixed</span>
                                            <span className="text-sm font-semibold text-accent-green">{usageStats.issuesFixed.toLocaleString()}</span>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            {/* Support */}
                            <Card className="p-6 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                                    Need Help?
                                </h3>
                                <p className="text-sm text-text-secondary mb-4">
                                    Contact our support team for assistance
                                </p>
                                <Link to="/contact">
                                    <Button variant="outline" size="sm" className="w-full">
                                        Contact Support
                                    </Button>
                                </Link>
                            </Card>
                        </div>
                    </div>
                </Container>
            </div>

            {/* Change Password Modal */}
            {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}

            {/* Enable 2FA Modal */}
            {showEnable2FA && <Enable2FAModal onClose={() => setShowEnable2FA(false)} />}

            {/* Sessions Modal */}
            {showSessions && <SessionsModal onClose={() => setShowSessions(false)} />}
        </Layout>
    );
}

/* ── Modal Components ────────────────────────────────────────────── */

function ModalOverlay({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
            <div className="bg-bg-primary border border-border-primary rounded-xl shadow-xl w-full max-w-lg max-h-[80vh] overflow-y-auto">
                {children}
            </div>
        </div>
    );
}

function ChangePasswordModal({ onClose }: { onClose: () => void }) {
    const [form, setForm] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' });
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        if (form.newPassword.length < 8) { setError('Password must be at least 8 characters'); return; }
        const pwResult = validatePassword(form.newPassword);
        if (!pwResult.isValid) { setError(pwResult.message); return; }
        if (form.newPassword !== form.confirmPassword) { setError('Passwords do not match'); return; }

        setIsLoading(true);
        try {
            await userAPI.changePassword(form);
            alert('Password changed successfully!');
            onClose();
        } catch (err: unknown) {
            const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
            setError(msg || 'Failed to change password');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <ModalOverlay onClose={onClose}>
            <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-heading font-semibold text-text-primary">Change Password</h2>
                    <button onClick={onClose} className="text-text-tertiary hover:text-text-primary">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                </div>
                <form onSubmit={handleSubmit} className="space-y-4">
                    <Input type="password" label="Current Password" value={form.currentPassword}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, currentPassword: e.target.value })} />
                    <div>
                        <Input type="password" label="New Password" value={form.newPassword}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, newPassword: e.target.value })} />
                        <PasswordStrengthMeter password={form.newPassword} />
                    </div>
                    <Input type="password" label="Confirm New Password" value={form.confirmPassword}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, confirmPassword: e.target.value })} />
                    {error && <p className="text-sm text-accent-red">{error}</p>}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="outline" size="sm" onClick={onClose} type="button">Cancel</Button>
                        <Button variant="primary" size="sm" type="submit" isLoading={isLoading}>Change Password</Button>
                    </div>
                </form>
            </div>
        </ModalOverlay>
    );
}

function Enable2FAModal({ onClose }: { onClose: () => void }) {
    const [step, setStep] = useState<'loading' | 'setup' | 'verify'>('loading');
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [code, setCode] = useState('');
    const [error, setError] = useState('');
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    const [isVerifying, setIsVerifying] = useState(false);

    useEffect(() => {
        userAPI.enable2FA().then(({ data }) => {
            setQrCode(data.qrCode || data.qr_code || '');
            setSecret(data.secret || '');
            setStep('setup');
        }).catch(() => {
            setError('Failed to initialize 2FA setup');
            setStep('setup');
        });
    }, []);

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (code.length !== 6) { setError('Enter a 6-digit code'); return; }
        setIsVerifying(true);
        try {
            const { data } = await userAPI.verify2FA(code);
            setBackupCodes(data.backupCodes || []);
            setStep('verify');
        } catch {
            setError('Invalid verification code. Please try again.');
        } finally {
            setIsVerifying(false);
        }
    };

    return (
        <ModalOverlay onClose={onClose}>
            <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-heading font-semibold text-text-primary">Enable Two-Factor Authentication</h2>
                    <button onClick={onClose} className="text-text-tertiary hover:text-text-primary">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                </div>

                {step === 'loading' && (
                    <div className="flex justify-center py-12">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-green" />
                    </div>
                )}

                {step === 'setup' && (
                    <div>
                        {qrCode ? (
                            <>
                                <p className="text-sm text-text-secondary mb-4">Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):</p>
                                <div className="flex justify-center mb-4">
                                    <img src={`data:image/png;base64,${qrCode}`} alt="2FA QR Code" className="w-48 h-48 rounded-lg border border-border-primary" />
                                </div>
                                <p className="text-xs text-text-tertiary text-center mb-4">Or enter this secret manually: <code className="text-accent-green">{secret}</code></p>
                            </>
                        ) : error ? (
                            <p className="text-accent-red text-sm mb-4">{error}</p>
                        ) : null}
                        <form onSubmit={handleVerify} className="space-y-4">
                            <Input type="text" label="Verification Code" placeholder="Enter 6-digit code" value={code} maxLength={6}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => { setCode(e.target.value.replace(/\D/g, '')); setError(''); }} />
                            {error && code && <p className="text-sm text-accent-red">{error}</p>}
                            <div className="flex justify-end gap-3">
                                <Button variant="outline" size="sm" type="button" onClick={onClose}>Cancel</Button>
                                <Button variant="primary" size="sm" type="submit" isLoading={isVerifying}>Verify & Enable</Button>
                            </div>
                        </form>
                    </div>
                )}

                {step === 'verify' && (
                    <div className="text-center">
                        <svg className="w-16 h-16 mx-auto text-accent-green mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <h3 className="text-lg font-semibold text-text-primary mb-2">2FA Enabled Successfully!</h3>
                        {backupCodes.length > 0 && (
                            <div className="mt-4 text-left">
                                <p className="text-sm text-text-secondary mb-2">Save these backup codes in a safe place:</p>
                                <div className="grid grid-cols-2 gap-2 p-4 bg-bg-secondary rounded-lg border border-border-primary">
                                    {backupCodes.map((c, i) => (
                                        <code key={i} className="text-sm text-accent-green font-mono">{c}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                        <Button variant="primary" size="sm" className="mt-6" onClick={onClose}>Done</Button>
                    </div>
                )}
            </div>
        </ModalOverlay>
    );
}

function SessionsModal({ onClose }: { onClose: () => void }) {
    const [sessions, setSessions] = useState<{
        id: string; ipAddress: string; userAgent: string; lastActivity: string; isActive: boolean;
    }[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        userAPI.getSessions().then(({ data }) => {
            const list = data.results || data || [];
            setSessions(list.map((s: Record<string, unknown>) => ({
                id: String(s.id || ''),
                ipAddress: String(s.ipAddress || s.ip_address || ''),
                userAgent: String(s.userAgent || s.user_agent || ''),
                lastActivity: String(s.lastActivity || s.last_activity || ''),
                isActive: Boolean(s.isActive ?? s.is_active ?? true),
            })));
        }).catch(() => {}).finally(() => setIsLoading(false));
    }, []);

    const getBrowserName = (ua: string) => {
        if (ua.includes('Chrome')) return 'Chrome';
        if (ua.includes('Firefox')) return 'Firefox';
        if (ua.includes('Safari')) return 'Safari';
        if (ua.includes('Edge')) return 'Edge';
        return 'Unknown Browser';
    };

    return (
        <ModalOverlay onClose={onClose}>
            <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-heading font-semibold text-text-primary">Active Sessions</h2>
                    <button onClick={onClose} className="text-text-tertiary hover:text-text-primary">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                </div>

                {isLoading ? (
                    <div className="flex justify-center py-12"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-green" /></div>
                ) : sessions.length === 0 ? (
                    <p className="text-center text-text-tertiary py-8">No active sessions found.</p>
                ) : (
                    <div className="space-y-3">
                        {sessions.map((session) => (
                            <div key={session.id} className="p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <div className={`w-2 h-2 rounded-full ${session.isActive ? 'bg-accent-green' : 'bg-text-tertiary'}`} />
                                        <span className="text-sm font-medium text-text-primary">{getBrowserName(session.userAgent)}</span>
                                    </div>
                                    <span className="text-xs text-text-tertiary">{session.ipAddress}</span>
                                </div>
                                <p className="text-xs text-text-tertiary truncate">{session.userAgent}</p>
                                <p className="text-xs text-text-tertiary mt-1">Last active: {session.lastActivity ? new Date(session.lastActivity).toLocaleString() : 'Unknown'}</p>
                            </div>
                        ))}
                    </div>
                )}
                <div className="flex justify-end mt-4">
                    <Button variant="outline" size="sm" onClick={onClose}>Close</Button>
                </div>
            </div>
        </ModalOverlay>
    );
}
