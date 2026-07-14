import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import { targetAPI } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';

export default function Onboarding() {
    const navigate = useNavigate();
    const { user, refreshProfile } = useAuth();
    
    const [step, setStep] = useState(1);
    const [domain, setDomain] = useState('');
    const [displayName, setDisplayName] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState('');

    // Step 1: Welcome
    // Step 2: Add Target

    const handleCreateTarget = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!domain) {
            setError('Please enter a valid domain.');
            return;
        }

        setIsSubmitting(true);
        setError('');
        try {
            await targetAPI.createTarget({
                domain: domain,
                display_name: displayName || domain,
                tags: ['onboarding'],
            });
            // Update profile so that `has_targets` is set to true
            await refreshProfile();
            
            // Redirect to scan page with pre-filled target
            navigate(`/scan?target=${encodeURIComponent(domain)}`);
        } catch (err: unknown) {
            const errorObj = err as { response?: { data?: { detail?: string } } };
            setError(errorObj?.response?.data?.detail || 'Failed to create target. Please try again.');
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Layout>
            <div className="py-20 min-h-screen bg-bg-primary flex flex-col items-center">
                <Container className="max-w-3xl">
                    
                    {step === 1 && (
                        <Card className="p-10 border-accent-green/30 text-center shadow-xl shadow-accent-green/5">
                            <div className="w-20 h-20 bg-accent-green/10 rounded-full flex items-center justify-center mx-auto mb-6">
                                <svg className="w-10 h-10 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                            </div>
                            <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                                Welcome to SafeWeb AI, {user?.name?.split(' ')[0] || 'User'}!
                            </h1>
                            <p className="text-lg text-text-secondary mb-10 max-w-xl mx-auto leading-relaxed">
                                You are just a few steps away from securing your web infrastructure. Let&apos;s start by adding your first web application or domain as a target.
                            </p>
                            <Button variant="primary" className="px-8 py-3 text-lg" onClick={() => setStep(2)}>
                                Get Started
                                <svg className="w-5 h-5 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                </svg>
                            </Button>
                        </Card>
                    )}

                    {step === 2 && (
                        <Card className="p-10 border-accent-green/30 shadow-xl shadow-accent-green/5">
                            <div className="mb-8">
                                <h2 className="text-3xl font-heading font-bold text-text-primary mb-2">Configure Your First Target</h2>
                                <p className="text-text-secondary">
                                    Enter the primary domain or application URL you wish to scan.
                                </p>
                            </div>

                            <form onSubmit={handleCreateTarget} className="space-y-6">
                                {error && (
                                    <div className="p-4 bg-status-critical/10 border border-status-critical/20 rounded-lg text-status-critical text-sm">
                                        {error}
                                    </div>
                                )}
                                
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-2">
                                        Target Domain / URL
                                    </label>
                                    <input 
                                        type="text" 
                                        required
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-4 py-3 text-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50 transition-all"
                                        placeholder="e.g. example.com or https://api.example.com"
                                        value={domain}
                                        onChange={(e) => setDomain(e.target.value)}
                                        autoFocus
                                    />
                                </div>
                                
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-2">
                                        Display Name (Optional)
                                    </label>
                                    <input 
                                        type="text"
                                        className="w-full bg-bg-secondary border border-border-primary rounded-lg px-4 py-3 text-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-green/50 transition-all"
                                        placeholder="e.g. Production API"
                                        value={displayName}
                                        onChange={(e) => setDisplayName(e.target.value)}
                                    />
                                </div>

                                <div className="pt-4 flex items-center justify-between">
                                    <button 
                                        type="button" 
                                        onClick={() => setStep(1)}
                                        className="text-text-tertiary hover:text-text-primary transition-colors font-medium text-sm"
                                    >
                                        Back
                                    </button>
                                    <Button variant="primary" type="submit" isLoading={isSubmitting} className="px-8 py-3 text-lg">
                                        Add Target & Continue
                                    </Button>
                                </div>
                            </form>
                        </Card>
                    )}

                </Container>
            </div>
        </Layout>
    );
}
