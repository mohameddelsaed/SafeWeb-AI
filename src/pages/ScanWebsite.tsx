import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';
import Button from '@components/ui/Button';
import ScrollReveal from '@components/ui/ScrollReveal';
import { isValidUrl } from '@utils/validation';
import { scanAPI } from '@/services/api';
import { AxiosError } from 'axios';
import type { ScopeType } from '@/types';

type ScanStep = 'configure' | 'confirm_domains';

interface WideScopeState {
    scanId: string;
    discoveredDomains: string[];
    selectedDomains: string[];
}

export default function ScanWebsite() {
    const navigate = useNavigate();
    const [scopeType, setScopeType] = useState<ScopeType>('single_domain');
    const [step, setStep] = useState<ScanStep>('configure');
    const [wideScopeState, setWideScopeState] = useState<WideScopeState | null>(null);

    const [formData, setFormData] = useState({
        target: '',
        seedDomains: '',
        scanDepth: 'medium',
        checkSsl: true,
        followRedirects: true,
        controlExternalTools: true,
        scanMode: 'normal',
        wafEvasion: false,
        authUrl: '',
        authUsername: '',
        authPassword: '',
    });
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [errors, setErrors] = useState({ target: '' });
    const [apiError, setApiError] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [isResolving, setIsResolving] = useState(false);
    const [showConsentModal, setShowConsentModal] = useState(false);
    const [allowlistChecked, setAllowlistChecked] = useState(false);

    const depthEstimates = formData.controlExternalTools
        ? {
            shallow: '12-18 minutes',
            medium: '35-55 minutes',
            deep: '80-130 minutes',
        }
        : {
            shallow: '3-6 minutes',
            medium: '10-18 minutes',
            deep: '28-45 minutes',
        };

    const scanDepthOptions = [
        { value: 'shallow', label: `Shallow (Fast - ${depthEstimates.shallow})` },
        { value: 'medium', label: `Medium (Recommended - ${depthEstimates.medium})` },
        { value: 'deep', label: `Deep (Thorough - ${depthEstimates.deep})` },
    ];

    const scanModeOptions = [
        { value: 'normal', label: 'Normal' },
        { value: 'stealth', label: 'Stealth (Low-noise, slower)' },
        { value: 'aggressive', label: 'Aggressive (More requests, faster)' },
    ];

    const scopeTypes: { id: ScopeType; title: string; description: string; icon: JSX.Element; example: string }[] = [
        {
            id: 'single_domain',
            title: 'Single Domain',
            description: 'Scan one domain and all its subdomains',
            example: 'https://example.com',
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                </svg>
            ),
        },
        {
            id: 'wildcard',
            title: 'Wildcard Domain',
            description: 'Discover and scan all matching domains via CT logs',
            example: '*.example.com',
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                </svg>
            ),
        },
        {
            id: 'wide_scope',
            title: 'Wide Scope (Company)',
            description: 'Full OSINT discovery — WHOIS, ASN, CT logs — then scan all found domains',
            example: 'Acme Corp',
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                </svg>
            ),
        },
    ];

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value, type } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: type === 'checkbox' ? (e.target as HTMLInputElement).checked : value,
        }));
        if (errors[name as keyof typeof errors]) {
            setErrors((prev) => ({ ...prev, [name]: '' }));
        }
    };

    const validateForm = () => {
        const target = formData.target.trim();
        if (!target) {
            setErrors({ target: 'Please enter a target' });
            return false;
        }

        if (scopeType === 'single_domain' && !isValidUrl(target)) {
            setErrors({ target: 'Please enter a valid URL (e.g., https://example.com)' });
            return false;
        }

        if (scopeType === 'wildcard' && !target.startsWith('*.')) {
            setErrors({ target: 'Wildcard pattern must start with *. (e.g., *.example.com)' });
            return false;
        }

        if (scopeType === 'wide_scope' && target.length < 2) {
            setErrors({ target: 'Please enter a company or organization name' });
            return false;
        }

        setErrors({ target: '' });
        return true;
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!validateForm()) return;
        setShowConsentModal(true);
    };

    const executeScan = async () => {
        setShowConsentModal(false);
        setIsScanning(true);
        setApiError('');

        try {
            const payload: Record<string, unknown> = {
                target: formData.target,
                scope_type: scopeType,
                scanDepth: formData.scanDepth,
                checkSsl: formData.checkSsl,
                followRedirects: formData.followRedirects,
                controlExternalTools: formData.controlExternalTools,
                scanMode: formData.scanMode,
                wafEvasion: formData.wafEvasion,
            };

            if (scopeType === 'wide_scope' && formData.seedDomains.trim()) {
                payload.seed_domains = formData.seedDomains.split('\n').map(d => d.trim()).filter(Boolean);
            }

            if (formData.authUrl && formData.authUsername) {
                payload.authConfig = {
                    loginUrl: formData.authUrl,
                    username: formData.authUsername,
                    password: formData.authPassword,
                };
            }

            const { data } = await scanAPI.createScan(payload as Parameters<typeof scanAPI.createScan>[0]);

            if (scopeType === 'wide_scope') {
                // Wide scope: resolve domains then ask user to confirm
                setIsResolving(true);
                try {
                    const resolveRes = await scanAPI.resolveScope(data.id);
                    const domains: string[] = resolveRes.data.discovered_domains || [];
                    setWideScopeState({
                        scanId: data.id,
                        discoveredDomains: domains,
                        selectedDomains: [...domains],
                    });
                    setStep('confirm_domains');
                } catch {
                    setApiError('Failed to resolve domains. You can retry from the scan results page.');
                    navigate(`/scan/results/${data.id}`);
                } finally {
                    setIsResolving(false);
                }
            } else {
                navigate(`/scan/results/${data.id}`);
            }
        } catch (err) {
            const axiosErr = err as AxiosError<{ detail?: string; message?: string }>;
            setApiError(
                axiosErr.response?.data?.detail ||
                axiosErr.response?.data?.message ||
                'Failed to start scan. Please try again.',
            );
        } finally {
            setIsScanning(false);
        }
    };

    const handleConfirmDomains = async () => {
        if (!wideScopeState || wideScopeState.selectedDomains.length === 0) return;

        setIsScanning(true);
        setApiError('');

        try {
            await scanAPI.confirmScope(wideScopeState.scanId, wideScopeState.selectedDomains);
            navigate(`/scan/results/${wideScopeState.scanId}`);
        } catch (err) {
            const axiosErr = err as AxiosError<{ detail?: string; message?: string }>;
            setApiError(
                axiosErr.response?.data?.detail ||
                axiosErr.response?.data?.message ||
                'Failed to confirm scope. Please try again.',
            );
            setIsScanning(false);
        }
    };

    const toggleDomain = (domain: string) => {
        if (!wideScopeState) return;
        setWideScopeState(prev => {
            if (!prev) return prev;
            const selected = prev.selectedDomains.includes(domain)
                ? prev.selectedDomains.filter(d => d !== domain)
                : [...prev.selectedDomains, domain];
            return { ...prev, selectedDomains: selected };
        });
    };

    const toggleAllDomains = () => {
        if (!wideScopeState) return;
        setWideScopeState(prev => {
            if (!prev) return prev;
            const allSelected = prev.selectedDomains.length === prev.discoveredDomains.length;
            return { ...prev, selectedDomains: allSelected ? [] : [...prev.discoveredDomains] };
        });
    };

    const getTargetLabel = () => {
        switch (scopeType) {
            case 'single_domain': return 'Target URL';
            case 'wildcard': return 'Wildcard Pattern';
            case 'wide_scope': return 'Company / Organization Name';
        }
    };

    const getTargetPlaceholder = () => {
        switch (scopeType) {
            case 'single_domain': return 'https://example.com';
            case 'wildcard': return '*.example.com';
            case 'wide_scope': return 'Acme Corporation';
        }
    };

    const getTargetHelperText = () => {
        switch (scopeType) {
            case 'single_domain': return 'Enter the full URL including http:// or https://';
            case 'wildcard': return 'All domains matching this pattern will be discovered via CT logs and scanned';
            case 'wide_scope': return 'We\'ll discover all domains belonging to this organization using OSINT techniques';
        }
    };

    const vulnerabilityChecks = [
        'SQL Injection', 'Cross-Site Scripting (XSS)', 'CSRF Attacks',
        'Broken Authentication', 'Security Misconfiguration', 'Sensitive Data Exposure',
        'Broken Access Control', 'XML External Entities (XXE)', 'Insecure Deserialization',
        'Known Vulnerable Components', 'Insufficient Logging', 'Server-Side Request Forgery (SSRF)',
    ];

    // ── Wide scope domain confirmation step ──────────────────────
    if (step === 'confirm_domains' && wideScopeState) {
        return (
            <Layout>
                <div className="py-12">
                    <Container>
                        <ScrollReveal>
                            <div className="mb-8">
                                <button
                                    onClick={() => { setStep('configure'); setWideScopeState(null); }}
                                    className="text-sm text-accent-green hover:text-accent-green-hover mb-2 inline-flex items-center gap-1"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                                    </svg>
                                    Back to Configuration
                                </button>
                                <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                                    Confirm Discovered Domains
                                </h1>
                                <p className="text-lg text-text-secondary">
                                    We discovered <span className="text-accent-green font-semibold">{wideScopeState.discoveredDomains.length}</span> domains
                                    for &ldquo;{formData.target}&rdquo;. Select which domains to include in the scan.
                                </p>
                            </div>
                        </ScrollReveal>

                        {apiError && (
                            <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm mb-6">
                                {apiError}
                            </div>
                        )}

                        <Card className="p-6 mb-6">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-3">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={wideScopeState.selectedDomains.length === wideScopeState.discoveredDomains.length}
                                            onChange={toggleAllDomains}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green"
                                        />
                                        <span className="text-sm font-medium text-text-primary">Select All</span>
                                    </label>
                                    <span className="text-sm text-text-tertiary">
                                        {wideScopeState.selectedDomains.length} of {wideScopeState.discoveredDomains.length} selected
                                    </span>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-96 overflow-y-auto">
                                {wideScopeState.discoveredDomains.map((domain) => (
                                    <label
                                        key={domain}
                                        className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                                            wideScopeState.selectedDomains.includes(domain)
                                                ? 'bg-accent-green/10 border border-accent-green/30'
                                                : 'bg-bg-secondary border border-transparent hover:bg-bg-hover'
                                        }`}
                                    >
                                        <input
                                            type="checkbox"
                                            checked={wideScopeState.selectedDomains.includes(domain)}
                                            onChange={() => toggleDomain(domain)}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green"
                                        />
                                        <span className="text-sm font-mono text-text-primary truncate">{domain}</span>
                                    </label>
                                ))}
                            </div>
                        </Card>

                        <div className="flex items-center gap-4">
                            <Button
                                variant="primary"
                                size="lg"
                                onClick={handleConfirmDomains}
                                isLoading={isScanning}
                                className="flex-1"
                            >
                                {isScanning
                                    ? 'Launching Scans...'
                                    : `Start Scanning ${wideScopeState.selectedDomains.length} Domain${wideScopeState.selectedDomains.length !== 1 ? 's' : ''}`}
                            </Button>
                            <Button
                                variant="outline"
                                size="lg"
                                onClick={() => { setStep('configure'); setWideScopeState(null); }}
                            >
                                Cancel
                            </Button>
                        </div>
                    </Container>
                </div>
            </Layout>
        );
    }

    // ── Main scan configuration form ─────────────────────────────
    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <ScrollReveal>
                        <div className="mb-8">
                            <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                                Web Application Penetration Test
                            </h1>
                            <p className="text-lg text-text-secondary">
                                Comprehensive security analysis powered by AI
                            </p>
                        </div>
                    </ScrollReveal>

                    {/* Scope Type Selector */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                        {scopeTypes.map((scope) => (
                            <button
                                key={scope.id}
                                onClick={() => { setScopeType(scope.id); setErrors({ target: '' }); setFormData(prev => ({ ...prev, target: '' })); }}
                                className={`p-6 rounded-xl border-2 text-left transition-all duration-200 ${
                                    scopeType === scope.id
                                        ? 'border-accent-green bg-accent-green/5 shadow-lg'
                                        : 'border-border-primary bg-bg-card hover:border-accent-green/50 hover:bg-bg-hover'
                                }`}
                            >
                                <div className={`mb-3 ${scopeType === scope.id ? 'text-accent-green' : 'text-text-tertiary'}`}>
                                    {scope.icon}
                                </div>
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-1">{scope.title}</h3>
                                <p className="text-sm text-text-tertiary mb-2">{scope.description}</p>
                                <code className="text-xs text-text-tertiary bg-bg-secondary px-2 py-1 rounded">{scope.example}</code>
                            </button>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Scan Form */}
                        <Card className="lg:col-span-2 p-8">
                            <form onSubmit={handleSubmit} className="space-y-6">
                                {apiError && (
                                    <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm">
                                        {apiError}
                                    </div>
                                )}

                                {isResolving && (
                                    <div className="p-4 rounded-lg bg-accent-green/5 border border-accent-green/20">
                                        <div className="flex items-center gap-3">
                                            <div className="w-5 h-5 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                                            <span className="text-sm text-text-primary">
                                                Discovering domains via OSINT (WHOIS, ASN, CT logs)...
                                            </span>
                                        </div>
                                    </div>
                                )}

                                {/* Target Input */}
                                <Input
                                    type="text"
                                    name="target"
                                    label={getTargetLabel()}
                                    placeholder={getTargetPlaceholder()}
                                    value={formData.target}
                                    onChange={handleChange}
                                    error={errors.target}
                                    helperText={getTargetHelperText()}
                                    leftIcon={
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                                        </svg>
                                    }
                                />

                                {/* Seed Domains — only for wide scope */}
                                {scopeType === 'wide_scope' && (
                                    <div>
                                        <label className="block text-sm font-medium text-text-secondary mb-2">
                                            Known Seed Domains (optional)
                                        </label>
                                        <textarea
                                            name="seedDomains"
                                            value={formData.seedDomains}
                                            onChange={handleChange}
                                            placeholder={'example.com\napp.example.com\napi.example.io'}
                                            rows={4}
                                            className="w-full px-4 py-3 rounded-lg bg-bg-secondary border border-border-primary text-text-primary text-sm font-mono placeholder:text-text-tertiary focus:outline-none focus:ring-2 focus:ring-accent-green focus:border-transparent resize-none"
                                        />
                                        <p className="text-xs text-text-tertiary mt-1">
                                            One domain per line. These will be included alongside OSINT-discovered domains.
                                        </p>
                                    </div>
                                )}

                                {/* Scan Depth */}
                                <div className="space-y-3">
                                    <label className="text-sm font-medium text-text-secondary block">
                                        Control External Tools
                                    </label>
                                    <button
                                        type="button"
                                        onClick={() => setFormData((prev) => ({
                                            ...prev,
                                            controlExternalTools: !prev.controlExternalTools,
                                        }))}
                                        className={`w-full rounded-lg border px-4 py-3 text-left transition-colors ${
                                            formData.controlExternalTools
                                                ? 'border-accent-green/50 bg-accent-green/10'
                                                : 'border-border-primary bg-bg-secondary hover:bg-bg-hover'
                                        }`}
                                    >
                                        <div className="flex items-center justify-between gap-3">
                                            <div>
                                                <p className="text-sm font-semibold text-text-primary">Control External Tools</p>
                                                <p className="text-xs text-text-tertiary mt-1">
                                                    {formData.controlExternalTools
                                                        ? 'Active: Runs external recon/scanner integrations, including Nuclei.'
                                                        : 'Deactivated: Runs built-in SafeWeb modules only (no external recon/scanner tools).'}
                                                </p>
                                            </div>
                                            <span
                                                className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
                                                    formData.controlExternalTools
                                                        ? 'bg-accent-green/20 text-accent-green'
                                                        : 'bg-text-tertiary/20 text-text-tertiary'
                                                }`}
                                            >
                                                {formData.controlExternalTools ? 'Active' : 'Deactivated'}
                                            </span>
                                        </div>
                                    </button>
                                </div>

                                <Select
                                    name="scanDepth"
                                    label="Scan Depth"
                                    options={scanDepthOptions}
                                    value={formData.scanDepth}
                                    onChange={handleChange}
                                    helperText={
                                        formData.controlExternalTools
                                            ? 'Expected times include external recon/scanner tools and Nuclei coverage.'
                                            : 'Expected times are for built-in SafeWeb modules only.'
                                    }
                                />

                                {/* Options */}
                                <div className="space-y-3">
                                    <label className="text-sm font-medium text-text-secondary block mb-3">
                                        Scan Options
                                    </label>

                                    <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors">
                                        <input
                                            type="checkbox"
                                            name="checkSsl"
                                            checked={formData.checkSsl}
                                            onChange={handleChange}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                        />
                                        <div className="flex-1">
                                            <span className="text-sm font-medium text-text-primary">
                                                Check SSL/TLS Configuration
                                            </span>
                                            <p className="text-xs text-text-tertiary mt-0.5">
                                                Verify certificate validity and configuration
                                            </p>
                                        </div>
                                    </label>

                                    <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors">
                                        <input
                                            type="checkbox"
                                            name="followRedirects"
                                            checked={formData.followRedirects}
                                            onChange={handleChange}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                        />
                                        <div className="flex-1">
                                            <span className="text-sm font-medium text-text-primary">
                                                Follow Redirects
                                            </span>
                                            <p className="text-xs text-text-tertiary mt-0.5">
                                                Automatically follow HTTP redirects during scan
                                            </p>
                                        </div>
                                    </label>
                                </div>

                                {/* Advanced Options */}
                                <div>
                                    <button
                                        type="button"
                                        className="flex items-center gap-2 text-sm text-text-secondary hover:text-accent-green transition-colors"
                                        onClick={() => setShowAdvanced((v) => !v)}
                                    >
                                        <svg className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                        </svg>
                                        Advanced Options
                                    </button>

                                    {showAdvanced && (
                                        <div className="mt-4 space-y-4 pl-6 border-l-2 border-border-primary">
                                            <Select
                                                name="scanMode"
                                                label="Scan Mode"
                                                options={scanModeOptions}
                                                value={formData.scanMode}
                                                onChange={handleChange}
                                                helperText="Stealth mode reduces detection probability; Aggressive is faster but noisier"
                                            />

                                            <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors">
                                                <input
                                                    type="checkbox"
                                                    name="wafEvasion"
                                                    checked={formData.wafEvasion}
                                                    onChange={handleChange}
                                                    className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                                />
                                                <div className="flex-1">
                                                    <span className="text-sm font-medium text-text-primary">WAF Evasion Techniques</span>
                                                    <p className="text-xs text-text-tertiary mt-0.5">Use payload obfuscation to bypass Web Application Firewalls</p>
                                                </div>
                                            </label>

                                            <div className="space-y-3">
                                                <p className="text-sm font-medium text-text-secondary">Authenticated Scan (optional)</p>
                                                <Input
                                                    type="url"
                                                    name="authUrl"
                                                    label="Login URL"
                                                    placeholder="https://example.com/login"
                                                    value={formData.authUrl}
                                                    onChange={handleChange}
                                                />
                                                <div className="grid grid-cols-2 gap-3">
                                                    <Input
                                                        type="text"
                                                        name="authUsername"
                                                        label="Username"
                                                        placeholder="user@example.com"
                                                        value={formData.authUsername}
                                                        onChange={handleChange}
                                                    />
                                                    <Input
                                                        type="password"
                                                        name="authPassword"
                                                        label="Password"
                                                        placeholder="••••••••"
                                                        value={formData.authPassword}
                                                        onChange={handleChange}
                                                    />
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>

                                {/* Submit Button */}
                                <div className="pt-4">
                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="lg"
                                        className="w-full"
                                        isLoading={isScanning || isResolving}
                                    >
                                        {isScanning || isResolving ? (
                                            scopeType === 'wide_scope' ? 'Discovering Domains...' : 'Initiating Scan...'
                                        ) : (
                                            <>
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                                </svg>
                                                {scopeType === 'wide_scope' ? 'Discover & Review Domains' : 'Start Security Scan'}
                                            </>
                                        )}
                                    </Button>
                                </div>
                            </form>
                        </Card>

                        {/* Info Sidebar */}
                        <div className="space-y-6">
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    What We Scan For
                                </h3>
                                <div className="space-y-2">
                                    {vulnerabilityChecks.map((check, index) => (
                                        <div key={index} className="flex items-center gap-2 text-sm text-text-secondary">
                                            <svg className="w-4 h-4 text-accent-green flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                            </svg>
                                            <span>{check}</span>
                                        </div>
                                    ))}
                                </div>
                            </Card>

                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Compliance Standards
                                </h3>
                                <div className="space-y-3">
                                    <div className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary">
                                        <div className="w-10 h-10 rounded bg-accent-green/10 flex items-center justify-center text-accent-green text-xs font-bold">OWASP</div>
                                        <div>
                                            <div className="text-sm font-medium text-text-primary">OWASP Top 10</div>
                                            <div className="text-xs text-text-tertiary">Web Security</div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary">
                                        <div className="w-10 h-10 rounded bg-accent-blue/10 flex items-center justify-center text-accent-blue text-xs font-bold">CWE</div>
                                        <div>
                                            <div className="text-sm font-medium text-text-primary">CWE Top 25</div>
                                            <div className="text-xs text-text-tertiary">Common Weaknesses</div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary">
                                        <div className="w-10 h-10 rounded bg-accent-green/10 flex items-center justify-center text-accent-green text-xs font-bold">PCI</div>
                                        <div>
                                            <div className="text-sm font-medium text-text-primary">PCI DSS</div>
                                            <div className="text-xs text-text-tertiary">Payment Security</div>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            <Card className="p-6 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                                <div className="flex items-start gap-3">
                                    <div className="w-10 h-10 rounded-lg bg-accent-green/20 flex items-center justify-center text-accent-green flex-shrink-0">
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-1">Need Help?</h4>
                                        <p className="text-xs text-text-tertiary mb-3">Check our documentation for scanning best practices</p>
                                        <Link to="/docs" className="text-sm text-accent-green hover:text-accent-green-hover font-medium">
                                            View Documentation →
                                        </Link>
                                    </div>
                                </div>
                            </Card>
                        </div>
                    </div>
                </Container>
            </div>

            {/* Scope Consent Modal */}
            {showConsentModal && (
                <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full text-slate-100 shadow-2xl">
                        <h3 className="text-xl font-bold text-cyan-400 mb-2">Scope Authorization Required</h3>
                        <p className="text-sm text-slate-300 mb-4">
                            You are initiating an autonomous multi-agent pentest against <span className="font-mono font-bold text-amber-300">{formData.target || 'target'}</span>. Autonomous offensive tools will execute active attacks and payloads.
                        </p>
                        <div className="bg-slate-950 p-3 rounded border border-slate-800 mb-6">
                            <label className="flex items-start gap-3 cursor-pointer">
                                <input
                                    type="checkbox"
                                    id="consent-allowlist-checkbox"
                                    checked={allowlistChecked}
                                    onChange={(e) => setAllowlistChecked(e.target.checked)}
                                    className="mt-1 rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-cyan-400"
                                />
                                <span className="text-xs text-slate-300">
                                    I confirm that I own or have explicit legal authorization to perform active pentesting against this target allowlist.
                                </span>
                            </label>
                        </div>
                        <div className="flex justify-end gap-3">
                            <Button variant="secondary" onClick={() => setShowConsentModal(false)}>
                                Cancel
                            </Button>
                            <Button
                                variant="primary"
                                disabled={!allowlistChecked}
                                id="confirm-start-scan-btn"
                                onClick={executeScan}
                            >
                                Confirm & Start Scan
                            </Button>
                        </div>
                    </div>
                </div>
            )}
        </Layout>
    );
}
