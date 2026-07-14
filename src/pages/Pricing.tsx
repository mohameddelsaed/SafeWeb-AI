import { useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import ScrollReveal from '@components/ui/ScrollReveal';
import { useLanguage } from '@/contexts/LanguageContext';

export default function Pricing() {
    const { t } = useLanguage();
    const [isAnnual, setIsAnnual] = useState(true);

    const checkIcon = (
        <svg className="w-5 h-5 text-accent-green flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
    );

    const plans = [
        {
            name: t.pricing.starterTitle,
            priceMonthly: '$49',
            priceAnnual: '$39',
            description: t.pricing.starterDesc,
            features: [
                '15 Autonomous AI Scans / month',
                'Up to 3 Target Web Applications / SPAs',
                'Standard Recon & Discovery Agents',
                'OWASP Top 10 & XSS / SQLi Coverage',
                'Interactive PDF & JSON Reports',
                'Community & Email Technical Support',
            ],
            buttonText: t.pricing.ctaStart,
            buttonVariant: 'outline' as const,
            isPopular: false,
            link: `/checkout?plan=starter&billing=${isAnnual ? 'annual' : 'monthly'}`,
        },
        {
            name: t.pricing.proTitle,
            priceMonthly: '$199',
            priceAnnual: '$159',
            description: t.pricing.proDesc,
            features: [
                '100 Autonomous AI Scans / month',
                'Up to 15 Target Web Applications / SPAs',
                'Full 5-Phase Multi-Agent Pipeline',
                'Active Evidence Verification (Zero False-Positives)',
                'Automated Exploit PoC Synthesis',
                'CI/CD Pipeline Integration (GitHub, GitLab, Jenkins)',
                'Scheduled Continuous Threat Monitoring',
                'API Access & Real-Time Webhook Alerting',
                'Priority 24/7 Security Support',
            ],
            buttonText: t.pricing.ctaPro,
            buttonVariant: 'primary' as const,
            isPopular: true,
            link: `/checkout?plan=pro&billing=${isAnnual ? 'annual' : 'monthly'}`,
        },
        {
            name: t.pricing.enterpriseTitle,
            priceMonthly: '$699',
            priceAnnual: '$549',
            description: t.pricing.enterpriseDesc,
            features: [
                'Unlimited Autonomous AI Scans',
                'Unlimited Target Applications & Wildcards',
                'Custom AI Agent Persona & Prompt Tuning',
                'Private Sandbox & Dedicated Worker Clusters',
                'Multi-Tenant Isolation & Role-Based Access (RBAC)',
                'On-Premise / VPC Deployment Options',
                'Compliance Audits (SOC 2, ISO 27001, HIPAA, PCI)',
                'Dedicated Security Architect & Custom SLAs',
            ],
            buttonText: t.pricing.ctaContact,
            buttonVariant: 'outline' as const,
            isPopular: false,
            link: `/checkout?plan=enterprise&billing=${isAnnual ? 'annual' : 'monthly'}`,
        },
    ];

    const faqs = [
        {
            q: 'How do SafeWeb AI agents prevent false positives compared to traditional scanners?',
            a: 'Unlike regex-only scanners (such as basic Acunetix or Zap modules), SafeWeb AI deploys specialized Validator Agents inside isolated Docker sandboxes. When a vulnerability is suspected, the Validator Agent dynamically synthesizes a harmless proof-of-concept (PoC) exploit and executes it against the target surface to actively confirm evidence before logging it.',
        },
        {
            q: 'Can I test authenticated web applications and single-page applications (SPAs)?',
            a: 'Yes. Our Recon and Discovery agents utilize headless Chromium browsers with full DOM execution capabilities. You can configure custom authentication headers, login scripts, JWT bearer tokens, or session cookies directly in your scan scope.',
        },
        {
            q: 'What happens if I exceed my monthly scan allocation?',
            a: 'You can easily purchase additional ad-hoc scan credits directly from your dashboard or upgrade your tier at any time with prorated billing. Scheduled scans will notify you before any credit exhaustion.',
        },
        {
            q: 'Is my source code or scan data used to train public LLM models?',
            a: 'Absolutely not. All client target data, scan logs, and custom prompt telemetry are strictly isolated within multi-tenant encrypted boundaries and are never shared or used to train external public foundation models.',
        },
    ];

    return (
        <Layout>
            <div className="py-16 md:py-24">
                <Container>
                    {/* Header */}
                    <ScrollReveal>
                        <div className="max-w-3xl mx-auto text-center mb-12">
                            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accent-green/10 border border-accent-green/20 mb-6">
                                <span className="w-2 h-2 bg-accent-green rounded-full animate-pulse"></span>
                                <span className="text-sm font-medium text-accent-green">
                                    {t.pricing.badge}
                                </span>
                            </div>
                            <h1 className="text-4xl md:text-5xl font-heading font-bold text-text-primary mb-4">
                                {t.pricing.title}
                            </h1>
                            <p className="text-lg text-text-secondary">
                                {t.pricing.subtitle}
                            </p>
                        </div>
                    </ScrollReveal>

                    {/* Billing Toggle */}
                    <ScrollReveal delay={100}>
                        <div className="flex items-center justify-center gap-4 mb-16">
                            <span className={`text-sm font-medium transition-colors ${!isAnnual ? 'text-text-primary' : 'text-text-tertiary'}`}>
                                {t.pricing.monthly}
                            </span>
                            <button
                                type="button"
                                onClick={() => setIsAnnual(!isAnnual)}
                                className="relative w-14 h-8 rounded-full bg-bg-secondary border border-border-primary transition-colors focus:outline-none"
                            >
                                <div
                                    className={`absolute top-1 left-1 w-5 h-5 rounded-full bg-accent-green shadow-lg transition-transform duration-300 ${
                                        isAnnual ? 'translate-x-6' : 'translate-x-0'
                                    }`}
                                />
                            </button>
                            <div className="flex items-center gap-2">
                                <span className={`text-sm font-medium transition-colors ${isAnnual ? 'text-text-primary' : 'text-text-tertiary'}`}>
                                    {t.pricing.annual}
                                </span>
                                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-accent-green/20 text-accent-green border border-accent-green/30">
                                    {t.pricing.save20}
                                </span>
                            </div>
                        </div>
                    </ScrollReveal>

                    {/* Pricing Cards Grid */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-stretch mb-24">
                        {plans.map((plan, idx) => (
                            <ScrollReveal key={plan.name} delay={idx * 150} className="flex">
                                <Card
                                    className={`flex flex-col justify-between w-full p-8 transition-all duration-300 relative ${
                                        plan.isPopular
                                            ? 'border-2 border-accent-green shadow-[0_0_30px_rgba(0,240,255,0.15)] bg-gradient-to-b from-bg-card via-bg-card to-accent-green/5'
                                            : 'hover:border-border-hover'
                                    }`}
                                >
                                    {plan.isPopular && (
                                        <div className="absolute -top-3.5 left-1/2 transform -translate-x-1/2 px-4 py-1 rounded-full bg-accent-green text-bg-primary font-bold text-xs uppercase tracking-wider shadow-lg">
                                            {t.pricing.mostPopular}
                                        </div>
                                    )}

                                    <div>
                                        {/* Tier Header */}
                                        <div className="mb-6">
                                            <h3 className="text-2xl font-heading font-bold text-text-primary mb-2">
                                                {plan.name}
                                            </h3>
                                            <p className="text-sm text-text-secondary min-h-[40px]">
                                                {plan.description}
                                            </p>
                                        </div>

                                        {/* Price Display */}
                                        <div className="mb-8 p-4 rounded-xl bg-bg-secondary/60 border border-border-primary/50">
                                            <div className="flex items-baseline gap-1">
                                                <span className="text-4xl md:text-5xl font-mono font-bold text-text-primary">
                                                    {isAnnual ? plan.priceAnnual : plan.priceMonthly}
                                                </span>
                                                <span className="text-sm text-text-tertiary">
                                                    {t.pricing.perMonth}
                                                </span>
                                            </div>
                                            <p className="text-xs text-accent-green mt-1">
                                                {isAnnual ? t.pricing.billedAnnually : 'Billed month-to-month'}
                                            </p>
                                        </div>

                                        {/* Features Checklist */}
                                        <div className="space-y-3 mb-8">
                                            {plan.features.map((feature) => (
                                                <div key={feature} className="flex items-start gap-3">
                                                    {checkIcon}
                                                    <span className="text-sm text-text-secondary leading-snug">
                                                        {feature}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Action Button */}
                                    <div className="pt-4 mt-auto border-t border-border-primary/50">
                                        <Link to={plan.link}>
                                            <Button
                                                variant={plan.buttonVariant}
                                                size="lg"
                                                className="w-full justify-center shadow-md"
                                            >
                                                {plan.buttonText}
                                            </Button>
                                        </Link>
                                    </div>
                                </Card>
                            </ScrollReveal>
                        ))}
                    </div>

                    {/* FAQ Section */}
                    <ScrollReveal>
                        <div className="max-w-4xl mx-auto">
                            <div className="text-center mb-12">
                                <h2 className="text-3xl font-heading font-bold text-text-primary mb-3">
                                    {t.pricing.faqTitle}
                                </h2>
                                <p className="text-text-secondary">
                                    {t.pricing.faqSubtitle}
                                </p>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {faqs.map((faq, i) => (
                                    <Card key={i} className="p-6 bg-bg-secondary/40 border-border-primary">
                                        <h4 className="text-lg font-heading font-semibold text-text-primary mb-2">
                                            {faq.q}
                                        </h4>
                                        <p className="text-sm text-text-secondary leading-relaxed">
                                            {faq.a}
                                        </p>
                                    </Card>
                                ))}
                            </div>
                        </div>
                    </ScrollReveal>

                    {/* Enterprise Custom Banner */}
                    <ScrollReveal delay={200}>
                        <Card className="mt-20 p-8 md:p-12 bg-gradient-to-r from-accent-green/10 via-bg-card to-accent-blue/10 border-accent-green/30 text-center relative overflow-hidden">
                            <div className="max-w-2xl mx-auto relative z-10">
                                <h3 className="text-2xl md:text-3xl font-heading font-bold text-text-primary mb-3">
                                    Need Custom Multi-Agent Deployment?
                                </h3>
                                <p className="text-text-secondary mb-6">
                                    Contact our engineering team for dedicated VPC deployments, custom agent skill integration, and specialized pentesting frameworks tailored to your stack.
                                </p>
                                <Link to="/contact">
                                    <Button variant="primary" size="lg">
                                        Schedule Architecture Consultation
                                    </Button>
                                </Link>
                            </div>
                        </Card>
                    </ScrollReveal>
                </Container>
            </div>
        </Layout>
    );
}
