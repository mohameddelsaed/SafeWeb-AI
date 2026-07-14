import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import ScrollReveal from '@components/ui/ScrollReveal';

export default function Services() {
    const plans = [
        {
            name: 'Free',
            price: '0',
            description: 'Perfect for personal projects and testing',
            features: [
                '5 scans per month',
                'Basic vulnerability detection',
                'Email support',
                'Scan history (30 days)',
                'PDF export',
            ],
            cta: 'Start Free',
            popular: false,
        },
        {
            name: 'Pro',
            price: '49',
            description: 'For professionals and small teams',
            features: [
                'Unlimited scans',
                'Advanced AI detection',
                'Priority support',
                'Unlimited scan history',
                'API access',
                'Custom integrations',
                'Scheduled scans',
            ],
            cta: 'Get Started',
            popular: true,
        },
        {
            name: 'Enterprise',
            price: 'Custom',
            description: 'For large organizations',
            features: [
                'Everything in Pro',
                'Dedicated support',
                'Custom ML models',
                'On-premise deployment',
                'SLA guarantees',
                'Advanced compliance',
                'Team management',
                'SSO integration',
            ],
            cta: 'Contact Sales',
            popular: false,
        },
    ];

    const features = [
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            ),
            title: 'Vulnerability Scanning',
            description: 'Comprehensive security analysis covering OWASP Top 10 and beyond',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
            ),
            title: 'AI-Powered Analysis',
            description: 'Machine learning algorithms detect complex patterns and zero-day vulnerabilities',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
            ),
            title: 'Detailed Reports',
            description: 'Actionable insights with remediation steps and compliance mapping',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
            ),
            title: 'API Integration',
            description: 'Seamless integration with your CI/CD pipeline and development workflow',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            ),
            title: 'Real-Time Monitoring',
            description: 'Live scan progress with instant notifications for critical issues',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                </svg>
            ),
            title: 'Education Resources',
            description: 'Access to learning materials and security best practices',
        },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <ScrollReveal>
                    <div className="text-center mb-16">
                        <h1 className="text-4xl md:text-5xl font-heading font-bold text-text-primary mb-4">
                            Pricing & Services
                        </h1>
                        <p className="text-xl text-text-secondary max-w-3xl mx-auto">
                            Choose the perfect plan for your security needs
                        </p>
                    </div>
                    </ScrollReveal>

                    {/* Pricing Cards */}
                    <ScrollReveal stagger staggerDelay={100}>
                    <div id="pricing" className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
                        {plans.map((plan, index) => (
                            <Card
                                key={index}
                                className={`p-8 relative ${plan.popular ? 'border-2 border-accent-green shadow-glow-green' : ''
                                    }`}
                            >
                                {plan.popular && (
                                    <div className="absolute -top-4 left-1/2 -translate-x-1/2">
                                        <span className="px-4 py-1.5 rounded-full bg-accent-green text-bg-primary text-sm font-semibold">
                                            Most Popular
                                        </span>
                                    </div>
                                )}

                                <div className="text-center mb-8">
                                    <h3 className="text-2xl font-heading font-bold text-text-primary mb-2">
                                        {plan.name}
                                    </h3>
                                    <p className="text-sm text-text-tertiary mb-6">{plan.description}</p>
                                    <div className="mb-6">
                                        {plan.price === 'Custom' ? (
                                            <div className="text-4xl font-bold text-accent-green">Custom</div>
                                        ) : (
                                            <>
                                                <span className="text-5xl font-bold text-accent-green">${plan.price}</span>
                                                <span className="text-text-tertiary ml-2">/month</span>
                                            </>
                                        )}
                                    </div>
                                    <Link to="/register">
                                        <Button
                                            variant={plan.popular ? 'primary' : 'outline'}
                                            size="lg"
                                            className="w-full"
                                        >
                                            {plan.cta}
                                        </Button>
                                    </Link>
                                </div>

                                <div className="space-y-4">
                                    {plan.features.map((feature, idx) => (
                                        <div key={idx} className="flex items-start gap-3">
                                            <svg
                                                className="w-5 h-5 text-accent-green flex-shrink-0 mt-0.5"
                                                fill="none"
                                                stroke="currentColor"
                                                viewBox="0 0 24 24"
                                            >
                                                <path
                                                    strokeLinecap="round"
                                                    strokeLinejoin="round"
                                                    strokeWidth={2}
                                                    d="M5 13l4 4L19 7"
                                                />
                                            </svg>
                                            <span className="text-sm text-text-secondary">{feature}</span>
                                        </div>
                                    ))}
                                </div>
                            </Card>
                        ))}
                    </div>
                    </ScrollReveal>

                    {/* Features */}
                    <div className="mb-20">
                        <h2 className="text-3xl font-heading font-bold text-text-primary text-center mb-12">
                            All Features Included
                        </h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {features.map((feature, index) => (
                                <Card key={index} hover className="p-6">
                                    <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-4">
                                        {feature.icon}
                                    </div>
                                    <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                                        {feature.title}
                                    </h3>
                                    <p className="text-sm text-text-tertiary leading-relaxed">
                                        {feature.description}
                                    </p>
                                </Card>
                            ))}
                        </div>
                    </div>

                    {/* FAQ */}
                    <div className="mb-20">
                        <h2 className="text-3xl font-heading font-bold text-text-primary text-center mb-12">
                            Frequently Asked Questions
                        </h2>
                        <div className="max-w-3xl mx-auto space-y-4">
                            {[
                                {
                                    q: 'Can I change plans later?',
                                    a: 'Yes, you can upgrade or downgrade your plan at any time.',
                                },
                                {
                                    q: 'What payment methods do you accept?',
                                    a: 'We accept all major credit cards, PayPal, and bank transfers for Enterprise plans.',
                                },
                                {
                                    q: 'Is there a free trial?',
                                    a: 'Yes, our Free plan allows you to test the platform with 5 scans per month.',
                                },
                                {
                                    q: 'Do you offer refunds?',
                                    a: 'Yes, we offer a 30-day money-back guarantee on all paid plans.',
                                },
                            ].map((faq, index) => (
                                <Card key={index} className="p-6">
                                    <h4 className="text-lg font-semibold text-text-primary mb-2">{faq.q}</h4>
                                    <p className="text-text-secondary">{faq.a}</p>
                                </Card>
                            ))}
                        </div>
                    </div>

                    {/* CTA */}
                    <Card className="p-12 bg-gradient-to-br from-accent-green/10 to-accent-blue/10 border-accent-green/20 text-center">
                        <h2 className="text-3xl font-heading font-bold text-text-primary mb-4">
                            Still Have Questions?
                        </h2>
                        <p className="text-lg text-text-secondary mb-8 max-w-2xl mx-auto">
                            Our team is here to help you choose the right plan for your needs
                        </p>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                            <Link to="/contact">
                                <Button variant="primary" size="lg">
                                    Contact Sales
                                </Button>
                            </Link>
                            <Link to="/docs">
                                <Button variant="outline" size="lg">
                                    View Documentation
                                </Button>
                            </Link>
                        </div>
                    </Card>
                </Container>
            </div>
        </Layout>
    );
}
