import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';

export default function Partners() {
    const partnerTypes = [
        {
            title: 'Technology Partners',
            description: 'Integrate SafeWeb AI scanning into your platform, CI/CD pipeline, or developer toolchain.',
            features: ['REST API access', 'Webhook notifications', 'White-label reports', 'Custom scan profiles'],
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
            ),
        },
        {
            title: 'Reseller Partners',
            description: 'Offer SafeWeb AI security scanning as part of your managed services portfolio with competitive margins.',
            features: ['Volume discounts', 'Partner portal', 'Co-branded materials', 'Dedicated account manager'],
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
            ),
        },
        {
            title: 'Consulting Partners',
            description: 'Complement your security advisory services with automated scanning powered by SafeWeb AI.',
            features: ['Priority support', 'Training & certification', 'Lead referrals', 'Joint case studies'],
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            ),
        },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="max-w-4xl mx-auto">
                        {/* Header */}
                        <div className="text-center mb-12">
                            <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                                Partner with SafeWeb AI
                            </h1>
                            <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                                Join our growing ecosystem of security-focused partners and help make the web a safer place.
                            </p>
                        </div>

                        {/* Partner Types */}
                        <div className="space-y-6 mb-12">
                            {partnerTypes.map((type) => (
                                <Card key={type.title} className="p-8">
                                    <div className="flex items-start gap-4">
                                        <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green flex-shrink-0">
                                            {type.icon}
                                        </div>
                                        <div className="flex-1">
                                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                                {type.title}
                                            </h2>
                                            <p className="text-text-secondary mb-4">{type.description}</p>
                                            <div className="grid grid-cols-2 gap-2">
                                                {type.features.map((f) => (
                                                    <div key={f} className="flex items-center gap-2 text-sm text-text-secondary">
                                                        <svg className="w-4 h-4 text-accent-green flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                                        </svg>
                                                        {f}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </Card>
                            ))}
                        </div>

                        {/* CTA */}
                        <Card className="p-8 text-center bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                            <h2 className="text-2xl font-heading font-semibold text-text-primary mb-3">
                                Become a Partner
                            </h2>
                            <p className="text-text-secondary mb-6 max-w-lg mx-auto">
                                Interested in partnering with us? Reach out to our partnerships team and we&apos;ll get back to you within 48 hours.
                            </p>
                            <Button
                                variant="primary"
                                onClick={() => window.location.href = 'mailto:partners@safeweb.ai?subject=Partnership Inquiry'}
                            >
                                Contact Partnerships Team
                            </Button>
                        </Card>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
