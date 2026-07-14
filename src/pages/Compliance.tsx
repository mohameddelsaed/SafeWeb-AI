import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';

export default function Compliance() {
    const standards = [
        {
            name: 'OWASP Top 10',
            status: 'Fully Aligned',
            badge: 'success' as const,
            description: 'Our scanning engine tests for all OWASP Top 10 vulnerability categories including injection, broken authentication, sensitive data exposure, XML external entities, broken access control, security misconfiguration, cross-site scripting, insecure deserialization, using components with known vulnerabilities, and insufficient logging.',
            items: ['A01: Broken Access Control', 'A02: Cryptographic Failures', 'A03: Injection', 'A04: Insecure Design', 'A05: Security Misconfiguration', 'A06: Vulnerable Components', 'A07: Authentication Failures', 'A08: Data Integrity Failures', 'A09: Logging Failures', 'A10: Server-Side Request Forgery'],
        },
        {
            name: 'GDPR',
            status: 'Compliant',
            badge: 'success' as const,
            description: 'SafeWeb AI is fully compliant with the General Data Protection Regulation (GDPR). We ensure that all personal data is processed lawfully, transparently, and for specific purposes.',
            items: ['Data minimization and purpose limitation', 'Right to access and data portability', 'Right to erasure (right to be forgotten)', 'Data breach notification within 72 hours', 'Privacy by design and default', 'Data Protection Impact Assessments'],
        },
        {
            name: 'SOC 2 Type II',
            status: 'In Progress',
            badge: 'info' as const,
            description: 'We are actively working toward SOC 2 Type II certification, demonstrating our commitment to security, availability, processing integrity, confidentiality, and privacy.',
            items: ['Security policies and procedures', 'Access control and authentication', 'Encryption at rest and in transit', 'Incident response procedures', 'Continuous monitoring and alerting', 'Vendor risk management'],
        },
        {
            name: 'ISO 27001',
            status: 'Planned',
            badge: 'default' as const,
            description: 'ISO 27001 certification is on our roadmap, establishing a comprehensive information security management system (ISMS) for our organization.',
            items: ['Information security policies', 'Asset management', 'Human resource security', 'Physical and environmental security', 'Operations security', 'Communications security'],
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
                                Security & Compliance
                            </h1>
                            <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                                SafeWeb AI is committed to maintaining the highest standards of security and regulatory compliance
                            </p>
                        </div>

                        {/* Standards */}
                        <div className="space-y-8">
                            {standards.map((standard) => (
                                <Card key={standard.name} className="p-8">
                                    <div className="flex items-start justify-between mb-4">
                                        <h2 className="text-2xl font-heading font-semibold text-text-primary">
                                            {standard.name}
                                        </h2>
                                        <Badge variant={standard.badge}>{standard.status}</Badge>
                                    </div>
                                    <p className="text-text-secondary leading-relaxed mb-6">
                                        {standard.description}
                                    </p>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        {standard.items.map((item) => (
                                            <div key={item} className="flex items-center gap-2 text-sm text-text-secondary">
                                                <svg className="w-4 h-4 text-accent-green flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                                </svg>
                                                {item}
                                            </div>
                                        ))}
                                    </div>
                                </Card>
                            ))}
                        </div>

                        {/* Data Security */}
                        <Card className="mt-8 p-8 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                            <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                Our Security Practices
                            </h2>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div>
                                    <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-3">
                                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                        </svg>
                                    </div>
                                    <h3 className="font-semibold text-text-primary mb-2">Encryption</h3>
                                    <p className="text-sm text-text-secondary">All data encrypted at rest (AES-256) and in transit (TLS 1.3)</p>
                                </div>
                                <div>
                                    <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-3">
                                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                    </div>
                                    <h3 className="font-semibold text-text-primary mb-2">Access Control</h3>
                                    <p className="text-sm text-text-secondary">Role-based access with MFA and session management</p>
                                </div>
                                <div>
                                    <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-3">
                                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                        </svg>
                                    </div>
                                    <h3 className="font-semibold text-text-primary mb-2">Monitoring</h3>
                                    <p className="text-sm text-text-secondary">24/7 security monitoring with automated threat detection</p>
                                </div>
                            </div>
                        </Card>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
