import Card from '@components/ui/Card';
import Container from '@components/ui/Container';
import ScrollReveal from '@components/ui/ScrollReveal';

export default function Features() {
    const features = [
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            ),
            title: 'Comprehensive Scanning',
            description: 'Deep analysis of websites, files, and URLs for OWASP Top 10 vulnerabilities, malware, and security misconfigurations.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
            ),
            title: 'AI-Powered Analysis',
            description: 'Machine learning algorithms detect complex attack patterns and zero-day vulnerabilities with industry-leading accuracy.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
            ),
            title: 'Detailed Reports',
            description: 'Actionable vulnerability reports with severity ratings, remediation steps, and compliance mapping (OWASP, CWE, CVSS).',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            ),
            title: 'Real-Time Monitoring',
            description: 'Live scan progress tracking with instant notifications for critical vulnerabilities discovered during analysis.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                </svg>
            ),
            title: 'Security Education',
            description: 'Access extensive learning resources, tutorials, and best practices to strengthen your security knowledge.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                </svg>
            ),
            title: 'Easy Integration',
            description: 'RESTful API and CI/CD integration support for seamless automation in your development pipeline.',
        },
    ];

    return (
        <section className="py-20 bg-bg-secondary">
            <Container>
                <ScrollReveal>
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-4">
                            Powerful Security Features
                        </h2>
                        <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                            Everything you need to protect your web applications from modern threats
                        </p>
                    </div>
                </ScrollReveal>

                <ScrollReveal stagger staggerDelay={100} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {features.map((feature, index) => (
                        <Card
                            key={index}
                            hover
                            className="p-6 group"
                        >
                            <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-4 group-hover:bg-accent-green/20 transition-colors duration-300">
                                {feature.icon}
                            </div>
                            <h3 className="text-xl font-heading font-semibold text-text-primary mb-3">
                                {feature.title}
                            </h3>
                            <p className="text-text-tertiary leading-relaxed">
                                {feature.description}
                            </p>
                        </Card>
                    ))}
                </ScrollReveal>
            </Container>
        </section>
    );
}
