import Container from '@components/ui/Container';
import ScrollReveal from '@components/ui/ScrollReveal';

export default function HowItWorks() {
    const steps = [
        {
            number: '01',
            title: 'Submit Target',
            description: 'Enter your website URL, upload files, or submit specific endpoints for comprehensive security analysis.',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
            ),
        },
        {
            number: '02',
            title: 'AI Analysis',
            description: 'Our advanced AI engine performs deep security scans, testing for vulnerabilities, malware, and potential attack vectors.',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
            ),
        },
        {
            number: '03',
            title: 'Get Results',
            description: 'Receive detailed vulnerability reports with severity ratings, impact analysis, and step-by-step remediation guidance.',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
            ),
        },
        {
            number: '04',
            title: 'Take Action',
            description: 'Implement recommended fixes, export reports for compliance, and monitor improvements with continuous scanning.',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
            ),
        },
    ];

    return (
        <section className="py-20">
            <Container>
                <ScrollReveal>
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-4">
                            How It Works
                        </h2>
                        <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                            Simple, fast, and effective vulnerability scanning in four steps
                        </p>
                    </div>
                </ScrollReveal>

                <ScrollReveal stagger staggerDelay={120} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                    {steps.map((step, index) => (
                        <div key={index} className="relative">
                            {/* Connector Line */}
                            {index < steps.length - 1 && (
                                <div className="hidden lg:block absolute top-12 left-full w-full h-0.5 bg-gradient-to-r from-accent-green to-transparent"></div>
                            )}

                            <div className="relative">
                                {/* Number Badge */}
                                <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-accent-green/20 to-accent-blue/20 border border-accent-green/30 flex items-center justify-center mb-6 mx-auto">
                                    <span className="text-3xl font-bold font-mono text-accent-green">
                                        {step.number}
                                    </span>
                                </div>

                                {/* Icon */}
                                <div className="w-12 h-12 rounded-lg bg-bg-card border border-border-primary flex items-center justify-center text-accent-green mb-4 mx-auto">
                                    {step.icon}
                                </div>

                                {/* Content */}
                                <div className="text-center">
                                    <h3 className="text-xl font-heading font-semibold text-text-primary mb-3">
                                        {step.title}
                                    </h3>
                                    <p className="text-text-tertiary leading-relaxed">
                                        {step.description}
                                    </p>
                                </div>
                            </div>
                        </div>
                    ))}
                </ScrollReveal>
            </Container>
        </section>
    );
}
