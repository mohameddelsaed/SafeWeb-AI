import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import ScrollReveal from '@components/ui/ScrollReveal';
import { Link } from 'react-router-dom';

export default function About() {
    const team = [
        {
            name: 'Security Team',
            role: 'Development & Research',
            description: 'Expert team specializing in web security and AI',
        },
    ];

    const values = [
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            ),
            title: 'Security First',
            description: 'We prioritize security in everything we do, from our platform to our processes.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
            ),
            title: 'Innovation',
            description: 'Leveraging cutting-edge AI technology to stay ahead of emerging threats.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
            ),
            title: 'Community',
            description: 'Building a community of security professionals sharing knowledge and expertise.',
        },
        {
            icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            ),
            title: 'Accuracy',
            description: 'Delivering precise vulnerability detection with minimal false positives.',
        },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Hero */}
                    <ScrollReveal>
                    <div className="text-center mb-16">
                        <h1 className="text-4xl md:text-5xl font-heading font-bold text-text-primary mb-4">
                            About SafeWeb AI
                        </h1>
                        <p className="text-xl text-text-secondary max-w-3xl mx-auto leading-relaxed">
                            Protecting web applications with advanced AI-powered vulnerability scanning
                        </p>
                    </div>
                    </ScrollReveal>

                    {/* Mission */}
                    <Card className="p-12 mb-16 text-center bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                        <ScrollReveal>
                        <h2 className="text-3xl font-heading font-bold text-text-primary mb-6">
                            Our Mission
                        </h2>
                        </ScrollReveal>
                        <p className="text-lg text-text-secondary max-w-3xl mx-auto leading-relaxed">
                            SafeWeb AI was created as a university graduation project with the goal of making
                            professional web security accessible to everyone. We combine cutting-edge artificial
                            intelligence with industry-standard security testing methodologies to provide
                            comprehensive vulnerability scanning that helps organizations protect their digital
                            assets and maintain user trust.
                        </p>
                    </Card>

                    {/* Values */}
                    <div className="mb-16">
                        <ScrollReveal>
                        <h2 className="text-3xl font-heading font-bold text-text-primary text-center mb-12">
                            Our Core Values
                        </h2>
                        </ScrollReveal>
                        <ScrollReveal stagger>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                            {values.map((value, index) => (
                                <Card key={index} hover className="p-6 text-center">
                                    <div className="w-16 h-16 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mx-auto mb-4">
                                        {value.icon}
                                    </div>
                                    <h3 className="text-xl font-heading font-semibold text-text-primary mb-3">
                                        {value.title}
                                    </h3>
                                    <p className="text-sm text-text-tertiary leading-relaxed">
                                        {value.description}
                                    </p>
                                </Card>
                            ))}
                        </div>
                        </ScrollReveal>
                    </div>

                    {/* Team */}
                    <div className="mb-16">
                        <ScrollReveal>
                        <h2 className="text-3xl font-heading font-bold text-text-primary text-center mb-12">
                            Our Team
                        </h2>
                        </ScrollReveal>
                        <div className="max-w-2xl mx-auto">
                            {team.map((member, index) => (
                                <Card key={index} className="p-8 text-center">
                                    <div className="w-24 h-24 rounded-full bg-gradient-to-br from-accent-green to-accent-blue mx-auto mb-4 flex items-center justify-center text-4xl font-bold text-bg-primary">
                                        {member.name.charAt(0)}
                                    </div>
                                    <h3 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                        {member.name}
                                    </h3>
                                    <p className="text-sm text-accent-green mb-3">{member.role}</p>
                                    <p className="text-text-secondary">{member.description}</p>
                                </Card>
                            ))}
                        </div>
                    </div>

                    {/* Technology */}
                    <Card className="p-12 mb-16">
                        <ScrollReveal>
                        <h2 className="text-3xl font-heading font-bold text-text-primary text-center mb-6">
                            Technology & Standards
                        </h2>
                        </ScrollReveal>
                        <p className="text-lg text-text-secondary text-center max-w-3xl mx-auto mb-8 leading-relaxed">
                            Our platform is built on industry-leading security frameworks and continuously
                            updated to detect the latest vulnerabilities.
                        </p>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                            {['OWASP Top 10', 'CWE/SANS Top 25', 'CVSS v3.1', 'PCI DSS'].map((standard, index) => (
                                <div
                                    key={index}
                                    className="p-6 rounded-lg bg-bg-secondary border border-border-primary text-center"
                                >
                                    <div className="text-2xl font-bold text-accent-green mb-2">✓</div>
                                    <div className="text-sm font-medium text-text-primary">{standard}</div>
                                </div>
                            ))}
                        </div>
                    </Card>

                    {/* CTA */}
                    <div className="text-center">
                        <ScrollReveal>
                        <h2 className="text-3xl font-heading font-bold text-text-primary mb-6">
                            Ready to Get Started?
                        </h2>
                        </ScrollReveal>
                        <p className="text-lg text-text-secondary mb-8 max-w-2xl mx-auto">
                            Join developers and security professionals using SafeWeb AI
                        </p>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                            <Link
                                to="/register"
                                className="px-8 py-3 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors"
                            >
                                Start Free Trial
                            </Link>
                            <Link
                                to="/contact"
                                className="px-8 py-3 rounded-lg bg-bg-secondary text-text-primary border border-border-primary font-medium hover:bg-bg-hover transition-colors"
                            >
                                Contact Us
                            </Link>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
