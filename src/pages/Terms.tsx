import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';

export default function Terms() {
    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="max-w-4xl mx-auto">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            Terms of Service
                        </h1>
                        <p className="text-text-tertiary mb-8">Last updated: February 1, 2026</p>

                        <div className="prose prose-invert max-w-none space-y-8">
                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    1. Acceptance of Terms
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    By accessing and using SafeWeb AI (&quot;the Service&quot;), you accept and agree to be
                                    bound by the terms and provision of this agreement. If you do not agree to these
                                    terms, please do not use the Service.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    2. Use License
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Permission is granted to temporarily use the Service for personal or commercial
                                    security testing purposes. This is the grant of a license, not a transfer of
                                    title, and under this license you may not:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Use the Service for any illegal purpose</li>
                                    <li>Attempt to reverse engineer or compromise the platform</li>
                                    <li>Share your account credentials with others</li>
                                    <li>Scan websites without proper authorization</li>
                                    <li>Use the Service to harm or exploit others</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    3. User Responsibilities
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    You are responsible for:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Maintaining the confidentiality of your account and password</li>
                                    <li>All activities that occur under your account</li>
                                    <li>Ensuring you have authorization to scan target websites</li>
                                    <li>Complying with all applicable laws and regulations</li>
                                    <li>Notifying us immediately of any unauthorized use of your account</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    4. Acceptable Use Policy
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    You agree not to use the Service to:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Scan websites without proper authorization from the website owner</li>
                                    <li>Perform any activity that could damage, disable, or impair the Service</li>
                                    <li>Attempt to gain unauthorized access to any systems or networks</li>
                                    <li>Interfere with or disrupt the Service or servers</li>
                                    <li>Violate any applicable laws or regulations</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    5. Service Availability
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We strive to maintain the Service with 99.9% uptime, but we do not guarantee that
                                    the Service will be uninterrupted or error-free. We reserve the right to suspend
                                    or terminate the Service for maintenance, updates, or any other reason.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    6. Payment Terms
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Paid subscriptions are billed in advance on a monthly or annual basis. All fees
                                    are non-refundable except as required by law. We reserve the right to change
                                    pricing with 30 days notice.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    7. Intellectual Property
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    The Service and its original content, features, and functionality are owned by
                                    SafeWeb AI and are protected by international copyright, trademark, patent, trade
                                    secret, and other intellectual property laws.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    8. Limitation of Liability
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    SafeWeb AI shall not be liable for any indirect, incidental, special,
                                    consequential, or punitive damages resulting from your use of or inability to use
                                    the Service. Our total liability shall not exceed the amount paid by you in the
                                    past 12 months.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    9. Termination
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We may terminate or suspend your account immediately, without prior notice or
                                    liability, for any reason, including breach of these Terms. Upon termination,
                                    your right to use the Service will immediately cease.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    10. Changes to Terms
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We reserve the right to modify these terms at any time. We will notify users of
                                    any material changes via email or through the Service. Your continued use of the
                                    Service after changes constitutes acceptance of the new terms.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    11. Contact Information
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    If you have any questions about these Terms, please contact us at:
                                </p>
                                <p className="text-text-secondary">
                                    Email: <a href="mailto:legal@safeweb.ai" className="text-accent-green hover:underline">legal@safeweb.ai</a>
                                </p>
                            </section>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
