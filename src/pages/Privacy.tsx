import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';

export default function Privacy() {
    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="max-w-4xl mx-auto">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            Privacy Policy
                        </h1>
                        <p className="text-text-tertiary mb-8">Last updated: February 1, 2026</p>

                        <div className="prose prose-invert max-w-none space-y-8">
                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    1. Introduction
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    SafeWeb AI (&quot;we&quot;, &quot;our&quot;, or &quot;us&quot;) is committed to protecting your privacy. This
                                    Privacy Policy explains how we collect, use, disclose, and safeguard your
                                    information when you use our web application vulnerability scanning service.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    2. Information We Collect
                                </h2>
                                <h3 className="text-xl font-semibold text-text-primary mb-3 mt-4">
                                    Personal Information
                                </h3>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We collect information that you provide directly to us, including:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Name and email address</li>
                                    <li>Company name and role</li>
                                    <li>Account credentials</li>
                                    <li>Payment information (processed securely by third-party providers)</li>
                                    <li>Communication preferences</li>
                                </ul>

                                <h3 className="text-xl font-semibold text-text-primary mb-3 mt-6">
                                    Scan Data
                                </h3>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    When you use our scanning service, we collect:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>URLs of websites you scan</li>
                                    <li>Scan configurations and settings</li>
                                    <li>Vulnerability findings and reports</li>
                                    <li>Scan history and metadata</li>
                                </ul>

                                <h3 className="text-xl font-semibold text-text-primary mb-3 mt-6">
                                    Usage Information
                                </h3>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We automatically collect certain information about your device and usage:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>IP address and browser type</li>
                                    <li>Operating system and device information</li>
                                    <li>Pages visited and features used</li>
                                    <li>Time and date of access</li>
                                    <li>API usage statistics</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    3. How We Use Your Information
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We use the information we collect to:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Provide, maintain, and improve our services</li>
                                    <li>Process your transactions and manage your account</li>
                                    <li>Send you technical notices and support messages</li>
                                    <li>Respond to your comments and questions</li>
                                    <li>Develop new features and functionality</li>
                                    <li>Monitor and analyze trends and usage</li>
                                    <li>Detect and prevent fraud and abuse</li>
                                    <li>Improve our AI models and detection algorithms</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    4. Information Sharing
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We do not sell your personal information. We may share your information in the
                                    following circumstances:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>With your consent or at your direction</li>
                                    <li>With service providers who assist in our operations</li>
                                    <li>To comply with legal obligations</li>
                                    <li>To protect our rights and prevent fraud</li>
                                    <li>In connection with a merger or acquisition</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    5. Data Security
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We implement appropriate technical and organizational measures to protect your
                                    information, including:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Encryption of data in transit and at rest</li>
                                    <li>Regular security assessments and audits</li>
                                    <li>Access controls and authentication mechanisms</li>
                                    <li>Secure development practices</li>
                                    <li>Employee training on data protection</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    6. Data Retention
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We retain your information for as long as necessary to provide our services and
                                    fulfill the purposes outlined in this policy. Scan data is retained according to
                                    your subscription plan. You can request deletion of your data at any time.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    7. Your Rights
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Depending on your location, you may have the following rights:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li>Access your personal information</li>
                                    <li>Correct inaccurate information</li>
                                    <li>Request deletion of your information</li>
                                    <li>Object to processing of your information</li>
                                    <li>Request data portability</li>
                                    <li>Withdraw consent</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    8. Cookies and Tracking
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We use cookies and similar tracking technologies to collect information about your
                                    browsing activities. You can control cookies through your browser settings. Note
                                    that disabling cookies may affect the functionality of our service.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    9. Third-Party Services
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Our service may contain links to third-party websites or integrate with
                                    third-party services. We are not responsible for the privacy practices of these
                                    third parties. We encourage you to review their privacy policies.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    10. Children&apos;s Privacy
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Our service is not intended for children under 13 years of age. We do not
                                    knowingly collect personal information from children. If you believe we have
                                    collected information from a child, please contact us immediately.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    11. International Data Transfers
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Your information may be transferred to and processed in countries other than your
                                    own. We ensure appropriate safeguards are in place to protect your information in
                                    accordance with this policy.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    12. Changes to This Policy
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We may update this Privacy Policy from time to time. We will notify you of any
                                    material changes by posting the new policy on this page and updating the &quot;Last
                                    updated&quot; date.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    13. Contact Us
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    If you have questions about this Privacy Policy or our data practices, please
                                    contact us at:
                                </p>
                                <p className="text-text-secondary">
                                    Email: <a href="mailto:privacy@safeweb.ai" className="text-accent-green hover:underline">privacy@safeweb.ai</a>
                                </p>
                            </section>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
