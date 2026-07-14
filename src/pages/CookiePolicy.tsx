import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';

export default function CookiePolicy() {
    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="max-w-4xl mx-auto">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            Cookie Policy
                        </h1>
                        <p className="text-text-tertiary mb-8">Last updated: February 1, 2026</p>

                        <div className="prose prose-invert max-w-none space-y-8">
                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    1. What Are Cookies
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Cookies are small text files that are placed on your computer or mobile device when you
                                    visit a website. They are widely used to make websites work more efficiently and to
                                    provide information to the owners of the site.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    2. How We Use Cookies
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    SafeWeb AI uses cookies for the following purposes:
                                </p>
                                <ul className="list-disc list-inside text-text-secondary space-y-2 ml-4">
                                    <li><strong className="text-text-primary">Essential Cookies:</strong> Required for the operation of our platform, including authentication tokens and session management.</li>
                                    <li><strong className="text-text-primary">Functional Cookies:</strong> Used to remember your preferences and settings, such as language and display options.</li>
                                    <li><strong className="text-text-primary">Analytics Cookies:</strong> Help us understand how visitors interact with our platform, allowing us to improve user experience.</li>
                                    <li><strong className="text-text-primary">Security Cookies:</strong> Used to support our security features and detect malicious activity.</li>
                                </ul>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    3. Types of Cookies We Use
                                </h2>
                                <div className="overflow-x-auto">
                                    <table className="w-full text-sm text-text-secondary border border-border-primary rounded-lg">
                                        <thead>
                                            <tr className="bg-bg-secondary">
                                                <th className="text-left p-3 text-text-primary border-b border-border-primary">Cookie Name</th>
                                                <th className="text-left p-3 text-text-primary border-b border-border-primary">Purpose</th>
                                                <th className="text-left p-3 text-text-primary border-b border-border-primary">Duration</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr className="border-b border-border-primary">
                                                <td className="p-3 font-mono text-accent-green">access_token</td>
                                                <td className="p-3">Authentication and session management</td>
                                                <td className="p-3">Session / 30 days</td>
                                            </tr>
                                            <tr className="border-b border-border-primary">
                                                <td className="p-3 font-mono text-accent-green">refresh_token</td>
                                                <td className="p-3">Token refresh for persistent sessions</td>
                                                <td className="p-3">30 days</td>
                                            </tr>
                                            <tr className="border-b border-border-primary">
                                                <td className="p-3 font-mono text-accent-green">preferences</td>
                                                <td className="p-3">User interface preferences</td>
                                                <td className="p-3">1 year</td>
                                            </tr>
                                            <tr>
                                                <td className="p-3 font-mono text-accent-green">_analytics</td>
                                                <td className="p-3">Anonymous usage analytics</td>
                                                <td className="p-3">1 year</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    4. Managing Cookies
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    Most web browsers allow you to control cookies through their settings. You can set your
                                    browser to refuse cookies, or to alert you when cookies are being sent. However, please
                                    note that disabling essential cookies may affect the functionality of our platform.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    5. Third-Party Cookies
                                </h2>
                                <p className="text-text-secondary leading-relaxed mb-4">
                                    We may use third-party services that set their own cookies. We do not control how third
                                    parties use their cookies. Please refer to the third party&apos;s own cookie policy for more
                                    information.
                                </p>
                            </section>

                            <section>
                                <h2 className="text-2xl font-heading font-semibold text-text-primary mb-4">
                                    6. Contact Us
                                </h2>
                                <p className="text-text-secondary leading-relaxed">
                                    If you have any questions about our use of cookies, please contact us at{' '}
                                    <a href="mailto:privacy@safeweb.ai" className="text-accent-green hover:text-accent-green-hover transition-colors">
                                        privacy@safeweb.ai
                                    </a>
                                </p>
                            </section>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
